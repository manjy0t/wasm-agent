//! HAL Runtime - WASM Host that provides ELASTIC HAL to WASM components
//!
//! This runtime:
//! - Loads WASM components built with cargo-component
//! - Implements WIT interfaces by bridging to native HAL
//! - Provides secure execution environment for WASM services

use anyhow::{Context, Result};
use std::path::PathBuf;
use wasmtime::component::*;
use wasmtime::{Config, Engine, OptLevel, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

mod host_impl;
pub use host_impl::HalHost;
/// Host-side mirrors of WIT types, for calling `HalHost` directly.
pub use host_impl::{
    Address, AllocationRequest, CipherAlgorithm, HashAlgorithm, Protocol, ResourceType,
};

mod wit_impl;
mod workload_access;
pub use hal_access_profile::Profile as WorkloadProfile;
pub use workload_access::check_imports as check_workload_imports;

/// Scoped storage supplied by the execution host; guest strings are names, not paths.
pub trait JobStorage: Send + Sync {
    fn open_container(&self, name: &str) -> std::result::Result<u64, String>;
    fn close_container(&self, handle: u64) -> std::result::Result<(), String>;
    fn write_object(&self, handle: u64, key: &str, data: &[u8])
        -> std::result::Result<u64, String>;
    fn read_object(&self, handle: u64, key: &str) -> std::result::Result<Vec<u8>, String>;
    fn delete_object(&self, handle: u64, key: &str) -> std::result::Result<(), String>;
    fn list_objects(&self, handle: u64) -> std::result::Result<Vec<String>, String>;
}

// Generate host-side bindings from the consolidated WIT (single package).
// Targets the `hal-consumer` world: WASM guests *import* all HAL interfaces
// and *export* run (to provide report-data for attestation).
wasmtime::component::bindgen!({
    world: "hal-consumer",
    path: "wit",
    async: true,
});

/// Runtime state that implements WASI and HAL interfaces
pub struct RuntimeState {
    wasi: WasiCtx,
    table: wasmtime::component::ResourceTable,
    pub(crate) hal: HalHost,
    limits: StoreLimits,
    restricted: bool,
    workload_scope: Option<(String, String)>,
    storage: Option<std::sync::Arc<dyn JobStorage>>,
    agent_permissions: Option<std::collections::HashSet<String>>,
    access_profile: Option<hal_access_profile::Budget>,
}

impl RuntimeState {
    /// Install once before instantiation; the workload cannot choose its identity.
    pub fn enforce_workload_policy(
        &mut self,
        tenant: &str,
        artifact: &str,
        permissions: &[String],
    ) -> Result<()> {
        anyhow::ensure!(
            self.workload_scope.is_none(),
            "workload access policy is immutable"
        );
        anyhow::ensure!(
            !tenant.is_empty() && artifact.len() == 64,
            "missing workload scope"
        );
        anyhow::ensure!(
            permissions
                .iter()
                .all(|p| ["crypto", "random", "clock", "storage"].contains(&p.as_str())),
            "unknown workload HAL permission"
        );
        self.workload_scope = Some((tenant.to_owned(), artifact.to_owned()));
        self.restrict_agent_permissions(permissions);
        Ok(())
    }

    /// A Wasm agent can only narrow the restricted job's HAL capabilities.
    /// HAL and WASI clock/random calls both consult these permissions.
    pub fn restrict_agent_permissions(&mut self, permissions: &[String]) {
        self.restricted = true;
        let requested = permissions
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        self.agent_permissions = Some(match &self.agent_permissions {
            Some(existing) => existing.intersection(&requested).cloned().collect(),
            None => requested,
        });
    }
    fn agent_allows(&self, interface: &str) -> bool {
        interface == "platform"
            || self
                .agent_permissions
                .as_ref()
                .is_none_or(|p| p.contains(interface))
    }
    fn require_agent_permission(&self, interface: &str) -> std::result::Result<(), String> {
        if !self.agent_allows(interface)
            || (interface == "storage" && self.restricted && self.storage.is_none())
        {
            Err(format!("{interface} is disabled by the agent policy"))
        } else {
            Ok(())
        }
    }
    fn agent_buffer(&self, bytes: usize) -> std::result::Result<(), String> {
        self.profile_buffer(bytes)?;
        if self.agent_permissions.is_some() && bytes > 1024 * 1024 {
            Err("HAL buffer exceeds the agent policy limit".into())
        } else {
            Ok(())
        }
    }
    pub fn restrict_to_job(&mut self, storage: std::sync::Arc<dyn JobStorage>) {
        self.restricted = true;
        self.storage = Some(storage);
    }
    fn require_unrestricted(&self, interface: &str) -> std::result::Result<(), String> {
        if self.restricted {
            Err(format!("{interface} is disabled by the tenant policy"))
        } else {
            Ok(())
        }
    }
}

impl WasiView for RuntimeState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut wasmtime::component::ResourceTable {
        &mut self.table
    }
}

/// HAL WASM Runtime
pub struct HalRuntime {
    engine: Engine,
}

impl HalRuntime {
    /// Create a new HAL runtime
    pub fn new() -> Result<Self> {
        Self::with_compilation(OptLevel::Speed, true)
    }

    /// Choose preparation cost versus generated-code speed. This does not enable
    /// a Wasmtime compilation cache or change per-job isolation/resource limits.
    pub fn with_compilation(opt_level: OptLevel, parallel: bool) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);
        config.cranelift_opt_level(opt_level);
        config.parallel_compilation(parallel);

        let engine = Engine::new(&config)?;

        Ok(Self { engine })
    }

    /// The underlying Wasmtime engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Load and instantiate a WASM component
    pub async fn load_component(&self, wasm_path: PathBuf) -> Result<Component> {
        let component = Component::from_file(&self.engine, &wasm_path)
            .with_context(|| format!("Failed to load component from {:?}", wasm_path))?;

        Ok(component)
    }

    /// Create a Linker with WASI + all HAL interfaces registered
    pub fn create_linker(&self) -> Result<Linker<RuntimeState>> {
        let mut linker = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        HalConsumer::add_to_linker(&mut linker, |state: &mut RuntimeState| state)?;
        workload_access::add_to_linker(&mut linker)?;
        Ok(linker)
    }

    /// Create a new store with HAL host implementation
    pub fn create_store(&self) -> Result<Store<RuntimeState>> {
        self.create_store_with_host(HalHost::new()?)
    }

    /// Create a store backed by a caller-provided HAL host
    pub fn create_store_with_host(&self, hal: HalHost) -> Result<Store<RuntimeState>> {
        self.create_job_store(hal, 64 * 1024 * 1024, 1_000_000_000, 3000)
    }

    /// A fresh job gets no inherited WASI environment, files, sockets or stdio.
    /// Explicit HAL imports remain available; this is not a general multi-tenant
    /// sandbox for untrusted components (HAL storage/network have wider access).
    pub fn create_job_store(
        &self,
        hal: HalHost,
        memory_bytes: usize,
        fuel: u64,
        epoch_ticks: u64,
    ) -> Result<Store<RuntimeState>> {
        let wasi = WasiCtxBuilder::new().build();
        let table = wasmtime::component::ResourceTable::new();
        let limits = StoreLimitsBuilder::new()
            .memory_size(memory_bytes)
            .instances(32)
            .memories(8)
            .tables(32)
            .table_elements(100_000)
            .build();
        let state = RuntimeState {
            wasi,
            table,
            hal,
            limits,
            restricted: false,
            workload_scope: None,
            storage: None,
            agent_permissions: None,
            access_profile: None,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(fuel)?;
        store.fuel_async_yield_interval(Some(100_000))?;
        store.set_epoch_deadline(epoch_ticks.max(1));
        Ok(store)
    }

    /// Instantiate a component with full HAL support and call its `run` export
    pub async fn run_component(&self, wasm_path: PathBuf) -> Result<Vec<u8>> {
        let component = self.load_component(wasm_path).await?;
        let linker = self.create_linker()?;
        let mut store = self.create_store()?;

        let instance = HalConsumer::instantiate_async(&mut store, &component, &linker).await?;
        let report_data = instance.elastic_hal_run().call_run(&mut store).await?;

        Ok(report_data)
    }
}

impl Default for HalRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create HAL runtime")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_creation() {
        let runtime = HalRuntime::new();
        assert!(runtime.is_ok());
    }
}

#[cfg(test)]
mod access_tests {
    use super::*;
    use crate::elastic::hal::{attestation, clock, crypto, random, storage};

    #[tokio::test]
    async fn workload_policy_is_mandatory_for_all_common_hal_imports_and_cannot_be_widened() {
        let runtime = HalRuntime::new().unwrap();
        let hal = HalHost::for_restricted_job(true).unwrap();
        let mut store = runtime
            .create_job_store(hal, 64 * 1024 * 1024, 10000, 100)
            .unwrap();
        let state = store.data_mut();
        state
            .enforce_workload_policy("alice", &"a".repeat(64), &[])
            .unwrap();
        assert!(
            crypto::Host::hash(state, vec![1], crypto::HashAlgorithm::Sha256)
                .await
                .is_err()
        );
        assert!(random::Host::get_random_bytes(state, 4).await.is_err());
        assert!(clock::Host::resolution(state).await.is_err());
        assert!(storage::Host::open_container(state, "x".into())
            .await
            .is_err());
        assert!(attestation::Host::attestation(state, vec![0; 64])
            .await
            .is_err());
        assert!(state
            .enforce_workload_policy("bob", &"b".repeat(64), &["crypto".into()])
            .is_err());
        state.restrict_agent_permissions(&["crypto".into()]);
        assert!(
            crypto::Host::hash(state, vec![1], crypto::HashAlgorithm::Sha256)
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod workload_access_tests;
