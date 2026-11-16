//! Per-workload enforcement. Compiled code may be shared; this state never is.
use crate::{RuntimeState, WorkloadProfile};
use anyhow::{ensure, Result};
use wasmtime::component::{types::ComponentItem, Component, Linker};
use wasmtime::{Engine, StoreContextMut};
use wasmtime_wasi::{
    bindings::{
        clocks::{monotonic_clock, wall_clock},
        random::{insecure, insecure_seed, random},
    },
    WasiImpl,
};

impl RuntimeState {
    /// Optional finer permissions can only narrow the already-installed rule.
    pub fn enforce_access_profile(&mut self, profile: &WorkloadProfile) -> Result<()> {
        ensure!(
            self.access_profile.is_none(),
            "workload profile is immutable"
        );
        let (_, artifact) = self
            .workload_scope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("install workload rule first"))?;
        let permissions = self
            .agent_permissions
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing workload permissions"))?
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        self.access_profile = Some(
            hal_access_profile::Budget::new(profile.clone(), artifact, &permissions)
                .map_err(anyhow::Error::msg)?,
        );
        Ok(())
    }
    pub(crate) fn profile_call(&mut self, operation: &str) -> std::result::Result<(), String> {
        match &mut self.access_profile {
            Some(p) => p.authorize(operation),
            None => Ok(()),
        }
    }
    pub(crate) fn profile_buffer(&self, bytes: usize) -> std::result::Result<(), String> {
        match &self.access_profile {
            Some(p) => p.buffer(bytes),
            None => Ok(()),
        }
    }
    pub fn access_profile_report(&self) -> Option<serde_json::Value> {
        self.access_profile.as_ref().map(|p| serde_json::json!({
            "version":p.profile.version, "artifact_sha256":p.profile.artifact_sha256,
            "enforced":true, "host_call_attempts":p.attempted, "denied_calls":p.denied,
            "max_host_calls":p.profile.max_host_calls, "max_buffer_bytes":p.profile.max_buffer_bytes,
            "operations":p.profile.operations,
        }))
    }
    fn wasi_call(&mut self, permission: &str, operation: &str) -> Result<()> {
        self.require_agent_permission(permission)
            .map_err(anyhow::Error::msg)?;
        self.profile_call(operation).map_err(anyhow::Error::msg)
    }
    fn wasi_bytes(&self, length: u64) -> Result<()> {
        let length = usize::try_from(length)?;
        self.agent_buffer(length).map_err(anyhow::Error::msg)
    }
    fn wasi_sleep(&mut self) -> Result<()> {
        self.wasi_call("clock", "wasi.clock")?;
        ensure!(
            self.agent_permissions.is_none(),
            "WASI clock subscriptions are disabled by the workload policy"
        );
        Ok(())
    }
}

/// Check the compiled component on every launch, including cache hits. Known
/// denied HAL interfaces have rejecting implementations. WASI has no inherited
/// environment, directories, sockets or stdio; unknown interfaces are rejected.
pub fn check_imports(engine: &Engine, component: &Component) -> Result<()> {
    for (name, ty) in component.component_type().imports(engine) {
        ensure!(
            hal_access_profile::known_interface(name)
                && matches!(ty, ComponentItem::ComponentInstance(_)),
            "workload profile rejects unknown host interface: {name}"
        );
    }
    Ok(())
}

// Implement the generated traits so an upstream interface change fails to
// compile instead of quietly leaving an unguarded function or version alias.
impl random::Host for RuntimeState {
    fn get_random_bytes(&mut self, len: u64) -> Result<Vec<u8>> {
        self.wasi_call("random", "wasi.random")?;
        self.wasi_bytes(len)?;
        random::Host::get_random_bytes(&mut WasiImpl(self), len)
    }
    fn get_random_u64(&mut self) -> Result<u64> {
        self.wasi_call("random", "wasi.random")?;
        random::Host::get_random_u64(&mut WasiImpl(self))
    }
}
impl insecure::Host for RuntimeState {
    fn get_insecure_random_bytes(&mut self, len: u64) -> Result<Vec<u8>> {
        self.wasi_call("random", "wasi.insecure-random")?;
        self.wasi_bytes(len)?;
        insecure::Host::get_insecure_random_bytes(&mut WasiImpl(self), len)
    }
    fn get_insecure_random_u64(&mut self) -> Result<u64> {
        self.wasi_call("random", "wasi.insecure-random")?;
        insecure::Host::get_insecure_random_u64(&mut WasiImpl(self))
    }
}
impl insecure_seed::Host for RuntimeState {
    fn insecure_seed(&mut self) -> Result<(u64, u64)> {
        self.wasi_call("random", "wasi.insecure-random")?;
        insecure_seed::Host::insecure_seed(&mut WasiImpl(self))
    }
}
impl wall_clock::Host for RuntimeState {
    fn now(&mut self) -> Result<wall_clock::Datetime> {
        self.wasi_call("clock", "wasi.clock")?;
        wall_clock::Host::now(&mut WasiImpl(self))
    }
    fn resolution(&mut self) -> Result<wall_clock::Datetime> {
        self.wasi_call("clock", "wasi.clock")?;
        wall_clock::Host::resolution(&mut WasiImpl(self))
    }
}
impl monotonic_clock::Host for RuntimeState {
    fn now(&mut self) -> Result<u64> {
        self.wasi_call("clock", "wasi.clock")?;
        monotonic_clock::Host::now(&mut WasiImpl(self))
    }
    fn resolution(&mut self) -> Result<u64> {
        self.wasi_call("clock", "wasi.clock")?;
        monotonic_clock::Host::resolution(&mut WasiImpl(self))
    }
    fn subscribe_instant(
        &mut self,
        when: u64,
    ) -> Result<wasmtime::component::Resource<wasmtime_wasi::Pollable>> {
        self.wasi_sleep()?;
        monotonic_clock::Host::subscribe_instant(&mut WasiImpl(self), when)
    }
    fn subscribe_duration(
        &mut self,
        duration: u64,
    ) -> Result<wasmtime::component::Resource<wasmtime_wasi::Pollable>> {
        self.wasi_sleep()?;
        monotonic_clock::Host::subscribe_duration(&mut WasiImpl(self), duration)
    }
}

/// Register the exact versions generated by the pinned WASI bindings. No
/// provider is replaced with fake data, and compatible aliases use these guards.
pub fn add_to_linker(linker: &mut Linker<RuntimeState>) -> Result<()> {
    linker.allow_shadowing(true);
    random::add_to_linker(linker, |s: &mut RuntimeState| s)?;
    insecure::add_to_linker(linker, |s: &mut RuntimeState| s)?;
    insecure_seed::add_to_linker(linker, |s: &mut RuntimeState| s)?;
    wall_clock::add_to_linker(linker, |s: &mut RuntimeState| s)?;
    monotonic_clock::add_to_linker(linker, |s: &mut RuntimeState| s)?;
    use crate::elastic::hal::platform::Host as _;
    let mut i = linker.instance("elastic:hal/platform@0.1.0")?;
    i.func_wrap_async(
        "get-platform-info",
        |mut cx: StoreContextMut<'_, RuntimeState>, (): ()| {
            Box::new(async move {
                let s = cx.data_mut();
                s.profile_call("platform.metadata")
                    .map_err(anyhow::Error::msg)?;
                Ok((s.get_platform_info().await,))
            })
        },
    )?;
    i.func_wrap_async(
        "list-capabilities",
        |mut cx: StoreContextMut<'_, RuntimeState>, (): ()| {
            Box::new(async move {
                let s = cx.data_mut();
                s.profile_call("platform.metadata")
                    .map_err(anyhow::Error::msg)?;
                Ok((s.list_capabilities().await,))
            })
        },
    )?;
    i.func_wrap_async(
        "has-capability",
        |mut cx: StoreContextMut<'_, RuntimeState>, (name,): (String,)| {
            Box::new(async move {
                let s = cx.data_mut();
                s.profile_call("platform.metadata")
                    .map_err(anyhow::Error::msg)?;
                s.profile_buffer(name.len()).map_err(anyhow::Error::msg)?;
                Ok((s.has_capability(name).await,))
            })
        },
    )?;
    linker.allow_shadowing(false);
    Ok(())
}
