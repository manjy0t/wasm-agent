//! Each pooled worker is an actual agent.wasm instance with its own Store.
//! Host capabilities and caches are bound to the authenticated tenant.
//! The server pools these workers separately for each tenant.
use crate::executor::{ms, Job as AuthorizedJob, Prepared, Shared};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{sync::Arc, time::Instant};
use wasmtime::component::{Component, Linker, ResourceTable, __internal::async_trait};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!({ path: "wit", world: "agent", async: true });
use elastic::job_agent::services;

struct Host {
    wasi: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
    shared: Arc<Shared>,
    job: Option<AuthorizedJob>,
    prepared: Option<Arc<Prepared>>,
    executed: Option<Vec<u8>>,
    authorized: bool,
    committed: bool,
    container_ready: bool,
    rule: Option<Arc<crate::agent_policy::Rule>>,
    record: Value,
}
impl WasiView for Host {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}
impl Host {
    fn event(&mut self, name: &str) {
        self.record["security_trace"]
            .as_array_mut()
            .unwrap()
            .push(json!(name));
    }
    fn require_authorized(&self) -> Result<()> {
        ensure!(
            self.authorized && !self.committed,
            "agent must authorize this job before using capabilities"
        );
        Ok(())
    }
    fn count(&mut self, key: &str) -> Result<()> {
        ensure!(self.job.is_some(), "no active job");
        let n = self.record["host_calls"][key].as_u64().unwrap_or(0) + 1;
        self.record["host_calls"][key] = json!(n);
        ensure!(n == 1, "agent called {key} more than once for this job");
        Ok(())
    }
    async fn prepare(&mut self) -> Result<()> {
        self.require_authorized()?;
        ensure!(
            !self.shared.args.user_containers,
            "workload preparation must occur in the user container"
        );
        self.count("prepare")?;
        ensure!(self.prepared.is_none(), "already prepared");
        let start = Instant::now();
        let result = self.shared.prepare(self.job.as_ref().unwrap()).await;
        self.record["timings_ms"]["prepare_wait"] = json!(ms(start));
        let (prepared, state) = result?;
        self.record["cache_status"] = json!(state);
        // This is work done once for a preparation, not once per waiter. Cache
        // hits deliberately do not repeat a historical compile/download timing.
        if state != "hit" {
            self.record["preparation"] = prepared.preparation.clone();
        }
        self.record["preparation_work_owner"] = json!(state == "miss" || state == "bypass");
        self.prepared = Some(prepared);
        self.event("prepared");
        Ok(())
    }
    async fn execute(&mut self) -> Result<Vec<u8>> {
        self.require_authorized()?;
        ensure!(
            !self.shared.args.user_containers,
            "workload execution must occur in the user container"
        );
        self.count("execute")?;
        let prepared = self
            .prepared
            .clone()
            .context("prepare workload before execution")?;
        let data = self
            .shared
            .execute(
                self.job.as_ref().context("no active job")?,
                &prepared,
                &mut self.record,
            )
            .await?;
        self.executed = Some(data.clone());
        self.event("executed_in_fresh_instance");
        Ok(data)
    }
}

#[async_trait]
impl services::Host for Host {
    async fn launch_workload(&mut self) -> Result<Vec<u8>, String> {
        self.ensure_user_container().await?;
        self.run_in_user_container().await
    }
    async fn ensure_user_container(&mut self) -> std::result::Result<(), String> {
        let outcome = async {
            self.require_authorized()?;
            self.count("ensure_user_container")?;
            let pool = self
                .shared
                .containers
                .get()
                .context("user containers are not enabled")?;
            let start = Instant::now();
            let info = pool
                .ensure(self.job.as_ref().context("no active job")?)
                .await?;
            self.record["timings_ms"]["container_acquire"] = json!(ms(start));
            self.record["container"] = info;
            self.container_ready = true;
            self.event("user_container_ready");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        outcome.map_err(|e| format!("{e:#}"))
    }

    async fn run_in_user_container(&mut self) -> std::result::Result<Vec<u8>, String> {
        let outcome = async {
            self.require_authorized()?;
            self.count("run_in_user_container")?;
            ensure!(
                self.container_ready,
                "agent must ensure its user container first"
            );
            let pool = self
                .shared
                .containers
                .get()
                .context("user containers are not enabled")?;
            let job = self.job.as_ref().context("no active job")?;
            let start = Instant::now();
            let result = pool.run(job).await?;
            let bytes = crate::containers::validate_result(
                job,
                &result,
                self.shared.args.max_output_bytes,
            )?;
            if let Some(authority) = &self.shared.authorization {
                let claims: crate::tickets_core::Claims =
                    serde_json::from_str(&job.ticket.as_ref().context("ticket missing")?.payload)?;
                ensure!(
                    result["job_authorization"]["verified"] == true
                        && result["job_authorization"]["worker_checked"] == true
                        && result["job_authorization"]["nonce"] == claims.nonce
                        && result["job_authorization"]["epoch"] == authority.epoch,
                    "worker did not confirm this job's authorization"
                );
                self.record["job_authorization"]["worker_checked"] = json!(true);
            }
            self.record["timings_ms"]["container_round_trip"] = json!(ms(start));
            // Copy measurements and runtime profile diagnostics, never job authorization,
            // identity, commit state or a replacement security trace.
            for field in [
                "cache_status",
                "preparation",
                "preparation_work_owner",
                "workload_access_profile",
            ] {
                if let Some(value) = result.get(field) {
                    self.record[field] = value.clone();
                }
            }
            self.record["container"]["worker_timings_ms"] = result["timings_ms"].clone();
            self.record["container"]["platform_metadata_source"] = json!("enclosing-broker");
            self.record["container"]["attestation_devices_exposed"] = json!(false);
            self.executed = Some(bytes.clone());
            self.event("executed_in_user_container");
            Ok::<_, anyhow::Error>(bytes)
        }
        .await;
        outcome.map_err(|e| format!("{e:#}"))
    }
    async fn authorize_cache(
        &mut self,
        selected: services::CachePolicy,
    ) -> std::result::Result<(), String> {
        let result = (|| -> Result<()> {
            self.count("authorize_cache")?;
            let job = self.job.as_mut().context("no active job")?;
            if let Some(authority) = &self.shared.authorization {
                let claims = authority.consume(job)?;
                self.record["job_authorization"] = json!({"verified":true,"scheme":"ed25519-user-ticket-v1",
                    "tenant":claims.tenant,"audience":claims.audience,"epoch":claims.epoch,
                    "nonce":claims.nonce,"expires_unix":claims.expires_unix,
                    "ticket_sha256":crate::cache::hash(job.ticket.as_ref().unwrap().payload.as_bytes()),
                    "helper_checked":true,"broker_checked":true,"worker_checked":false});
                self.record["security_trace"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("signed_job_authorized"));
            } else {
                ensure!(
                    job.ticket.is_none(),
                    "signed job submitted to an unsigned host"
                );
            }
            let expected = job.reuse && self.rule.as_ref().is_none_or(|r| r.cache);
            ensure!(
                matches!(selected, services::CachePolicy::Reuse) == expected,
                "agent attempted to change the authorized cache plan"
            );
            job.reuse = expected;
            self.record["cache_policy"] = json!(if expected { "reuse" } else { "bypass" });
            self.authorized = true;
            self.event("policy_accepted");
            Ok(())
        })();
        result.map_err(|e| format!("{e:#}"))
    }
    async fn find_prepared(&mut self) -> std::result::Result<bool, String> {
        let result = (|| -> Result<bool> {
            self.require_authorized()?;
            ensure!(
                !self.shared.args.user_containers,
                "cache lookup must occur in the user container"
            );
            ensure!(
                self.prepared.is_none() && self.executed.is_none(),
                "cache lookup must precede preparation and execution"
            );
            self.count("find_prepared")?;
            let job = self.job.as_ref().unwrap();
            ensure!(job.reuse, "bypass jobs cannot read the cache");
            let start = Instant::now();
            self.prepared = self.shared.lookup(job)?;
            self.record["timings_ms"]["cache_lookup"] = json!(ms(start));
            if self.prepared.is_some() {
                self.record["cache_status"] = json!("hit");
                self.event("private_cache_hit");
            }
            Ok(self.prepared.is_some())
        })();
        result.map_err(|e| format!("{e:#}"))
    }
    async fn prepare(&mut self) -> std::result::Result<(), String> {
        Host::prepare(self).await.map_err(|e| format!("{e:#}"))
    }
    async fn execute(&mut self) -> std::result::Result<Vec<u8>, String> {
        Host::execute(self).await.map_err(|e| format!("{e:#}"))
    }
    async fn commit_result(&mut self) -> std::result::Result<(), String> {
        let result = (|| -> Result<()> {
            self.require_authorized()?;
            self.count("commit_result")?;
            let data = self
                .executed
                .as_ref()
                .context("cannot commit before execution")?;
            if let Some(rule) = &self.rule {
                rule.validate(data)?;
            }
            self.record["result_sha256"] = json!(crate::cache::hash(data));
            self.record["agent_result_validation"] = json!(if self.rule.is_some() {
                "passed"
            } else {
                "size_only"
            });
            self.committed = true;
            self.event("result_committed");
            Ok(())
        })();
        result.map_err(|e| format!("{e:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use services::Host as _;

    #[tokio::test]
    async fn native_gate_rejects_forgery_even_if_helper_skips_its_signature_check() {
        let (_dir, mut h) = host();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let context = crate::tickets_core::Context {
            tenant: "legacy".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            audience: "test".into(),
            epoch: "e".repeat(64),
            max_ttl_seconds: 120,
            component: "test.wasm".into(),
            sha256: "0".repeat(64),
            artifact_bytes: 8,
            rule_sha256: "f".repeat(64),
            cache_allowed: false,
            isolation: "in-process".into(),
            max_output_bytes: 4096,
            result_rule: json!({"kind":"bounded"}),
        };
        Arc::get_mut(&mut h.shared).unwrap().authorization =
            Some(crate::authorization::Authority::test_context(context));
        h.job.as_mut().unwrap().ticket = Some(crate::tickets_core::Ticket {
            payload: "{}".into(),
            signature: "0".repeat(128),
        });
        assert!(h
            .authorize_cache(services::CachePolicy::Bypass)
            .await
            .unwrap_err()
            .contains("signature"));
        assert!(!h.authorized);
        assert!(services::Host::prepare(&mut h).await.is_err());
        assert!(h.ensure_user_container().await.is_err());
    }

    #[tokio::test]
    async fn real_helper_cannot_replace_initial_authorization_rules() {
        let (_dir, h) = host();
        let bytes =
            std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("dist/agent.wasm"))
                .unwrap();
        let factory = Factory::new(&bytes).unwrap();
        let mut vm = factory.worker(h.shared).await.unwrap();
        vm.instance
            .call_initialize_authorization(&mut vm.store, "")
            .await
            .unwrap()
            .unwrap();
        let error = vm
            .instance
            .call_initialize_authorization(&mut vm.store, "")
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.contains("immutable"));
    }

    #[tokio::test]
    async fn container_capability_requires_authorization_and_enablement() {
        let (_dir, mut h) = host();
        assert!(h.ensure_user_container().await.is_err());
        assert!(h.run_in_user_container().await.is_err());
        h.authorize_cache(services::CachePolicy::Bypass)
            .await
            .unwrap();
        assert!(h.ensure_user_container().await.is_err());
        assert!(h.run_in_user_container().await.is_err());
        assert!(!h.container_ready);
        assert!(h.executed.is_none());
    }

    #[tokio::test]
    async fn guest_cannot_fall_back_to_in_process_execution() {
        let (_dir, mut h) = host();
        Arc::get_mut(&mut h.shared).unwrap().args.user_containers = true;
        h.authorize_cache(services::CachePolicy::Bypass)
            .await
            .unwrap();
        assert!(h.find_prepared().await.unwrap_err().contains("container"));
        assert!(services::Host::prepare(&mut h)
            .await
            .unwrap_err()
            .contains("container"));
        assert!(services::Host::execute(&mut h)
            .await
            .unwrap_err()
            .contains("container"));
        assert!(h
            .run_in_user_container()
            .await
            .unwrap_err()
            .contains("ensure"));
        assert!(h.commit_result().await.is_err());
        assert_eq!(h.shared.stats()["executions"], 0);
        assert_eq!(h.shared.stats()["compiles"], 0);
    }

    fn host() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let args = crate::Args::parse_from([
            "test",
            "--allow-non-tee",
            "--file-server",
            "http://127.0.0.1:1/",
            "--token-file",
            "unused",
            "--cache-dir",
            dir.path().join("cache").to_str().unwrap(),
        ]);
        let shared = Shared::new(args).unwrap();
        let host = Host {
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new().build(),
            shared,
            job: Some(AuthorizedJob {
                id: "test".into(),
                tenant: "legacy".into(),
                name: "test.wasm".into(),
                sha: "0".repeat(64),
                size: 8,
                reuse: false,
                ticket: None,
            }),
            prepared: None,
            executed: None,
            authorized: false,
            committed: false,
            container_ready: false,
            rule: None,
            record: json!({"host_calls":{}, "timings_ms":{}, "security_trace":[]}),
        };
        (dir, host)
    }

    #[tokio::test]
    async fn guest_cannot_use_imports_before_authorization_or_upgrade_bypass() {
        let (_dir, mut h) = host();
        assert!(services::Host::prepare(&mut h).await.is_err());
        assert!(services::Host::execute(&mut h).await.is_err());
        assert!(h.find_prepared().await.is_err());
        assert!(h.commit_result().await.is_err());
        assert!(h
            .authorize_cache(services::CachePolicy::Reuse)
            .await
            .is_err());
        assert!(!h.authorized);
        assert_eq!(h.shared.stats()["downloads"], 0);
        assert_eq!(h.shared.stats()["executions"], 0);
    }

    #[tokio::test]
    async fn guest_cannot_commit_wrong_output_even_if_it_skips_its_own_validation() {
        let (_dir, mut h) = host();
        h.rule = Some(Arc::new(crate::agent_policy::Rule {
            component: "test.wasm".into(),
            cache: false,
            ttl_ms: 1000,
            permissions: vec![],
            access_profile: None,
            memory_mib: 64,
            fuel: 1000,
            execution_ms: 1000,
            output_bytes: 32,
            worker_max_jobs: 1,
            validation: json!({"kind":"hex", "value":"abcd"}),
        }));
        h.authorize_cache(services::CachePolicy::Bypass)
            .await
            .unwrap();
        // Represents the bytes retained by the host after workload execution.
        h.executed = Some(vec![0]);
        assert!(h
            .commit_result()
            .await
            .unwrap_err()
            .contains("result validation failed"));
        assert!(!h.committed);
        assert!(h.record.get("result_sha256").is_none());
    }

    #[tokio::test]
    async fn committed_job_cannot_execute_or_commit_again() {
        let (_dir, mut h) = host();
        h.authorize_cache(services::CachePolicy::Bypass)
            .await
            .unwrap();
        h.executed = Some(vec![0]);
        h.commit_result().await.unwrap();
        assert!(h.commit_result().await.is_err());
        assert!(services::Host::execute(&mut h).await.is_err());
        assert!(services::Host::prepare(&mut h).await.is_err());
        assert!(h.find_prepared().await.is_err());
    }
}

pub struct Factory {
    engine: Engine,
    component: Component,
    linker: Linker<Host>,
}
impl Factory {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .async_support(true)
            .consume_fuel(true);
        let engine = Engine::new(&config)?;
        let component = Component::from_binary(&engine, bytes)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        Agent::add_to_linker(&mut linker, |s: &mut Host| s)?;
        // Check imports before announcing readiness (including the new WIT ABI).
        let pre = linker
            .instantiate_pre(&component)
            .context("agent imports do not match this HAL interface")?;
        AgentPre::new(pre).context("agent exports do not match this HAL interface")?;
        Ok(Self {
            engine,
            component,
            linker,
        })
    }
    pub async fn worker(&self, shared: Arc<Shared>) -> Result<Vm> {
        let host = Host {
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(32 * 1024 * 1024)
                .instances(32)
                .memories(8)
                .tables(32)
                .table_elements(100_000)
                .build(),
            shared,
            job: None,
            prepared: None,
            executed: None,
            authorized: false,
            committed: false,
            container_ready: false,
            rule: None,
            record: Value::Null,
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(50_000_000)?;
        store.fuel_async_yield_interval(Some(100_000))?;
        let instance = Agent::instantiate_async(&mut store, &self.component, &self.linker).await?;
        let configuration = match &store.data().shared.args.agent_configuration {
            Some(path) => {
                ensure!(
                    std::fs::metadata(path)?.len() <= 65536,
                    "agent configuration too large"
                );
                std::fs::read_to_string(path)?
            }
            None => "{}".into(),
        };
        // Do not include the guest error or private configuration in diagnostics.
        ensure!(
            matches!(
                instance
                    .call_initialize_configuration(&mut store, &configuration)
                    .await,
                Ok(Ok(()))
            ),
            "agent configuration initialization failed"
        );
        Ok(Vm {
            instance,
            store,
            poisoned: false,
            runs: 0,
            authorization_initialized: false,
        })
    }
}

pub struct Vm {
    instance: Agent,
    store: Store<Host>,
    pub poisoned: bool,
    pub runs: u64,
    authorization_initialized: bool,
}
impl Vm {
    pub async fn run(&mut self, job: AuthorizedJob) -> Value {
        self.runs += 1;
        let rule = match self.store.data().shared.agent_rule(&job) {
            Ok(rule) => rule,
            Err(error) => {
                return json!({"status":"error", "job_id":job.id, "error":error.to_string(), "timings_ms":{}})
            }
        };
        let policy_digest = self
            .store
            .data()
            .shared
            .agent_policy
            .as_ref()
            .map(|p| p.digest.clone())
            .unwrap_or_default();
        let request = services::Job {
            id: job.id.clone(),
            tenant: job.tenant.clone(),
            artifact_sha256: job.sha.clone(),
            component: job.name.clone(),
            artifact_bytes: job.size,
            ticket_json: job
                .ticket
                .as_ref()
                .map(|t| serde_json::to_string(t).unwrap())
                .unwrap_or_default(),
            policy: if job.reuse {
                services::CachePolicy::Reuse
            } else {
                services::CachePolicy::Bypass
            },
            limits: services::Constraints {
                policy_sha256: policy_digest.clone(),
                cache_allowed: rule.as_ref().is_none_or(|r| r.cache),
                max_output_bytes: rule
                    .as_ref()
                    .map_or(self.store.data().shared.args.max_output_bytes, |r| {
                        r.output_bytes
                    }) as u32,
                result_rule_json: rule
                    .as_ref()
                    .map_or(json!({"kind":"bounded"}), |r| r.validation.clone())
                    .to_string(),
                container_required: self.store.data().shared.args.user_containers,
            },
        };
        if !self.authorization_initialized {
            let context = self
                .store
                .data()
                .shared
                .authorization
                .as_ref()
                .map(|a| a.context(&job).and_then(|c| Ok(serde_json::to_string(c)?)))
                .transpose();
            let context = match context {
                Ok(context) => context.unwrap_or_default(),
                Err(error) => {
                    return json!({"status":"error","job_id":job.id,"error":error.to_string(),"timings_ms":{}})
                }
            };
            match self
                .instance
                .call_initialize_authorization(&mut self.store, &context)
                .await
            {
                Ok(Ok(())) => self.authorization_initialized = true,
                result => {
                    self.poisoned = true;
                    return json!({"status":"error","job_id":job.id,"error":format!("helper authorization setup failed: {result:?}"),"timings_ms":{}});
                }
            }
        }
        let host = self.store.data_mut();
        host.record = json!({ "protocol": 1, "job_id": job.id, "component": job.name,
            "sha256": job.sha, "artifact_bytes": job.size, "cache_policy": if job.reuse { "reuse" } else { "bypass" },
            "cache_status": "none", "preparation_work_owner": false,
            "host_calls": {}, "timings_ms": {}, "attestation_verified": false, "security_trace":[],
            "runtime_reused": true, "workload_instance_reused": false, "agent_kind": "wasm" });
        host.record["requested_cache_policy"] = host.record["cache_policy"].clone();
        if let Some(rule) = &rule {
            host.record["agent_security"] = rule.description();
            host.record["agent_security"]["policy_sha256"] = json!(policy_digest);
            host.record["agent_security"]["worker_scope"] = json!("tenant-and-artifact");
        }
        host.rule = rule;
        host.authorized = false;
        host.committed = false;
        host.container_ready = false;
        host.job = Some(job);
        let start = Instant::now();
        let outcome = async {
            self.store.set_fuel(50_000_000)?;
            let out = match self
                .instance
                .call_handle_job(&mut self.store, &request)
                .await
            {
                Ok(result) => result.map_err(anyhow::Error::msg)?,
                Err(error) => {
                    self.poisoned = true;
                    return Err(error);
                }
            };
            ensure!(
                self.store.data().committed,
                "agent returned without committing the validated result"
            );
            ensure!(
                self.store.data().executed.as_ref() == Some(&out.data),
                "agent result differs from native workload result"
            );
            self.store.data_mut().record["agent_worker_job_number"] = json!(out.worker_job_number);
            Ok::<_, anyhow::Error>(out.data)
        }
        .await;
        let host = self.store.data_mut();
        match outcome {
            Ok(data) => {
                host.record["status"] = json!("ok");
                host.record["result"] = json!({ "bytes": data.len(), "hex": hex::encode(&data),
                    "utf8": String::from_utf8(data).ok() });
            }
            Err(error) => {
                self.poisoned = true;
                host.record["status"] = json!("error");
                host.record["error"] = json!(format!("{error:#}"));
            }
        }
        host.job = None;
        let release = Instant::now();
        host.prepared = None;
        host.record["timings_ms"]["component_release"] = json!(ms(release));
        host.executed = None;
        host.rule = None;
        host.record["timings_ms"]["agent_job"] = json!(ms(start));
        std::mem::take(&mut host.record)
    }
}
