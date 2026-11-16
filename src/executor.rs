//! Shared native capabilities: acquisition, verification, compilation and execution.
//! Components are always compiled from verified Wasm, never deserialized from a
//! network-supplied native-code cache.
use crate::{agent_policy, cache, compiler::Compiler, protocol, storage, tenancy, Args};
use anyhow::{ensure, Context, Result};
use hal_runtime::{HalConsumer, HalHost, HalRuntime, RuntimeState};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::sync::{watch, Semaphore};
use wasmtime::component::{Component, Linker};

pub fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn lock_native_storage_root(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

    cache::private_directory(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join(".lock"))?;
    ensure!(
        file.metadata()?.is_file(),
        "state lock must be a regular file"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "state directory already in use"
    );
    Ok(file)
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub sha: String,
    pub size: u64,
    pub reuse: bool,
    pub tenant: String,
    pub ticket: Option<crate::tickets_core::Ticket>,
}
impl Job {
    pub fn parse(v: &Value, maximum: usize) -> Result<Self> {
        ensure!(v["protocol"] == protocol::VERSION, "unsupported protocol");
        ensure!(
            v.get("input").is_none(),
            "this workload ABI is run() with no input argument"
        );
        let id = protocol::string(v, "job_id")?.to_owned();
        let name = protocol::string(v, "component")?.to_owned();
        let sha = protocol::string(v, "sha256")?.to_ascii_lowercase();
        let size = protocol::unsigned(v, "artifact_bytes")?;
        ensure!(protocol::safe_name(&id), "invalid job_id");
        ensure!(
            protocol::safe_name(&name) && name.ends_with(".wasm"),
            "invalid component filename"
        );
        ensure!(protocol::valid_sha(&sha), "invalid SHA-256");
        ensure!(
            size >= 8 && size <= maximum as u64,
            "invalid component size"
        );
        let reuse = match protocol::string(v, "cache")? {
            "reuse" => true,
            "bypass" => false,
            _ => anyhow::bail!("cache must be reuse or bypass"),
        };
        Ok(Self {
            id,
            name,
            sha,
            size,
            reuse,
            tenant: "legacy".into(),
            ticket: v
                .get("job_ticket")
                .map(|t| serde_json::from_value(t.clone()))
                .transpose()?,
        })
    }
}

pub struct Prepared {
    pub tenant: String,
    pub sha: String,
    pub component: Component,
    pub size: u64,
    pub preparation: Value,
    pub expires: Option<Instant>,
}
type BuildResult = std::result::Result<Arc<Prepared>, String>;
struct Entry {
    prepared: Arc<Prepared>,
    used: u64,
}
#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    flights: HashMap<String, watch::Receiver<Option<BuildResult>>>,
    clock: u64,
    expired: u64,
}
impl State {
    fn expire(&mut self) {
        let before = self.entries.len();
        self.entries.retain(|_, e| {
            e.prepared
                .expires
                .is_none_or(|until| until > Instant::now())
        });
        self.expired += (before - self.entries.len()) as u64;
    }
}

struct Namespace {
    // Public native execution has no disk cache object, even at startup.
    disk: Option<Arc<Mutex<cache::Cache>>>,
    state: Mutex<State>,
    entries: usize,
    memory_cache_bytes: u64,
    storage: HashMap<String, Arc<storage::PrivateStorage>>,
    permits: Arc<Semaphore>,
}

pub struct Shared {
    pub containers: std::sync::OnceLock<Arc<crate::containers::Pool>>,
    pub args: Args,
    pub runtime: HalRuntime,
    pub linker: Linker<RuntimeState>,
    pub platform: String,
    client: reqwest::Client,
    namespaces: HashMap<String, Namespace>,
    pub policy: Option<tenancy::Policy>,
    pub agent_policy: Option<agent_policy::Policy>,
    pub authorization: Option<crate::authorization::Authority>,
    _root_lock: Option<cache::Cache>,
    _native_storage_lock: Option<std::fs::File>,
    downloads: Arc<Semaphore>,
    compiler: Compiler,
    executions: Arc<Semaphore>,
    preparations: Arc<Semaphore>,
    pub download_count: AtomicU64,
    pub shared_count: AtomicU64,
    pub execution_count: AtomicU64,
}

impl Shared {
    pub fn new(args: Args) -> Result<Arc<Self>> {
        let hal = if let Some(worker) = &args.container_worker {
            worker.hal()?
        } else if args.tenant_policy.is_some() {
            HalHost::for_restricted_job(args.allow_non_tee)?
        } else {
            Self::make_hal(args.allow_non_tee)?
        };
        let platform = if args.allow_non_tee {
            "NON_TEE_TEST_ONLY".into()
        } else {
            hal.platform_info().platform_type
        };
        let runtime = HalRuntime::with_compilation(
            args.compile_opt_level.wasmtime(),
            args.parallel_compilation,
        )?;
        let linker = runtime.create_linker()?;
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(path) = &args.file_token_file {
            let credential = tenancy::token(path)?;
            let mut value =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}"))?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
        let mut client_builder = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(args.download_timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(std::time::Duration::from_secs(5))
            .pool_max_idle_per_host(args.downloads);
        if let Some(path) = &args.file_ca_cert {
            let pem = cache::read_bounded(path, 64 * 1024)?;
            client_builder = client_builder.add_root_certificate(
                reqwest::Certificate::from_pem(&pem)
                    .context("invalid artifact-server CA certificate")?,
            );
        }
        let client = client_builder.build()?;
        let policy = args
            .tenant_policy
            .as_ref()
            .map(|p| {
                tenancy::Policy::load(
                    p,
                    &tenancy::token(&args.token_file)?,
                    args.max_component_bytes,
                    args.max_inflight,
                )
            })
            .transpose()?;
        let agent_policy = args
            .agent_policy
            .as_ref()
            .map(|path| {
                ensure!(
                    args.mode == crate::Mode::Wasm,
                    "agent-policy requires --mode wasm"
                );
                agent_policy::Policy::load(
                    path,
                    policy
                        .as_ref()
                        .context("agent-policy requires --tenant-policy")?,
                    &args,
                )
            })
            .transpose()?;
        let authorization = args
            .job_authorization
            .as_ref()
            .map(|path| {
                ensure!(
                    args.mode == crate::Mode::Wasm,
                    "signed job policy requires Wasm agent mode"
                );
                crate::authorization::Authority::load(
                    path,
                    policy
                        .as_ref()
                        .context("signed jobs require tenant policy")?,
                    agent_policy
                        .as_ref()
                        .context("signed jobs require agent policy")?,
                    &args,
                )
            })
            .transpose()?;
        let mut namespaces = HashMap::new();
        let mut root_lock = None;
        let mut native_storage_lock = None;
        let uncached = args.mode == crate::Mode::Native;
        if let Some(policy) = &policy {
            if let Some(path) = &args.file_token_file {
                let file_token = tenancy::token(path)?;
                ensure!(
                    policy.authenticate(&file_token).is_none()
                        && !tenancy::same_token(&file_token, &tenancy::token(&args.token_file)?),
                    "file-server credential must be distinct from worker and operator credentials"
                );
            }
            // Hold the top-level lock too: two processes cannot independently
            // account for the same persistent tenant storage or cache.
            if uncached {
                // Keep the storage accounting lock without inspecting, cleaning
                // or evicting any earlier agent code-cache files.
                native_storage_lock = Some(lock_native_storage_root(&args.cache_dir)?);
            } else {
                root_lock = Some(cache::Cache::open(&args.cache_dir, u64::MAX)?);
            }
            let root = args.cache_dir.join("tenants");
            cache::private_directory(&root)?;
            for tenant in &policy.tenants {
                let directory = root.join(&tenant.id);
                cache::private_directory(&directory)?;
                let storage_root = directory.join("storage");
                cache::private_directory(&storage_root)?;
                let budget = Arc::new(storage::Budget {
                    root: storage_root,
                    bytes: tenant.storage_bytes,
                    entries: tenant.storage_entries,
                    lock: Mutex::new(()),
                });
                let mut storage = HashMap::new();
                for (sha, _) in tenant.artifacts.values() {
                    if !storage.contains_key(sha) {
                        storage.insert(
                            sha.clone(),
                            Arc::new(storage::PrivateStorage::new(budget.clone(), sha)?),
                        );
                    }
                }
                namespaces.insert(
                    tenant.id.clone(),
                    Namespace {
                        disk: if uncached {
                            None
                        } else {
                            Some(Arc::new(Mutex::new(cache::Cache::open(
                                // Leave the earlier on-disk workload cache untouched.
                                // This profile needs only an exclusive namespace lock.
                                &directory.join(if agent_policy.is_some() {
                                    "agent-memory-cache"
                                } else {
                                    "cache"
                                }),
                                tenant.cache_bytes,
                            )?)))
                        },
                        state: Mutex::new(State::default()),
                        entries: tenant.cache_entries,
                        memory_cache_bytes: tenant.cache_bytes,
                        storage,
                        permits: Arc::new(Semaphore::new(tenant.max_inflight)),
                    },
                );
            }
        } else {
            namespaces.insert(
                "legacy".into(),
                Namespace {
                    disk: if uncached {
                        None
                    } else {
                        Some(Arc::new(Mutex::new(cache::Cache::open(
                            &args.cache_dir,
                            args.disk_cache_bytes,
                        )?)))
                    },
                    state: Mutex::new(State::default()),
                    entries: args.compiled_cache_entries,
                    memory_cache_bytes: args.disk_cache_bytes,
                    storage: HashMap::new(),
                    permits: Arc::new(Semaphore::new(args.max_inflight)),
                },
            );
        }
        Ok(Arc::new(Self {
            containers: std::sync::OnceLock::new(),
            runtime,
            linker,
            platform,
            client,
            namespaces,
            policy,
            agent_policy,
            authorization,
            _root_lock: root_lock,
            _native_storage_lock: native_storage_lock,
            downloads: Arc::new(Semaphore::new(args.downloads)),
            compiler: Compiler::new(args.compilers, args.compiler_threads)?,
            executions: Arc::new(Semaphore::new(args.executions)),
            preparations: Arc::new(Semaphore::new(args.max_inflight)),
            args,
            download_count: AtomicU64::new(0),
            shared_count: AtomicU64::new(0),
            execution_count: AtomicU64::new(0),
        }))
    }

    fn make_hal(non_tee: bool) -> Result<HalHost> {
        if non_tee {
            HalHost::with_platform(elastic_tee_hal::platform::PlatformType::AmdSev)
        } else {
            HalHost::new()
        }
    }

    fn namespace(&self, job: &Job) -> Result<&Namespace> {
        if let Some(policy) = &self.policy {
            policy.get(&job.tenant)?.allows(job)?;
        }
        self.namespaces
            .get(&job.tenant)
            .context("unknown cache namespace")
    }
    /// Network fetch remains in the trusted broker for networkless workers.
    pub async fn download_artifact(&self, job: &Job) -> Result<Vec<u8>> {
        self.namespace(job)?;
        self.check_cache_policy(job)?;
        let _permit = self.downloads.acquire().await?;
        self.download_count.fetch_add(1, Ordering::Relaxed);
        let data = cache::download(
            &self.client,
            self.args.file_server.join(&job.name)?,
            self.args.max_component_bytes,
        )
        .await?;
        cache::verify(&data, &job.sha, Some(job.size))?;
        Ok(data)
    }
    pub fn tenant_permits(&self, job: &Job) -> Result<Arc<Semaphore>> {
        Ok(self.namespace(job)?.permits.clone())
    }
    pub fn agent_rule(&self, job: &Job) -> Result<Option<Arc<agent_policy::Rule>>> {
        self.agent_policy.as_ref().map(|p| p.rule(job)).transpose()
    }
    fn check_cache_policy(&self, job: &Job) -> Result<()> {
        ensure!(
            self.args.mode != crate::Mode::Native || !job.reuse,
            "no-agent mode has no code cache; submit with --cache bypass"
        );
        if let Some(rule) = self.agent_rule(job)? {
            ensure!(!job.reuse || rule.cache, "cache use denied by agent policy");
        }
        Ok(())
    }
    /// Remove expired prepared code. Existing executions retain their own Arc.
    pub fn expire_agent_cache(&self) {
        if self.agent_policy.is_some() {
            for namespace in self.namespaces.values() {
                namespace.state.lock().unwrap().expire();
            }
        }
    }
    pub fn lookup(&self, job: &Job) -> Result<Option<Arc<Prepared>>> {
        self.check_cache_policy(job)?;
        if self.args.mode == crate::Mode::Native {
            self.namespace(job)?;
            return Ok(None);
        }
        let mut state = self.namespace(job)?.state.lock().unwrap();
        state.expire();
        state.clock += 1;
        let tick = state.clock;
        if let Some(entry) = state.entries.get_mut(&job.sha) {
            ensure!(
                entry.prepared.size == job.size,
                "expected size differs from cached component"
            );
            entry.used = tick;
            return Ok(Some(entry.prepared.clone()));
        }
        Ok(None)
    }

    pub async fn prepare(self: &Arc<Self>, job: &Job) -> Result<(Arc<Prepared>, &'static str)> {
        self.check_cache_policy(job)?;
        if !job.reuse {
            return Ok((self.build(job).await?, "bypass"));
        }
        if let Some(component) = self.lookup(job)? {
            return Ok((component, "hit"));
        }
        let (mut receiver, joined) = {
            let mut state = self.namespace(job)?.state.lock().unwrap();
            state.expire();
            // Check again under the same lock as insertion into flights.
            if let Some(entry) = state.entries.get(&job.sha) {
                ensure!(
                    entry.prepared.size == job.size,
                    "expected size differs from cached component"
                );
                return Ok((entry.prepared.clone(), "hit"));
            }
            if let Some(receiver) = state.flights.get(&job.sha) {
                (receiver.clone(), true)
            } else {
                // Permit lives with the background task even if a client times out.
                let permit = self
                    .preparations
                    .clone()
                    .try_acquire_owned()
                    .context("preparation capacity exhausted; try again later")?;
                let (sender, receiver) = watch::channel(None);
                state.flights.insert(job.sha.clone(), receiver.clone());
                let shared = self.clone();
                let job = job.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = shared.build(&job).await.map_err(|e| format!("{e:#}"));
                    {
                        let mut state = shared.namespaces[&job.tenant].state.lock().unwrap();
                        if let Ok(prepared) = &result {
                            state.clock += 1;
                            let used = state.clock;
                            state.entries.insert(
                                job.sha.clone(),
                                Entry {
                                    prepared: prepared.clone(),
                                    used,
                                },
                            );
                            while state.entries.len() > shared.namespaces[&job.tenant].entries
                                || (shared.agent_policy.is_some()
                                    && state.entries.values().map(|e| e.prepared.size).sum::<u64>()
                                        > shared.namespaces[&job.tenant].memory_cache_bytes)
                            {
                                let oldest = state
                                    .entries
                                    .iter()
                                    .min_by_key(|(_, e)| e.used)
                                    .map(|(key, _)| key.clone())
                                    .unwrap();
                                state.entries.remove(&oldest);
                            }
                        }
                        state.flights.remove(&job.sha);
                        // Notify current waiters after publishing the cache result.
                        let _ = sender.send(Some(result));
                    }
                });
                (receiver, false)
            }
        };
        if joined {
            self.shared_count.fetch_add(1, Ordering::Relaxed);
        }
        let prepared = loop {
            let value = receiver.borrow().clone();
            if let Some(value) = value {
                break value.map_err(anyhow::Error::msg)?;
            }
            receiver
                .changed()
                .await
                .context("preparation task stopped")?;
        };
        ensure!(
            prepared.size == job.size,
            "expected size differs from prepared component"
        );
        Ok((prepared, if joined { "shared" } else { "miss" }))
    }

    async fn build(self: &Arc<Self>, job: &Job) -> Result<Arc<Prepared>> {
        self.namespace(job)?;
        self.check_cache_policy(job)?;
        let rule = self.agent_rule(job)?;
        let mut times = json!({});
        let started = Instant::now();
        let mut bytes = None;
        let mut corrupt = false;
        let mut evicted = 0;
        let mut stored = false;
        if job.reuse && rule.is_none() {
            let disk = self
                .namespace(job)?
                .disk
                .as_ref()
                .context("workload code caching is disabled")?
                .clone();
            let job = job.clone();
            let maximum = self.args.max_component_bytes;
            let start = Instant::now();
            let (cached, invalid) = tokio::task::spawn_blocking(move || -> Result<_> {
                let disk = disk.lock().unwrap();
                if let Some(data) = disk.get(&job.sha, maximum)? {
                    if cache::verify(&data, &job.sha, None).is_ok() {
                        ensure!(
                            data.len() as u64 == job.size,
                            "expected size differs from disk cache"
                        );
                        return Ok((Some(data), false));
                    }
                    disk.remove(&job.sha)?;
                    return Ok((None, true));
                }
                Ok((None, false))
            })
            .await??;
            times["disk_read_verify"] = json!(ms(start));
            bytes = cached;
            corrupt = invalid;
        }
        let source = if bytes.is_some() { "disk" } else { "download" };
        let bytes = match bytes {
            Some(data) => data,
            None => {
                let start = Instant::now();
                let _permit = self.downloads.acquire().await?;
                times["download_queue"] = json!(ms(start));
                let start = Instant::now();
                self.download_count.fetch_add(1, Ordering::Relaxed);
                let data = if let Some(worker) = &self.args.container_worker {
                    worker
                        .download(job, self.args.download_timeout_secs)
                        .await?
                } else {
                    cache::download(
                        &self.client,
                        self.args.file_server.join(&job.name)?,
                        self.args.max_component_bytes,
                    )
                    .await?
                };
                times["download"] = json!(ms(start));
                let start = Instant::now();
                cache::verify(&data, &job.sha, Some(job.size))?;
                times["verify"] = json!(ms(start));
                data
            }
        };
        // Keep a copy only if it needs to be written to the persistent file cache.
        let disk_data = if job.reuse && rule.is_none() && source == "download" {
            Some(bytes.clone())
        } else {
            None
        };
        let start = Instant::now();
        let engine = self.runtime.engine().clone();
        let (component, compile) = self
            .compiler
            .run(move || Component::from_binary(&engine, &bytes))
            .await?;
        times["compile_queue"] = json!(compile.slot_wait_ms);
        times["compile_executor_queue"] = json!(compile.executor_wait_ms);
        times["compile_work"] = json!(compile.work_ms);
        // Preserve the previous metric boundary: slot acquisition is excluded,
        // but executor queueing and notification back to Tokio are included.
        times["compile"] = json!((ms(start) - compile.slot_wait_ms).max(0.0));
        if let Some(data) = disk_data {
            let disk = self
                .namespace(job)?
                .disk
                .as_ref()
                .context("workload code caching is disabled")?
                .clone();
            let sha = job.sha.clone();
            let start = Instant::now();
            (stored, evicted) =
                tokio::task::spawn_blocking(move || disk.lock().unwrap().put(&sha, &data))
                    .await??;
            times["disk_write"] = json!(ms(start));
        }
        times["total"] = json!(ms(started));
        Ok(Arc::new(Prepared {
            tenant: job.tenant.clone(),
            sha: job.sha.clone(),
            component,
            size: job.size,
            preparation: json!({
                "source": source, "stored": stored, "evicted": evicted,
                "repaired_corrupt_file": corrupt, "work_ms": times,
            }),
            expires: rule.map(|r| Instant::now() + std::time::Duration::from_millis(r.ttl_ms)),
        }))
    }

    pub async fn execute(
        &self,
        job: &Job,
        prepared: &Prepared,
        record: &mut Value,
    ) -> Result<Vec<u8>> {
        let namespace = self.namespace(job)?;
        let rule = self.agent_rule(job)?;
        ensure!(
            !self.args.managed_broker && self.args.container_worker.is_none() || rule.is_some(),
            "managed workload policy is mandatory"
        );
        ensure!(
            prepared.tenant == job.tenant && prepared.sha == job.sha,
            "prepared workload belongs to a different scope"
        );
        let storage = namespace
            .storage
            .get(&job.sha)
            .map(|s| Arc::new(s.session()));
        let restricted = self.policy.is_some();
        let start = Instant::now();
        let permit = self.executions.clone().acquire_owned().await?;
        // Recheck after compilation and queueing: an expired authorization may
        // not start a new execution even if it was valid at admission.
        if let Some(authority) = &self.authorization {
            authority.verify(job)?;
        } else {
            ensure!(
                job.ticket.is_none(),
                "signed job requires an authorization policy"
            );
        }
        record["timings_ms"]["execution_queue"] = json!(ms(start));
        self.execution_count.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let non_tee = self.args.allow_non_tee;
        let worker = self.args.container_worker.clone();
        // HAL initialization may perform blocking OS operations; keep Tokio free.
        let (_permit, hal) = tokio::task::spawn_blocking(move || {
            let hal = if let Some(worker) = &worker {
                worker.hal()
            } else if restricted {
                HalHost::for_restricted_job(non_tee)
            } else {
                Self::make_hal(non_tee)
            };
            hal.map(|hal| (permit, hal))
        })
        .await??;
        record["timings_ms"]["hal_init"] = json!(ms(start));
        let start = Instant::now();
        let mut store = self.runtime.create_job_store(
            hal,
            rule.as_ref()
                .map_or(self.args.workload_memory_mib, |r| r.memory_mib)
                * 1024
                * 1024,
            rule.as_ref().map_or(self.args.workload_fuel, |r| r.fuel),
            rule.as_ref()
                .map_or(self.args.execution_timeout_secs * 100, |r| {
                    r.execution_ms.div_ceil(10)
                }),
        )?;
        if let Some(storage) = storage {
            store.data_mut().restrict_to_job(storage);
        }
        if let Some(rule) = &rule {
            store
                .data_mut()
                .enforce_workload_policy(&job.tenant, &job.sha, &rule.permissions)?;
            if let Some(profile) = &rule.access_profile {
                hal_runtime::check_workload_imports(self.runtime.engine(), &prepared.component)?;
                store.data_mut().enforce_access_profile(profile)?;
            }
        }
        record["timings_ms"]["store_create"] = json!(ms(start));
        let start = Instant::now();
        let operation = async {
            let instance =
                HalConsumer::instantiate_async(&mut store, &prepared.component, &self.linker)
                    .await?;
            record["timings_ms"]["instantiate"] = json!(ms(start));
            let call = Instant::now();
            let bytes = instance.elastic_hal_run().call_run(&mut store).await?;
            record["timings_ms"]["call"] = json!(ms(call));
            ensure!(
                bytes.len()
                    <= rule
                        .as_ref()
                        .map_or(self.args.max_output_bytes, |r| r.output_bytes),
                "workload output exceeds limit"
            );
            Ok::<_, anyhow::Error>(bytes)
        };
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(
                rule.as_ref()
                    .map_or(self.args.execution_timeout_secs * 1000, |r| r.execution_ms),
            ),
            operation,
        )
        .await
        .context("workload execution deadline exceeded");
        if let Some(report) = store.data().access_profile_report() {
            record["workload_access_profile"] = report;
        }
        let start = Instant::now();
        drop(store);
        record["timings_ms"]["store_drop"] = json!(ms(start));
        outcome?
    }

    pub fn stats(&self) -> Value {
        self.expire_agent_cache();
        let states: Vec<_> = self
            .namespaces
            .values()
            .map(|n| n.state.lock().unwrap())
            .collect();
        let entries: usize = states.iter().map(|s| s.entries.len()).sum();
        let flights: usize = states.iter().map(|s| s.flights.len()).sum();
        let compiler = self.compiler.stats();
        json!({ "downloads": self.download_count.load(Ordering::Relaxed),
            "compiles": compiler["submitted"],
            "compiler": compiler,
            "shared_preparations": self.shared_count.load(Ordering::Relaxed),
            "executions": self.execution_count.load(Ordering::Relaxed),
            "cache_expirations": states.iter().map(|s| s.expired).sum::<u64>(),
            "agent_policy_sha256": self.agent_policy.as_ref().map(|p| &p.digest),
            "compiled_entries": entries, "preparations_inflight": flights })
    }
}
