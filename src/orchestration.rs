//! Shared management agent and its native, job-bound HAL control surface.
//! One Wasm Store makes decisions. Broker jobs run concurrently outside that Store.
use crate::{
    cache,
    executor::{ms, Job, Shared},
    protocol, tickets_core,
};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::BufReader,
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    sync::{Mutex, Semaphore},
};
use wasmtime::component::{Component, Linker, ResourceTable, __internal::async_trait};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};
wasmtime::component::bindgen!({path:"wit-orchestration", world:"orchestrator", async:true});
use elastic::orchestration::control;
pub const ABI: &str = "elastic:orchestration@1.1.0";
const CERT_DOMAIN: &[u8] = b"HAL-AGENT-CERTIFICATE-v1\0";
const PROOF_DOMAIN: &[u8] = b"HAL-AGENT-PROOF-v1\0";
const MAX_AGENT_CERTIFICATE_SECONDS: u64 = 3 * 60 * 60;
pub const RIGHTS: &[&str] = &[
    "broker.launch",
    "workload.policy",
    "workload.launch",
    "result.commit",
    "identity.sign",
];
fn now() -> Result<u64> {
    crate::authorization::now()
}
fn random() -> Result<[u8; 32]> {
    let mut b = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}
fn save(path: &Path, value: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(value)?;
    f.sync_all()?;
    Ok(())
}
fn save_json(path: &Path, v: &Value) -> Result<()> {
    save(path, v.to_string().as_bytes())
}
fn lock(path: &Path) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(f.metadata()?.is_file(), "agent lock must be regular");
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another agent already owns this VM runtime slot"
    );
    Ok(f)
}
fn signed(key: &SigningKey, value: &Value) -> Value {
    let payload = value.to_string();
    let mut data = PROOF_DOMAIN.to_vec();
    data.extend(payload.as_bytes());
    json!({"payload":payload,"signature":hex::encode(key.sign(&data).to_bytes())})
}
fn verify_certificate(owner: &str, envelope: &Value) -> Result<Value> {
    let payload = protocol::string(envelope, "payload")?;
    ensure!(payload.len() <= 8192, "certificate too large");
    let signature = Signature::from_slice(&hex::decode(protocol::string(envelope, "signature")?)?)?;
    let mut data = CERT_DOMAIN.to_vec();
    data.extend(payload.as_bytes());
    tickets_core::public_key(owner)
        .map_err(anyhow::Error::msg)?
        .verify_strict(&data, &signature)?;
    Ok(serde_json::from_str(payload)?)
}

struct Broker {
    child: Child,
    _root: tempfile::TempDir,
    token: String,
    url: String,
    session: Value,
    document: Value,
    contexts: Vec<tickets_core::Context>,
    active: usize,
    until: u64,
    credential_scope: String,
}
impl Broker {
    fn signal_stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            if let Some(pid) = self.child.id() {
                ensure!(
                    unsafe { libc::kill(pid as i32, libc::SIGTERM) } == 0,
                    "could not signal user broker"
                );
            }
        }
        Ok(())
    }
    async fn stop_until(&mut self, deadline: Instant) -> Result<()> {
        self.signal_stop()?;
        let status = match tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            self.child.wait(),
        )
        .await
        {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                anyhow::bail!(
                    "user broker did not confirm sandbox cleanup; investigate before redeployment"
                );
            }
        };
        // The broker exits successfully only after Pool::shutdown removed its workers.
        ensure!(
            status.success(),
            "user broker exited without confirming sandbox cleanup"
        );
        Ok(())
    }
    async fn stop(&mut self) -> Result<()> {
        self.stop_until(Instant::now() + Duration::from_secs(25))
            .await
    }
    async fn start(
        config: &Value,
        grant: &Value,
        agent_sha: &str,
        client: &reqwest::Client,
    ) -> Result<Self> {
        let doc = &grant["document"];
        let tenant = protocol::string(doc, "subject")?;
        ensure!(
            protocol::safe_name(tenant) && tenant.len() <= 48,
            "invalid user"
        );
        tickets_core::public_key(protocol::string(doc, "public_key")?)
            .map_err(anyhow::Error::msg)?;
        let root = tempfile::Builder::new()
            .prefix("user-")
            .tempdir_in(protocol::string(config, "runtime_dir")?)?;
        let path = root.path();
        let admin = hex::encode(random()?);
        let token = hex::encode(random()?);
        save(&path.join("operator.token"), admin.as_bytes())?;
        save(&path.join("tenant.token"), token.as_bytes())?;
        let rows = doc["workloads"].as_array().context("workloads missing")?;
        ensure!(!rows.is_empty() && rows.len() <= 128, "invalid grant count");
        let mut tenant_row = doc["limits"].clone();
        ensure!(tenant_row.is_object(), "limits missing");
        tenant_row["id"] = json!(tenant);
        tenant_row["token_file"] = json!("tenant.token");
        tenant_row["artifacts"]=json!(rows.iter().map(|r| json!({"component":r["component"],"sha256":r["sha256"],"artifact_bytes":r["artifact_bytes"]})).collect::<Vec<_>>());
        save_json(
            &path.join("tenant.json"),
            &json!({"version":1,"tenants":[tenant_row]}),
        )?;
        let rules: Vec<Value> = rows
            .iter()
            .map(|r| {
                let mut rule = r["rule"].clone();
                rule["tenant"] = json!(tenant);
                rule["sha256"] = r["sha256"].clone();
                rule
            })
            .collect();
        save_json(
            &path.join("policy.json"),
            &json!({"version":1,"agent_sha256":agent_sha,"workloads":rules}),
        )?;
        let grants:Vec<Value>=rows.iter().map(|r| json!({"component":r["component"],"sha256":r["sha256"],"artifact_bytes":r["artifact_bytes"],"rule_sha256":cache::hash(r["rule"].to_string().as_bytes())})).collect();
        let test = config["test_in_process"] == true;
        let isolation = if test {
            "in-process"
        } else {
            "per-user-container"
        };
        save_json(
            &path.join("authorization.json"),
            &json!({"version":1,"audience":config["audience"],"max_ttl_seconds":120,"isolation":isolation,"users":[{"tenant":tenant,"public_key":doc["public_key"],"workloads":grants}]}),
        )?;
        let file_token = protocol::string(grant, "file_token")?;
        ensure!(
            file_token.len() == 64 && protocol::valid_sha(file_token),
            "invalid scoped file credential"
        );
        save(&path.join("file.token"), file_token.as_bytes())?;
        let url = reqwest::Url::parse(protocol::string(grant, "file_server")?)?;
        ensure!(
            url.scheme() == "https"
                || (test && url.scheme() == "http" && url.host_str() == Some("127.0.0.1")),
            "artifact service needs HTTPS"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid artifact URL"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);
        let mut argv = vec![
            "--managed-broker".into(),
            "--mode".into(),
            "wasm".into(),
            "--transport".into(),
            "http".into(),
            "--listen".into(),
            addr.to_string(),
            "--file-server".into(),
            url.to_string(),
        ];
        for (flag, name) in [
            ("token-file", "operator.token"),
            ("tenant-policy", "tenant.json"),
            ("agent-policy", "policy.json"),
            ("job-authorization", "authorization.json"),
            ("file-token-file", "file.token"),
            ("cache-dir", "storage"),
        ] {
            argv.extend([
                format!("--{flag}"),
                path.join(name).to_string_lossy().into_owned(),
            ]);
        }
        if let Some(pem) = grant["file_ca_pem"].as_str() {
            save(&path.join("file-ca.pem"), pem.as_bytes())?;
            argv.extend([
                "--file-ca-cert".into(),
                path.join("file-ca.pem").to_string_lossy().into_owned(),
            ]);
        }
        if test {
            argv.push("--allow-non-tee".into());
        } else {
            argv.extend([
                "--user-containers".into(),
                "--container-image".into(),
                protocol::string(config, "container_image")?.into(),
                "--container-state-dir".into(),
                path.join("ipc").to_string_lossy().into_owned(),
            ]);
        }
        if let Some(settings) = config["settings"].as_object() {
            for (name, value) in settings {
                ensure!(
                    [
                        "downloads",
                        "compilers",
                        "compiler_threads",
                        "executions",
                        "max_inflight",
                        "compile_opt_level",
                        "execution_timeout_secs",
                        "max_output_bytes",
                        "workload_memory_mib",
                        "workload_fuel",
                        "max_component_bytes",
                        "container_cpus",
                        "container_memory_mib",
                        "container_pids",
                        "container_storage_mib"
                    ]
                    .contains(&name.as_str()),
                    "unknown runtime setting"
                );
                if !test || !name.starts_with("container_") {
                    argv.extend([
                        format!("--{}", name.replace('_', "-")),
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string()),
                    ]);
                }
            }
        }
        let log = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("broker.log"))?;
        let start = Instant::now();
        let child = Command::new(std::env::current_exe()?)
            .args(argv)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()?;
        let mut broker = Self {
            child,
            _root: root,
            token,
            url: format!("http://{addr}"),
            session: Value::Null,
            document: doc.clone(),
            contexts: vec![],
            active: 0,
            until: protocol::unsigned(grant, "expires_unix")?,
            credential_scope: cache::hash(grant.to_string().as_bytes()),
        };
        let status = loop {
            ensure!(
                broker.child.try_wait()?.is_none(),
                "user broker failed to start; inspect its private broker.log"
            );
            if let Ok(response) = client
                .get(format!("{}/v1/stats", broker.url))
                .bearer_auth(&admin)
                .send()
                .await
            {
                if let Ok(body) = response.bytes().await {
                    if let Ok(s) = serde_json::from_slice::<Value>(&body) {
                        if s["status"] == "ok" {
                            break s;
                        }
                    }
                }
            }
            ensure!(
                start.elapsed() < Duration::from_secs(60),
                "user broker startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let epoch = protocol::string(&status["job_authorization"], "epoch")?;
        broker.session = json!({"tenant":tenant,"revision":doc["revision"],"epoch":epoch,"audience":config["audience"],"mode":"wasm","isolation":isolation,"broker_startup_ms":ms(start),"settings":config["settings"]});
        for row in rows {
            broker.contexts.push(serde_json::from_value(json!({"tenant":tenant,"public_key":doc["public_key"],"audience":config["audience"],"epoch":epoch,"max_ttl_seconds":120,"component":row["component"],"sha256":row["sha256"],"artifact_bytes":row["artifact_bytes"],"rule_sha256":cache::hash(row["rule"].to_string().as_bytes()),"cache_allowed":row["rule"]["cache"]=="memory","isolation":isolation,"max_output_bytes":row["rule"]["max_output_bytes"],"result_rule":row["rule"]["validation"]}))?);
        }
        Ok(broker)
    }
}

struct Host {
    audit: crate::audit::Journal,
    audit_result: Option<Value>,
    wasi: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
    config: Value,
    agent_sha: String,
    rights: HashSet<String>,
    brokers: HashMap<String, Broker>,
    client: reqwest::Client,
    grant: Option<Value>,
    job: Option<Value>,
    policy_set: bool,
    launched: bool,
    result: Option<Value>,
    committed: bool,
    enrollment: Option<Value>,
    drain_operation: Option<String>,
    drain_complete: Option<Value>,
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
    fn audit_job(&self) -> Result<Value> {
        let request = self.job.as_ref().context("audit job context missing")?;
        let tenant = protocol::string(request, "tenant")?;
        let broker = self
            .brokers
            .get(tenant)
            .context("audit broker context missing")?;
        Ok(
            json!({"tenant":tenant,"user_key":broker.document["public_key"],
            "job_id":request["job"]["job_id"],"artifact_sha256":request["job"]["sha256"],
            "policy_sha256":cache::hash(request["policy"].to_string().as_bytes()),
            "cache_policy":request["job"]["cache"],"revision":request["revision"]}),
        )
    }
    fn permit(&self, right: &str) -> Result<()> {
        ensure!(
            self.rights.contains(right),
            "agent HAL permission denied: {right}"
        );
        Ok(())
    }
    fn scope(&self) -> Result<(&Broker, &Value)> {
        let req = self.job.as_ref().context("no bound job")?;
        let tenant = protocol::string(req, "tenant")?;
        let b = self.brokers.get(tenant).context("user broker absent")?;
        ensure!(
            b.until > now()? && b.document["revision"] == req["revision"],
            "user policy expired or changed"
        );
        let row = b.document["workloads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["sha256"] == req["job"]["sha256"])
            .context("artifact outside user grant")?;
        Ok((b, row))
    }
}
#[async_trait]
impl control::Host for Host {
    async fn stop_user_brokers(&mut self) -> Result<(), String> {
        let outcome = async {
            ensure!(
                self.drain_operation.is_some(),
                "no management-authorized drain"
            );
            ensure!(
                self.brokers.values().all(|b| b.active == 0),
                "jobs still active"
            );
            let deadline = Instant::now() + Duration::from_secs(25);
            // Signal everyone first, then use one shared cleanup deadline.
            let mut errors = Vec::new();
            for b in self.brokers.values_mut() {
                if let Err(e) = b.signal_stop() {
                    errors.push(format!("{e:#}"));
                }
            }
            for b in self.brokers.values_mut() {
                if let Err(e) = b.stop_until(deadline).await {
                    errors.push(format!("{e:#}"));
                }
            }
            ensure!(
                errors.is_empty(),
                "broker cleanup not confirmed: {}",
                errors.join("; ")
            );
            self.brokers.clear(); // drops private grants, broker credentials and temporary files
            Ok(())
        }
        .await;
        outcome.map_err(|e: anyhow::Error| format!("{e:#}"))
    }
    async fn launch_user_broker(&mut self) -> Result<String, String> {
        let outcome = async {
            ensure!(self.drain_operation.is_none(), "agent is draining");
            self.permit("broker.launch")?;
            let grant = self.grant.as_ref().context("no management grant")?.clone();
            let doc = &grant["document"];
            let tenant = protocol::string(doc, "subject")?.to_owned();
            let revision = protocol::unsigned(doc, "revision")?;
            ensure!(
                protocol::unsigned(&grant, "expires_unix")? > now()?,
                "expired grant"
            );
            if let Some(old) = self.brokers.get_mut(&tenant) {
                ensure!(old.active == 0, "user broker has active work");
                ensure!(
                    old.document["public_key"] == doc["public_key"]
                        && revision >= protocol::unsigned(&old.document, "revision")?,
                    "user key replacement or policy rollback"
                );
                if revision == protocol::unsigned(&old.document, "revision")? {
                    ensure!(
                        old.document["workloads"] == doc["workloads"]
                            && old.document["limits"] == doc["limits"],
                        "policy change requires a new user revision"
                    );
                }
                if old.child.try_wait()?.is_some()
                    || old.credential_scope != cache::hash(grant.to_string().as_bytes())
                {
                    old.stop().await?;
                    self.brokers.remove(&tenant);
                }
            }
            // Expired idle grants do not occupy a broker slot forever.
            let expired: Vec<_> = self
                .brokers
                .iter()
                .filter(|(_, b)| b.active == 0 && b.until <= now().unwrap_or(0))
                .map(|(t, _)| t.clone())
                .collect();
            for name in expired {
                if let Some(mut b) = self.brokers.remove(&name) {
                    b.stop().await?;
                }
            }
            if !self.brokers.contains_key(&tenant) {
                ensure!(
                    self.brokers.len()
                        < self.config["max_active_users"].as_u64().unwrap_or(64) as usize,
                    "user capacity reached"
                );
                let b = Broker::start(&self.config, &grant, &self.agent_sha, &self.client).await?;
                self.brokers.insert(tenant.clone(), b);
            }
            let b = &self.brokers[&tenant];
            self.enrollment = Some(b.session.clone());
            Ok::<_, anyhow::Error>(json!({"session":b.session,"contexts":b.contexts}).to_string())
        }
        .await;
        outcome.map_err(|e| format!("{e:#}"))
    }
    async fn apply_workload_policy(&mut self, policy_json: String) -> Result<(), String> {
        (|| -> Result<()> {
            self.permit("workload.policy")?;
            ensure!(!self.policy_set && !self.launched, "policy already applied");
            let req = self.job.as_ref().context("no job")?;
            let (b, row) = self.scope()?;
            let policy: Value = serde_json::from_str(&policy_json)?;
            ensure!(
                policy == row["rule"] && req["policy"] == policy,
                "policy differs from management grant"
            );
            let ctx = b
                .contexts
                .iter()
                .find(|c| c.sha256 == req["job"]["sha256"])
                .context("missing user context")?;
            let job = Job::parse(&req["job"], 16 * 1024 * 1024)?;
            tickets_core::verify(
                ctx,
                job.ticket.as_ref().context("user signature required")?,
                &tickets_core::Request {
                    tenant: &ctx.tenant,
                    job_id: &job.id,
                    component: &job.name,
                    sha256: &job.sha,
                    artifact_bytes: job.size,
                    reuse: job.reuse,
                },
                now()?,
            )
            .map_err(anyhow::Error::msg)?;
            self.policy_set = true;
            Ok(())
        })()
        .map_err(|e| format!("{e:#}"))
    }
    async fn launch_workload(&mut self) -> Result<(), String> {
        (|| -> Result<()> {
            ensure!(self.drain_operation.is_none(), "agent is draining");
            self.permit("workload.launch")?;
            self.scope()?;
            ensure!(
                self.policy_set && !self.launched,
                "apply the bound policy before launch"
            );
            let active = self.brokers.values().map(|b| b.active).sum();
            self.audit.admit(active)?;
            self.audit.append("job_accepted", self.audit_job()?)?;
            self.launched = true;
            Ok(())
        })()
        .map_err(|e| format!("{e:#}"))
    }
    async fn commit_result(&mut self) -> Result<(), String> {
        (|| -> Result<()> {
            self.permit("result.commit")?;
            ensure!(
                self.result.is_some() && !self.committed,
                "no uncommitted result"
            );
            let result = self.result.as_ref().unwrap();
            let mut data = self.audit_job()?;
            data["outcome"] = json!(if result["execution_outcome"] == "unknown" { "unknown" }
                else if result["status"] == "ok" { "completed" } else { "failed" });
            if result["status"] == "ok" {
                let bytes = hex::decode(protocol::string(&result["result"], "hex")?)?;
                data["result_sha256"] = json!(cache::hash(&bytes));
            }
            // Explicit allowlist: no arbitrary error text, input/output or credentials.
            data["cache_status"] = result["cache_status"].clone();
            data["sandbox"] = json!({"name":result["container"]["name"],
                "runtime":result["container"]["runtime"],"profile":result["container"]["sandbox_profile"],
                "reused":result["container"]["reused"]});
            self.audit_result = Some(self.audit.append("result_committed", data)?);
            self.committed = true;
            Ok(())
        })()
        .map_err(|e| format!("{e:#}"))
    }
}

pub fn check(bytes: &[u8]) -> Result<()> {
    let (_, component, linker) = factory(bytes)?;
    OrchestratorPre::new(linker.instantiate_pre(&component)?)?;
    Ok(())
}
fn factory(bytes: &[u8]) -> Result<(Engine, Component, Linker<Host>)> {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .async_support(true)
        .consume_fuel(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_binary(&engine, bytes)?;
    let mut linker = Linker::new(&engine);
    // No inherited directories, sockets, environment, stdin/stdout or secrets.
    wasmtime_wasi::add_to_linker_async(&mut linker)?;
    Orchestrator::add_to_linker(&mut linker, |s: &mut Host| s)?;
    OrchestratorPre::new(linker.instantiate_pre(&component)?)?;
    Ok((engine, component, linker))
}
struct Vm {
    instance: Orchestrator,
    store: Store<Host>,
    poisoned: bool,
}
struct Service {
    vm: Mutex<Vm>,
    key: SigningKey,
    public: Value,
    owner: String,
    certificate: Mutex<Option<Value>>,
    permits: Semaphore,
    drain_lock: Mutex<()>,
}
impl Service {
    fn proof(&self, kind: &str, challenge: Value, data: Value) -> Value {
        signed(
            &self.key,
            &json!({"kind":kind,"identity":self.public,"challenge":challenge,"data":data}),
        )
    }
    async fn active(&self) -> Result<()> {
        let cert = self.certificate.lock().await;
        ensure!(
            cert.as_ref().is_some_and(|c| c["expires_unix"]
                .as_u64()
                .is_some_and(|t| now().is_ok_and(|n| n < t))),
            "agent identity certificate expired or missing"
        );
        Ok(())
    }
    async fn handle(&self, req: Value) -> Result<Value> {
        let outcome = self.handle_inner(req.clone()).await;
        let activated = self.certificate.lock().await.is_some();
        if outcome.is_err() && matches!(req["op"].as_str(), Some("run" | "enroll")) && activated {
            let mut vm = self.vm.lock().await;
            if vm.store.data().drain_complete.is_some() {
                return outcome;
            }
            // Failed user claims must never be attributed to a verified tenant.
            vm.store.data_mut().audit.append("control_rejected", json!({
                "operation":req["op"],"request_sha256":cache::hash(req.to_string().as_bytes()),
                "reason":"control_operation_failed",
                "execution_outcome":if req["op"] == "run" { "unknown" } else { "not_applicable" }
            }))?;
        }
        outcome
    }
    async fn drain(&self, req: Value) -> Result<Value> {
        self.active().await?;
        ensure!(
            req["agent_instance"] == self.public["instance"],
            "drain belongs to another agent"
        );
        let operation = protocol::string(&req, "operation_id")?.to_owned();
        ensure!(
            operation.len() == 64 && operation.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid drain identifier"
        );
        let seconds = protocol::unsigned(&req, "drain_seconds")?;
        ensure!(seconds <= 60, "drain deadline must be 0..60 seconds");
        let _drain = self.drain_lock.lock().await;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        {
            let mut vm = self.vm.lock().await;
            if let Some(old) = &vm.store.data().drain_operation {
                ensure!(old == &operation, "another drain is in progress");
            } else {
                // Set native admission state before calling the trusted agent or audit.
                vm.store.data_mut().drain_operation = Some(operation.clone());
                vm.store.set_fuel(100_000_000)?;
                let Vm {
                    instance, store, ..
                } = &mut *vm;
                instance
                    .call_begin_drain(&mut *store)
                    .await?
                    .map_err(anyhow::Error::msg)?;
                store
                    .data_mut()
                    .audit
                    .append("agent_drain_started", json!({"operation_id":operation}))?;
            }
        }
        loop {
            let mut vm = self.vm.lock().await;
            if let Some(data) = &vm.store.data().drain_complete {
                return Ok(self.proof("drain", req["challenge"].clone(), data.clone()));
            }
            let active: usize = vm.store.data().brokers.values().map(|b| b.active).sum();
            if active == 0 {
                ensure!(
                    !vm.poisoned,
                    "agent trapped; cleanup requires investigation"
                );
                let users = vm.store.data().brokers.len();
                vm.store.set_fuel(100_000_000)?;
                let Vm {
                    instance, store, ..
                } = &mut *vm;
                instance
                    .call_finish_drain(&mut *store)
                    .await?
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    store.data().brokers.is_empty(),
                    "agent did not stop every broker"
                );
                let data = json!({"operation_id":operation,"state":"drained","active_jobs":0,
                    "brokers_stopped":users,"ownership_reserved":true});
                let checkpoint = store
                    .data_mut()
                    .audit
                    .append("agent_drained", data.clone())?;
                let mut data = data;
                data["checkpoint"] = checkpoint;
                store.data_mut().drain_complete = Some(data.clone());
                return Ok(self.proof("drain", req["challenge"].clone(), data));
            }
            if Instant::now() >= deadline {
                return Ok(self.proof(
                    "drain",
                    req["challenge"].clone(),
                    json!({"operation_id":operation,
                    "state":"draining","active_jobs":active,"ownership_reserved":true}),
                ));
            }
            drop(vm);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn handle_inner(&self, req: Value) -> Result<Value> {
        match req["op"].as_str() {
            Some("status") => {
                let vm = self.vm.lock().await;
                ensure!(!vm.poisoned, "agent trapped; restart runtime");
                Ok(self.proof(
                    "status",
                    req["challenge"].clone(),
                    json!({"users":vm.store.data().brokers.len(),"audit":vm.store.data().audit.head(),
                        "lifecycle":if vm.store.data().drain_complete.is_some() {"drained"}
                            else if vm.store.data().drain_operation.is_some() {"draining"} else {"active"}}),
                ))
            }
            Some("activate") => {
                let cert = verify_certificate(&self.owner, &req["certificate"])?;
                ensure!(
                    cert["version"] == 1
                        && cert["kind"] == "agent-identity"
                        && cert["identity"] == self.public,
                    "certificate identity mismatch"
                );
                let t = now()?;
                let issued = protocol::unsigned(&cert, "issued_unix")?;
                let expires = protocol::unsigned(&cert, "expires_unix")?;
                ensure!(
                    issued <= t + 5 && t < expires && expires > issued
                        && expires - issued <= MAX_AGENT_CERTIFICATE_SECONDS,
                    "certificate lifetime invalid"
                );
                let mut vm = self.vm.lock().await;
                vm.store
                    .data_mut()
                    .audit
                    .activate(req["certificate"].clone());
                // A renewed attested channel may collect the final checkpoint. Keep that
                // checkpoint immutable once draining has completed.
                if vm.store.data().drain_complete.is_none() {
                    vm.store
                        .data_mut()
                        .audit
                        .append("agent_activated", json!({}))?;
                }
                *self.certificate.lock().await = Some(cert);
                Ok(self.proof("activated", req["challenge"].clone(), json!({})))
            }
            Some("audit") => {
                self.active().await?;
                let mut vm = self.vm.lock().await;
                let page = vm.store.data_mut().audit.page(
                    protocol::unsigned(&req, "after")?,
                    protocol::string(&req, "previous_hash")?,
                    protocol::unsigned(&req, "limit")? as usize,
                )?;
                Ok(self.proof("audit", req["challenge"].clone(), page))
            }
            Some("drain") => self.drain(req).await,
            Some("enroll") => {
                self.active().await?;
                let mut vm = self.vm.lock().await;
                ensure!(!vm.poisoned, "agent trapped");
                ensure!(
                    vm.store.data().drain_operation.is_none(),
                    "agent is draining"
                );
                vm.store.data_mut().grant = Some(req["grant"].clone());
                vm.store.data_mut().enrollment = None;
                vm.store.set_fuel(100_000_000)?;
                let Vm {
                    instance, store, ..
                } = &mut *vm;
                let outcome = instance
                    .call_enroll_user(&mut *store, &req["grant"].to_string())
                    .await;
                store.data_mut().grant = None;
                let result = match outcome {
                    Ok(v) => v.map_err(anyhow::Error::msg),
                    Err(e) => {
                        vm.poisoned = true;
                        Err(e)
                    }
                };
                result?;
                let doc = &req["grant"]["document"];
                vm.store.data_mut().audit.append(
                    "user_enrolled",
                    json!({"tenant":doc["subject"],
                    "user_key":doc["public_key"],"revision":doc["revision"]}),
                )?;
                vm.store
                    .data_mut()
                    .enrollment
                    .take()
                    .context("agent did not launch user broker")
            }
            Some("run") => {
                self.active().await?;
                let _permit = self.permits.acquire().await?;
                self.active().await?;
                let request = req["request"].clone();
                let tenant = protocol::string(&request, "tenant")?.to_owned();
                let id = protocol::string(&request["job"], "job_id")?.to_owned();
                let sha = protocol::string(&request["job"], "sha256")?.to_owned();
                let start = Instant::now();
                let (url, token, client) = {
                    let mut vm = self.vm.lock().await;
                    ensure!(!vm.poisoned, "agent trapped");
                    ensure!(
                        vm.store.data().drain_operation.is_none(),
                        "agent is draining"
                    );
                    let host = vm.store.data_mut();
                    host.job = Some(request.clone());
                    host.policy_set = false;
                    host.launched = false;
                    vm.store.set_fuel(100_000_000)?;
                    let Vm {
                        instance, store, ..
                    } = &mut *vm;
                    let outcome = instance
                        .call_authorize_job(&mut *store, &request.to_string())
                        .await;
                    let admitted = store.data().launched;
                    store.data_mut().job = None;
                    match outcome {
                        Ok(v) => v.map_err(anyhow::Error::msg)?,
                        Err(e) => {
                            vm.poisoned = true;
                            return Err(e);
                        }
                    };
                    ensure!(admitted, "agent did not launch the authorized job");
                    let host = vm.store.data_mut();
                    let b = host.brokers.get_mut(&tenant).context("broker missing")?;
                    b.active += 1;
                    (b.url.clone(), b.token.clone(), host.client.clone())
                };
                // The Store lock is released: other users can be authorized while this runs.
                let outcome = async {
                    let response = client
                        .post(format!("{url}/v1/run"))
                        .bearer_auth(token)
                        .json(&request["job"])
                        .send()
                        .await?;
                    ensure!(response.status().is_success(), "broker request failed");
                    let bytes = response.bytes().await?;
                    ensure!(bytes.len() <= 1024 * 1024, "broker result too large");
                    Ok::<Value, anyhow::Error>(serde_json::from_slice(&bytes)?)
                }
                .await;
                let outcome = outcome.and_then(|r| {
                    if r["status"] == "ok" {
                        ensure!(
                            r["job_id"] == id
                                && r["tenant"] == tenant
                                && r["sha256"] == sha
                                && r["component"] == request["job"]["component"]
                                && r["cache_policy"] == request["job"]["cache"],
                            "broker result scope mismatch"
                        );
                    }
                    Ok(r)
                });
                let mut result=outcome.unwrap_or_else(|_|json!({"status":"error","execution_outcome":"unknown","error":"broker connection failed; job is not retried"}));
                result["job_id"] = json!(id);
                result["tenant"] = json!(tenant);
                result["sha256"] = json!(sha);
                let mut vm = self.vm.lock().await;
                if let Some(b) = vm.store.data_mut().brokers.get_mut(&tenant) {
                    b.active -= 1;
                }
                ensure!(!vm.poisoned, "agent trapped before completion");
                vm.store.data_mut().result = Some(result.clone());
                vm.store.data_mut().job = Some(request.clone());
                vm.store.data_mut().committed = false;
                vm.store.data_mut().audit_result = None;
                vm.store.set_fuel(100_000_000)?;
                let Vm {
                    instance, store, ..
                } = &mut *vm;
                let outcome = instance
                    .call_complete_job(&mut *store, &result.to_string())
                    .await;
                store.data_mut().result = None;
                store.data_mut().job = None;
                match outcome {
                    Ok(v) => v.map_err(anyhow::Error::msg)?,
                    Err(e) => {
                        vm.poisoned = true;
                        return Err(e);
                    }
                };
                ensure!(vm.store.data().committed, "agent did not commit completion");
                result["audit"] = vm
                    .store
                    .data()
                    .audit_result
                    .clone()
                    .context("audit commitment missing")?;
                vm.store.data().permit("identity.sign")?;
                result["shared_agent_total_ms"] = json!(ms(start));
                result["agent_instance"] = self.public["instance"].clone();
                result["agent_sha256"] = self.public["agent_sha256"].clone();
                result["agent_kind"] = json!("wasm");
                result["configuration"]["agent_interface"] = json!(ABI);
                result["configuration"]["agent_scope"] = json!("one-per-vm");
                result["configuration"]["audit_log"] = json!(crate::audit::FORMAT);
                if result["job_authorization"].is_object() {
                    result["job_authorization"]["agent_checked"] = json!(true);
                }
                result["security_trace"] = json!([
                    "user_signature_checked_by_agent",
                    "mandatory_workload_policy_applied",
                    "user_broker_selected",
                    "result_committed_by_agent"
                ]);
                result["agent_result_validation"] = json!(if result["status"] == "ok" {
                    "passed"
                } else {
                    "failed"
                });
                Ok(self.proof("result", json!(id), result))
            }
            _ => anyhow::bail!("unknown agent control operation"),
        }
    }
}
async fn connection(service: Arc<Service>, stream: UnixStream) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let request = tokio::time::timeout(
        Duration::from_secs(10),
        protocol::read(&mut stream, 2 * 1024 * 1024),
    )
    .await??;
    // Once admitted, a lost caller does not cancel a running job or silently retry it.
    let response = match service.handle(request).await {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(e) => json!({"ok":false,"error":format!("{e:#}")}),
    };
    protocol::write(stream.get_mut(), &response, 2 * 1024 * 1024).await
}
pub async fn serve(path: &Path) -> Result<()> {
    let config: Value = serde_json::from_slice(&cache::read_bounded(path, 128 * 1024)?)?;
    let root = PathBuf::from(protocol::string(&config, "runtime_dir")?);
    cache::private_directory(&root)?;
    let _slot = lock(&PathBuf::from(protocol::string(&config, "slot_lock")?))?;
    let agent = cache::read_bounded(
        Path::new(protocol::string(&config, "agent")?),
        8 * 1024 * 1024,
    )?;
    let sha = cache::hash(&agent);
    ensure!(
        config["agent_sha256"] == sha,
        "agent fingerprint differs from deployment"
    );
    let rights: HashSet<String> = serde_json::from_value(config["agent_permissions"].clone())?;
    ensure!(
        rights.iter().all(|r| RIGHTS.contains(&r.as_str())),
        "unknown agent HAL right"
    );
    ensure!(
        rights.contains("identity.sign"),
        "agent identity signing permission required"
    );
    let (engine, component, linker) = factory(&agent)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let key = SigningKey::from_bytes(&random()?);
    let public = json!({"vm_id":config["vm_id"],"instance":hex::encode(random()?),"agent_sha256":sha,"interface":ABI,"public_key":hex::encode(key.verifying_key().to_bytes()),"management_key":config["management_key"]});
    let audit = crate::audit::Journal::open(
        Path::new(protocol::string(&config, "audit_path")?),
        public.clone(),
        key.clone(),
        config["audit_max_bytes"]
            .as_u64()
            .unwrap_or(crate::audit::DEFAULT_LIMIT),
    )?;
    let host = Host {
        audit,
        audit_result: None,
        wasi: WasiCtxBuilder::new().build(),
        table: ResourceTable::new(),
        limits: StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024)
            .instances(32)
            .memories(8)
            .tables(32)
            .table_elements(100_000)
            .build(),
        config: config.clone(),
        agent_sha: sha.clone(),
        rights,
        brokers: HashMap::new(),
        client,
        grant: None,
        job: None,
        policy_set: false,
        launched: false,
        result: None,
        committed: false,
        enrollment: None,
        drain_operation: None,
        drain_complete: None,
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|s| &mut s.limits);
    store.set_fuel(100_000_000)?;
    store.fuel_async_yield_interval(Some(100_000))?;
    let instance = Orchestrator::instantiate_async(&mut store, &component, &linker).await?;
    instance
        .call_initialize(&mut store, &config["configuration"].to_string())
        .await?
        .map_err(anyhow::Error::msg)?;
    let service = Arc::new(Service {
        vm: Mutex::new(Vm {
            instance,
            store,
            poisoned: false,
        }),
        key,
        public,
        owner: protocol::string(&config, "management_key")?.into(),
        certificate: Mutex::new(None),
        permits: Semaphore::new(16),
        drain_lock: Mutex::new(()),
    });
    let socket = root.join("agent.sock");
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let connections = Arc::new(Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            accepted=listener.accept()=>{let(stream,_)=accepted?;if let Ok(permit)=connections.clone().try_acquire_owned(){let svc=service.clone();tasks.spawn(async move {let _permit=permit;let _=connection(svc,stream).await;});}},
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            _=term.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
        }
    }
    while tasks.join_next().await.is_some() {}
    let mut vm = service.vm.lock().await;
    for b in vm.store.data_mut().brokers.values_mut() {
        b.stop().await?;
    }
    vm.store.data_mut().brokers.clear();
    Ok(())
}

/// User broker entry point: performs no Wasm-agent loading.
pub async fn broker_run(shared: &Arc<Shared>, job: Job) -> Value {
    let mut result = json!({"status":"error","job_id":job.id,"tenant":job.tenant,"sha256":job.sha,"timings_ms":{},"workload_instance_reused":false});
    let outcome=async {
        let authority=shared.authorization.as_ref().context("managed broker needs signed jobs")?;
        let claims=authority.consume(&job)?;
        let rule=shared.agent_rule(&job)?.context("managed broker needs mandatory workload policy")?;
        if let Some(pool)=shared.containers.get(){
            let start=Instant::now();let info=pool.ensure(&job).await?;
            let startup=ms(start);let mut record=pool.run(&job).await?;
            let bytes=crate::containers::validate_result(&job,&record,rule.output_bytes)?;rule.validate(&bytes)?;
            ensure!(record["job_authorization"]["worker_checked"]==true && record["job_authorization"]["epoch"]==claims.epoch,"worker authorization missing");
            record["container"]=info;record["timings_ms"]["container_acquire"]=json!(startup);
            record["job_authorization"]["broker_checked"]=json!(true);Ok(record)
        } else {
            ensure!(shared.args.allow_non_tee,"managed workloads require a user container");
            // Explicit local integration fixture, unreachable in production profile.
            let mut record=crate::native::run(shared,job.clone()).await;
            if record["status"]=="ok" {rule.validate(&hex::decode(protocol::string(&record["result"],"hex")?)?)?;}
            record["job_authorization"]=json!({"verified":true,"broker_checked":true,"worker_checked":true,"epoch":claims.epoch,"nonce":claims.nonce});Ok(record)
        }
    }.await;
    match outcome {
        Ok(record) => result = record,
        Err(e) => result["error"] = json!(format!("{e:#}")),
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use control::Host as _;

    #[tokio::test]
    async fn control_imports_need_both_permissions_and_a_host_bound_operation() {
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[1; 32]);
        let mut h = Host {
            audit: crate::audit::Journal::open(&root.path().join("audit/agent.jsonl"),
                json!({"vm_id":"test","management_key":hex::encode(key.verifying_key().to_bytes())}),
                key, crate::audit::DEFAULT_LIMIT).unwrap(),
            audit_result: None,
            wasi: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new().build(),
            config: json!({}),
            agent_sha: "0".repeat(64),
            rights: HashSet::new(),
            brokers: HashMap::new(),
            client: reqwest::Client::new(),
            grant: None,
            job: None,
            policy_set: false,
            launched: false,
            result: None,
            committed: false,
            enrollment: None,
        drain_operation: None,
        drain_complete: None,
        };
        assert!(h
            .launch_user_broker()
            .await
            .unwrap_err()
            .contains("permission denied"));
        assert!(h
            .apply_workload_policy("{}".into())
            .await
            .unwrap_err()
            .contains("permission denied"));
        assert!(h
            .launch_workload()
            .await
            .unwrap_err()
            .contains("permission denied"));
        assert!(h
            .commit_result()
            .await
            .unwrap_err()
            .contains("permission denied"));
        h.rights = RIGHTS.iter().map(|s| s.to_string()).collect();
        assert!(h
            .launch_user_broker()
            .await
            .unwrap_err()
            .contains("management grant"));
        assert!(h
            .apply_workload_policy("{}".into())
            .await
            .unwrap_err()
            .contains("no job"));
        assert!(h
            .launch_workload()
            .await
            .unwrap_err()
            .contains("no bound job"));
        assert!(h
            .commit_result()
            .await
            .unwrap_err()
            .contains("no uncommitted result"));
    }
}
