mod agent;
mod agent_policy;
mod audit;
mod authorization;
mod cache;
mod compiler;
mod container_worker;
mod containers;
mod executor;
mod http;
mod metrics;
mod native;
mod orchestration;
mod protocol;
mod sandbox;
mod storage;
mod tenancy;
#[cfg(test)]
mod tests;
mod tickets_core;

use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use executor::{ms, Job, Shared};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Native,
    Wasm,
}
impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Wasm => "wasm",
        }
    }
    fn agent_kind(self) -> &'static str {
        match self {
            Self::Native => "none",
            Self::Wasm => "wasm",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Transport {
    Tcp,
    Http,
}
impl Transport {
    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CompileOptLevel {
    None,
    Speed,
    SpeedAndSize,
}
impl CompileOptLevel {
    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Speed => "speed",
            Self::SpeedAndSize => "speed-and-size",
        }
    }
    fn wasmtime(self) -> wasmtime::OptLevel {
        match self {
            Self::None => wasmtime::OptLevel::None,
            Self::Speed => wasmtime::OptLevel::Speed,
            Self::SpeedAndSize => wasmtime::OptLevel::SpeedAndSize,
        }
    }
}

#[derive(Clone, Parser)]
#[command(about = "Execute HAL workloads directly or through a real Wasm agent")]
pub struct Args {
    /// native skips agent.wasm and code caching; runtime reuse and execution limits remain.
    #[arg(long, value_enum, default_value = "wasm")]
    mode: Mode,
    /// Internal user broker launched only by the shared orchestration HAL.
    #[arg(long, hide = true)]
    managed_broker: bool,
    #[arg(long, value_enum, default_value = "tcp")]
    transport: Transport,
    #[arg(long, default_value = "dist/agent.wasm")]
    agent: PathBuf,
    /// Decrypted management configuration for the trusted agent only.
    #[arg(long)]
    agent_configuration: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9100")]
    listen: SocketAddr,
    #[arg(long)]
    token_file: PathBuf,
    /// Enable authenticated tenant namespaces. The original token becomes stats-only.
    #[arg(long)]
    tenant_policy: Option<PathBuf>,
    /// Wasm-only workload policy: ephemeral code cache, least-privilege HAL and result checks.
    #[arg(long)]
    agent_policy: Option<PathBuf>,
    /// Require user-signed jobs using operator-owned public keys and pinned rules.
    #[arg(long)]
    job_authorization: Option<PathBuf>,
    /// Isolate each user's workload runtime/cache in a Docker container (Wasm agent only).
    #[arg(long)]
    user_containers: bool,
    /// Locally built worker image; resolved once to an immutable Docker image ID.
    #[arg(long, default_value = "hal-user-worker:local")]
    container_image: String,
    #[arg(long, default_value = "/usr/bin/docker")]
    docker_bin: PathBuf,
    #[arg(long, default_value = "/var/run/docker.sock")]
    docker_socket: PathBuf,
    /// Short, private host IPC directory. Not mounted in its entirety in any worker.
    #[arg(long, default_value = "/run/hal-user-workers")]
    container_state_dir: PathBuf,
    #[arg(long, default_value_t = 1024)]
    container_memory_mib: usize,
    #[arg(long, default_value_t = 2)]
    container_cpus: usize,
    #[arg(long, default_value_t = 128)]
    container_pids: usize,
    /// Volatile application storage per container; lost when the container is removed.
    #[arg(long, default_value_t = 64)]
    container_storage_mib: usize,
    /// Internal worker identity is loaded from the read-only broker-generated config.
    #[arg(skip)]
    container_worker: Option<container_worker::Identity>,
    /// Credential for a protected artifact server; never exposed to a guest.
    #[arg(long)]
    file_token_file: Option<PathBuf>,
    /// Additional trusted PEM CA for an HTTPS artifact server (e.g. a private IP certificate).
    /// Certificate and hostname verification stay enabled; never passed to workload guests.
    #[arg(long)]
    file_ca_cert: Option<PathBuf>,
    #[arg(long)]
    file_server: reqwest::Url,
    #[arg(long, default_value = "state/cache")]
    cache_dir: PathBuf,
    #[arg(long, default_value_t = 16)]
    max_inflight: usize,
    #[arg(long, default_value_t = 4)]
    downloads: usize,
    #[arg(long, default_value_t = 1)]
    compilers: usize,
    /// Bound ALL workload compilation threads in a dedicated shared pool.
    /// Omit to retain Tokio blocking tasks plus Wasmtime's global Rayon pool.
    #[arg(long)]
    compiler_threads: Option<usize>,
    /// none minimizes compilation work; speed preserves the original setting.
    #[arg(long, value_enum, default_value = "speed")]
    compile_opt_level: CompileOptLevel,
    /// Parallelize functions within a compilation; separate from --compilers.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    parallel_compilation: bool,
    /// Reuse HTTP control connections. Jobs and workload instances remain separate.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    http_keep_alive: bool,
    #[arg(long, default_value_t = 4)]
    executions: usize,
    #[arg(long, default_value_t = 16)]
    compiled_cache_entries: usize,
    #[arg(long, default_value_t = 268435456)]
    disk_cache_bytes: u64,
    #[arg(long, default_value_t = 16777216)]
    max_component_bytes: usize,
    #[arg(long, default_value_t = 1048576)]
    max_output_bytes: usize,
    #[arg(long, default_value_t = 64)]
    workload_memory_mib: usize,
    #[arg(long, default_value_t = 1000000000)]
    workload_fuel: u64,
    #[arg(long, default_value_t = 30)]
    download_timeout_secs: u64,
    #[arg(long, default_value_t = 30)]
    execution_timeout_secs: u64,
    #[arg(long, default_value_t = 120)]
    job_timeout_secs: u64,
    /// SOFTWARE TESTING ONLY: explicitly use a synthetic HAL on a non-TEE host.
    #[arg(long)]
    allow_non_tee: bool,
}

struct Server {
    shared: Arc<Shared>,
    factory: Option<agent::Factory>,
    workers: Mutex<std::collections::VecDeque<(String, agent::Vm)>>,
    permits: Arc<Semaphore>,
    token: String,
    instance: String,
    agent_sha: Option<String>,
    host_sha: String,
    started: Instant,
    http_connections: std::sync::atomic::AtomicU64,
}

fn configuration(args: &Args) -> Value {
    let mut value = json!({ "runtime_role": if AGENT_RUNNER { "hal-agent-runner" } else { "legacy-broker" }, "wasmtime": "25.0.3", "compiler": "cranelift",
        "compile_opt_level": args.compile_opt_level.label(),
        "parallel_compilation": args.parallel_compilation,
        "http_keep_alive": args.http_keep_alive,
        "downloads": args.downloads, "compilers": args.compilers,
        "compiler_pool": if args.compiler_threads.is_some() { "dedicated" } else { "legacy" },
        "compiler_threads": args.compiler_threads,
        "available_parallelism": std::thread::available_parallelism().ok().map(|n| n.get()),
        "executions": args.executions, "max_inflight": args.max_inflight,
        "isolation": if args.tenant_policy.is_some() { "tenant-and-artifact" } else { "legacy-single-user" },
        "agent_policy_enabled": args.agent_policy.is_some(),
        "signed_jobs_required": args.job_authorization.is_some(),
        "agent_interface": if args.mode == Mode::Wasm { Some("elastic:job-agent@0.5.0") } else { None },
        "workload_isolation": if args.user_containers { "per-user-container" } else { "in-process" },
        "workload_sandbox": if args.user_containers { Some(sandbox::profile()) } else { None },
        "container_limits": if args.user_containers { Some(json!({"memory_mib":args.container_memory_mib,
            "cpus":args.container_cpus,"pids":args.container_pids,"storage_mib":args.container_storage_mib,
            "network":"none","read_only_root":true,"uid":65532})) } else { None },
        "code_cache_storage": if args.agent_policy.is_some() { "memory-only" } else { "disk-and-memory" },
        "cache_limits_source": if args.tenant_policy.is_some() { "tenant-policy" } else { "command-line" },
        "compiled_cache_entries": args.compiled_cache_entries,
        "workload_fuel": args.workload_fuel,
        "memory_limit_per_wasm_memory_mib": args.workload_memory_mib,
        "rayon_num_threads_env": std::env::var("RAYON_NUM_THREADS").ok() });
    if args.mode == Mode::Native {
        value["execution_profile"] = json!("native-optimized-uncached-v1");
        value["runtime_reused"] = json!(true);
        value["workload_instance_reused"] = json!(false);
        value["execution_limits_enabled"] = json!(true);
        value["execution_timeout_secs"] = json!(args.execution_timeout_secs);
        value["job_timeout_secs"] = json!(args.job_timeout_secs);
        value["max_output_bytes"] = json!(args.max_output_bytes);
        value["code_cache_storage"] = json!("disabled");
        value["cache_limits_source"] = json!("disabled");
        value["compiled_cache_entries"] = json!(0);
        value["inactive_options"] = json!(["compiled-cache-entries", "disk-cache-bytes"]);
    }
    value
}

async fn request(server: &Arc<Server>, value: Value) -> Result<Value> {
    let credential = protocol::string(&value, "token")?;
    let admin = tenancy::same_token(credential, &server.token);
    if value["op"] == "stats" {
        ensure!(
            admin,
            "unauthorized: statistics require the operator credential"
        );
        let containers = match server.shared.containers.get() {
            Some(pool) => pool.stats().await,
            None => Value::Null,
        };
        return Ok(
            json!({ "status": "ok", "stats": server.shared.stats(), "containers":containers,
            "stats_scope": if server.shared.args.user_containers {"broker-only; worker counters are in containers.users"} else {"execution-process"},
            "instance": server.instance, "platform": server.shared.platform,
            "execution_mode": server.shared.args.mode.label(), "agent_kind": server.shared.args.mode.agent_kind(),
            "transport": server.shared.args.transport.label(),
            "configuration": configuration(&server.shared.args),
            "job_authorization":server.shared.authorization.as_ref().map(|a| a.status()),
            "process_resources": metrics::process_resources(),
            "uptime_ms": ms(server.started),
            "requests_inflight": server.shared.args.max_inflight - server.permits.available_permits(),
            "http_connections": server.http_connections.load(std::sync::atomic::Ordering::Relaxed),
            "agent_sha256": server.agent_sha, "host_sha256": server.host_sha, "attestation_verified": false }),
        );
    }
    ensure!(value["op"] == "run", "unknown operation");
    ensure!(
        value.get("tenant").is_none(),
        "tenant is derived from authentication, not the request"
    );
    let mut job = Job::parse(&value, server.shared.args.max_component_bytes)?;
    if let Some(policy) = &server.shared.policy {
        let tenant = policy
            .authenticate(credential)
            .context("unauthorized tenant credential")?;
        tenant.allows(&job)?;
        job.tenant = tenant.id.clone();
    } else {
        ensure!(admin, "unauthorized");
    }
    if server.shared.args.mode == Mode::Native {
        ensure!(
            !job.reuse,
            "no-agent mode has no code cache; submit with --cache bypass"
        );
        ensure!(
            job.ticket.is_none(),
            "signed jobs require --mode wasm with job authorization"
        );
    }
    let tenant_id = job.tenant.clone();
    let agent_rule = server.shared.agent_rule(&job)?;
    let worker_scope = if agent_rule.is_some() {
        format!("{}:{}", job.tenant, job.sha)
    } else {
        tenant_id.clone()
    };
    let worker_max_jobs = agent_rule.as_ref().map_or(u64::MAX, |r| r.worker_max_jobs);
    let _tenant_permit = match server.shared.tenant_permits(&job)?.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(
                json!({"status":"busy", "job_id":job.id, "executed":false, "error":"tenant capacity exhausted"}),
            )
        }
    };
    let _permit = match server.permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Ok(json!({ "status": "busy", "job_id": job.id, "executed": false })),
    };
    let start = Instant::now();
    let id = job.id.clone();
    let deadline = Duration::from_secs(server.shared.args.job_timeout_secs);
    let mut worker_reused = false;
    let mut worker_acquire = 0.0;
    let outcome = match &server.factory {
        None if server.shared.args.managed_broker => {
            tokio::time::timeout(deadline, orchestration::broker_run(&server.shared, job)).await
        }
        None => tokio::time::timeout(deadline, native::run(&server.shared, job)).await,
        Some(factory) => {
            let existing = {
                let mut workers = server.workers.lock().await;
                workers
                    .iter()
                    .rposition(|(scope, _)| scope == &worker_scope)
                    .and_then(|index| workers.remove(index))
                    .map(|(_, vm)| vm)
            };
            worker_reused = existing.is_some();
            let mut worker = match existing {
                Some(worker) => worker,
                None => factory.worker(server.shared.clone()).await?,
            };
            worker_acquire = ms(start);
            let outcome = tokio::time::timeout(deadline, worker.run(job)).await;
            if outcome.is_ok() && !worker.poisoned && worker.runs < worker_max_jobs {
                let mut workers = server.workers.lock().await;
                // Bound idle agent memory across all tenants and workloads.
                if workers.len() >= server.shared.args.max_inflight {
                    workers.pop_front();
                }
                workers.push_back((worker_scope, worker));
            }
            outcome
        }
    };
    let mut record = outcome.unwrap_or_else(|_| {
        json!({ "status": "error", "job_id": id,
        "error": "job deadline exceeded", "execution_outcome": "unknown", "timings_ms": {} })
    });
    record["timings_ms"]["worker_acquire"] = json!(worker_acquire);
    record["timings_ms"]["host_request"] = json!(ms(start));
    record["execution_mode"] = json!(server.shared.args.mode.label());
    record["tenant"] = json!(tenant_id);
    if let Some(policy) = &server.shared.policy {
        let tenant = policy.get(&tenant_id)?;
        record["tenant_limits"] = json!({
            "cache_bytes": tenant.cache_bytes, "compiled_cache_entries": tenant.cache_entries,
            "storage_bytes": tenant.storage_bytes, "storage_entries": tenant.storage_entries,
            "max_inflight": tenant.max_inflight,
            "storage_scope": "tenant-and-artifact-sha256",
            "network_access": false, "communication_access": false,
        });
    }
    record["transport"] = json!(server.shared.args.transport.label());
    record["agent_kind"] = json!(server.shared.args.mode.agent_kind());
    record["host_instance"] = json!(server.instance);
    record["agent_instance"] = if server.factory.is_some() {
        json!(server.instance)
    } else {
        Value::Null
    };
    record["agent_sha256"] = json!(server.agent_sha);
    record["host_sha256"] = json!(server.host_sha);
    record["agent_worker_reused"] = json!(worker_reused);
    record["platform"] = json!(server.shared.platform);
    record["non_tee_test_mode"] = json!(server.shared.args.allow_non_tee);
    record["attestation_verified"] = json!(false);
    record["configuration"] = configuration(&server.shared.args);
    Ok(record)
}

async fn connection(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut stream = BufReader::new(stream);
    let value = tokio::time::timeout(
        Duration::from_secs(10),
        protocol::read(&mut stream, protocol::REQUEST_LIMIT),
    )
    .await
    .context("request read timeout")?;
    let response = match value {
        Ok(value) => request(&server, value).await,
        Err(error) => Err(error),
    }
    .unwrap_or_else(|e| json!({ "status": "error", "error": format!("{e:#}") }));
    tokio::time::timeout(
        Duration::from_secs(10),
        protocol::write(stream.get_mut(), &response, protocol::RESPONSE_LIMIT),
    )
    .await
    .context("response write timeout")??;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    // An internal entry point, never selected by an HTTP request or Wasm guest.
    let raw: Vec<_> = std::env::args_os().collect();
    if raw.get(1).is_some_and(|s| s == "--container-worker-config") {
        ensure!(raw.len() == 3, "worker requires exactly one config path");
        return container_worker::serve(&PathBuf::from(&raw[2])).await;
    }
    if AGENT_RUNNER && raw.get(1).is_some_and(|s| s == "--attestation-evidence") {
        use std::io::Read;
        let mut input = String::new();
        std::io::stdin().take(4097).read_to_string(&mut input)?;
        ensure!(input.len() <= 4096, "attestation request too large");
        let request: Value = serde_json::from_str(&input)?;
        let platform = request["platform"].as_str().unwrap_or("");
        let tag = match platform {
            "intel-tdx" => "tdx",
            "amd-sev-snp" => "snp",
            _ => anyhow::bail!("unsupported evidence platform"),
        };
        let data = hex::decode(request["report_data"].as_str().unwrap_or(""))?;
        ensure!(
            data.len() == 64,
            "REPORTDATA must contain the complete binding hash"
        );
        // Preserve the signed evidence. Parsing measurements is not verification.
        let (report, certificates) =
            elastic_tee_hal::attestation::request_report_with_aux(tag, &data, tag == "snp")?;
        let mut evidence = json!({"platform":platform,"report_hex":hex::encode(report)});
        if !certificates.is_empty() {
            evidence["certificates_hex"] = json!(hex::encode(certificates));
        }
        println!("{}", evidence);
        return Ok(());
    }
    if AGENT_RUNNER && raw.get(1).is_some_and(|s| s == "--hal-capabilities") {
        println!(
            "{}",
            json!({"interface":orchestration::ABI,"agent_rights":orchestration::RIGHTS,
            "single_agent":true,"agent_undeployment":"drain-audit-retire-v1","mandatory_workload_policy":true,"workload_interface":"elastic:hal@0.1.0",
            "workload_sandbox":sandbox::profile(),"audit_log":audit::FORMAT})
        );
        return Ok(());
    }
    if raw.get(1).is_some_and(|s| s == "--check-agent") {
        ensure!(raw.len() == 3, "check-agent requires one component path");
        let bytes = std::fs::read(&raw[2])?;
        ensure!(bytes.len() <= 8 * 1024 * 1024, "agent too large");
        if AGENT_RUNNER {
            orchestration::check(&bytes)?;
            println!(
                "{}",
                json!({"interface":orchestration::ABI,"sha256":cache::hash(&bytes),"agent_rights":orchestration::RIGHTS})
            );
        } else {
            agent::Factory::new(&bytes)?;
            println!(
                "{}",
                json!({"interface":"elastic:job-agent@0.4.0","sha256":cache::hash(&bytes)})
            );
        }
        return Ok(());
    }
    if AGENT_RUNNER && raw.get(1).is_some_and(|s| s == "--orchestrator-config") {
        ensure!(raw.len() == 3, "one orchestration configuration required");
        return orchestration::serve(&PathBuf::from(&raw[2])).await;
    }
    let mut args = Args::parse();
    if AGENT_RUNNER && !args.managed_broker {
        ensure!(
            args.mode == Mode::Wasm,
            "HAL agent runner only accepts Wasm agents"
        );
        ensure!(
            args.agent_configuration.is_some(),
            "management agent configuration required"
        );
    }
    for (name, n) in [
        ("max-inflight", args.max_inflight),
        ("downloads", args.downloads),
        ("compilers", args.compilers),
        ("executions", args.executions),
        ("compiled-cache-entries", args.compiled_cache_entries),
        ("workload-memory-mib", args.workload_memory_mib),
    ] {
        ensure!(n > 0 && n <= 1024, "{name} must be in 1..1024");
    }
    ensure!(
        args.max_component_bytes >= 8 && args.max_component_bytes <= 64 * 1024 * 1024,
        "invalid maximum component size"
    );
    ensure!(
        args.max_output_bytes > 0 && args.max_output_bytes <= 1024 * 1024,
        "output limit must be 1..1048576"
    );
    ensure!(args.workload_fuel > 0, "fuel must be positive");
    if let Some(threads) = args.compiler_threads {
        ensure!(
            (1..=1024).contains(&threads),
            "compiler-threads must be in 1..1024"
        );
    }
    ensure!(
        args.job_timeout_secs > 0
            && args.job_timeout_secs <= 3600
            && args.execution_timeout_secs > 0
            && args.execution_timeout_secs <= args.job_timeout_secs
            && args.download_timeout_secs > 0,
        "invalid timeouts"
    );
    ensure!(
        matches!(args.file_server.scheme(), "http" | "https")
            && args.file_server.host_str().is_some()
            && args.file_server.username().is_empty()
            && args.file_server.password().is_none()
            && args.file_server.query().is_none()
            && args.file_server.fragment().is_none(),
        "invalid file-server base URL"
    );
    if !args.file_server.path().ends_with('/') {
        args.file_server
            .set_path(&format!("{}/", args.file_server.path()));
    }
    if args.managed_broker {
        ensure!(
            args.mode == Mode::Wasm
                && args.job_authorization.is_some()
                && args.agent_policy.is_some()
                && (args.user_containers || args.allow_non_tee),
            "managed broker requires signed grants and containment"
        );
    }
    let token = std::fs::read_to_string(&args.token_file)?.trim().to_owned();
    ensure!(
        token.len() >= 32 && token.len() <= 256,
        "token must be 32..256 characters"
    );
    let mode = args.mode;
    let agent_path = args.agent.clone();
    let max_inflight = args.max_inflight;
    let listen = args.listen;
    let shared = Shared::new(args)?;
    let (factory, agent_sha) = if mode == Mode::Wasm && !shared.args.managed_broker {
        let bytes = std::fs::read(&agent_path)?;
        ensure!(bytes.len() <= 16 * 1024 * 1024, "agent component too large");
        let digest = cache::hash(&bytes);
        if let Some(policy) = &shared.agent_policy {
            ensure!(digest == policy.agent_sha, "agent.wasm SHA-256 differs from trusted agent policy; rebuild and review the policy together");
        }
        (Some(agent::Factory::new(&bytes)?), Some(digest))
    } else {
        (None, None)
    };
    if shared.args.user_containers {
        let pool = containers::Pool::new(&shared).await?;
        shared
            .containers
            .set(pool)
            .map_err(|_| anyhow::anyhow!("container pool already set"))?;
    }
    let host_sha = cache::hash(&std::fs::read(std::env::current_exe()?)?);
    let engine = shared.runtime.engine().clone();
    let epochs = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(10));
        loop {
            ticker.tick().await;
            engine.increment_epoch();
        }
    });
    let weak_shared = Arc::downgrade(&shared);
    let cache_expiry = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let Some(shared) = weak_shared.upgrade() else {
                break;
            };
            shared.expire_agent_cache();
        }
    });
    let instance = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let server = Arc::new(Server {
        shared,
        factory,
        workers: Mutex::new(std::collections::VecDeque::new()),
        permits: Arc::new(Semaphore::new(max_inflight)),
        token,
        instance,
        agent_sha,
        host_sha,
        started: Instant::now(),
        http_connections: std::sync::atomic::AtomicU64::new(0),
    });
    let listener = TcpListener::bind(listen).await?;
    println!(
        "{}",
        json!({ "status": "ready", "listen": listener.local_addr()?.to_string(),
        "agent_kind": server.shared.args.mode.agent_kind(), "execution_mode": server.shared.args.mode.label(),
        "transport": server.shared.args.transport.label(), "agent_sha256": server.agent_sha, "instance": server.instance,
        "platform": server.shared.platform, "attestation_verified": false,
        "job_authorization":server.shared.authorization.as_ref().map(|a| a.status()),
        "configuration": configuration(&server.shared.args),
        "max_inflight": max_inflight, "downloads": server.shared.args.downloads,
        "compilers": server.shared.args.compilers, "executions": server.shared.args.executions })
    );
    let connections = Arc::new(Semaphore::new(max_inflight + 16));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                if let Ok(permit) = connections.clone().try_acquire_owned() {
                    let server = server.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let outcome = match server.shared.args.transport {
                            Transport::Tcp => connection(server, stream).await,
                            Transport::Http => http::connection(server, stream).await,
                        };
                        if let Err(error) = outcome { log::warn!("connection ended: {error:#}"); }
                    });
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    epochs.abort();
    cache_expiry.abort();
    if let Some(pool) = server.shared.containers.get() {
        pool.shutdown().await?;
    }
    Ok(())
}
