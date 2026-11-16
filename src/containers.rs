//! Trusted container broker. A Wasm guest may ask only for its authenticated
//! user's worker; it cannot select an image, shell command, user, mount or device.
//! Workload bytes are compiled only in that worker. No network/Docker credentials
//! are mounted there. The only reverse IPC operation is an allowlisted download.
use crate::{
    cache,
    container_worker::{job_wire, Identity},
    executor::{ms, Job, Shared},
    protocol, Args, Mode,
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{Mutex, Semaphore},
};

const UID: u32 = 65532;
const WORKER_PROTOCOL: u64 = 1;

pub struct Pool {
    shared: Weak<Shared>,
    image: String,
    session: String,
    slots: HashMap<String, Slot>,
    _root_lock: cache::Cache,
    _directory: tempfile::TempDir,
    stopping: AtomicBool,
}
struct Slot {
    name: String,
    directory: PathBuf,
    worker: Mutex<Option<Worker>>,
    failed: AtomicBool,
}
struct Worker {
    socket: PathBuf,
    artifact_task: tokio::task::JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.artifact_task.abort();
    }
}

fn random_id() -> Result<String> {
    let mut bytes = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

pub fn validate_options(args: &Args) -> Result<()> {
    ensure!(
        args.mode == Mode::Wasm && args.tenant_policy.is_some() && args.agent_policy.is_some(),
        "--user-containers requires --mode wasm, --tenant-policy and --agent-policy"
    );
    ensure!(
        args.container_worker.is_none(),
        "nested container creation is forbidden"
    );
    ensure!(
        (256..=65536).contains(&args.container_memory_mib),
        "container-memory-mib must be 256..65536"
    );
    ensure!(
        (1..=128).contains(&args.container_cpus),
        "container-cpus must be 1..128"
    );
    ensure!(
        (32..=4096).contains(&args.container_pids),
        "container-pids must be 32..4096"
    );
    ensure!(
        (8..=4096).contains(&args.container_storage_mib),
        "container-storage-mib must be 8..4096"
    );
    ensure!(
        args.container_image.len() <= 256
            && !args.container_image.starts_with('-')
            && args
                .container_image
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"/:@._-".contains(&c)),
        "invalid worker image reference"
    );
    for path in [
        &args.docker_bin,
        &args.docker_socket,
        &args.container_state_dir,
    ] {
        ensure!(
            path.is_absolute() && !path.to_string_lossy().contains([',', '\n', '\r']),
            "container paths must be absolute and contain no commas/newlines"
        );
    }
    Ok(())
}

async fn docker(args: &Args, command: &[String]) -> Result<String> {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new(&args.docker_bin)
            // Never inherit a remote DOCKER_HOST, context, credentials or TLS setup.
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("--host")
            .arg(format!("unix://{}", args.docker_socket.display()))
            .args(command)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Docker command timed out")??;
    ensure!(
        result.status.success(),
        "Docker operation failed: {}",
        String::from_utf8_lossy(&result.stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

fn validate_daemon(info: &Value) -> Result<()> {
    crate::sandbox::validate_daemon(info)?;
    ensure!(
        info["OSType"] == "linux",
        "worker daemon must run Linux containers"
    );
    for control in ["MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"] {
        ensure!(
            info[control] == true,
            "Docker cannot enforce required {control}; refusing weaker containment"
        );
    }
    let security = info["SecurityOptions"]
        .as_array()
        .context("Docker security information missing")?;
    let named = |name: &str| {
        security
            .iter()
            .filter_map(Value::as_str)
            .any(|s| s.split(',').any(|part| part == name))
    };
    ensure!(
        security.iter().filter_map(Value::as_str).any(|s| {
            s.split(',').any(|p| p == "name=seccomp")
                && s.split(',').any(|p| p == "profile=builtin")
        }),
        "this worker profile requires Docker's built-in seccomp filter"
    );
    ensure!(!named("name=rootless") && !named("name=userns"),
        "this socket ownership implementation requires a local rootful daemon without user-namespace remapping");
    Ok(())
}

/// Arguments are entirely operator-controlled. Do not replace with shell text.
pub fn launch_arguments(
    args: &Args,
    image: &str,
    name: &str,
    session: &str,
    tenant: &str,
    root: &Path,
) -> Vec<String> {
    let tmpfs = crate::sandbox::tmpfs_options(args.container_storage_mib);
    vec![
        "run".into(),
        "--detach".into(),
        "--rm".into(),
        "--pull=never".into(),
        "--name".into(),
        name.into(),
        "--label".into(),
        format!("hal.broker={session}"),
        "--label".into(),
        format!("hal.tenant={tenant}"),
        format!("--runtime={}", crate::sandbox::RUNTIME),
        "--init".into(),
        "--read-only".into(),
        "--network=none".into(),
        "--ipc=private".into(),
        "--cgroupns=private".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges:true".into(),
        "--user=65532:65532".into(),
        format!("--cpus={}", args.container_cpus),
        format!("--memory={}m", args.container_memory_mib),
        format!("--memory-swap={}m", args.container_memory_mib),
        format!("--pids-limit={}", args.container_pids),
        "--ulimit=nofile=1024:1024".into(),
        "--ulimit=core=0:0".into(),
        "--log-driver=none".into(),
        format!("--tmpfs={}:{}", tmpfs[0].0, tmpfs[0].1),
        format!("--tmpfs={}:{}", tmpfs[1].0, tmpfs[1].1),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/config,readonly,bind-propagation=rprivate",
            root.join("config").display()
        ),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/run/broker,readonly,bind-propagation=rprivate",
            root.join("broker").display()
        ),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/run/worker,bind-propagation=rprivate",
            root.join("worker").display()
        ),
        "--entrypoint=/usr/local/bin/hal-on-demand".into(),
        image.into(),
        "--container-worker-config".into(),
        "/config/worker.json".into(),
    ]
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    // systemd's UMask=0077 must not leave these root-owned snapshots unreadable
    // to UID 65532. Set the final mode on the new fd, after writing. The parent
    // tenant directory stays root-only; only this user's read-only /config mount
    // exposes the snapshot inside its container. Never relax the service umask.
    file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    Ok(())
}

/// No management/file-server tokens, URLs, or other users' policies cross this boundary.
pub fn worker_config(
    shared: &Shared,
    tenant: &str,
    config_root: &Path,
    ipc_root: &Path,
    broker_root: &Path,
    state: &Path,
) -> Result<Value> {
    let args = &shared.args;
    let t = shared
        .policy
        .as_ref()
        .context("user policy missing")?
        .get(tenant)?;
    let mut argv = vec![
        "hal-worker".to_string(),
        "--mode".into(),
        "wasm".into(),
        "--file-server".into(),
        "http://127.0.0.1.invalid/".into(), // unused: worker fetches only over private IPC
        "--token-file".into(),
        config_root
            .join("operator.token")
            .to_string_lossy()
            .into_owned(),
        "--tenant-policy".into(),
        config_root
            .join("tenant.json")
            .to_string_lossy()
            .into_owned(),
        "--agent-policy".into(),
        config_root
            .join("agent-policy.json")
            .to_string_lossy()
            .into_owned(),
        "--cache-dir".into(),
        state.to_string_lossy().into_owned(),
        "--compile-opt-level".into(),
        args.compile_opt_level.label().into(),
        "--parallel-compilation".into(),
        args.parallel_compilation.to_string(),
    ];
    for (key, n) in [
        ("max-inflight", t.max_inflight as u64),
        ("downloads", args.downloads as u64),
        ("compilers", args.compilers as u64),
        ("executions", args.executions as u64),
        (
            "compiler-threads",
            args.compiler_threads.unwrap_or(args.container_cpus) as u64,
        ),
        ("max-component-bytes", args.max_component_bytes as u64),
        ("max-output-bytes", args.max_output_bytes as u64),
        ("workload-memory-mib", args.workload_memory_mib as u64),
        ("workload-fuel", args.workload_fuel),
        ("download-timeout-secs", args.download_timeout_secs),
        ("execution-timeout-secs", args.execution_timeout_secs),
        ("job-timeout-secs", args.job_timeout_secs),
    ] {
        argv.extend([format!("--{key}"), n.to_string()]);
    }
    if args.allow_non_tee {
        argv.push("--allow-non-tee".into());
    }
    if shared.authorization.is_some() {
        argv.extend([
            "--job-authorization".into(),
            config_root
                .join("job-authorization.json")
                .to_string_lossy()
                .into_owned(),
        ]);
    }
    Ok(
        json!({"version":WORKER_PROTOCOL,"tenant":tenant,"platform":shared.platform,
        "authorization_epoch":shared.authorization.as_ref().map(|a| &a.epoch),
        "args":argv,"socket":ipc_root.join("worker.sock"),"broker_socket":broker_root.join("artifacts.sock")}),
    )
}

pub fn write_worker_config(
    shared: &Shared,
    tenant: &str,
    output: &Path,
    config: &Value,
) -> Result<()> {
    let t = shared
        .policy
        .as_ref()
        .context("user policy missing")?
        .get(tenant)?;
    write_new(&output.join("operator.token"), random_id()?.as_bytes())?;
    write_new(&output.join("worker.token"), random_id()?.as_bytes())?;
    write_new(
        &output.join("tenant.json"),
        &serde_json::to_vec(&t.worker_document())?,
    )?;
    write_new(
        &output.join("agent-policy.json"),
        &serde_json::to_vec(
            &shared
                .agent_policy
                .as_ref()
                .context("workload policy missing")?
                .worker_document(tenant),
        )?,
    )?;
    if let Some(authority) = &shared.authorization {
        write_new(
            &output.join("job-authorization.json"),
            &serde_json::to_vec(&authority.worker_document(tenant))?,
        )?;
    }
    write_new(&output.join("worker.json"), &serde_json::to_vec(config)?)?;
    Ok(())
}

pub async fn rpc(path: &Path, request: &Value, seconds: u64) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        let mut stream = BufReader::new(connect_worker(path).await?);
        protocol::write(stream.get_mut(), request, protocol::REQUEST_LIMIT).await?;
        protocol::read(&mut stream, protocol::RESPONSE_LIMIT).await
    })
    .await
    .context("private worker request timed out; execution outcome unknown")?
}

async fn connect_worker(path: &Path) -> Result<UnixStream> {
    #[cfg(target_os = "linux")]
    {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{FileTypeExt, OpenOptionsExt},
        };
        // The worker owns this directory. lstat-then-connect would allow a
        // symlink-swap attack against this privileged broker. Pin the socket
        // inode with O_PATH|O_NOFOLLOW and connect through our own proc fd.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure!(
            file.metadata()?.file_type().is_socket(),
            "worker endpoint is not a socket"
        );
        let stream = UnixStream::connect(format!("/proc/self/fd/{}", file.as_raw_fd())).await?;
        drop(file);
        Ok(stream)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Only used by software protocol tests; Pool::new refuses non-Linux.
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_socket(),
            "worker endpoint is not a socket"
        );
        Ok(UnixStream::connect(path).await?)
    }
}

pub async fn artifact_connection(
    shared: &Arc<Shared>,
    tenant: &str,
    stream: UnixStream,
) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let operation = async {
        let value = protocol::read(&mut stream, protocol::REQUEST_LIMIT).await?;
        ensure!(
            value["op"] == "run",
            "unsupported artifact broker operation"
        );
        let identity = Identity {
            tenant: tenant.into(),
            platform: shared.platform.clone(),
            broker_socket: PathBuf::new(),
            authorization_epoch: shared.authorization.as_ref().map(|a| a.epoch.clone()),
        };
        let job = crate::container_worker::authorize(shared, &identity, &value)?;
        let data = shared.download_artifact(&job).await?;
        protocol::write(
            stream.get_mut(),
            &json!({"status":"ok","bytes":data.len()}),
            protocol::REQUEST_LIMIT,
        )
        .await?;
        stream.get_mut().write_all(&data).await?;
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(
        Duration::from_secs(shared.args.download_timeout_secs + 5),
        operation,
    )
    .await
    .context("artifact request deadline exceeded")?
}

impl Pool {
    pub async fn new(shared: &Arc<Shared>) -> Result<Arc<Self>> {
        let args = &shared.args;
        validate_options(args)?;
        ensure!(
            cfg!(target_os = "linux"),
            "per-user Docker workers require a Linux execution VM"
        );
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "container broker currently requires sudo on the Linux VM"
        );
        let daemon: Value = serde_json::from_str(
            &docker(args, &["info".into(), "--format={{json .}}".into()]).await?,
        )?;
        validate_daemon(&daemon)?;
        let image = docker(
            args,
            &[
                "image".into(),
                "inspect".into(),
                "--format={{.Id}}".into(),
                args.container_image.clone(),
            ],
        )
        .await?;
        ensure!(
            image
                .strip_prefix("sha256:")
                .is_some_and(protocol::valid_sha),
            "expected immutable local Docker image ID"
        );
        let root_lock = cache::Cache::open(&args.container_state_dir, u64::MAX)?;
        let directory = tempfile::Builder::new()
            .prefix("b-")
            .tempdir_in(&args.container_state_dir)?;
        let session = random_id()?[..12].to_string();
        let mut slots = HashMap::new();
        for t in &shared.policy.as_ref().unwrap().tenants {
            ensure!(
                t.storage_bytes + 8 * 1024 * 1024
                    <= args.container_storage_mib as u64 * 1024 * 1024,
                "container-storage-mib must allow user {}'s storage quota plus 8 MiB metadata",
                t.id
            );
            let directory = directory.path().join(&cache::hash(t.id.as_bytes())[..12]);
            ensure!(
                directory.join("worker/worker.sock").as_os_str().len() < 104,
                "container-state-dir is too long for Unix sockets"
            );
            slots.insert(
                t.id.clone(),
                Slot {
                    name: format!("hal-u-{session}-{}", &cache::hash(t.id.as_bytes())[..12]),
                    directory,
                    worker: Mutex::new(None),
                    failed: AtomicBool::new(false),
                },
            );
        }
        Ok(Arc::new(Self {
            shared: Arc::downgrade(shared),
            image,
            session,
            slots,
            _root_lock: root_lock,
            _directory: directory,
            stopping: AtomicBool::new(false),
        }))
    }

    fn shared(&self) -> Result<Arc<Shared>> {
        self.shared.upgrade().context("broker stopped")
    }

    pub async fn ensure(&self, job: &Job) -> Result<Value> {
        let shared = self.shared()?;
        shared
            .policy
            .as_ref()
            .unwrap()
            .get(&job.tenant)?
            .allows(job)?;
        shared.agent_rule(job)?.context("workload policy missing")?;
        ensure!(!self.stopping.load(Ordering::SeqCst), "broker stopping");
        let slot = self
            .slots
            .get(&job.tenant)
            .context("unknown user container")?;
        // The startup owner holds this lock while failed is provisionally true.
        // Wait for its outcome before treating that flag as a permanent failure.
        let mut worker = slot.worker.lock().await;
        ensure!(
            !self.stopping.load(Ordering::SeqCst) && !slot.failed.load(Ordering::SeqCst),
            "user container is stopping or failed; creation will not be retried"
        );
        let reused = worker.is_some();
        let start = Instant::now();
        if worker.is_none() {
            // A cancelled/failed creation is never silently retried under a new identity.
            slot.failed.store(true, Ordering::SeqCst);
            *worker = Some(self.start(&shared, &job.tenant, slot).await?);
            slot.failed.store(false, Ordering::SeqCst);
        }
        Ok(
            json!({"kind":"docker","name":slot.name,"image_id":self.image,"tenant":job.tenant,
            "reused":reused,"startup_ms":if reused {0.0} else {ms(start)},
            "network":"none","private_kernel":false,"storage":"private-volatile-tmpfs",
            "runtime":crate::sandbox::RUNTIME,"sandbox_scope":"user",
            "sandbox_profile":crate::sandbox::profile()["profile"],"application_kernel":"gvisor-sentry",
            "launch_configuration_checked":true}),
        )
    }

    async fn start(&self, shared: &Arc<Shared>, tenant: &str, slot: &Slot) -> Result<Worker> {
        use std::os::unix::fs::PermissionsExt;
        cache::private_directory(&slot.directory)?;
        for name in ["config", "broker", "worker"] {
            let path = slot.directory.join(name);
            cache::private_directory(&path)?;
            if name == "worker" {
                std::os::unix::fs::chown(&path, Some(UID), Some(UID))?;
            } else {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        let config = worker_config(
            shared,
            tenant,
            Path::new("/config"),
            Path::new("/run/worker"),
            Path::new("/run/broker"),
            Path::new("/state"),
        )?;
        write_worker_config(shared, tenant, &slot.directory.join("config"), &config)?;
        let broker_socket = slot.directory.join("broker/artifacts.sock");
        let listener = UnixListener::bind(&broker_socket)?;
        std::os::unix::fs::chown(&broker_socket, None, Some(UID))?;
        std::fs::set_permissions(&broker_socket, std::fs::Permissions::from_mode(0o660))?;
        let weak = Arc::downgrade(shared);
        let owner = tenant.to_string();
        let permits = Arc::new(Semaphore::new(shared.args.max_inflight));
        let artifact_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Some(shared) = weak.upgrade() else { break };
                if let Ok(permit) = permits.clone().try_acquire_owned() {
                    let owner = owner.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = artifact_connection(&shared, &owner, stream).await {
                            log::warn!("user artifact request rejected: {error:#}");
                        }
                    });
                }
            }
        });
        let worker = Worker {
            socket: slot.directory.join("worker/worker.sock"),
            artifact_task,
        };
        let start_result = async {
            docker(
                &shared.args,
                &launch_arguments(
                    &shared.args,
                    &self.image,
                    &slot.name,
                    &self.session,
                    tenant,
                    &slot.directory,
                ),
            )
            .await?;
            let actual: Value = serde_json::from_str(
                &docker(
                    &shared.args,
                    &[
                        "inspect".into(),
                        "--format={{json .}}".into(),
                        slot.name.clone(),
                    ],
                )
                .await?,
            )?;
            crate::sandbox::validate_container(
                &actual,
                &crate::sandbox::ContainerPolicy {
                    image: &self.image,
                    tenant,
                    session: &self.session,
                    root: &slot.directory,
                    cpus: shared.args.container_cpus,
                    memory_mib: shared.args.container_memory_mib,
                    pids: shared.args.container_pids,
                    storage_mib: shared.args.container_storage_mib,
                },
            )?;
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(20) {
                if let Ok(value) = rpc(&worker.socket, &json!({"op":"stats"}), 1).await {
                    ensure!(
                        value["status"] == "ok"
                            && value["tenant"] == tenant
                            && value["worker_protocol"] == WORKER_PROTOCOL,
                        "wrong user or protocol in container handshake"
                    );
                    // No untrusted workload has run yet. Revoke directory write
                    // permission before dispatch so the bind mount cannot become
                    // unbounded host storage after a native worker compromise.
                    // The existing socket still works without directory writes.
                    let ipc_dir = slot.directory.join("worker");
                    let entries =
                        std::fs::read_dir(&ipc_dir)?.collect::<std::io::Result<Vec<_>>>()?;
                    use std::os::unix::fs::FileTypeExt;
                    ensure!(
                        entries.len() == 1
                            && entries[0].file_name() == "worker.sock"
                            && entries[0].file_type()?.is_socket(),
                        "unexpected worker IPC files at startup"
                    );
                    std::os::unix::fs::chown(&ipc_dir, Some(0), Some(0))?;
                    std::fs::set_permissions(&ipc_dir, std::fs::Permissions::from_mode(0o555))?;
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::bail!(
                "container did not become ready; check the worker image and Docker configuration"
            )
        }
        .await;
        if let Err(error) = start_result {
            worker.artifact_task.abort();
            let _ = docker(
                &shared.args,
                &["rm".into(), "--force".into(), slot.name.clone()],
            )
            .await;
            return Err(error);
        }
        Ok(worker)
    }

    pub async fn run(&self, job: &Job) -> Result<Value> {
        let shared = self.shared()?;
        shared
            .policy
            .as_ref()
            .unwrap()
            .get(&job.tenant)?
            .allows(job)?;
        shared.agent_rule(job)?.context("workload policy missing")?;
        ensure!(!self.stopping.load(Ordering::SeqCst), "broker stopping");
        let slot = self
            .slots
            .get(&job.tenant)
            .context("unknown user container")?;
        ensure!(
            !slot.failed.load(Ordering::SeqCst),
            "user worker is unavailable"
        );
        let socket = slot
            .worker
            .lock()
            .await
            .as_ref()
            .context("agent must ensure its user container first")?
            .socket
            .clone();
        let result = rpc(&socket, &job_wire(job), shared.args.job_timeout_secs).await;
        if result.is_err() {
            slot.failed.store(true, Ordering::SeqCst);
        }
        // Never retry after dispatch: a failed response does not prove no execution occurred.
        let result = result?;
        if let Err(error) = validate_result(job, &result, shared.args.max_output_bytes) {
            // Normal execution errors are reported to the caller. A malformed
            // successful response disables this worker until a broker restart.
            if result["status"] == "ok" {
                slot.failed.store(true, Ordering::SeqCst);
            }
            return Err(error);
        }
        Ok(result)
    }

    pub async fn stats(&self) -> Value {
        let mut users = serde_json::Map::new();
        for (tenant, slot) in &self.slots {
            let socket = slot.worker.lock().await.as_ref().map(|w| w.socket.clone());
            if let Some(socket) = socket {
                let result = rpc(&socket, &json!({"op":"stats"}), 1).await;
                users.insert(
                    tenant.clone(),
                    json!({"name":slot.name,"failed":slot.failed.load(Ordering::SeqCst),
                    "worker":result.unwrap_or_else(|_| json!({"status":"unavailable"}))}),
                );
            }
        }
        json!({"image_id":self.image,"stats_scope":"private-workers","users":users,
            "sandbox_profile":crate::sandbox::profile()})
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        let shared = self.shared()?;
        let mut errors = Vec::new();
        for slot in self.slots.values() {
            let mut worker = slot.worker.lock().await;
            if worker.is_some() || slot.failed.load(Ordering::SeqCst) {
                if let Err(error) = docker(
                    &shared.args,
                    &["rm".into(), "--force".into(), slot.name.clone()],
                )
                .await
                {
                    if !format!("{error:#}").contains("No such container") {
                        errors.push(format!("{error:#}"));
                    }
                }
                if let Some(worker) = worker.take() {
                    worker.artifact_task.abort();
                }
            }
        }
        ensure!(
            errors.is_empty(),
            "container cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}

/// Worker JSON is untrusted input to the privileged broker, even over private IPC.
pub fn validate_result(job: &Job, value: &Value, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        value["status"] == "ok",
        "user worker returned an error: {}",
        value["error"]
            .as_str()
            .unwrap_or("invalid response")
            .chars()
            .take(2048)
            .collect::<String>()
    );
    ensure!(
        value["worker_protocol"] == WORKER_PROTOCOL
            && value["tenant"] == job.tenant
            && value["job_id"] == job.id
            && value["component"] == job.name
            && value["sha256"] == job.sha
            && value["artifact_bytes"].as_u64() == Some(job.size),
        "worker response differs from the authorized user/job/artifact"
    );
    let status = value["cache_status"]
        .as_str()
        .context("worker cache status missing")?;
    ensure!(
        if job.reuse {
            ["hit", "miss", "shared"].contains(&status)
        } else {
            status == "bypass"
        },
        "worker changed cache plan"
    );
    let encoded = protocol::string(&value["result"], "hex")?;
    ensure!(
        encoded.len() <= maximum * 2,
        "worker output exceeds host limit"
    );
    let bytes = hex::decode(encoded)?;
    ensure!(
        value["result"]["bytes"].as_u64() == Some(bytes.len() as u64),
        "worker output length mismatch"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    fn args() -> Args {
        Args::parse_from([
            "test",
            "--allow-non-tee",
            "--token-file",
            "unused",
            "--file-server",
            "http://localhost/",
            "--tenant-policy",
            "tenant.json",
            "--agent-policy",
            "agent.json",
            "--user-containers",
        ])
    }
    fn job() -> Job {
        Job {
            id: "first".into(),
            name: "f.wasm".into(),
            sha: "a".repeat(64),
            size: 8,
            reuse: false,
            tenant: "alice".into(),
            ticket: None,
        }
    }
    fn result() -> Value {
        let job = job();
        json!({"status":"ok","worker_protocol":1,"tenant":job.tenant,"job_id":job.id,"component":job.name,
            "sha256":job.sha,"artifact_bytes":8,"cache_status":"bypass","result":{"bytes":1,"hex":"41"}})
    }

    fn scoped_shared(root: &Path) -> Arc<Shared> {
        scoped_shared_profile(root, false)
    }
    fn scoped_shared_profile(root: &Path, with_profile: bool) -> Arc<Shared> {
        let mut args = args();
        args.token_file = root.join("operator.token");
        std::fs::write(&args.token_file, "original-operator-secret-".repeat(3)).unwrap();
        args.file_token_file = Some(root.join("file-server.token"));
        std::fs::write(
            args.file_token_file.as_ref().unwrap(),
            "original-file-server-secret-".repeat(3),
        )
        .unwrap();
        std::fs::write(root.join("alice.token"), "original-alice-secret-".repeat(3)).unwrap();
        std::fs::write(root.join("bob.token"), "original-bob-secret-".repeat(3)).unwrap();
        let tenant = |id: &str| {
            json!({"id":id,"token_file":format!("{id}.token"),
            "artifacts":[{"component":"f.wasm","sha256":"a".repeat(64),"artifact_bytes":8}]})
        };
        args.tenant_policy = Some(root.join("tenants.json"));
        std::fs::write(
            args.tenant_policy.as_ref().unwrap(),
            serde_json::to_vec(&json!({"version":1,
            "tenants":[tenant("alice"),tenant("bob")]}))
            .unwrap(),
        )
        .unwrap();
        let rule = |id: &str| {
            let mut rule = json!({"tenant":id,"component":"f.wasm","sha256":"a".repeat(64),
            "cache":"memory","cache_ttl_ms":300000,"hal_permissions":[],"memory_mib":1,"fuel":100000,
            "execution_timeout_ms":1000,"max_output_bytes":4096,"worker_max_jobs":128,"validation":{"kind":"hex","value":"41"}});
            if with_profile {
                rule["access_profile"] = json!({"version":1,"artifact_sha256":"a".repeat(64),
                    "operations":[],"max_host_calls":1,"max_buffer_bytes":64});
            }
            rule
        };
        args.agent_policy = Some(root.join("agent.json"));
        std::fs::write(
            args.agent_policy.as_ref().unwrap(),
            serde_json::to_vec(&json!({"version":1,"agent_sha256":"b".repeat(64),
            "workloads":[rule("alice"),rule("bob")]}))
            .unwrap(),
        )
        .unwrap();
        args.cache_dir = root.join("state");
        Shared::new(args).unwrap()
    }

    async fn concurrent_startup_waiters(startup_succeeds: bool) {
        use std::{future::Future, task::Poll};

        let dir = tempfile::tempdir().unwrap();
        let shared = scoped_shared(dir.path());
        let pool = Pool {
            shared: Arc::downgrade(&shared),
            image: "test-double".into(),
            session: "test".into(),
            slots: HashMap::from([(
                "alice".into(),
                Slot {
                    name: "test-alice".into(),
                    directory: dir.path().into(),
                    worker: Mutex::new(None),
                    failed: AtomicBool::new(false),
                },
            )]),
            _root_lock: cache::Cache::open(&dir.path().join("pool-lock"), u64::MAX).unwrap(),
            _directory: tempfile::tempdir_in(dir.path()).unwrap(),
            stopping: AtomicBool::new(false),
        };
        let slot = &pool.slots["alice"];
        // Pause the owner exactly where ensure() awaits the container launch.
        // No Docker process is needed to exercise the real admission path.
        let mut starting = slot.worker.lock().await;
        slot.failed.store(true, Ordering::SeqCst);
        let job = job();
        let mut waiters: Vec<_> = (0..4).map(|_| Box::pin(pool.ensure(&job))).collect();
        for waiter in &mut waiters {
            let polled = std::future::poll_fn(|cx| Poll::Ready(waiter.as_mut().poll(cx))).await;
            assert!(polled.is_pending(), "request must wait for the startup owner");
        }
        if startup_succeeds {
            *starting = Some(Worker {
                socket: dir.path().join("unused.sock"),
                artifact_task: tokio::spawn(std::future::pending()),
            });
            slot.failed.store(false, Ordering::SeqCst);
        }
        // Failed or cancelled startup drops this lock with failed still set.
        drop(starting);
        for waiter in waiters {
            let result = waiter.await;
            if startup_succeeds {
                let metadata = result.unwrap();
                assert_eq!(metadata["name"], "test-alice");
                assert_eq!(metadata["reused"], true);
                assert_eq!(metadata["startup_ms"], 0.0);
            } else {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("creation will not be retried"));
            }
        }
        assert_eq!(slot.worker.lock().await.is_some(), startup_succeeds);
        assert_eq!(slot.failed.load(Ordering::SeqCst), !startup_succeeds);
    }

    #[tokio::test]
    async fn concurrent_requests_wait_for_successful_worker_startup() {
        tokio::time::timeout(Duration::from_secs(5), concurrent_startup_waiters(true))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_requests_do_not_retry_failed_or_cancelled_worker_startup() {
        tokio::time::timeout(Duration::from_secs(5), concurrent_startup_waiters(false))
            .await
            .unwrap();
    }

    #[test]
    fn worker_snapshot_contains_only_its_own_policy_and_new_internal_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let shared = scoped_shared(dir.path());
        let config_dir = dir.path().join("config");
        cache::private_directory(&config_dir).unwrap();
        let config = worker_config(
            &shared,
            "alice",
            Path::new("/config"),
            Path::new("/run/worker"),
            Path::new("/run/broker"),
            Path::new("/state"),
        )
        .unwrap();
        write_worker_config(&shared, "alice", &config_dir, &config).unwrap();
        let all = std::fs::read_dir(&config_dir)
            .unwrap()
            .map(|p| std::fs::read_to_string(p.unwrap().path()).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "original-operator-secret",
            "original-alice-secret",
            "original-bob-secret",
            "original-file-server-secret",
            "file-server.token",
            "\"bob\"",
            "http://localhost/",
            "docker.sock",
        ] {
            assert!(!all.contains(forbidden), "{forbidden}");
        }
        let policy: Value =
            serde_json::from_slice(&std::fs::read(config_dir.join("tenant.json")).unwrap())
                .unwrap();
        assert_eq!(policy["tenants"].as_array().unwrap().len(), 1);
        assert_eq!(policy["tenants"][0]["id"], "alice");
        assert!(
            write_worker_config(&shared, "alice", &config_dir, &config).is_err(),
            "must not overwrite existing config"
        );
    }

    #[test]
    fn worker_snapshot_preserves_the_full_signed_access_profile() {
        let dir = tempfile::tempdir().unwrap();
        let shared = scoped_shared_profile(dir.path(), true);
        let rule = shared.agent_rule(&job()).unwrap().unwrap();
        let document = shared
            .agent_policy
            .as_ref()
            .unwrap()
            .worker_document("alice");
        let row = &document["workloads"][0];
        assert_eq!(
            row["access_profile"],
            rule.authorization_value()["access_profile"]
        );
        let mut worker_rule = row.clone();
        worker_rule.as_object_mut().unwrap().remove("tenant");
        worker_rule.as_object_mut().unwrap().remove("sha256");
        assert_eq!(
            cache::hash(worker_rule.to_string().as_bytes()),
            rule.authorization_digest()
        );
        assert_eq!(document["workloads"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn real_wasm_agent_uses_scoped_worker_capabilities_and_host_rechecks_response() {
        // A private IPC test double exercises the real agent component and host
        // state machine. This is deliberately not presented as a Docker test.
        for malicious in [false, true] {
            let dir = tempfile::Builder::new()
                .prefix("hal-ipc-")
                .tempdir_in("/tmp")
                .unwrap();
            let shared = scoped_shared(dir.path());
            let socket = dir.path().join("worker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let request = protocol::read(&mut stream, protocol::REQUEST_LIMIT)
                    .await
                    .unwrap();
                assert!(request.get("tenant").is_none());
                let mut response = result();
                if malicious {
                    response["tenant"] = json!("bob");
                }
                protocol::write(stream.get_mut(), &response, protocol::RESPONSE_LIMIT)
                    .await
                    .unwrap();
            });
            let pool_dir = tempfile::Builder::new()
                .prefix("pool-")
                .tempdir_in(dir.path())
                .unwrap();
            let root_lock = cache::Cache::open(&dir.path().join("pool-lock"), u64::MAX).unwrap();
            let idle = tokio::spawn(std::future::pending());
            let pool = Arc::new(Pool {
                shared: Arc::downgrade(&shared),
                image: "test-double".into(),
                session: "test".into(),
                slots: HashMap::from([(
                    "alice".into(),
                    Slot {
                        name: "test-alice".into(),
                        directory: dir.path().into(),
                        worker: Mutex::new(Some(Worker {
                            socket,
                            artifact_task: idle,
                        })),
                        failed: AtomicBool::new(false),
                    },
                )]),
                _root_lock: root_lock,
                _directory: pool_dir,
                stopping: AtomicBool::new(false),
            });
            shared
                .containers
                .set(pool)
                .unwrap_or_else(|_| panic!("pool already set"));
            let bytes =
                std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("dist/agent.wasm"))
                    .unwrap();
            let factory = crate::agent::Factory::new(&bytes).unwrap();
            let mut vm = factory.worker(shared.clone()).await.unwrap();
            let record = vm.run(job()).await;
            task.await.unwrap();
            if malicious {
                assert_eq!(record["status"], "error");
                assert!(record["error"]
                    .as_str()
                    .unwrap()
                    .contains("authorized user"));
                assert!(record.get("result").is_none());
            } else {
                assert_eq!(record["status"], "ok", "{record}");
                assert_eq!(record["result"]["hex"], "41");
                assert_eq!(record["host_calls"]["ensure_user_container"], 1);
                assert_eq!(record["host_calls"]["run_in_user_container"], 1);
                assert_eq!(record["host_calls"]["commit_result"], 1);
                assert_eq!(
                    record["security_trace"],
                    json!([
                        "policy_accepted",
                        "user_container_ready",
                        "executed_in_user_container",
                        "result_committed"
                    ])
                );
            }
            assert_eq!(
                shared.stats()["executions"],
                0,
                "no workload execution in broker"
            );
            assert_eq!(
                shared.stats()["compiles"],
                0,
                "no workload compilation in broker"
            );
        }
    }

    #[test]
    fn signed_worker_handoff_preserves_public_rules_and_epoch_without_signing_keys() {
        use ed25519_dalek::{Signer, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let mut shared = scoped_shared(dir.path());
        let key = SigningKey::from_bytes(&[19; 32]);
        let mut job = job();
        let rule = shared.agent_rule(&job).unwrap().unwrap();
        let path = dir.path().join("approvals.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"version":1,"audience":"handoff-test",
            "isolation":"per-user-container","max_ttl_seconds":120,
            "users":[{"tenant":"alice","public_key":hex::encode(key.verifying_key().to_bytes()),
                "workloads":[{"component":job.name,"sha256":job.sha,"artifact_bytes":job.size,
                    "rule_sha256":rule.authorization_digest()}]}]}))
            .unwrap(),
        )
        .unwrap();
        let authority = crate::authorization::Authority::load(
            &path,
            shared.policy.as_ref().unwrap(),
            shared.agent_policy.as_ref().unwrap(),
            &shared.args,
        )
        .unwrap();
        let epoch = authority.epoch.clone();
        let now = crate::authorization::now().unwrap();
        let payload = json!({"version":1,"tenant":job.tenant,"audience":"handoff-test","epoch":epoch,
            "job_id":job.id,"nonce":"d".repeat(64),"operation":"run","component":job.name,
            "sha256":job.sha,"artifact_bytes":job.size,"cache":"bypass","rule_sha256":rule.authorization_digest(),
            "isolation":"per-user-container","input":"none","issued_unix":now,"expires_unix":now+120}).to_string();
        let mut bytes = crate::tickets_core::DOMAIN.to_vec();
        bytes.extend_from_slice(payload.as_bytes());
        job.ticket = Some(crate::tickets_core::Ticket {
            payload,
            signature: hex::encode(key.sign(&bytes).to_bytes()),
        });
        let shared_mut = Arc::get_mut(&mut shared).unwrap();
        shared_mut.args.job_authorization = Some(path);
        shared_mut.authorization = Some(authority);
        shared
            .authorization
            .as_ref()
            .unwrap()
            .consume(&job)
            .unwrap();
        let config_dir = dir.path().join("config");
        cache::private_directory(&config_dir).unwrap();
        let config = worker_config(
            &shared,
            "alice",
            &config_dir,
            &dir.path().join("ipc"),
            &dir.path().join("broker"),
            &dir.path().join("worker-state"),
        )
        .unwrap();
        write_worker_config(&shared, "alice", &config_dir, &config).unwrap();
        let text = std::fs::read_to_string(config_dir.join("job-authorization.json")).unwrap();
        assert!(!text.contains("private_key") && !text.contains("bob"));
        assert_eq!(config["authorization_epoch"], epoch);
        let argv: Vec<String> = serde_json::from_value(config["args"].clone()).unwrap();
        let mut args = Args::try_parse_from(argv).unwrap();
        let identity = Identity {
            tenant: "alice".into(),
            platform: shared.platform.clone(),
            broker_socket: PathBuf::new(),
            authorization_epoch: Some(epoch),
        };
        args.container_worker = Some(identity.clone());
        let worker = Shared::new(args).unwrap();
        let received =
            crate::container_worker::authorize(&worker, &identity, &job_wire(&job)).unwrap();
        worker
            .authorization
            .as_ref()
            .unwrap()
            .consume(&received)
            .unwrap();
        assert!(worker
            .authorization
            .as_ref()
            .unwrap()
            .consume(&received)
            .is_err());
        let mut changed = job_wire(&job);
        changed["cache"] = json!("reuse");
        assert!(crate::container_worker::authorize(&worker, &identity, &changed).is_err());
    }
    #[test]
    fn replies_cannot_cross_users_jobs_artifacts_or_cache_plans() {
        assert_eq!(validate_result(&job(), &result(), 8).unwrap(), b"A");
        for (key, value) in [
            ("tenant", json!("bob")),
            ("job_id", json!("other")),
            ("sha256", json!("b".repeat(64))),
            ("artifact_bytes", json!(9)),
            ("component", json!("g.wasm")),
            ("cache_status", json!("hit")),
            ("worker_protocol", json!(2)),
        ] {
            let mut reply = result();
            reply[key] = value;
            assert!(validate_result(&job(), &reply, 8).is_err(), "{key}");
        }
        let mut reply = result();
        reply["result"]["hex"] = json!("41".repeat(9));
        assert!(validate_result(&job(), &reply, 8).is_err());
        let mut reply = result();
        reply["result"]["bytes"] = json!(2);
        assert!(validate_result(&job(), &reply, 8).is_err());
    }
    #[test]
    fn missing_daemon_controls_fail_closed() {
        let mut info = json!({"OSType":"linux", "MemoryLimit":true,"SwapLimit":true,
            "CpuCfsQuota":true,"PidsLimit":true,"SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]});
        let spec = crate::sandbox::profile();
        info["Runtimes"] = json!({crate::sandbox::RUNTIME: {"path":spec["path"],"runtimeArgs":spec["runtimeArgs"]}});
        validate_daemon(&info).unwrap();
        for field in ["MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit"] {
            let mut weaker = info.clone();
            weaker[field] = json!(false);
            assert!(validate_daemon(&weaker).is_err(), "{field}");
        }
        for security in [
            json!([]),
            json!(["name=seccomp,profile=unconfined"]),
            json!(["name=seccomp,profile=builtin", "name=rootless"]),
            json!(["name=seccomp,profile=builtin", "name=userns"]),
        ] {
            let mut incompatible = info.clone();
            incompatible["SecurityOptions"] = security;
            assert!(validate_daemon(&incompatible).is_err());
        }
    }
    #[test]
    fn launch_is_networkless_unprivileged_and_exposes_only_this_user() {
        let args = args();
        validate_options(&args).unwrap();
        let command = launch_arguments(
            &args,
            "sha256:abc",
            "owned",
            "session",
            "alice",
            Path::new("/run/private/alice"),
        );
        for needed in [
            "--runtime=hal-gvisor",
            "--read-only",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=65532:65532",
            "--memory=1024m",
            "--memory-swap=1024m",
            "--pids-limit=128",
            "--pull=never",
        ] {
            assert!(command.iter().any(|s| s == needed), "{needed}");
        }
        let joined = command.join(" ");
        for forbidden in [
            "docker.sock",
            "--privileged",
            "--pid=host",
            "--network=host",
            "--device",
            "/dev/tdx",
            "seccomp=unconfined",
            "/bob",
        ] {
            assert!(!joined.contains(forbidden), "{forbidden}");
        }
        assert_eq!(
            command.iter().filter(|s| s.as_str() == "--mount").count(),
            3
        );
        let mut invalid = args.clone();
        invalid.mode = Mode::Native;
        assert!(validate_options(&invalid).is_err());
        let mut invalid = args.clone();
        invalid.container_image = "--privileged".into();
        assert!(validate_options(&invalid).is_err());
        let mut invalid = args.clone();
        invalid.container_state_dir = "/run/x,target=/".into();
        assert!(validate_options(&invalid).is_err());
        let mut invalid = args;
        invalid.container_cpus = 0;
        assert!(validate_options(&invalid).is_err());
    }
    #[tokio::test]
    async fn worker_socket_symlinks_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("real.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let link = dir.path().join("redirect.sock");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        assert!(connect_worker(&link).await.is_err());
        assert!(connect_worker(&socket).await.is_ok());
    }
    #[tokio::test]
    async fn confined_hal_exposes_metadata_without_enabling_attestation() {
        let identity = Identity {
            tenant: "alice".into(),
            platform: "IntelTdx".into(),
            broker_socket: PathBuf::new(),
            authorization_epoch: None,
        };
        let mut hal = identity.hal().unwrap();
        assert_eq!(hal.platform_info().platform_type, "IntelTdx");
        assert!(!hal.platform_info().attestation_support);
        assert!(hal.attestation(vec![0; 32]).is_err());
    }
}
