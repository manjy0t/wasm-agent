//! Private, single-user execution service. No HTTP listener, Docker access,
//! cloud credentials, TEE devices, or network access are needed in the container.
use crate::{
    cache,
    executor::{Job, Shared},
    native, protocol, Args,
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

#[derive(Clone)]
pub struct Identity {
    pub tenant: String,
    pub platform: String,
    pub broker_socket: PathBuf,
    pub authorization_epoch: Option<String>,
}
impl Identity {
    pub fn hal(&self) -> Result<hal_runtime::HalHost> {
        use elastic_tee_hal::platform::PlatformType;
        let platform = match self.platform.as_str() {
            "IntelTdx" => PlatformType::IntelTdx,
            "AmdSev" | "NON_TEE_TEST_ONLY" => PlatformType::AmdSev,
            _ => anyhow::bail!("unsupported broker platform metadata"),
        };
        hal_runtime::HalHost::for_confined_job(platform)
    }

    pub async fn download(&self, job: &Job, seconds: u64) -> Result<Vec<u8>> {
        ensure!(job.tenant == self.tenant, "cross-user artifact request");
        tokio::time::timeout(Duration::from_secs(seconds), async {
            let mut stream = BufReader::new(UnixStream::connect(&self.broker_socket).await?);
            protocol::write(stream.get_mut(), &job_wire(job), protocol::REQUEST_LIMIT).await?;
            let header = protocol::read(&mut stream, protocol::REQUEST_LIMIT).await?;
            ensure!(
                header["status"] == "ok" && header["bytes"].as_u64() == Some(job.size),
                "artifact broker rejected the download"
            );
            let mut data = vec![0; job.size as usize];
            stream.read_exact(&mut data).await?;
            // Verify at the receiving boundary as well as in the broker.
            cache::verify(&data, &job.sha, Some(job.size))?;
            Ok(data)
        })
        .await
        .context("artifact broker timeout")?
    }
}

pub fn job_wire(job: &Job) -> Value {
    let mut value = json!({"protocol":1,"op":"run","job_id":job.id,"component":job.name,
        "sha256":job.sha,"artifact_bytes":job.size,"cache":if job.reuse {"reuse"} else {"bypass"}});
    if let Some(ticket) = &job.ticket {
        value["job_ticket"] = serde_json::to_value(ticket).unwrap();
    }
    value
}

pub fn authorize(shared: &Shared, identity: &Identity, value: &Value) -> Result<Job> {
    ensure!(
        value.get("tenant").is_none(),
        "user identity cannot be supplied over IPC"
    );
    let mut job = Job::parse(value, shared.args.max_component_bytes)?;
    job.tenant = identity.tenant.clone();
    shared
        .policy
        .as_ref()
        .context("worker needs a user policy")?
        .get(&job.tenant)?
        .allows(&job)?;
    let rule = shared
        .agent_rule(&job)?
        .context("worker needs a workload policy")?;
    ensure!(
        !job.reuse || rule.cache,
        "cache plan forbidden by workload policy"
    );
    if let Some(authority) = &shared.authorization {
        authority.verify(&job)?;
    } else {
        ensure!(
            job.ticket.is_none(),
            "signed job sent to unsigned container worker"
        );
    }
    Ok(job)
}

pub async fn serve(config_path: &Path) -> Result<()> {
    let bytes = cache::read_bounded(config_path, 4 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(value["version"] == 1, "unsupported worker protocol");
    let argv: Vec<String> = serde_json::from_value(value["args"].clone())?;
    let mut args = Args::try_parse_from(argv)?;
    ensure!(
        !args.user_containers && args.file_token_file.is_none(),
        "worker cannot launch containers or hold file credentials"
    );
    let identity = Identity {
        tenant: protocol::string(&value, "tenant")?.into(),
        platform: protocol::string(&value, "platform")?.into(),
        broker_socket: PathBuf::from(protocol::string(&value, "broker_socket")?),
        authorization_epoch: value["authorization_epoch"].as_str().map(str::to_owned),
    };
    ensure!(
        args.allow_non_tee == (identity.platform == "NON_TEE_TEST_ONLY"),
        "inconsistent test-mode metadata"
    );
    identity.hal()?;
    args.container_worker = Some(identity.clone());
    let shared = Shared::new(args)?;
    let policy = shared
        .policy
        .as_ref()
        .context("worker needs a user policy")?;
    ensure!(
        policy.tenants.len() == 1 && policy.tenants[0].id == identity.tenant,
        "worker must have exactly its own user"
    );
    ensure!(
        shared.agent_policy.is_some(),
        "worker requires the constrained HAL policy"
    );
    let socket = PathBuf::from(protocol::string(&value, "socket")?);
    cache::private_directory(socket.parent().context("worker socket parent missing")?)?;
    // Never unlink somebody else's listener on startup.
    let listener = UnixListener::bind(&socket)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let permits = Arc::new(Semaphore::new(shared.args.max_inflight));
    let engine = shared.runtime.engine().clone();
    let weak = Arc::downgrade(&shared);
    let maintenance = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        let mut ticks = 0;
        loop {
            interval.tick().await;
            engine.increment_epoch();
            ticks += 1;
            if ticks % 100 == 0 {
                let Some(shared) = weak.upgrade() else { break };
                shared.expire_agent_cache();
            }
        }
    });
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!(
        "{}",
        json!({"status":"ready","worker_protocol":1,"tenant":identity.tenant})
    );
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                if let Ok(permit) = permits.clone().try_acquire_owned() {
                    let shared = shared.clone();
                    let identity = identity.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let mut stream = BufReader::new(stream);
                        let result = tokio::time::timeout(Duration::from_secs(shared.args.job_timeout_secs), async {
                            let value = protocol::read(&mut stream, protocol::REQUEST_LIMIT).await?;
                            if value["op"] == "stats" {
                                return Ok::<_, anyhow::Error>(json!({"status":"ok","worker_protocol":1,
                                    "tenant":identity.tenant,"stats":shared.stats()}));
                            }
                            ensure!(value["op"] == "run", "unsupported worker operation");
                            let job = authorize(&shared, &identity, &value)?;
                            let authorized = shared.authorization.as_ref().map(|a| a.consume(&job)).transpose()?;
                            let rule = shared.agent_rule(&job)?.unwrap();
                            let mut result = native::run(&shared, job).await;
                            if result["status"] == "ok" {
                                let data = hex::decode(protocol::string(&result["result"], "hex")?)?;
                                rule.validate(&data)?;
                            }
                            result["tenant"] = json!(identity.tenant);
                            result["worker_protocol"] = json!(1);
                            result["attestation_verified"] = json!(false);
                            result["platform_metadata_source"] = json!("enclosing-broker");
                            if let Some(claims) = authorized {
                                result["job_authorization"] = json!({"verified":true,"worker_checked":true,
                                    "nonce":claims.nonce,"audience":claims.audience,"epoch":claims.epoch});
                            }
                            Ok(result)
                        }).await;
                        let response = match result {
                            Ok(Ok(value)) => value,
                            Ok(Err(e)) => json!({"status":"error","error":format!("{e:#}")}),
                            Err(_) => json!({"status":"error","error":"worker deadline exceeded","execution_outcome":"unknown"}),
                        };
                        let _ = tokio::time::timeout(Duration::from_secs(5),
                            protocol::write(stream.get_mut(), &response, protocol::RESPONSE_LIMIT)).await;
                    });
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    maintenance.abort();
    Ok(())
}
