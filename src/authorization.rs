//! Operator-owned public trust anchors, never supplied by management/jobs.
//! One-time admission spans all helper instances. A new boot epoch invalidates
//! old tickets after restart, so an erased in-memory replay set is not a bypass.
use crate::{agent_policy, cache, executor::Job, tenancy, tickets_core as core, Args};
use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_ACCEPTED_PER_USER: usize = 100_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    component: String,
    sha256: String,
    artifact_bytes: u64,
    rule_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    tenant: String,
    public_key: String,
    workloads: Vec<Grant>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    version: u32,
    audience: String,
    max_ttl_seconds: u64,
    isolation: String,
    users: Vec<User>,
}
#[derive(Default)]
struct Seen {
    nonces: HashSet<String>,
    jobs: HashSet<String>,
}
pub struct Authority {
    document: Document,
    pub epoch: String,
    contexts: HashMap<(String, String), core::Context>,
    seen: Mutex<HashMap<String, Seen>>,
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
impl Authority {
    pub fn load(
        path: &Path,
        tenants: &tenancy::Policy,
        policy: &agent_policy::Policy,
        args: &Args,
    ) -> Result<Self> {
        let bytes = cache::read_bounded(path, 4 * 1024 * 1024)?;
        let document: Document = serde_json::from_slice(&bytes)?;
        ensure!(
            document.version == 1 && (1..=300).contains(&document.max_ttl_seconds),
            "invalid job authorization version/lifetime"
        );
        ensure!(
            crate::protocol::safe_name(&document.audience),
            "invalid authorization audience"
        );
        let isolation = if args.user_containers || args.container_worker.is_some() {
            "per-user-container"
        } else {
            "in-process"
        };
        ensure!(
            document.isolation == isolation,
            "job authorization policy requires a different isolation mode"
        );
        let epoch = if let Some(worker) = &args.container_worker {
            worker
                .authorization_epoch
                .clone()
                .context("worker authorization epoch missing")?
        } else {
            let mut bytes = [0u8; 32];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            hex::encode(bytes)
        };
        ensure!(
            crate::protocol::valid_sha(&epoch),
            "invalid worker authorization epoch"
        );
        ensure!(
            !document.users.is_empty() && document.users.len() <= 64,
            "invalid authorization user count"
        );
        let mut users = HashSet::new();
        let mut keys = HashSet::new();
        let mut contexts = HashMap::new();
        for user in &document.users {
            ensure!(
                users.insert(user.tenant.clone()) && keys.insert(user.public_key.clone()),
                "authorization users and keys must be distinct"
            );
            core::public_key(&user.public_key).map_err(anyhow::Error::msg)?;
            let tenant = tenants.get(&user.tenant)?;
            ensure!(
                !user.workloads.is_empty() && user.workloads.len() <= 128,
                "invalid authorization workload count"
            );
            for grant in &user.workloads {
                let job = Job {
                    id: "policy-check".into(),
                    name: grant.component.clone(),
                    sha: grant.sha256.clone(),
                    size: grant.artifact_bytes,
                    reuse: false,
                    tenant: user.tenant.clone(),
                    ticket: None,
                };
                tenant.allows(&job)?;
                let rule = policy.rule(&job)?;
                ensure!(grant.rule_sha256 == rule.authorization_digest(), "authorization pins a different workload rule; review and regenerate public/client authorization configs");
                let context = core::Context {
                    tenant: user.tenant.clone(),
                    public_key: user.public_key.clone(),
                    audience: document.audience.clone(),
                    epoch: epoch.clone(),
                    max_ttl_seconds: document.max_ttl_seconds,
                    component: grant.component.clone(),
                    sha256: grant.sha256.clone(),
                    artifact_bytes: grant.artifact_bytes,
                    rule_sha256: grant.rule_sha256.clone(),
                    cache_allowed: rule.cache,
                    isolation: document.isolation.clone(),
                    max_output_bytes: rule.output_bytes as u32,
                    result_rule: rule.validation.clone(),
                };
                ensure!(
                    contexts
                        .insert((user.tenant.clone(), grant.sha256.clone()), context)
                        .is_none(),
                    "duplicate authorization workload"
                );
            }
        }
        Ok(Self {
            document,
            epoch,
            contexts,
            seen: Mutex::new(HashMap::new()),
        })
    }
    pub fn context(&self, job: &Job) -> Result<&core::Context> {
        self.contexts
            .get(&(job.tenant.clone(), job.sha.clone()))
            .context("job is not permitted by authorization policy")
    }
    pub fn verify(&self, job: &Job) -> Result<core::Claims> {
        core::verify(
            self.context(job)?,
            job.ticket
                .as_ref()
                .context("user-signed job ticket required")?,
            &core::Request {
                tenant: &job.tenant,
                job_id: &job.id,
                component: &job.name,
                sha256: &job.sha,
                artifact_bytes: job.size,
                reuse: job.reuse,
            },
            now()?,
        )
        .map_err(anyhow::Error::msg)
    }
    /// Never evict live or expired entries within an epoch. Clock rollback cannot
    /// resurrect a consumed ticket. At capacity fail closed; restart rotates epoch.
    pub fn consume(&self, job: &Job) -> Result<core::Claims> {
        let claims = self.verify(job)?;
        let mut all = self
            .seen
            .lock()
            .map_err(|_| anyhow::anyhow!("authorization replay lock failed"))?;
        let seen = all.entry(job.tenant.clone()).or_default();
        ensure!(
            !seen.nonces.contains(&claims.nonce) && !seen.jobs.contains(&job.id),
            "job ticket or job ID already consumed; not replayed"
        );
        ensure!(
            seen.jobs.len() < MAX_ACCEPTED_PER_USER,
            "authorization history full; restart worker and obtain its new epoch"
        );
        seen.nonces.insert(claims.nonce.clone());
        seen.jobs.insert(job.id.clone());
        Ok(claims)
    }
    pub fn worker_document(&self, tenant: &str) -> Value {
        let mut document = self.document.clone();
        document.users.retain(|u| u.tenant == tenant);
        serde_json::to_value(document).unwrap()
    }
    pub fn status(&self) -> Value {
        json!({"required":true,"scheme":"ed25519-user-ticket-v1","audience":self.document.audience,
            "epoch":self.epoch,"isolation":self.document.isolation,"max_ttl_seconds":self.document.max_ttl_seconds,
            "replay_limit_per_user_per_epoch":MAX_ACCEPTED_PER_USER,"signing_keys_on_host":false})
    }
}

#[cfg(test)]
impl Authority {
    pub fn test_context(context: core::Context) -> Self {
        Self {
            document: Document {
                version: 1,
                audience: context.audience.clone(),
                max_ttl_seconds: context.max_ttl_seconds,
                isolation: context.isolation.clone(),
                users: vec![],
            },
            epoch: context.epoch.clone(),
            contexts: HashMap::from([((context.tenant.clone(), context.sha256.clone()), context)]),
            seen: Mutex::new(HashMap::new()),
        }
    }
}
