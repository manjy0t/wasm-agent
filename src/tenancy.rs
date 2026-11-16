//! Operator-controlled identities. Neither a request nor an agent chooses its owner.
use crate::{executor::Job, protocol};
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct Tenant {
    pub id: String,
    token: String,
    pub artifacts: HashMap<String, (String, u64)>,
    pub cache_bytes: u64,
    pub cache_entries: usize,
    pub storage_bytes: u64,
    pub storage_entries: usize,
    pub max_inflight: usize,
}

impl Tenant {
    /// A single-user snapshot for a private worker. Never export the real token.
    pub fn worker_document(&self) -> Value {
        serde_json::json!({"version":1,"tenants":[{"id":self.id,"token_file":"worker.token",
            "artifacts": self.artifacts.iter().map(|(name,(sha,size))|
                serde_json::json!({"component":name,"sha256":sha,"artifact_bytes":size})).collect::<Vec<_>>(),
            "cache_bytes":self.cache_bytes,"compiled_cache_entries":self.cache_entries,
            "storage_bytes":self.storage_bytes,"storage_entries":self.storage_entries,
            "max_inflight":self.max_inflight}]})
    }
    pub fn allows(&self, job: &Job) -> Result<()> {
        ensure!(
            self.artifacts.get(&job.name) == Some(&(job.sha.clone(), job.size)),
            "artifact is not authorized for this tenant"
        );
        Ok(())
    }
}

pub fn token(path: &Path) -> Result<String> {
    let value = std::fs::read_to_string(path)?.trim().to_owned();
    ensure!(
        (32..=256).contains(&value.len()) && value.bytes().all(|c| c.is_ascii_graphic()),
        "token must contain 32..256 printable ASCII characters"
    );
    Ok(value)
}

pub fn same_token(a: &str, b: &str) -> bool {
    // Hash to fixed-size arrays before comparing; never log credential values.
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

pub struct Policy {
    pub tenants: Vec<Tenant>,
}
impl Policy {
    pub fn load(path: &Path, admin: &str, maximum: usize, inflight: usize) -> Result<Self> {
        let data: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(data["version"] == 1, "unsupported tenant policy version");
        let rows = data["tenants"]
            .as_array()
            .context("tenants must be an array")?;
        ensure!(
            !rows.is_empty() && rows.len() <= 64,
            "policy requires 1..64 tenants"
        );
        let mut tenants: Vec<Tenant> = Vec::new();
        for row in rows {
            let id = protocol::string(row, "id")?.to_owned();
            ensure!(
                protocol::safe_name(&id)
                    && id.len() <= 64
                    && id != "legacy"
                    && id == id.to_ascii_lowercase(),
                "invalid tenant id"
            );
            let file = PathBuf::from(protocol::string(row, "token_file")?);
            let token = token(&path.parent().unwrap_or(Path::new(".")).join(file))?;
            ensure!(
                !same_token(&token, admin)
                    && tenants
                        .iter()
                        .all(|t| t.id != id && !same_token(&t.token, &token)),
                "tenant IDs and credentials must be distinct, including the admin credential"
            );
            let bounded = |field: &str, default: u64, maximum: u64| -> Result<u64> {
                let n = match row.get(field) {
                    None => default,
                    Some(v) => v.as_u64().context("quota must be an integer")?,
                };
                ensure!(n > 0 && n <= maximum, "invalid {field}");
                Ok(n)
            };
            let mut artifacts = HashMap::new();
            let list = row["artifacts"]
                .as_array()
                .context("artifacts must be an array")?;
            ensure!(
                !list.is_empty() && list.len() <= 128,
                "each tenant requires 1..128 allowed artifacts"
            );
            for artifact in list {
                let name = protocol::string(artifact, "component")?.to_owned();
                let sha = protocol::string(artifact, "sha256")?.to_ascii_lowercase();
                let size = protocol::unsigned(artifact, "artifact_bytes")?;
                ensure!(
                    protocol::safe_name(&name)
                        && name.ends_with(".wasm")
                        && protocol::valid_sha(&sha)
                        && (8..=maximum as u64).contains(&size),
                    "invalid allowed artifact"
                );
                ensure!(
                    artifacts.insert(name, (sha, size)).is_none(),
                    "duplicate artifact name"
                );
            }
            let storage_entries = bounded("storage_entries", 1024, 100000)? as usize;
            ensure!(
                storage_entries > artifacts.len(),
                "storage_entries must leave space beyond artifact directories"
            );
            tenants.push(Tenant {
                id,
                token,
                artifacts,
                cache_bytes: bounded("cache_bytes", 268435456, 1 << 40)?,
                cache_entries: bounded("compiled_cache_entries", 16, 1024)? as usize,
                storage_bytes: bounded("storage_bytes", 16777216, 1 << 40)?,
                storage_entries,
                max_inflight: bounded("max_inflight", (inflight.min(4)) as u64, inflight as u64)?
                    as usize,
            });
        }
        Ok(Self { tenants })
    }
    pub fn authenticate(&self, credential: &str) -> Option<&Tenant> {
        self.tenants
            .iter()
            .find(|t| same_token(&t.token, credential))
    }
    pub fn get(&self, id: &str) -> Result<&Tenant> {
        self.tenants
            .iter()
            .find(|t| t.id == id)
            .context("unknown tenant")
    }
}
