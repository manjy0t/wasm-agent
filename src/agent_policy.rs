//! Operator-owned constraints for the Wasm agent. Requests cannot change these.
use crate::{cache, executor::Job, tenancy, Args};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path, sync::Arc};

#[derive(Clone, Debug)]
pub struct Rule {
    pub component: String,
    pub cache: bool,
    pub ttl_ms: u64,
    pub permissions: Vec<String>,
    pub access_profile: Option<hal_runtime::WorkloadProfile>,
    pub memory_mib: usize,
    pub fuel: u64,
    pub execution_ms: u64,
    pub output_bytes: usize,
    pub worker_max_jobs: u64,
    pub validation: Value,
}
impl Rule {
    /// Stable encoding shared with configure_authorization.py. This includes
    /// every authority-bearing field, not only the filename or cache setting.
    pub fn authorization_value(&self) -> Value {
        let mut value = json!({"component":self.component,"cache":if self.cache {"memory"} else {"disabled"},
            "cache_ttl_ms":self.ttl_ms,"hal_permissions":self.permissions,
            "memory_mib":self.memory_mib,"fuel":self.fuel,
            "execution_timeout_ms":self.execution_ms,"max_output_bytes":self.output_bytes,
            "worker_max_jobs":self.worker_max_jobs,"validation":self.validation});
        if let Some(profile) = &self.access_profile {
            value["access_profile"] = json!(profile);
        }
        value
    }
    pub fn authorization_digest(&self) -> String {
        cache::hash(self.authorization_value().to_string().as_bytes())
    }
    pub fn validate(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= self.output_bytes,
            "agent policy output limit exceeded"
        );
        validate(&self.validation, bytes)
    }
    pub fn description(&self) -> Value {
        let mut description = json!({"cache": if self.cache {"memory"} else {"disabled"}, "cache_ttl_ms":self.ttl_ms,
            "hal_permissions":self.permissions, "platform_metadata":true,
            "memory_mib_per_memory":self.memory_mib, "fuel":self.fuel,
            "execution_timeout_ms":self.execution_ms, "max_output_bytes":self.output_bytes,
            "worker_max_jobs":self.worker_max_jobs, "result_rule":self.validation["kind"],
            "persistent_code_cache":false, "clock_sleep":false, "max_hal_buffer_bytes":1048576,
            "wasi_clock":self.permissions.iter().any(|p| p == "clock"),
            "wasi_random":self.permissions.iter().any(|p| p == "random")});
        if let Some(profile) = &self.access_profile {
            description["access_profile"] = json!(profile);
            description["platform_metadata"] =
                json!(profile.operations.iter().any(|p| p == "platform.metadata"));
            description["wasi_clock"] = json!(profile.operations.iter().any(|p| p == "wasi.clock"));
            description["wasi_random"] = json!(profile
                .operations
                .iter()
                .any(|p| p == "wasi.random" || p == "wasi.insecure-random"));
            description["max_hal_buffer_bytes"] = json!(profile.max_buffer_bytes);
        }
        description
    }
}

pub fn validate(rule: &Value, bytes: &[u8]) -> Result<()> {
    let valid = match rule["kind"].as_str() {
        Some("bounded") => true,
        Some("hex") => hex::encode(bytes) == rule["value"].as_str().unwrap_or("!"),
        Some("length") => Some(bytes.len() as u64) == rule["value"].as_u64(),
        Some("utf8_contains") => std::str::from_utf8(bytes)
            .is_ok_and(|s| s.contains(rule["value"].as_str().unwrap_or("\0"))),
        Some("clock") => serde_json::from_slice::<Value>(bytes).is_ok_and(|v| {
            v.as_object().is_some_and(|o| o.len() == 2)
                && v["seconds"].as_u64().is_some()
                && v["nanoseconds"].as_u64().is_some_and(|n| n < 1_000_000_000)
        }),
        _ => false,
    };
    ensure!(valid, "agent policy result validation failed");
    Ok(())
}

pub struct Policy {
    pub digest: String,
    pub agent_sha: String,
    rules: HashMap<(String, String), Arc<Rule>>,
}

fn fields(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("policy entry must be an object")?;
    ensure!(
        object.keys().all(|k| allowed.contains(&k.as_str())),
        "unknown agent policy field"
    );
    Ok(())
}

impl Policy {
    pub fn worker_document(&self, tenant: &str) -> Value {
        json!({"version":1,"agent_sha256":self.agent_sha,"workloads":self.rules.iter()
            .filter(|((owner,_),_)| owner == tenant)
            .map(|((owner,sha),r)| {
                let mut value = r.authorization_value();
                value["tenant"] = json!(owner);
                value["sha256"] = json!(sha);
                value
            }).collect::<Vec<_>>()})
    }
    pub fn load(path: &Path, tenants: &tenancy::Policy, args: &Args) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 4 * 1024 * 1024, "agent policy too large");
        let data: Value = serde_json::from_slice(&bytes)?;
        fields(&data, &["version", "agent_sha256", "workloads"])?;
        ensure!(data["version"] == 1, "unsupported agent policy version");
        let agent_sha = data["agent_sha256"]
            .as_str()
            .context("agent_sha256 is required")?
            .to_owned();
        ensure!(
            crate::protocol::valid_sha(&agent_sha),
            "invalid agent SHA-256"
        );
        let rows = data["workloads"]
            .as_array()
            .context("workloads must be an array")?;
        ensure!(
            !rows.is_empty() && rows.len() <= 8192,
            "agent policy requires 1..8192 workloads"
        );
        let mut rules = HashMap::new();
        for row in rows {
            fields(
                row,
                &[
                    "tenant",
                    "component",
                    "sha256",
                    "cache",
                    "cache_ttl_ms",
                    "hal_permissions",
                    "access_profile",
                    "memory_mib",
                    "fuel",
                    "execution_timeout_ms",
                    "max_output_bytes",
                    "worker_max_jobs",
                    "validation",
                ],
            )?;
            let text = |key: &str| row[key].as_str().with_context(|| format!("missing {key}"));
            let tenant = tenants.get(text("tenant")?)?;
            let component = text("component")?.to_owned();
            let sha = text("sha256")?.to_owned();
            ensure!(
                tenant
                    .artifacts
                    .get(&component)
                    .is_some_and(|(s, _)| s == &sha),
                "agent workload must also be allowed by tenant policy"
            );
            let number = |key: &str, maximum: u64| -> Result<u64> {
                let n = row[key]
                    .as_u64()
                    .with_context(|| format!("{key} must be an integer"))?;
                ensure!(
                    n > 0 && n <= maximum,
                    "agent {key} exceeds the host limit or is zero"
                );
                Ok(n)
            };
            let cache = match text("cache")? {
                "memory" => true,
                "disabled" => false,
                _ => anyhow::bail!("agent cache must be memory or disabled"),
            };
            let ttl_ms = number("cache_ttl_ms", 86_400_000)?;
            let mut permissions = Vec::new();
            for permission in row["hal_permissions"]
                .as_array()
                .context("hal_permissions must be an array")?
            {
                let p = permission
                    .as_str()
                    .context("HAL permission must be a string")?;
                ensure!(
                    ["crypto", "random", "clock", "storage"].contains(&p)
                        && !permissions.iter().any(|s| s == p),
                    "unknown or duplicate HAL permission"
                );
                permissions.push(p.to_owned());
            }
            let access_profile: Option<hal_runtime::WorkloadProfile> = row
                .get("access_profile")
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()?;
            if let Some(profile) = &access_profile {
                profile
                    .validate(&sha, &permissions)
                    .map_err(anyhow::Error::msg)?;
            }
            let output_bytes = number("max_output_bytes", args.max_output_bytes as u64)? as usize;
            let validation = row["validation"].clone();
            fields(&validation, &["kind", "value"])?;
            match validation["kind"].as_str() {
                Some("bounded" | "clock") => ensure!(
                    validation.get("value").is_none(),
                    "unexpected validation value"
                ),
                Some("hex") => {
                    let value = validation["value"]
                        .as_str()
                        .context("hex validation requires a string")?;
                    let decoded = hex::decode(value).context("invalid expected hex")?;
                    ensure!(
                        decoded.len() <= output_bytes && hex::encode(decoded) == value,
                        "expected hex must be lowercase and fit output limit"
                    );
                }
                Some("length") => ensure!(
                    validation["value"]
                        .as_u64()
                        .is_some_and(|n| n <= output_bytes as u64),
                    "invalid expected length"
                ),
                Some("utf8_contains") => ensure!(
                    validation["value"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= output_bytes),
                    "invalid expected text"
                ),
                _ => anyhow::bail!("unknown result validation rule"),
            }
            let rule = Rule {
                component,
                cache,
                ttl_ms,
                permissions,
                access_profile,
                memory_mib: number("memory_mib", args.workload_memory_mib as u64)? as usize,
                fuel: number("fuel", args.workload_fuel)?,
                execution_ms: number("execution_timeout_ms", args.execution_timeout_secs * 1000)?,
                output_bytes,
                worker_max_jobs: number("worker_max_jobs", 10000)?,
                validation,
            };
            ensure!(
                rules
                    .insert((tenant.id.clone(), sha), Arc::new(rule))
                    .is_none(),
                "duplicate tenant/artifact policy"
            );
        }
        Ok(Self {
            digest: cache::hash(&bytes),
            agent_sha,
            rules,
        })
    }
    pub fn rule(&self, job: &Job) -> Result<Arc<Rule>> {
        let rule = self
            .rules
            .get(&(job.tenant.clone(), job.sha.clone()))
            .context("workload denied by agent policy")?;
        ensure!(
            rule.component == job.name,
            "component name differs from agent policy"
        );
        Ok(rule.clone())
    }
}
