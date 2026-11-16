//! Small policy core. The runtime, not the workload or an HTTP client, owns Budget.
//! This crate deliberately has no model, network, runtime or filesystem dependency.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

pub const DEFINITION: &str = include_str!("../profile-v1.json");

#[derive(Deserialize)]
pub struct Definition {
    pub version: u32,
    pub operations: BTreeMap<String, String>,
    pub templates: BTreeMap<String, Vec<String>>,
    pub host_interfaces: Vec<String>,
}

pub fn definition() -> &'static Definition {
    static VALUE: OnceLock<Definition> = OnceLock::new();
    VALUE.get_or_init(|| serde_json::from_str(DEFINITION).expect("checked-in profile definition"))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub artifact_sha256: String,
    pub operations: Vec<String>,
    pub max_host_calls: u64,
    pub max_buffer_bytes: usize,
}

impl Profile {
    /// Permissions are an intersection with the existing management rule.
    /// Public platform metadata is the sole category needing no HAL grant.
    pub fn validate(&self, artifact: &str, permissions: &[String]) -> Result<(), String> {
        if self.version != 1
            || self.artifact_sha256 != artifact
            || artifact.len() != 64
            || !artifact
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("unsupported profile version or artifact binding".into());
        }
        if !(1..=100_000).contains(&self.max_host_calls)
            || !(1..=1_048_576).contains(&self.max_buffer_bytes)
            || self.operations.len() > definition().operations.len()
        {
            return Err("profile limit exceeds runtime ceiling".into());
        }
        let mut seen = HashSet::new();
        for operation in &self.operations {
            let category = definition()
                .operations
                .get(operation)
                .ok_or_else(|| format!("unknown profile operation: {operation}"))?;
            if !seen.insert(operation) || (!category.is_empty() && !permissions.contains(category))
            {
                return Err(
                    "duplicate profile operation or permission exceeds management rule".into(),
                );
            }
        }
        Ok(())
    }
}

/// Exact HAL version; compatible WASI 0.2 patch versions are type-checked by
/// Wasmtime's linker. No prefix match accepts an arbitrary package or major ABI.
pub fn known_interface(name: &str) -> bool {
    if definition().host_interfaces.iter().any(|n| n == name) {
        return true;
    }
    let Some((base, patch)) = name.rsplit_once("@0.2.") else {
        return false;
    };
    !patch.is_empty()
        && patch.len() <= 3
        && patch.bytes().all(|b| b.is_ascii_digit())
        && (patch == "0" || !patch.starts_with('0'))
        && definition()
            .host_interfaces
            .contains(&format!("{base}@0.2.0"))
}

#[derive(Debug)]
pub struct Budget {
    pub profile: Profile,
    allowed: HashSet<String>,
    pub attempted: u64,
    pub denied: u64,
}

impl Budget {
    pub fn new(profile: Profile, artifact: &str, permissions: &[String]) -> Result<Self, String> {
        profile.validate(artifact, permissions)?;
        let allowed = profile.operations.iter().cloned().collect();
        Ok(Self {
            profile,
            allowed,
            attempted: 0,
            denied: 0,
        })
    }
    pub fn authorize(&mut self, operation: &str) -> Result<(), String> {
        self.attempted = self.attempted.saturating_add(1);
        if self.attempted > self.profile.max_host_calls || !self.allowed.contains(operation) {
            self.denied = self.denied.saturating_add(1);
            return Err(format!(
                "workload profile denied {operation} (permission or call budget)"
            ));
        }
        Ok(())
    }
    pub fn buffer(&self, size: usize) -> Result<(), String> {
        if size > self.profile.max_buffer_bytes {
            Err("workload profile buffer limit exceeded".into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        Profile {
            version: 1,
            artifact_sha256: "a".repeat(64),
            operations: vec!["crypto.hash.sha256".into()],
            max_host_calls: 2,
            max_buffer_bytes: 32,
        }
    }
    #[test]
    fn binding_and_ceiling_are_mandatory() {
        assert!(profile()
            .validate(&"b".repeat(64), &["crypto".into()])
            .is_err());
        assert!(profile().validate(&"a".repeat(64), &[]).is_err());
        let mut p = profile();
        p.operations.push("crypto.hash.sha256".into());
        assert!(p.validate(&"a".repeat(64), &["crypto".into()]).is_err());
        p.operations = vec!["crypto.future-operation".into()];
        assert!(p.validate(&"a".repeat(64), &["crypto".into()]).is_err());
        let mut v = serde_json::to_value(profile()).unwrap();
        v["allow_all"] = true.into();
        assert!(serde_json::from_value::<Profile>(v).is_err());
    }
    #[test]
    fn limited_calls_do_not_grant_adjacent_operations() {
        let mut b = Budget::new(profile(), &"a".repeat(64), &["crypto".into()]).unwrap();
        assert!(b.authorize("crypto.sign").is_err());
        assert!(b.authorize("crypto.hash.sha256").is_ok());
        assert!(b.authorize("crypto.hash.sha256").is_err());
        assert!(b.buffer(32).is_ok());
        assert!(b.buffer(33).is_err());
        assert_eq!(b.denied, 2);
        let mut fresh = Budget::new(profile(), &"a".repeat(64), &["crypto".into()]).unwrap();
        assert!(fresh.authorize("crypto.hash.sha256").is_ok());
    }
    #[test]
    fn interfaces_fail_closed() {
        assert!(known_interface("elastic:hal/crypto@0.1.0"));
        assert!(known_interface("wasi:random/random@0.2.9"));
        for name in [
            "evil:hal/crypto@0.1.0",
            "elastic:hal/crypto@0.2.0",
            "wasi:random/random@1.2.0",
            "wasi:random/random@0.2.01",
            "wasi:sockets/network@0.2.0",
        ] {
            assert!(!known_interface(name), "{name}");
        }
    }
    #[test]
    fn every_template_has_known_unique_operations() {
        for ops in definition().templates.values() {
            let p = Profile {
                operations: ops.clone(),
                ..profile()
            };
            p.validate(
                &"a".repeat(64),
                &[
                    "crypto".into(),
                    "clock".into(),
                    "random".into(),
                    "storage".into(),
                ],
            )
            .unwrap();
        }
    }
}
