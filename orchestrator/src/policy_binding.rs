//! The agent retains management's policy, not a policy reconstructed from a job.
use crate::tickets_core::Context;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub fn validate_document(doc: &Value) -> Result<(), String> {
    let rows = doc["workloads"].as_array().ok_or("missing workloads")?;
    if rows.is_empty() || rows.len() > 128 || doc["revision"].as_u64().unwrap_or(0) == 0 {
        return Err("invalid workload grant or revision".into());
    }
    let mut seen = HashSet::new();
    for row in rows {
        let sha = row["sha256"].as_str().ok_or("missing artifact digest")?;
        if sha.len() != 64
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !seen.insert(sha)
            || row["component"] != format!("{sha}.wasm")
            || row["rule"]["component"] != row["component"]
        {
            return Err("invalid or duplicate workload binding".into());
        }
        if let Some(value) = row["rule"].get("access_profile") {
            let profile: hal_access_profile::Profile = serde_json::from_value(value.clone())
                .map_err(|_| "invalid workload access profile")?;
            let permissions: Vec<String> =
                serde_json::from_value(row["rule"]["hal_permissions"].clone())
                    .map_err(|_| "invalid workload permissions")?;
            profile.validate(sha, &permissions)?;
        }
    }
    Ok(())
}

pub fn validate_contexts(doc: &Value, session: &Value, contexts: &[Context]) -> Result<(), String> {
    validate_document(doc)?;
    if session["tenant"] != doc["subject"]
        || session["revision"] != doc["revision"]
        || session["audience"] != doc["audience"]
        || session["mode"] != "wasm"
        || !matches!(
            session["isolation"].as_str(),
            Some("in-process" | "per-user-container")
        )
    {
        return Err("broker session differs from management grant".into());
    }
    let rows = doc["workloads"].as_array().ok_or("missing workloads")?;
    let mut seen = HashSet::new();
    for ctx in contexts {
        let row = rows
            .iter()
            .find(|w| w["sha256"] == ctx.sha256)
            .ok_or("unexpected broker workload")?;
        let rule = &row["rule"];
        let expected_hash = hex::encode(Sha256::digest(rule.to_string().as_bytes()));
        if !seen.insert(&ctx.sha256)
            || doc["subject"] != ctx.tenant
            || doc["public_key"] != ctx.public_key
            || session["audience"] != ctx.audience
            || session["epoch"] != ctx.epoch
            || session["isolation"] != ctx.isolation
            || ctx.max_ttl_seconds != 120
            || row["component"] != ctx.component
            || row["artifact_bytes"].as_u64() != Some(ctx.artifact_bytes)
            || ctx.rule_sha256 != expected_hash
            || ctx.cache_allowed != (rule["cache"] == "memory")
            || rule["max_output_bytes"].as_u64() != Some(ctx.max_output_bytes.into())
            || rule["validation"] != ctx.result_rule
        {
            return Err("broker authorization differs from the approved workload policy".into());
        }
    }
    if seen.len() != rows.len() {
        return Err("incomplete broker workload grant".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value, Vec<Context>) {
        let sha = "a".repeat(64);
        let component = format!("{sha}.wasm");
        let rule = json!({"component":component,"cache":"memory","max_output_bytes":64,
            "hal_permissions":["crypto"],"validation":{"kind":"bounded"},
            "access_profile":{"version":1,"artifact_sha256":sha,"operations":["crypto.hash.sha256"],"max_host_calls":1,"max_buffer_bytes":64}});
        let doc = json!({"subject":"alice","public_key":"b".repeat(64),"revision":2,"audience":"worker-1",
            "workloads":[{"component":component,"sha256":sha,"artifact_bytes":100,"rule":rule}]});
        let session = json!({"tenant":"alice","revision":2,"audience":"worker-1","epoch":"c".repeat(64),"mode":"wasm","isolation":"per-user-container"});
        let ctx = Context {
            tenant: "alice".into(),
            public_key: "b".repeat(64),
            audience: "worker-1".into(),
            epoch: "c".repeat(64),
            max_ttl_seconds: 120,
            component,
            sha256: sha,
            artifact_bytes: 100,
            rule_sha256: hex::encode(Sha256::digest(rule.to_string().as_bytes())),
            cache_allowed: true,
            isolation: "per-user-container".into(),
            max_output_bytes: 64,
            result_rule: rule["validation"].clone(),
        };
        (doc, session, vec![ctx])
    }
    #[test]
    fn context_cannot_change_policy_artifact_session_or_user() {
        let (doc, session, ctx) = fixture();
        validate_contexts(&doc, &session, &ctx).unwrap();
        for field in [
            "tenant",
            "public_key",
            "audience",
            "epoch",
            "component",
            "sha256",
            "rule_sha256",
            "isolation",
        ] {
            let mut changed = serde_json::to_value(&ctx[0]).unwrap();
            changed[field] = json!("different");
            assert!(
                validate_contexts(&doc, &session, &[serde_json::from_value(changed).unwrap()])
                    .is_err(),
                "{field}"
            );
        }
        for field in ["max_ttl_seconds", "artifact_bytes", "max_output_bytes"] {
            let mut changed = serde_json::to_value(&ctx[0]).unwrap();
            changed[field] = json!(1);
            assert!(
                validate_contexts(&doc, &session, &[serde_json::from_value(changed).unwrap()])
                    .is_err(),
                "{field}"
            );
        }
        let mut changed = ctx[0].clone();
        changed.cache_allowed = false;
        assert!(validate_contexts(&doc, &session, &[changed]).is_err());
        assert!(validate_contexts(&doc, &session, &[]).is_err());
        assert!(validate_contexts(&doc, &session, &[ctx[0].clone(), ctx[0].clone()]).is_err());
    }
    #[test]
    fn profile_is_part_of_the_agent_policy_binding() {
        let (mut doc, session, ctx) = fixture();
        doc["workloads"][0]["rule"]["access_profile"]["operations"] = json!(["crypto.sign"]);
        assert!(validate_contexts(&doc, &session, &ctx).is_err());
        doc["workloads"][0]["rule"]["access_profile"]["operations"] =
            json!(["storage.store-object"]);
        assert!(validate_document(&doc).is_err());
        doc["workloads"][0]["rule"]["access_profile"] = Value::Null;
        assert!(validate_document(&doc).is_err());
    }
}
