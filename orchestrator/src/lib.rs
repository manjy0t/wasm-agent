//! One trusted agent coordinates multiple users. Workloads run outside this Store.
wit_bindgen::generate!({path: "../wit-orchestration", world: "orchestrator", generate_all});
use elastic::orchestration::control;
use serde_json::Value;
use std::{cell::RefCell, collections::HashMap};
mod policy_binding;
#[path = "../../src/tickets_core.rs"]
mod tickets_core;

#[derive(Default)]
struct State {
    configured: bool,
    draining: bool,
    users: HashMap<
        String,
        (
            u64,
            HashMap<String, tickets_core::Context>,
            HashMap<String, Value>,
        ),
    >,
    jobs: HashMap<String, (String, String, usize, Value)>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
struct Agent;
fn parse(s: &str) -> Result<Value, String> {
    serde_json::from_str(s).map_err(|_| "invalid control document".into())
}
impl Guest for Agent {
    fn initialize(configuration_json: String) -> Result<(), String> {
        let config = parse(&configuration_json)?;
        if !config.is_object() {
            return Err("configuration must be an object".into());
        }
        STATE.with(|cell| {
            let mut s = cell.borrow_mut();
            if s.configured {
                return Err("configuration is immutable".into());
            }
            s.configured = true;
            Ok(())
        })
    }
    fn begin_drain() -> Result<(), String> {
        STATE.with(|cell| cell.borrow_mut().draining = true);
        Ok(())
    }
    fn finish_drain() -> Result<(), String> {
        STATE.with(|cell| {
            let mut s = cell.borrow_mut();
            if !s.draining || !s.jobs.is_empty() {
                return Err("agent still has pending jobs".into());
            }
            control::stop_user_brokers()?;
            s.users.clear();
            Ok(())
        })
    }
    fn enroll_user(grant_json: String) -> Result<(), String> {
        let grant = parse(&grant_json)?;
        let doc = &grant["document"];
        policy_binding::validate_document(doc)?;
        let tenant = doc["subject"].as_str().ok_or("missing user")?.to_owned();
        let revision = doc["revision"].as_u64().ok_or("missing revision")?;
        tickets_core::public_key(doc["public_key"].as_str().ok_or("missing public key")?)?;
        STATE.with(|cell| {
            let s = cell.borrow();
            if s.draining {
                return Err("agent is draining");
            }
            if !s.configured {
                return Err("agent not initialized");
            }
            if s.jobs.values().any(|(t, _, _, _)| t == &tenant) {
                return Err("user has active jobs");
            }
            if let Some((old, _, _)) = s.users.get(&tenant) {
                if revision < *old {
                    return Err("policy rollback");
                }
            }
            if s.users.len() >= 64 && !s.users.contains_key(&tenant) {
                return Err("user capacity reached");
            }
            Ok(())
        })?;
        let ready = parse(&control::launch_user_broker()?)?;
        let contexts: Vec<tickets_core::Context> =
            serde_json::from_value(ready["contexts"].clone())
                .map_err(|_| "invalid broker authorization")?;
        policy_binding::validate_contexts(doc, &ready["session"], &contexts)?;
        let rows = doc["workloads"].as_array().ok_or("missing workloads")?;
        let mut keys = HashMap::new();
        let mut rules = HashMap::new();
        for ctx in contexts {
            let row = rows
                .iter()
                .find(|w| w["sha256"] == ctx.sha256)
                .ok_or("unexpected broker grant")?;
            if ctx.tenant != tenant
                || doc["public_key"] != ctx.public_key
                || row["rule"]["validation"] != ctx.result_rule
            {
                return Err("broker scope mismatch".into());
            }
            rules.insert(ctx.sha256.clone(), row["rule"].clone());
            keys.insert(ctx.sha256.clone(), ctx);
        }
        if keys.len() != rows.len() {
            return Err("incomplete broker grant".into());
        }
        STATE.with(|cell| {
            cell.borrow_mut()
                .users
                .insert(tenant, (revision, keys, rules))
        });
        Ok(())
    }
    fn authorize_job(request_json: String) -> Result<(), String> {
        let req = parse(&request_json)?;
        let tenant = req["tenant"].as_str().ok_or("missing user")?;
        let job = &req["job"];
        let id = job["job_id"].as_str().ok_or("missing job id")?;
        let sha = job["sha256"].as_str().ok_or("missing digest")?;
        STATE.with(|cell| {
            let mut s = cell.borrow_mut();
            if s.draining {
                return Err("agent is draining".into());
            }
            if s.jobs.len() >= 64 || s.jobs.contains_key(id) {
                return Err("job capacity or duplicate job".into());
            }
            let (revision, contexts, rules) = s.users.get(tenant).ok_or("user not enrolled")?;
            if req["revision"].as_u64() != Some(*revision) {
                return Err("user policy changed".into());
            }
            let ctx = contexts.get(sha).ok_or("workload not approved")?;
            let rule = rules.get(sha).ok_or("policy missing")?;
            if req["policy"] != *rule {
                return Err("launch policy differs from the approved policy".into());
            }
            let ticket = serde_json::from_value(job["job_ticket"].clone())
                .map_err(|_| "missing user signature")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock unavailable")?
                .as_secs();
            tickets_core::verify(
                ctx,
                &ticket,
                &tickets_core::Request {
                    tenant,
                    job_id: id,
                    component: job["component"].as_str().ok_or("missing component")?,
                    sha256: sha,
                    artifact_bytes: job["artifact_bytes"].as_u64().ok_or("missing size")?,
                    reuse: job["cache"] == "reuse",
                },
                now,
            )?;
            control::apply_workload_policy(&rule.to_string())?;
            control::launch_workload()?;
            let pending = (
                tenant.to_owned(),
                sha.to_owned(),
                ctx.max_output_bytes as usize,
                ctx.result_rule.clone(),
            );
            s.jobs.insert(id.to_owned(), pending);
            Ok(())
        })
    }
    fn complete_job(completion_json: String) -> Result<(), String> {
        let result = parse(&completion_json)?;
        let id = result["job_id"].as_str().ok_or("missing completion id")?;
        let (tenant, sha, max, rule) = STATE
            .with(|cell| cell.borrow_mut().jobs.remove(id))
            .ok_or("job not launched")?;
        if result["tenant"] != tenant || result["sha256"] != sha {
            return Err("completion scope mismatch".into());
        }
        if result["status"] == "ok" {
            let bytes = hex::decode(result["result"]["hex"].as_str().ok_or("missing bytes")?)
                .map_err(|_| "invalid bytes")?;
            if bytes.len() > max {
                return Err("output limit exceeded".into());
            }
            let valid = match rule["kind"].as_str() {
                Some("bounded") => true,
                Some("hex") => rule["value"] == hex::encode(&bytes),
                Some("length") => rule["value"].as_u64() == Some(bytes.len() as u64),
                Some("utf8_contains") => std::str::from_utf8(&bytes).is_ok_and(|s| {
                    rule["value"]
                        .as_str()
                        .is_some_and(|n| !n.is_empty() && s.contains(n))
                }),
                Some("clock") => serde_json::from_slice::<Value>(&bytes).is_ok_and(|v| {
                    v.as_object().is_some_and(|o| o.len() == 2)
                        && v["seconds"].as_u64().is_some()
                        && v["nanoseconds"].as_u64().is_some_and(|n| n < 1_000_000_000)
                }),
                _ => false,
            };
            if !valid {
                return Err("result validation failed".into());
            }
        }
        control::commit_result()
    }
}
export!(Agent);
