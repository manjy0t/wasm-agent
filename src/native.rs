//! Direct execution control: the same native services, without an agent component.
use crate::executor::{ms, Job, Shared};
use anyhow::Result;
use serde_json::{json, Value};
use std::{sync::Arc, time::Instant};

pub async fn run(shared: &Arc<Shared>, job: Job) -> Value {
    let start = Instant::now();
    let mut record = json!({ "protocol": 1, "job_id": job.id, "component": job.name,
        "sha256": job.sha, "artifact_bytes": job.size,
        "cache_policy": if job.reuse { "reuse" } else { "bypass" },
        "cache_status": "none", "preparation_work_owner": false,
        "timings_ms": {}, "attestation_verified": false,
        "runtime_reused": true, "workload_instance_reused": false, "agent_kind": "none" });
    let outcome: Result<Vec<u8>> = async {
        let cached = if job.reuse {
            let lookup = Instant::now();
            let result = shared.lookup(&job);
            record["timings_ms"]["cache_lookup"] = json!(ms(lookup));
            result?
        } else {
            None
        };
        let prepared = match cached {
            Some(prepared) => {
                record["cache_status"] = json!("hit");
                prepared
            }
            None => {
                let prepare = Instant::now();
                let result = shared.prepare(&job).await;
                record["timings_ms"]["prepare_wait"] = json!(ms(prepare));
                let (prepared, state) = result?;
                record["cache_status"] = json!(state);
                if state != "hit" {
                    record["preparation"] = prepared.preparation.clone();
                }
                record["preparation_work_owner"] = json!(state == "miss" || state == "bypass");
                prepared
            }
        };
        let outcome = shared.execute(&job, &prepared, &mut record).await;
        let release = Instant::now();
        drop(prepared);
        record["timings_ms"]["component_release"] = json!(ms(release));
        outcome
    }
    .await;
    record["timings_ms"]["native_job"] = json!(ms(start));
    match outcome {
        Ok(data) => {
            record["status"] = json!("ok");
            record["result"] = json!({ "bytes": data.len(), "hex": hex::encode(&data),
                "utf8": String::from_utf8(data).ok() });
        }
        Err(error) => {
            record["status"] = json!("error");
            record["error"] = json!(format!("{error:#}"));
        }
    }
    record
}
