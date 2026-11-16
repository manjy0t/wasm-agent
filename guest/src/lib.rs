//! Real Wasm orchestration logic. Downloading and compiling are capabilities
//! supplied by our native HAL extension, not operations Wasm can perform alone.
wit_bindgen::generate!({ path: "../wit", world: "agent", generate_all });
use elastic::job_agent::services::{self, CachePolicy};
use std::cell::Cell;
use std::cell::RefCell;
#[path = "../../src/tickets_core.rs"]
mod tickets_core;

thread_local! { static JOB_NUMBER: Cell<u64> = const { Cell::new(0) }; }
thread_local! { static AUTHORIZATION: RefCell<Option<Option<tickets_core::Context>>> = const { RefCell::new(None) }; }

struct Agent;
thread_local! { static CONFIGURATION: RefCell<Option<serde_json::Value>> = const { RefCell::new(None) }; }
impl Guest for Agent {
    fn initialize_configuration(config_json: String) -> Result<(), String> {
        CONFIGURATION.with(|cell| {
            let mut state = cell.borrow_mut();
            if state.is_some() {
                return Err("agent configuration is immutable".into());
            }
            let config: serde_json::Value = serde_json::from_str(&config_json)
                .map_err(|_| "invalid management configuration")?;
            if !config.is_object() {
                return Err("expected configuration object".into());
            }
            *state = Some(config);
            Ok(())
        })
    }
    fn initialize_authorization(context_json: String) -> Result<(), String> {
        AUTHORIZATION.with(|cell| {
            let mut state = cell.borrow_mut();
            if state.is_some() {
                return Err("helper authorization rules are immutable".into());
            }
            let context = if context_json.is_empty() {
                None
            } else {
                let context: tickets_core::Context = serde_json::from_str(&context_json)
                    .map_err(|_| "invalid trusted helper rules")?;
                tickets_core::public_key(&context.public_key)?;
                Some(context)
            };
            *state = Some(context);
            Ok(())
        })
    }
    fn handle_job(request: Job) -> Result<Completion, String> {
        let trusted = AUTHORIZATION
            .with(|cell| cell.borrow().clone())
            .ok_or("helper rules were not initialized")?;
        if let Some(ctx) = &trusted {
            let ticket: tickets_core::Ticket = serde_json::from_str(&request.ticket_json)
                .map_err(|_| "user-signed job ticket required")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock unavailable")?
                .as_secs();
            tickets_core::verify(
                ctx,
                &ticket,
                &tickets_core::Request {
                    tenant: &request.tenant,
                    job_id: &request.id,
                    component: &request.component,
                    sha256: &request.artifact_sha256,
                    artifact_bytes: request.artifact_bytes,
                    reuse: matches!(request.policy, CachePolicy::Reuse),
                },
                now,
            )?;
            if request.limits.cache_allowed != ctx.cache_allowed
                || request.limits.container_required != (ctx.isolation == "per-user-container")
                || request.limits.max_output_bytes != ctx.max_output_bytes
                || serde_json::from_str::<serde_json::Value>(&request.limits.result_rule_json)
                    .ok()
                    .as_ref()
                    != Some(&ctx.result_rule)
            {
                return Err("job attempted to replace the helper's fixed rules".into());
            }
        } else if !request.ticket_json.is_empty() {
            return Err("signed job submitted to an unsigned helper".into());
        }
        if request.id.is_empty() || request.tenant.is_empty() || request.artifact_sha256.len() != 64
        {
            return Err("authenticated job identity is required".into());
        }
        let number = JOB_NUMBER.with(|n| {
            let next = n.get() + 1;
            n.set(next);
            next
        });
        // The trusted policy can force a requested reuse to bypass. A client may
        // always request a stricter no-cache run. Deployment credentials belong only to this trusted agent and its HAL.
        let selected = if request.limits.cache_allowed {
            request.policy
        } else {
            CachePolicy::Bypass
        };
        services::authorize_cache(selected)?;
        // Reuse prepared code only for the policy explicitly selected for this job.
        // prepare() joins an existing preparation if another worker needs the same
        // hash, or downloads, verifies and compiles it on demand.
        let data = if request.limits.container_required {
            // Ask for this user's container. Wasm never receives the Docker
            // socket or chooses a user/image/mount/command. A persistent private
            // worker downloads via the broker, compiles and instantiates there.
            services::launch_workload()?
        } else {
            let ready = match selected {
                CachePolicy::Reuse => services::find_prepared()?,
                CachePolicy::Bypass => false,
            };
            if !ready {
                services::prepare()?;
            }
            // The host creates a fresh workload store and instance on every call.
            services::execute()?
        };
        if data.len() > request.limits.max_output_bytes as usize {
            return Err("agent policy output limit exceeded".into());
        }
        // Run the admission check within the sandbox too. The host independently
        // repeats it at commit so a different guest cannot approve invalid output.
        let rule: serde_json::Value = serde_json::from_str(&request.limits.result_rule_json)
            .map_err(|_| "invalid result policy")?;
        let valid = match rule["kind"].as_str() {
            Some("bounded") => true,
            Some("hex") => {
                let expected = rule["value"].as_str().ok_or("invalid expected bytes")?;
                expected.len() == data.len() * 2
                    && data.iter().enumerate().all(|(i, byte)| {
                        let digits = b"0123456789abcdef";
                        expected.as_bytes()[2 * i] == digits[(byte >> 4) as usize]
                            && expected.as_bytes()[2 * i + 1] == digits[(byte & 15) as usize]
                    })
            }
            Some("length") => rule["value"].as_u64() == Some(data.len() as u64),
            Some("utf8_contains") => std::str::from_utf8(&data).is_ok_and(|s| {
                rule["value"]
                    .as_str()
                    .is_some_and(|needle| !needle.is_empty() && s.contains(needle))
            }),
            Some("clock") => serde_json::from_slice::<serde_json::Value>(&data).is_ok_and(|v| {
                v.as_object().is_some_and(|o| o.len() == 2)
                    && v["seconds"].as_u64().is_some()
                    && v["nanoseconds"].as_u64().is_some_and(|n| n < 1_000_000_000)
            }),
            _ => false,
        };
        if !valid {
            return Err("agent policy result validation failed".into());
        }
        services::commit_result()?;
        Ok(Completion {
            worker_job_number: number,
            data,
        })
    }
}
export!(Agent);
