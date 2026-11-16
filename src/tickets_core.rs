//! The same strict verifier is compiled into the Wasm helper and native worker.
//! No signing keys, network access, or policy mutation live in this module.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const DOMAIN: &[u8] = b"HAL-JOB-TICKET-v1\0";
pub const MAX_PAYLOAD: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u32,
    pub tenant: String,
    pub audience: String,
    pub epoch: String,
    pub job_id: String,
    pub nonce: String,
    pub operation: String,
    pub component: String,
    pub sha256: String,
    pub artifact_bytes: u64,
    pub cache: String,
    pub rule_sha256: String,
    pub isolation: String,
    pub input: String,
    pub issued_unix: u64,
    pub expires_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub tenant: String,
    pub public_key: String,
    pub audience: String,
    pub epoch: String,
    pub max_ttl_seconds: u64,
    pub component: String,
    pub sha256: String,
    pub artifact_bytes: u64,
    pub rule_sha256: String,
    pub cache_allowed: bool,
    pub isolation: String,
    pub max_output_bytes: u32,
    pub result_rule: serde_json::Value,
}

pub struct Request<'a> {
    pub tenant: &'a str,
    pub job_id: &'a str,
    pub component: &'a str,
    pub sha256: &'a str,
    pub artifact_bytes: u64,
    pub reuse: bool,
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn public_key(value: &str) -> Result<VerifyingKey, String> {
    if !lower_hex(value, 32) {
        return Err("invalid authorization public key".into());
    }
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| "invalid key")?
        .try_into()
        .map_err(|_| "invalid key size")?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid authorization public key")?;
    if key.is_weak() {
        return Err("weak authorization public key".into());
    }
    Ok(key)
}

pub fn verify(
    ctx: &Context,
    ticket: &Ticket,
    request: &Request<'_>,
    now: u64,
) -> Result<Claims, String> {
    if ticket.payload.is_empty()
        || ticket.payload.len() > MAX_PAYLOAD
        || !lower_hex(&ticket.signature, 64)
    {
        return Err("invalid signed ticket size or encoding".into());
    }
    let signature =
        Signature::from_slice(&hex::decode(&ticket.signature).map_err(|_| "invalid signature")?)
            .map_err(|_| "invalid signature")?;
    let mut message = Vec::with_capacity(DOMAIN.len() + ticket.payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(ticket.payload.as_bytes());
    public_key(&ctx.public_key)?
        .verify_strict(&message, &signature)
        .map_err(|_| "job ticket signature rejected")?;
    // Typed deserialization rejects duplicate and unknown claim names. Signature
    // verification covers the original bytes, without JSON reserialization.
    let c: Claims =
        serde_json::from_str(&ticket.payload).map_err(|_| "invalid signed job claims")?;
    if c.version != 1 || c.operation != "run" || c.input != "none" {
        return Err("unsupported signed operation or input ABI".into());
    }
    if c.tenant != ctx.tenant
        || c.tenant != request.tenant
        || c.audience != ctx.audience
        || c.epoch != ctx.epoch
        || c.isolation != ctx.isolation
    {
        return Err(
            "job ticket belongs to a different user, worker, session or isolation mode".into(),
        );
    }
    if c.job_id != request.job_id
        || !lower_hex(&c.nonce, 32)
        || c.component != ctx.component
        || c.component != request.component
        || c.sha256 != ctx.sha256
        || c.sha256 != request.sha256
        || c.artifact_bytes != ctx.artifact_bytes
        || c.artifact_bytes != request.artifact_bytes
        || c.rule_sha256 != ctx.rule_sha256
    {
        return Err("signed job differs from request or trusted workload policy".into());
    }
    if c.cache != if request.reuse { "reuse" } else { "bypass" }
        || (request.reuse && !ctx.cache_allowed)
    {
        return Err("signed cache permission rejected".into());
    }
    if !(1..=300).contains(&ctx.max_ttl_seconds)
        || c.issued_unix > now.saturating_add(5)
        || c.expires_unix <= now
        || c.expires_unix <= c.issued_unix
        || c.expires_unix - c.issued_unix > ctx.max_ttl_seconds
    {
        return Err("job ticket expired, not yet valid, or exceeds allowed lifetime".into());
    }
    Ok(c)
}
