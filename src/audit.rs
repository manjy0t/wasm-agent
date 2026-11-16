//! Durable agent audit records. No workload receives this API or the signing key.
use crate::{cache, protocol, tickets_core};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

pub const FORMAT: &str = "hal-agent-audit-v1";
const DOMAIN: &[u8] = b"HAL-AGENT-AUDIT-v1\0";
const CERT_DOMAIN: &[u8] = b"HAL-AGENT-CERTIFICATE-v1\0";
const MAX_RECORD: usize = 8192;
// Keep a page below 512 KiB so its signed, escaped envelope fits the IPC limit.
const MAX_PAGE_RECORDS: usize = 64;
pub const DEFAULT_LIMIT: u64 = 256 * 1024 * 1024;
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn verify_signature(key: &str, domain: &[u8], envelope: &Value) -> Result<Value> {
    let payload = protocol::string(envelope, "payload")?;
    ensure!(payload.len() <= MAX_RECORD, "audit payload too large");
    let signature = Signature::from_slice(&hex::decode(protocol::string(envelope, "signature")?)?)?;
    let mut bytes = domain.to_vec();
    bytes.extend(payload.as_bytes());
    tickets_core::public_key(key)
        .map_err(anyhow::Error::msg)?
        .verify_strict(&bytes, &signature)?;
    Ok(serde_json::from_str(payload)?)
}

pub fn verify_record(
    record: &Value,
    owner: &str,
    vm: &str,
    seq: u64,
    previous: &str,
) -> Result<Value> {
    let payload = protocol::string(record, "payload")?;
    let untrusted: Value = serde_json::from_str(payload)?;
    let certificate = verify_signature(owner, CERT_DOMAIN, &untrusted["certificate"])?;
    let identity = &certificate["identity"];
    ensure!(
        certificate["version"] == 1
            && certificate["kind"] == "agent-identity"
            && identity["vm_id"] == vm
            && identity["management_key"] == owner,
        "audit certificate scope mismatch"
    );
    let value = verify_signature(protocol::string(identity, "public_key")?, DOMAIN, record)?;
    let timestamp = protocol::unsigned(&value, "timestamp_unix")?;
    ensure!(
        timestamp + 5 >= protocol::unsigned(&certificate, "issued_unix")?
            && timestamp < protocol::unsigned(&certificate, "expires_unix")?,
        "audit record outside certificate lifetime"
    );
    ensure!(
        value["format"] == FORMAT
            && value["vm_id"] == vm
            && value["sequence"] == seq
            && value["previous_hash"] == previous
            && value["agent_instance"] == identity["instance"],
        "audit chain or identity mismatch"
    );
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(payload.as_bytes());
    ensure!(
        record["hash"] == cache::hash(&bytes),
        "audit record hash mismatch"
    );
    Ok(value)
}

pub struct Journal {
    file: File,
    index: Vec<(u64, usize, String)>,
    length: u64,
    limit: u64,
    owner: String,
    identity: Value,
    certificate: Option<Value>,
    key: SigningKey,
    failed: bool,
}
impl Journal {
    pub fn open(path: &Path, identity: Value, key: SigningKey, limit: u64) -> Result<Self> {
        ensure!(
            limit >= 1024 * 1024 && limit <= 4 * 1024 * 1024 * 1024,
            "invalid audit storage limit"
        );
        cache::private_directory(path.parent().context("audit directory missing")?)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.permissions().mode() & 0o077 == 0,
            "audit journal must be a private regular file"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "audit journal already open"
        );
        ensure!(
            file.metadata()?.len() <= limit,
            "audit journal exceeds storage limit"
        );
        // Persist the directory entry as well as subsequent record contents.
        File::open(path.parent().unwrap())?.sync_all()?;
        let owner = protocol::string(&identity, "management_key")?.to_owned();
        let vm = protocol::string(&identity, "vm_id")?;
        let mut index = Vec::new();
        let mut length = 0;
        let mut previous = ZERO.to_owned();
        let mut reader = BufReader::new(file.try_clone()?);
        loop {
            let mut line = Vec::new();
            let read = (&mut reader)
                .take((MAX_RECORD + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            ensure!(
                read <= MAX_RECORD && line.last() == Some(&b'\n'),
                "incomplete or oversized audit record; restore from verified archive"
            );
            let record: Value = serde_json::from_slice(&line)?;
            verify_record(&record, &owner, vm, index.len() as u64 + 1, &previous)?;
            previous = protocol::string(&record, "hash")?.into();
            index.push((length, read, previous.clone()));
            length += read as u64;
        }
        Ok(Self {
            file,
            index,
            length,
            limit,
            owner,
            identity,
            certificate: None,
            key,
            failed: false,
        })
    }
    pub fn activate(&mut self, certificate: Value) {
        self.certificate = Some(certificate);
    }
    pub fn head(&self) -> Value {
        json!({"vm_id":self.identity["vm_id"],"sequence":self.index.len(),
            "hash":self.index.last().map(|r| r.2.as_str()).unwrap_or(ZERO)})
    }
    pub fn admit(&self, active: usize) -> Result<()> {
        // Leave space for completions and failure records of already admitted jobs.
        ensure!(
            !self.failed && self.length + (((active + 2) * MAX_RECORD * 4) as u64) < self.limit,
            "audit storage unavailable or full; new jobs are blocked"
        );
        Ok(())
    }
    pub fn append(&mut self, event: &str, data: Value) -> Result<Value> {
        ensure!(!self.failed, "audit journal failed; new jobs are blocked");
        let outcome = (|| -> Result<Value> {
            let certificate = self
                .certificate
                .as_ref()
                .context("audit signing certificate missing")?;
            let sequence = self.index.len() as u64 + 1;
            let previous = self.index.last().map(|r| r.2.as_str()).unwrap_or(ZERO);
            let body = json!({"format":FORMAT,"vm_id":self.identity["vm_id"],"sequence":sequence,
                "previous_hash":previous,"agent_instance":self.identity["instance"],
                "timestamp_unix":crate::authorization::now()?,"event":event,"data":data,"certificate":certificate});
            let payload = body.to_string();
            let mut bytes = DOMAIN.to_vec();
            bytes.extend(payload.as_bytes());
            let hash = cache::hash(&bytes);
            let record = json!({"payload":payload,"hash":hash,"signature":hex::encode(self.key.sign(&bytes).to_bytes())});
            verify_record(
                &record,
                &self.owner,
                protocol::string(&self.identity, "vm_id")?,
                sequence,
                previous,
            )?;
            let mut line = serde_json::to_vec(&record)?;
            line.push(b'\n');
            ensure!(
                line.len() <= MAX_RECORD && self.length + line.len() as u64 <= self.limit,
                "audit journal full"
            );
            ensure!(
                self.file.metadata()?.len() == self.length,
                "audit journal changed outside the runtime"
            );
            self.file.write_all(&line)?;
            self.file.sync_all()?;
            self.index.push((self.length, line.len(), hash));
            self.length += line.len() as u64;
            Ok(self.head())
        })();
        if outcome.is_err() {
            self.failed = true;
        }
        outcome.context(
            "audit persistence failed; execution outcome must not be reported as successful",
        )
    }
    pub fn page(&mut self, after: u64, previous: &str, limit: usize) -> Result<Value> {
        ensure!(
            limit > 0 && limit <= MAX_PAGE_RECORDS,
            "invalid audit page limit"
        );
        ensure!(
            after <= self.index.len() as u64,
            "audit rollback: requested checkpoint is beyond journal"
        );
        let expected = if after == 0 {
            ZERO
        } else {
            &self.index[after as usize - 1].2
        };
        ensure!(
            previous == expected,
            "audit checkpoint hash differs; possible rollback or fork"
        );
        let until = (after as usize + limit).min(self.index.len());
        let mut records = Vec::new();
        let mut previous = previous.to_owned();
        for position in after as usize..until {
            let (offset, length, hash) = &self.index[position];
            self.file.seek(SeekFrom::Start(*offset))?;
            let mut bytes = vec![0; *length];
            self.file.read_exact(&mut bytes)?;
            let row: Value = serde_json::from_slice(&bytes)?;
            verify_record(
                &row,
                &self.owner,
                protocol::string(&self.identity, "vm_id")?,
                position as u64 + 1,
                &previous,
            )?;
            ensure!(row["hash"] == *hash, "audit journal content changed");
            previous = hash.clone();
            records.push(row);
        }
        Ok(
            json!({"records":records,"checkpoint":{"vm_id":self.identity["vm_id"],"sequence":until,"hash":previous},"tip":self.head()}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub fn fixture(path: &Path, instance: &str) -> Journal {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let key = SigningKey::from_bytes(&[2; 32]);
        let identity = json!({"vm_id":"vm-a","management_key":hex::encode(owner.verifying_key().to_bytes()),
            "public_key":hex::encode(key.verifying_key().to_bytes()),"instance":instance,"agent_sha256":"abc"});
        let t = crate::authorization::now().unwrap();
        let payload = json!({"version":1,"kind":"agent-identity","identity":identity,
            "issued_unix":t-1,"expires_unix":t+300})
        .to_string();
        let mut bytes = CERT_DOMAIN.to_vec();
        bytes.extend(payload.as_bytes());
        let cert =
            json!({"payload":payload,"signature":hex::encode(owner.sign(&bytes).to_bytes())});
        let mut journal = Journal::open(path, identity, key, DEFAULT_LIMIT).unwrap();
        journal.activate(cert);
        journal
    }
    #[test]
    fn signed_chain_survives_restart_and_changes_agent_epoch() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit/agent.jsonl");
        let mut journal = fixture(&path, "first");
        let anchor = journal
            .append("job_accepted", json!({"job_id":"one"}))
            .unwrap();
        drop(journal);
        let mut restarted = fixture(&path, "second");
        restarted
            .append("result_committed", json!({"job_id":"one"}))
            .unwrap();
        let page = restarted
            .page(1, anchor["hash"].as_str().unwrap(), 64)
            .unwrap();
        let entry: Value =
            serde_json::from_str(page["records"][0]["payload"].as_str().unwrap()).unwrap();
        assert_eq!(entry["agent_instance"], "second");
        assert_eq!(entry["sequence"], 2);
        assert_eq!(page["checkpoint"]["sequence"], 2);
        assert!(restarted.page(1, ZERO, 64).is_err());
    }
    #[test]
    fn truncated_tail_is_detected_against_external_checkpoint() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit/agent.jsonl");
        let mut journal = fixture(&path, "first");
        journal.append("job_accepted", json!({})).unwrap();
        let first = std::fs::read(&path).unwrap();
        let anchor = journal.append("result_committed", json!({})).unwrap();
        drop(journal);
        std::fs::write(&path, first).unwrap();
        let mut restarted = fixture(&path, "second");
        assert!(restarted
            .page(2, anchor["hash"].as_str().unwrap(), 64)
            .is_err());
    }
    #[test]
    fn tampering_partial_records_and_write_failure_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit/agent.jsonl");
        let mut journal = fixture(&path, "first");
        journal.append("job_accepted", json!({})).unwrap();
        let pristine = std::fs::read(&path).unwrap();
        let mut row: Value = serde_json::from_slice(&pristine).unwrap();
        row["signature"] = json!("0".repeat(128));
        std::fs::write(&path, format!("{row}\n")).unwrap();
        assert!(journal.page(0, ZERO, 64).is_err());
        std::fs::write(&path, b"partial").unwrap();
        assert!(journal.append("result_committed", json!({})).is_err());
        assert!(journal.admit(0).is_err());
        let identity = journal.identity.clone();
        let key = journal.key.clone();
        drop(journal);
        assert!(Journal::open(&path, identity, key, DEFAULT_LIMIT).is_err());
    }
    #[test]
    fn admission_reserves_room_and_concurrent_open_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit/agent.jsonl");
        let mut journal = fixture(&path, "first");
        journal.limit = 1024 * 1024;
        assert!(journal.admit(32).is_err());
        assert!(journal.admit(0).is_ok());
        assert!(Journal::open(
            &path,
            journal.identity.clone(),
            journal.key.clone(),
            DEFAULT_LIMIT
        )
        .is_err());
    }
    #[test]
    fn export_pages_fit_signed_transport_and_preserve_the_cursor() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("audit/agent.jsonl");
        let mut journal = fixture(&path, "first");
        for _ in 0..65 {
            journal
                .append("test", json!({"padding":"x".repeat(6000)}))
                .unwrap();
        }
        assert!(journal.page(0, ZERO, 65).is_err());
        let first = journal.page(0, ZERO, 64).unwrap();
        assert_eq!(first["records"].as_array().unwrap().len(), 64);
        assert!(serde_json::to_vec(&first).unwrap().len() < 1024 * 1024);
        let rest = journal
            .page(64, first["checkpoint"]["hash"].as_str().unwrap(), 64)
            .unwrap();
        assert_eq!(rest["records"].as_array().unwrap().len(), 1);
        assert_eq!(rest["checkpoint"], rest["tip"]);
    }
}
