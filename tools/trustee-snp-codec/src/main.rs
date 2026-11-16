//! Translate a raw SNP report into Trustee v0.22.0's serde evidence format.
//! This is NOT a vendor-signature verifier and has no network or device access.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sev::{
    firmware::guest::AttestationReport,
    parser::{ByteParser, Encoder},
};
use std::io::{self, Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    report_hex: String,
}

fn convert(raw: &[u8]) -> Result<Value> {
    ensure!(
        raw.len() == 1184,
        "expected one complete 1184-byte SNP report"
    );
    let report = AttestationReport::from_bytes(raw).context("unsupported SNP report encoding")?;
    ensure!(
        (3..=5).contains(&report.version),
        "Trustee v0.22.0 accepts SNP reports 3..5"
    );
    // A JSON translation must not change the signed byte representation.
    let mut roundtrip = Vec::new();
    report.encode(&mut roundtrip, ())?;
    ensure!(
        roundtrip == raw,
        "SNP report does not round-trip without changing signed bytes"
    );
    let product = match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(0x19), Some(0x00..=0x0f)) => "Milan",
        (Some(0x19), Some(0x10..=0x1f)) | (Some(0x19), Some(0xa0..=0xae)) => "Genoa",
        _ => anyhow::bail!("unsupported SNP product for this HAL appraisal policy"),
    };
    Ok(
        json!({"evidence": {"attestation_report": report, "cert_chain": null},
              "product": product, "vmpl": report.vmpl,
              "report_data": hex::encode(report.report_data), "chip_id": hex::encode(report.chip_id)}),
    )
}

fn main() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().take(4097).read_to_end(&mut input)?;
    ensure!(input.len() <= 4096, "request too large");
    let input: Input = serde_json::from_slice(&input)?;
    println!("{}", convert(&hex::decode(input.report_hex)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(version: u32) -> Vec<u8> {
        let mut raw = vec![0; 1184];
        raw[..4].copy_from_slice(&version.to_le_bytes());
        raw[0x188] = 0x19;
        raw[0x189] = 0x11;
        raw[0x50..0x90].fill(0x5a);
        raw
    }

    #[test]
    fn versions_preserve_report_data_and_exact_wire_bytes() {
        for version in 3..=5 {
            let value = convert(&raw(version)).unwrap();
            let report: AttestationReport =
                serde_json::from_value(value["evidence"]["attestation_report"].clone()).unwrap();
            let mut encoded = Vec::new();
            report.encode(&mut encoded, ()).unwrap();
            assert_eq!(encoded, raw(version));
            assert_eq!(value["product"], "Genoa");
            assert_eq!(value["report_data"], "5a".repeat(64));
        }
    }

    #[test]
    fn reject_truncation_trailing_unknown_versions_and_changed_reserved_bytes() {
        for version in [0, 2, 6] {
            assert!(convert(&raw(version)).is_err());
        }
        assert!(convert(&raw(3)[..1183]).is_err());
        let mut extended = raw(3);
        extended.push(0);
        assert!(convert(&extended).is_err());
        let mut reserved = raw(3);
        reserved[0x4c] = 1;
        assert!(convert(&reserved).is_err());
    }
}
