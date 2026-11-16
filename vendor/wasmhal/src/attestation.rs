//! Attestation plumbing shared by the Intel TDX and AMD SEV-SNP paths.
//!
//! Neither of those is vendor-specific, so they live here rather than in
//! either vendor's module:
//!
//! * [`compute_hal_hash`] — identifies which HAL build produced the evidence.
//! * [`request_report`] — asks the firmware for a hardware attestation report
//!   bound to caller-supplied report data, via the Linux TSM configfs.
//!
//! The TSM interface is vendor-neutral: the kernel routes the request to
//! whichever attestation engine the guest has, producing an SNP attestation
//! report on AMD and a TDX quote on Intel. One implementation therefore serves
//! every guest that exposes it, which is why bare-metal and GCP AMD guests land
//! on the same code path as Intel ones.
//!
//! See `Documentation/arch/x86/tdx/guest_attestation.rst` in the Linux kernel
//! tree for the configfs interface, and the AMD SEV-SNP Firmware ABI
//! Specification for the report layout that [`crate::snp_report`] parses.

use crate::error::{HalError, HalResult};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Length of the report-data field on both SNP and TDX.
///
/// Report data is the verifier's nonce: binding it into the signed report is
/// what makes the evidence fresh rather than replayable.
pub const REPORT_DATA_LEN: usize = 64;

/// Configfs mount point for the TSM report interface (Linux >= 6.7).
const TSM_REPORT_BASE: &str = "/sys/kernel/config/tsm/report";

/// Whether the kernel exposes the TSM configfs report interface.
pub fn tsm_available() -> bool {
    Path::new(TSM_REPORT_BASE).exists()
}

/// Compute SHA-256 of the currently running HAL binary (`/proc/self/exe`).
///
/// This identifies which HAL build produced the attestation, so a verifier can
/// decide whether it trusts the code that generated the evidence. If the binary
/// cannot be read we return all-zero, a deliberate "unknown" sentinel rather than
/// a failure: the firmware measurements are the security-critical fields, and a
/// missing binary hash should not suppress them.
pub fn compute_hal_hash() -> [u8; 32] {
    match std::fs::read("/proc/self/exe") {
        Ok(bytes) => {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.finalize().into()
        }
        Err(e) => {
            log::warn!("Failed to read /proc/self/exe for HAL hash: {}", e);
            [0u8; 32]
        }
    }
}

/// Ask the firmware for an attestation report bound to `report_data`.
///
/// `vendor_tag` only labels the configfs entry (it appears in the directory
/// name so a stale entry is identifiable); it does not change the request.
///
/// Sequence, per the kernel documentation:
///   1. `mkdir /sys/kernel/config/tsm/report/<unique>`
///   2. write `report_data` to the entry's `inblob` — this triggers generation
///   3. read the finished report from the entry's `outblob`
///   4. `rmdir` the entry
///
/// Shorter `report_data` is zero-padded to [`REPORT_DATA_LEN`], which is what
/// both SNP and TDX require; longer input is rejected rather than truncated,
/// because a silently truncated nonce would still sign and verify.
pub fn request_report(vendor_tag: &str, report_data: &[u8]) -> HalResult<Vec<u8>> {
    request_report_with_aux(vendor_tag, report_data, false).map(|(report, _)| report)
}

/// Also collect the SNP extended-report endorsements (AWS VLEK). Collection
/// does not verify their authenticity; the relying party's verifier does that.
pub fn request_report_with_aux(
    vendor_tag: &str,
    report_data: &[u8],
    include_aux: bool,
) -> HalResult<(Vec<u8>, Vec<u8>)> {
    if report_data.len() > REPORT_DATA_LEN {
        return Err(HalError::InvalidParameter(format!(
            "report_data must be at most {} bytes, got {}",
            REPORT_DATA_LEN,
            report_data.len()
        )));
    }

    if !tsm_available() {
        return Err(HalError::TeeInitializationFailed(format!(
            "TSM configfs not available at {}",
            TSM_REPORT_BASE
        )));
    }

    let mut padded = [0u8; REPORT_DATA_LEN];
    padded[..report_data.len()].copy_from_slice(report_data);

    let entry = TsmReportEntry::create(vendor_tag)?;
    entry.write_inblob(&padded)?;
    let report = entry.read_outblob()?;
    let auxiliary = if include_aux {
        entry.read_blob("auxblob", 64 * 1024)?
    } else {
        Vec::new()
    };
    Ok((report, auxiliary))
}

/// Reduce a caller-supplied vendor tag to characters that cannot escape the TSM
/// directory.
///
/// The tag is interpolated into a filesystem path, so it is the untrusted
/// boundary that keeps a crafted tag from reaching outside `TSM_REPORT_BASE`.
/// Unusable input degrades to `report` rather than failing, because the tag is
/// cosmetic — it only names the entry.
fn sanitise_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(16)
        .collect();

    if cleaned.is_empty() {
        "report".to_string()
    } else {
        cleaned
    }
}

/// A single configfs entry under `/sys/kernel/config/tsm/report`.
///
/// Creating the directory is what makes the kernel materialise the `inblob` and
/// `outblob` nodes for this request; removing it releases them. Cleanup is
/// therefore tied to every exit path, including the error paths, or a failed
/// attestation would leak a directory that blocks nothing but accumulates.
struct TsmReportEntry {
    path: std::path::PathBuf,
}

impl TsmReportEntry {
    fn create(vendor_tag: &str) -> HalResult<Self> {
        let safe_tag = sanitise_tag(vendor_tag);

        // Timestamp plus pid: two concurrent attestations in the same process
        // would otherwise race on a name derived from the clock alone.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let path = Path::new(TSM_REPORT_BASE).join(format!(
            "hal_{}_{}_{}",
            if safe_tag.is_empty() {
                "report"
            } else {
                safe_tag.as_str()
            },
            std::process::id(),
            unique
        ));

        std::fs::create_dir(&path).map_err(|e| {
            HalError::TeeInitializationFailed(format!(
                "failed to create TSM report entry '{}': {}",
                path.display(),
                e
            ))
        })?;

        // Keep the kernel's private node permissions. The native attestation
        // collector runs with the privileges needed to use configfs.
        Ok(Self { path })
    }

    fn write_inblob(&self, report_data: &[u8; REPORT_DATA_LEN]) -> HalResult<()> {
        std::fs::write(self.path.join("inblob"), report_data).map_err(|e| {
            HalError::TeeInitializationFailed(format!("failed to write TSM inblob: {}", e))
        })
    }

    fn read_outblob(&self) -> HalResult<Vec<u8>> {
        let report = self.read_blob("outblob", 1024 * 1024)?;

        if report.is_empty() {
            return Err(HalError::TeeInitializationFailed(
                "TSM returned an empty report".to_string(),
            ));
        }
        Ok(report)
    }

    fn read_blob(&self, name: &str, maximum: usize) -> HalResult<Vec<u8>> {
        let file = std::fs::File::open(self.path.join(name)).map_err(|e| {
            HalError::TeeInitializationFailed(format!("failed to open TSM {}: {}", name, e))
        })?;
        let mut bytes = Vec::new();
        file.take((maximum + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                HalError::TeeInitializationFailed(format!("failed to read TSM {}: {}", name, e))
            })?;
        if bytes.len() > maximum {
            return Err(HalError::TeeInitializationFailed(format!(
                "TSM {} exceeds size limit",
                name
            )));
        }
        Ok(bytes)
    }
}

impl Drop for TsmReportEntry {
    /// Remove the configfs entry, releasing the kernel's report nodes.
    ///
    /// Best-effort: a leftover directory is untidy but harmless, and there is
    /// nothing useful to do about a failure here on an error path that is
    /// already returning an error.
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir(&self.path) {
            log::debug!(
                "failed to remove TSM report entry '{}': {}",
                self.path.display(),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxiliary_reads_are_bounded() {
        let folder = tempfile::tempdir().unwrap();
        let entry = TsmReportEntry {
            path: folder.path().to_path_buf(),
        };
        std::fs::write(folder.path().join("auxblob"), [7; 17]).unwrap();
        assert!(entry.read_blob("auxblob", 16).is_err());
        assert_eq!(entry.read_blob("auxblob", 17).unwrap(), vec![7; 17]);
    }

    #[test]
    fn entry_is_cleaned_up_after_a_read_error() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("report");
        std::fs::create_dir(&path).unwrap();
        {
            let entry = TsmReportEntry { path: path.clone() };
            assert!(entry.read_blob("missing", 16).is_err());
        }
        assert!(!path.exists());
    }

    #[test]
    fn report_data_longer_than_the_field_is_rejected_not_truncated() {
        // Truncating here would produce a report that signs and verifies while
        // binding only part of the verifier's nonce.
        let too_long = vec![0u8; REPORT_DATA_LEN + 1];
        let err = request_report("test", &too_long).unwrap_err();
        assert!(
            err.to_string().contains("at most"),
            "expected a length error, got: {}",
            err
        );
    }

    #[test]
    fn vendor_tag_cannot_escape_the_tsm_directory() {
        // The tag is interpolated into a path; a traversal attempt must be
        // reduced to harmless characters rather than reaching outside TSM_REPORT_BASE.
        for hostile in ["../../etc/passwd", "/abs/path", "a/b", "..", "."] {
            let cleaned = sanitise_tag(hostile);
            assert!(
                !cleaned.contains('/') && !cleaned.contains('.') && !cleaned.is_empty(),
                "tag {:?} escaped its directory: {:?}",
                hostile,
                cleaned
            );
        }
    }

    #[test]
    fn empty_tag_degrades_to_a_usable_name() {
        assert_eq!(sanitise_tag(""), "report");
        assert_eq!(sanitise_tag("///"), "report");
    }
}
