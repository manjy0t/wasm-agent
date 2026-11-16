//! Process totals: differences between snapshots are meaningful for a batch.
//! They must not be attributed to individual overlapping jobs.
pub fn process_resources() -> serde_json::Value {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // getrusage writes the complete struct on success.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return serde_json::json!({"available": false});
        }
        let usage = unsafe { usage.assume_init() };
        let milliseconds = |t: libc::timeval| t.tv_sec as f64 * 1000.0 + t.tv_usec as f64 / 1000.0;
        // Darwin reports bytes; Linux reports KiB. This is a lifetime peak.
        let rss_unit = if cfg!(target_os = "macos") {
            1.0
        } else {
            1024.0
        };
        serde_json::json!({
            "available": true,
            "user_cpu_ms": milliseconds(usage.ru_utime),
            "system_cpu_ms": milliseconds(usage.ru_stime),
            "peak_rss_mib": usage.ru_maxrss as f64 * rss_unit / (1024.0 * 1024.0),
            "peak_rss_scope": "host process lifetime, not this batch or one workload",
            "voluntary_context_switches": usage.ru_nvcsw,
            "involuntary_context_switches": usage.ru_nivcsw,
        })
    }
    #[cfg(not(unix))]
    serde_json::json!({"available": false})
}
