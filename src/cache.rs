use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const HEADER: &[u8] = b"\0asm\x0d\0\x01\0";

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn private_directory(path: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Directory must not be a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "Directory must be private (chmod 700): {}",
        path.display()
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "Directory must belong to the agent's user: {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    // O_NONBLOCK prevents opening an unexpected FIFO from blocking the daemon.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "Cache entry is not a regular file");
    ensure!(
        metadata.len() <= limit as u64,
        "Cache entry exceeds component size limit"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "Cache entry exceeds component size limit"
    );
    Ok(bytes)
}

pub fn verify(bytes: &[u8], expected: &str, size: Option<u64>) -> Result<()> {
    ensure!(bytes.starts_with(HEADER), "Expected a Wasm component");
    if let Some(size) = size {
        ensure!(
            bytes.len() as u64 == size,
            "Component size differs from expected size"
        );
    }
    ensure!(hash(bytes) == expected, "Component SHA-256 mismatch");
    Ok(())
}

pub struct Cache {
    pub directory: PathBuf,
    pub staging: PathBuf,
    _lock: File,
    limit: u64,
}

impl Cache {
    pub fn open(directory: &Path, limit: u64) -> Result<Self> {
        private_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(".lock"))?;
        ensure!(
            lock.metadata()?.is_file(),
            "Cache lock is not a regular file"
        );
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "Cache directory is already in use by another agent"
        );
        let staging = directory.join("staging");
        private_directory(&staging)?;
        // Only clean our own interrupted staging files while holding the cache lock.
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("job-")
                && entry.file_type()?.is_file()
            {
                fs::remove_file(entry.path())?;
            }
        }
        let cache = Self {
            directory: directory.to_path_buf(),
            staging,
            _lock: lock,
            limit,
        };
        cache.evict_for(0, None)?;
        Ok(cache)
    }

    fn path(&self, sha: &str) -> PathBuf {
        self.directory.join(format!("{sha}.wasm"))
    }

    fn evict_for(&self, incoming: u64, keep: Option<&Path>) -> Result<usize> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(sha) = name.strip_suffix(".wasm") {
                if crate::protocol::valid_sha(sha) && entry.file_type()?.is_file() {
                    let metadata = entry.metadata()?;
                    entries.push((metadata.modified()?, entry.path(), metadata.len()));
                }
            }
        }
        let mut total: u64 = entries.iter().map(|e| e.2).sum();
        if let Some(keep) = keep {
            total -= entries
                .iter()
                .filter(|e| e.1 == keep)
                .map(|e| e.2)
                .sum::<u64>();
        }
        entries.sort();
        let mut evicted = 0;
        for (_, path, size) in entries {
            if total.saturating_add(incoming) <= self.limit {
                break;
            }
            if keep == Some(path.as_path()) {
                continue;
            }
            fs::remove_file(&path)?;
            total = total.saturating_sub(size);
            evicted += 1;
        }
        ensure!(
            total.saturating_add(incoming) <= self.limit,
            "Cache cannot satisfy its size limit"
        );
        Ok(evicted)
    }

    fn save(&self, sha: &str, bytes: &[u8]) -> Result<usize> {
        let path = self.path(sha);
        let evicted = self.evict_for(bytes.len() as u64, Some(&path))?;
        let mut file = tempfile::Builder::new()
            .prefix("job-cache-")
            .tempfile_in(&self.staging)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        // Atomic rename: incomplete downloads are never visible as cache entries.
        file.persist(path).map_err(|e| e.error)?;
        Ok(evicted)
    }

    // Storage primitives only. The native executor enforces ownership, cache policy and hash checks.
    pub fn get(&self, sha: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        let path = self.path(sha);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
            Ok(metadata) => ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unsafe cache entry: expected a regular file"
            ),
        }
        let bytes = read_bounded(&path, maximum)?;
        File::open(&path)?.set_modified(SystemTime::now())?;
        Ok(Some(bytes))
    }

    pub fn remove(&self, sha: &str) -> Result<()> {
        let path = self.path(sha);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(metadata) => ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Unsafe cache entry: expected a regular file"
            ),
        }
        fs::remove_file(path)?;
        Ok(())
    }

    pub fn put(&self, sha: &str, bytes: &[u8]) -> Result<(bool, usize)> {
        if bytes.len() as u64 > self.limit {
            return Ok((false, 0));
        }
        Ok((true, self.save(sha, bytes)?))
    }
}

pub async fn download(
    client: &reqwest::Client,
    url: reqwest::Url,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .context("HTTP download failed")?
        .error_for_status()?;
    ensure!(
        response.status().is_success(),
        "Expected successful HTTP response; redirects are not followed"
    );
    if let Some(size) = response.content_length() {
        ensure!(
            size <= max_bytes as u64,
            "Component exceeds download size limit"
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= max_bytes.saturating_sub(bytes.len()),
            "Component exceeds download size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
