//! Private persistent storage for an authenticated tenant and artifact hash.
//! All scopes for a tenant share one quota lock. Guests never supply filesystem paths.
use crate::{cache, protocol};
use anyhow::{ensure, Context, Result};
use hal_runtime::JobStorage;
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub struct Budget {
    pub root: PathBuf,
    pub bytes: u64,
    pub entries: usize,
    pub lock: Mutex<()>,
}
pub struct PrivateStorage {
    root: PathBuf,
    budget: Arc<Budget>,
    handles: Mutex<HashMap<u64, PathBuf>>,
    next_handle: std::sync::atomic::AtomicU64,
}

fn usage(path: &Path, depth: usize) -> Result<(u64, usize)> {
    ensure!(depth < 5, "unexpected storage nesting");
    let mut bytes = 0u64;
    let mut entries = 0;
    for item in fs::read_dir(path)? {
        let item = item?;
        let kind = item.file_type()?;
        ensure!(!kind.is_symlink(), "storage contains an unsafe symlink");
        entries += 1;
        if kind.is_dir() {
            let (b, n) = usage(&item.path(), depth + 1)?;
            bytes += b;
            entries += n;
        } else {
            ensure!(kind.is_file(), "storage contains an unsafe entry");
            bytes += item.metadata()?.len();
        }
    }
    Ok((bytes, entries))
}

fn name(value: &str) -> Result<()> {
    ensure!(
        protocol::safe_name(value) && value.len() <= 128,
        "invalid storage name or key"
    );
    Ok(())
}

impl PrivateStorage {
    pub fn new(budget: Arc<Budget>, sha: &str) -> Result<Self> {
        ensure!(protocol::valid_sha(sha), "invalid storage artifact hash");
        let root = budget.root.join(sha);
        cache::private_directory(&root)?;
        Ok(Self {
            root,
            budget,
            handles: Mutex::new(HashMap::new()),
            next_handle: std::sync::atomic::AtomicU64::new(1),
        })
    }
    pub fn session(&self) -> Self {
        Self {
            root: self.root.clone(),
            budget: self.budget.clone(),
            handles: Mutex::new(HashMap::new()),
            next_handle: std::sync::atomic::AtomicU64::new(1),
        }
    }
    fn container(&self, handle: u64) -> Result<PathBuf> {
        let path = self
            .handles
            .lock()
            .unwrap()
            .get(&handle)
            .cloned()
            .context("invalid container handle")?;
        cache::private_directory(&path)?;
        Ok(path)
    }
    fn file(&self, handle: u64, key: &str) -> Result<PathBuf> {
        name(key)?;
        Ok(self.container(handle)?.join(format!("{key}.obj")))
    }
    fn regular_size(path: &Path) -> Result<Option<u64>> {
        match fs::symlink_metadata(path) {
            Ok(m) => {
                ensure!(
                    m.is_file() && !m.file_type().is_symlink(),
                    "unsafe storage object"
                );
                Ok(Some(m.len()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn open(&self, container: &str) -> Result<u64> {
        name(container)?;
        let _guard = self.budget.lock.lock().unwrap();
        let path = self.root.join(cache::hash(container.as_bytes()));
        if !path.try_exists()? {
            let (_, count) = usage(&self.budget.root, 0)?;
            ensure!(
                count < self.budget.entries,
                "tenant storage entry quota exceeded"
            );
        }
        cache::private_directory(&path)?;
        let mut handles = self.handles.lock().unwrap();
        if let Some((id, _)) = handles.iter().find(|(_, p)| **p == path) {
            return Ok(*id);
        }
        ensure!(
            handles.len() < self.budget.entries,
            "container handle quota exceeded"
        );
        let id = self
            .next_handle
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        handles.insert(id, path);
        Ok(id)
    }
    fn write(&self, handle: u64, key: &str, data: &[u8]) -> Result<u64> {
        ensure!(data.len() <= 1024 * 1024, "storage object exceeds 1 MiB");
        let _guard = self.budget.lock.lock().unwrap();
        let path = self.file(handle, key)?;
        let old = Self::regular_size(&path)?;
        let (bytes, count) = usage(&self.budget.root, 0)?;
        ensure!(
            bytes
                .saturating_sub(old.unwrap_or(0))
                .saturating_add(data.len() as u64)
                <= self.budget.bytes,
            "tenant storage byte quota exceeded"
        );
        ensure!(
            old.is_some() || count < self.budget.entries,
            "tenant storage entry quota exceeded"
        );
        let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
        file.write_all(data)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|e| e.error)?;
        Ok(handle)
    }
    fn read(&self, handle: u64, key: &str) -> Result<Vec<u8>> {
        let _guard = self.budget.lock.lock().unwrap();
        let path = self.file(handle, key)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.len() <= 1024 * 1024,
            "invalid storage object"
        );
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "storage object exceeds 1 MiB");
        Ok(bytes)
    }
}

impl JobStorage for PrivateStorage {
    fn open_container(&self, name: &str) -> Result<u64, String> {
        self.open(name).map_err(|e| e.to_string())
    }
    // Keep the existing HAL meaning: delete-container closes a handle; it does
    // not recursively delete persisted objects. Handles are namespace-local.
    fn close_container(&self, handle: u64) -> Result<(), String> {
        self.handles
            .lock()
            .unwrap()
            .remove(&handle)
            .map(|_| ())
            .ok_or_else(|| "invalid container handle".into())
    }
    fn write_object(&self, handle: u64, key: &str, data: &[u8]) -> Result<u64, String> {
        self.write(handle, key, data).map_err(|e| e.to_string())
    }
    fn read_object(&self, handle: u64, key: &str) -> Result<Vec<u8>, String> {
        self.read(handle, key).map_err(|e| e.to_string())
    }
    fn delete_object(&self, handle: u64, key: &str) -> Result<(), String> {
        let operation = || -> Result<()> {
            let _guard = self.budget.lock.lock().unwrap();
            let path = self.file(handle, key)?;
            ensure!(Self::regular_size(&path)?.is_some(), "object not found");
            fs::remove_file(path)?;
            Ok(())
        };
        operation().map_err(|e| e.to_string())
    }
    fn list_objects(&self, handle: u64) -> Result<Vec<String>, String> {
        let operation = || -> Result<Vec<String>> {
            let _guard = self.budget.lock.lock().unwrap();
            let mut names = Vec::new();
            for entry in fs::read_dir(self.container(handle)?)? {
                let entry = entry?;
                ensure!(entry.file_type()?.is_file(), "unsafe storage entry");
                if let Some(key) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.strip_suffix(".obj"))
                {
                    name(key)?;
                    names.push(key.to_owned());
                }
            }
            names.sort();
            Ok(names)
        };
        operation().map_err(|e| e.to_string())
    }
}
