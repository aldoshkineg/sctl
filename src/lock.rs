//! Per-secret advisory locking to prevent concurrent operations racing.

use anyhow::{Context, Result, bail};
use std::fs::{File, TryLockError};
use std::path::Path;

/// Held lock; releases (closes the file) on drop.
pub struct Lock {
    _file: File,
}

/// Acquire an exclusive, non-blocking lock for a secret. Fails immediately if
/// another `sctl` process already holds it.
pub fn acquire(state_dir: &Path, safe: &str, name: &str) -> Result<Lock> {
    let dir = state_dir.join("locks");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating lock dir {}", dir.display()))?;
    let path = dir.join(format!("{safe}.lock"));
    let file = File::create(&path).with_context(|| format!("opening lock {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Lock { _file: file }),
        Err(TryLockError::WouldBlock) => {
            bail!("another sctl operation is already in progress for '{name}'")
        }
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking {}", path.display()))
        }
    }
}
