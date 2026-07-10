//! Thin wrappers around external tools: gocryptfs, fusermount, gpg, hooks.

use crate::procfs::which;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `gpgconf --kill all`, ignoring failures (best-effort).
pub fn gpg_kill() {
    let _ = Command::new("gpgconf").arg("--kill").arg("all").status();
}

/// Run a list of shell hook commands; abort on the first failure.
pub fn run_hooks(label: &str, hooks: &[String]) -> Result<()> {
    for cmd in hooks {
        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .with_context(|| format!("running {label} hook: {cmd}"))?;
        if !status.success() {
            bail!("{label} hook failed: {cmd}");
        }
    }
    Ok(())
}

/// `gocryptfs -init` on an encrypted directory using a passfile.
pub fn gocryptfs_init(enc: &Path, passfile: &Path) -> Result<()> {
    let status = Command::new("gocryptfs")
        .arg("-init")
        .arg("-q")
        .arg("-passfile")
        .arg(passfile)
        .arg(enc)
        .stdout(Stdio::null())
        .status()
        .context("spawning gocryptfs -init")?;
    if !status.success() {
        bail!("gocryptfs -init failed for {}", enc.display());
    }
    Ok(())
}

/// Mount an encrypted directory. `idle` is a raw gocryptfs duration or `None`.
pub fn gocryptfs_mount(enc: &Path, mnt: &Path, passfile: &Path, idle: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("gocryptfs");
    cmd.arg("-q");
    if let Some(idle) = idle {
        cmd.arg("-idle").arg(idle);
    }
    cmd.arg("-passfile").arg(passfile).arg(enc).arg(mnt);
    cmd.stdout(Stdio::null());
    let status = cmd.status().context("spawning gocryptfs")?;
    if !status.success() {
        bail!("gocryptfs mount failed for {}", mnt.display());
    }
    Ok(())
}

/// Unmount a FUSE mountpoint via fusermount3 (fallback fusermount).
pub fn fuse_unmount(mnt: &Path, lazy: bool) -> Result<()> {
    let bin = if which("fusermount3").is_some() {
        "fusermount3"
    } else {
        "fusermount"
    };
    let mut cmd = Command::new(bin);
    cmd.arg("-u");
    if lazy {
        cmd.arg("-z");
    }
    cmd.arg(mnt);
    let status = cmd.status().with_context(|| format!("spawning {bin}"))?;
    if !status.success() {
        bail!("{bin} -u failed for {}", mnt.display());
    }
    Ok(())
}
