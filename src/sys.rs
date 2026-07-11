//! Thin wrappers around external tools: gocryptfs, fusermount, gpg, hooks.

use crate::procfs::which;
use anyhow::{Context, Result, bail};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Run `gpgconf --kill all`, best-effort, with a hard timeout so a wedged agent
/// can't hang the calling operation (e.g. `sctl umount gpg`).
pub fn gpg_kill() {
    const TIMEOUT: Duration = Duration::from_secs(5);
    let mut child = match Command::new("gpgconf")
        .arg("--kill")
        .arg("all")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let pid = Pid::from_raw(child.id() as i32);
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed() >= TIMEOUT {
                    let _ = kill(pid, Signal::SIGKILL);
                    let _ = child.wait();
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return,
        }
    }
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
