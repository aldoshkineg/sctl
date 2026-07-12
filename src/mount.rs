//! `init` and `mount` operations for a single secret.

use crate::config::{Config, Secret};
use crate::notify::notify;
use crate::passfile;
use crate::procfs::is_mounted;
use crate::secret;
use crate::state;
use crate::sys;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Options controlling a mount.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountOpts {
    pub no_idle: bool,
    pub notify: bool,
}

/// Resolve the effective idle value: per-secret > SCTL_IDLE > default_idle.
/// Returns `None` when idle is disabled.
fn effective_idle(cfg: &Config, secret: &Secret, no_idle: bool) -> Option<String> {
    if no_idle || std::env::var_os("SCTL_NO_IDLE").is_some() {
        return None;
    }
    secret
        .idle
        .clone()
        .or_else(|| std::env::var("SCTL_IDLE").ok().filter(|s| !s.is_empty()))
        .or_else(|| cfg.default_idle.clone())
        .filter(|s| !s.is_empty())
}

/// Create an encrypted container and migrate any existing cleartext into it.
pub fn init_one(cfg: &Config, secret: &Secret) -> Result<()> {
    let _lock = crate::lock::acquire(&cfg.state_dir, &secret.safe(), &secret.name)?;
    let enc = secret.enc_dir(&cfg.enc_root);
    let mnt = secret.mountpoint(&cfg.home);

    if secret.gpg {
        sys::gpg_kill();
    }
    if enc.join("gocryptfs.conf").exists() {
        bail!("{} already initialized at {}", secret.name, enc.display());
    }
    std::fs::create_dir_all(&enc)?;
    std::fs::create_dir_all(&mnt)?;

    let pf = passfile::resolve(&secret.name, &cfg.keyfile)?;
    println!("Initializing encrypted container: {}", enc.display());
    sys::gocryptfs_init(&enc, pf.path())?;

    // Mount to a scratch dir to migrate existing data.
    let scratch = tempfile::tempdir().context("creating scratch mount dir")?;
    sys::gocryptfs_mount(&enc, scratch.path(), pf.path(), None)?;
    if dir_nonempty(&mnt) {
        println!(
            "Migrating existing data from {} into container...",
            mnt.display()
        );
        migrate_into(&mnt, scratch.path())?;
    }
    sys::fuse_unmount(scratch.path(), false)?;
    println!(
        "Initialized: {} -> {} (mountpoint: {})",
        secret.name,
        enc.display(),
        mnt.display()
    );
    Ok(())
}

/// Mount a single secret's container.
pub fn mount_one(cfg: &Config, secret: &Secret, opts: MountOpts) -> Result<()> {
    let _lock = crate::lock::acquire(&cfg.state_dir, &secret.safe(), &secret.name)?;
    let enc = secret.enc_dir(&cfg.enc_root);
    let mnt = secret.mountpoint(&cfg.home);

    sys::run_hooks("pre_mount", &secret.pre_mount)?;

    if is_mounted(&mnt) {
        println!("{}: already mounted ({})", secret.name, mnt.display());
        notify(opts.notify, &format!("{} already mounted", secret.name));
        return Ok(());
    }

    // Only (re)start gpg-agent when we are actually (re)mounting this volume.
    // Killing it for an already-mounted gpg dependency would wipe the cached
    // passphrases of other volumes without re-running the preset below.
    if secret.gpg {
        sys::gpg_kill();
    }
    if !enc.join("gocryptfs.conf").exists() {
        bail!(
            "{} not initialized, run: sctl init {}",
            secret.name,
            secret.name
        );
    }

    if dir_nonempty(&mnt) {
        move_stray_aside(cfg, secret, &mnt)?;
    }
    std::fs::create_dir_all(&mnt)?;

    let idle = effective_idle(cfg, secret, opts.no_idle);
    let pf = resolve_gocryptfs_passfile(cfg, secret)?;
    sys::gocryptfs_mount(&enc, &mnt, pf.path(), idle.as_deref())?;

    let tag = match &idle {
        Some(v) => format!(" (idle: {v})"),
        None => " (no idle)".to_string(),
    };
    println!("mounted: {} -> {}{}", secret.name, mnt.display(), tag);
    notify(
        opts.notify,
        &format!("Mounted {} -> {}{}", secret.name, mnt.display(), tag),
    );

    state::persist(
        &cfg.state_dir,
        &secret.safe(),
        idle.as_deref().unwrap_or("none"),
    )?;
    if (secret.gpg || secret.gpg_preset)
        && let Err(e) = crate::gpg::preset_all(cfg)
    {
        eprintln!("warning: gpg preset failed: {e:#}");
    }
    sys::run_hooks("post_mount", &secret.post_mount)?;
    Ok(())
}

fn dir_nonempty(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// Resolve the gocryptfs passfile for a mount.
///
/// In backend mode (`secret_backend` set) the shared key `G` is read from the
/// backend via `secret::resolve_secret` (zero input from the user). Otherwise
/// the legacy plaintext `keyfile` is used.
fn resolve_gocryptfs_passfile(cfg: &Config, secret: &Secret) -> Result<passfile::Passfile> {
    if cfg.secret_backend.is_some() {
        let g = secret::resolve_secret(cfg, "gocryptfs", "__shared__").with_context(|| {
            format!(
                "resolving gocryptfs key for '{}' from the secret backend \
                 (run `sctl install` first)",
                secret.name
            )
        })?;
        return passfile::from_bytes(&g);
    }
    passfile::resolve(&secret.name, &cfg.keyfile)
}

fn migrate_into(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        // rename works within the same fs; fall back to copy+remove otherwise.
        if std::fs::rename(entry.path(), &target).is_err() {
            let meta = entry.metadata()?;
            if meta.is_dir() {
                copy_dir(&entry.path(), &target)?;
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::copy(entry.path(), &target)?;
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.metadata()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

fn move_stray_aside(cfg: &Config, secret: &Secret, mnt: &Path) -> Result<()> {
    std::fs::create_dir_all(&cfg.stray_dir)?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dest = cfg.stray_dir.join(format!("{}_{}", secret.safe(), ts));
    println!(
        "Mountpoint {} not empty (stray files) -> moving aside to {}",
        mnt.display(),
        dest.display()
    );
    std::fs::rename(mnt, &dest)?;
    std::fs::create_dir_all(mnt)?;
    Ok(())
}
