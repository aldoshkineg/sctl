//! First-class gpg secret-key preloading into gpg-agent after a mount.
//!
//! After the `.gnupg` container is mounted, sctl can preset the secret-key
//! passphrases for every enrolled primary key into the (freshly started)
//! gpg-agent via `gpg-preset-passphrase`, so the user is not prompted on every
//! mount.
//!
//! In backend mode (`secret_backend` set + per-secret `tpm_gpg`) the
//! passphrases come from the secret backend via `secret::resolve_secret`;
//! otherwise (legacy/manual) nothing is preloaded and gpg falls back to an
//! interactive prompt. The historical `.common-seed` seed-file mechanism has
//! been removed (see docs/SECRETS.md §6/§8).

use crate::config::{Config, Secret};
use crate::procfs;
use crate::secret;
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Preset passphrases for all enrolled secret keys in the secret's gnupg home.
///
/// - Backend mode (`secret_backend` set + `tpm_gpg`): resolve each primary
///   key's passphrase from the backend and preset it (plus its subkeys) into
///   gpg-agent. Best-effort: individual failures are warnings.
/// - Otherwise (legacy/manual): no-op — gpg prompts interactively.
pub fn preset(cfg: &Config, secret: &Secret) -> Result<()> {
    if cfg.secret_backend.is_none() || !secret.tpm_gpg {
        // Legacy or manual mode: nothing to preload automatically.
        return Ok(());
    }

    let mnt = secret.mountpoint(&cfg.home);
    let keys = keys_with_keygrips(&mnt)?;
    if keys.is_empty() {
        eprintln!(
            "warning: gpg preset: no secret keys found for '{}'",
            secret.name
        );
        return Ok(());
    }

    let bin = preset_bin()?;
    let mut count = 0usize;
    for (fpr, grips) in &keys {
        let id = secret::gpg_id_tail(&secret.name, fpr);
        let pass = match secret::resolve_secret(cfg, "gpg", &id) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: gpg preset: {e:#}");
                continue;
            }
        };
        for g in grips {
            match run_preset(&bin, g, &pass) {
                Ok(()) => count += 1,
                Err(e) => eprintln!("warning: gpg preset failed for keygrip {g}: {e:#}"),
            }
        }
    }

    if count > 0 {
        println!("gpg: preset for {count} key(s)");
    }
    Ok(())
}

/// Re-preset passphrases for every currently-mounted secret that has
/// `gpg_preset` enabled.
///
/// Mounting a `gpg` secret kills the gpg-agent (`gpgconf --kill all`), which
/// wipes any passphrases preset for *other* already-mounted gpg volumes. After
/// such a restart we re-apply the preset for all mounted gpg secrets, so the
/// user is not prompted again for volumes they mounted earlier in the session.
pub fn preset_all(cfg: &Config) -> Result<()> {
    for secret in cfg.secrets.values() {
        if !secret.gpg_preset {
            continue;
        }
        let mnt = secret.mountpoint(&cfg.home);
        if !procfs::is_mounted(&mnt) {
            continue;
        }
        if let Err(e) = preset(cfg, secret) {
            eprintln!("warning: gpg preset failed for '{}': {e:#}", secret.name);
        }
    }
    Ok(())
}

/// Collect `(primary_fpr, [keygrip, ...])` pairs for every secret key in a gpg
/// home. Each primary key's list includes its own keygrip plus every subkey's
/// keygrip (they share the primary key's passphrase, which is what we preset).
fn keys_with_keygrips(home: &Path) -> Result<Vec<(String, Vec<String>)>> {
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--with-keygrip")
        .arg("--list-secret-keys")
        .output()
        .context("running gpg --list-secret-keys")?;
    if !out.status.success() {
        bail!("gpg --list-secret-keys failed for {}", home.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let mut keys: Vec<(String, Vec<String>)> = Vec::new();
    let mut cur: Option<(String, Vec<String>)> = None;
    let mut in_primary = false;
    let mut got_primary_fpr = false;

    for line in text.lines() {
        if line.starts_with("sec:") {
            if let Some(c) = cur.take() {
                keys.push(c);
            }
            in_primary = true;
            got_primary_fpr = false;
            cur = None;
        } else if line.starts_with("ssb:") {
            // Subkey block: its grips belong to the current primary key.
            in_primary = false;
        } else if line.starts_with("fpr:") && in_primary && !got_primary_fpr {
            if let Some(f) = line.split(':').nth(9) {
                cur = Some((f.to_string(), Vec::new()));
                got_primary_fpr = true;
            }
        } else if line.starts_with("grp:") {
            let Some((_, grips)) = cur.as_mut() else {
                continue;
            };
            let Some(g) = line.split(':').nth(9) else {
                continue;
            };
            if !g.is_empty() && !grips.iter().any(|x| x == g) {
                grips.push(g.to_string());
            }
        }
    }
    if let Some(c) = cur.take() {
        keys.push(c);
    }
    Ok(keys)
}

/// List primary (master) key fingerprints in a gpg home.
///
/// Used by `install` to discover which keys to enroll. Returns the field-9
/// fingerprint of each `sec` record — one per primary key. Subkeys (`ssb`) are
/// skipped because they share the primary key's passphrase.
pub fn list_primary_fprs(home: &Path) -> Result<Vec<String>> {
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--list-secret-keys")
        .output()
        .context("running gpg --list-secret-keys")?;
    if !out.status.success() {
        bail!("gpg --list-secret-keys failed for {}", home.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fprs = Vec::new();
    let mut in_sec = false;
    for line in text.lines() {
        if line.starts_with("sec:") {
            in_sec = true;
        } else if line.starts_with("ssb:") {
            in_sec = false;
        } else if line.starts_with("fpr:") && in_sec {
            if let Some(f) = line.split(':').nth(9) {
                fprs.push(f.to_string());
            }
            in_sec = false;
        }
    }
    Ok(fprs)
}

/// Locate `gpg-preset-passphrase` (lives in gpg's libexecdir).
fn preset_bin() -> Result<PathBuf> {
    let out = Command::new("gpgconf")
        .arg("--list-dirs")
        .arg("libexecdir")
        .output()
        .context("running gpgconf --list-dirs")?;
    if !out.status.success() {
        bail!("gpgconf --list-dirs failed");
    }
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bin = Path::new(&dir).join("gpg-preset-passphrase");
    if !bin.is_file() {
        bail!("gpg-preset-passphrase not found at {}", bin.display());
    }
    Ok(bin)
}

/// Feed the passphrase to `gpg-preset-passphrase --preset <keygrip>` via stdin.
fn run_preset(bin: &Path, keygrip: &str, passphrase: &[u8]) -> Result<()> {
    let mut child = Command::new(bin)
        .arg("--preset")
        .arg(keygrip)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("spawning gpg-preset-passphrase")?;
    {
        let mut stdin = child.stdin.take().context("gpg-preset-passphrase stdin")?;
        stdin.write_all(passphrase)?;
        // stdin dropped here -> EOF
    }
    let status = child.wait()?;
    if !status.success() {
        bail!("gpg-preset-passphrase exited with {status}");
    }
    Ok(())
}
