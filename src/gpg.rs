//! First-class gpg passphrase preloading into gpg-agent after a mount.
//!
//! After the `.gnupg` container is mounted, sctl can read the secret-key
//! keygrips and preset their passphrase into the (freshly started) gpg-agent
//! via `gpg-preset-passphrase`, so the user is not prompted on every mount.
//!
//! The passphrase is read from a file that normally lives *inside* the
//! encrypted volume (so it only exists while mounted) and is zeroed in memory
//! after use.

use crate::config::{Config, Secret, expand_tilde};
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// Preset passphrases for all secret keys in the secret's gnupg home.
/// Best-effort: individual failures are reported as warnings, not fatal.
pub fn preset(cfg: &Config, secret: &Secret) -> Result<()> {
    let mnt = secret.mountpoint(&cfg.home);
    let pf = passphrase_file(cfg, secret, &mnt);
    if !pf.is_file() {
        eprintln!(
            "warning: gpg_preset enabled for '{}' but passphrase file not found: {}",
            secret.name,
            pf.display()
        );
        return Ok(());
    }

    // Zeroizing guarantees the buffer is wiped on drop (even on early return),
    // using volatile writes the compiler is not allowed to elide.
    let mut passphrase = Zeroizing::new(
        std::fs::read(&pf).with_context(|| format!("reading passphrase file {}", pf.display()))?,
    );
    while matches!(passphrase.last(), Some(b'\n' | b'\r')) {
        passphrase.pop();
    }

    let keygrips = keygrips(&mnt)?;
    if keygrips.is_empty() {
        eprintln!(
            "warning: gpg_preset: no secret-key keygrips found for '{}'",
            secret.name
        );
        return Ok(());
    }
    let bin = preset_bin()?;
    let mut count = 0;
    for kg in &keygrips {
        match run_preset(&bin, kg, &passphrase) {
            Ok(()) => count += 1,
            Err(e) => eprintln!("warning: gpg_preset failed for keygrip {kg}: {e:#}"),
        }
    }

    if count > 0 {
        println!("gpg: preset passphrase for {count} key(s)");
    }
    Ok(())
}

/// Resolve the passphrase file: config value (absolute, ~, or relative to the
/// mountpoint), defaulting to `<mnt>/.gpg-passphrase`.
fn passphrase_file(cfg: &Config, secret: &Secret, mnt: &Path) -> PathBuf {
    match &secret.gpg_passphrase_file {
        Some(p) => {
            let expanded = expand_tilde(p, &cfg.home);
            if expanded.is_absolute() {
                expanded
            } else {
                mnt.join(p)
            }
        }
        None => mnt.join(".gpg-passphrase"),
    }
}

/// Collect secret-key keygrips from `gpg --with-keygrip --list-secret-keys`.
fn keygrips(mnt: &Path) -> Result<Vec<String>> {
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(mnt)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--with-keygrip")
        .arg("--list-secret-keys")
        .output()
        .context("running gpg --list-secret-keys")?;
    if !out.status.success() {
        bail!("gpg --list-secret-keys failed");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut grips: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.starts_with("grp:") {
            // grp record: grp:::::::::<KEYGRIP>:
            if let Some(g) = line.split(':').nth(9)
                && !g.is_empty()
                && !grips.iter().any(|x| x == g)
            {
                grips.push(g.to_string());
            }
        }
    }
    Ok(grips)
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
