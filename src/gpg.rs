//! First-class gpg secret-key preloading into gpg-agent after a mount.
//!
//! After the `.gnupg` container is mounted, sctl can read the secret-key
//! keygrips and preset them into the (freshly started) gpg-agent via
//! `gpg-preset-passphrase`, so the user is not prompted on every mount.
//!
//! The credential is read from a stealthily-named seed file that normally
//! lives *inside* the encrypted volume (so it only exists while mounted) and
//! is zeroed in memory after use. Only a single line (12th from the end) is
//! taken, and its trailing `-word` is dropped, so the file can double as
//! ordinary notes without ever spelling out the real secret in plaintext.

use crate::config::{Config, Secret, expand_tilde};
use crate::procfs;
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
            "warning: gpg preset: seed file missing for '{}'",
            secret.name
        );
        return Ok(());
    }

    // Zeroizing guarantees the buffer is wiped on drop (even on early return),
    // using volatile writes the compiler is not allowed to elide.
    let raw = std::fs::read(&pf).with_context(|| format!("reading seed file {}", pf.display()))?;
    let passphrase = extract_secret(&raw);

    let keygrips = keygrips(&mnt)?;
    if keygrips.is_empty() {
        eprintln!(
            "warning: gpg preset: no secret keys found for '{}'",
            secret.name
        );
        return Ok(());
    }
    let bin = preset_bin()?;
    let mut count = 0;
    for kg in &keygrips {
        match run_preset(&bin, kg, &passphrase) {
            Ok(()) => count += 1,
            Err(e) => eprintln!("warning: gpg preset failed for keygrip {kg}: {e:#}"),
        }
    }

    if count > 0 {
        println!("gpg: preset for {count} key(s)");
    }
    Ok(())
}

/// Derive the actual credential from a seed file.
///
/// The secret lives on the **12th line from the end** of the file, and the
/// trailing `-word` is dropped. For example, a line `words-planet-plant-next`
/// yields `words-planet-plant`. This lets the file masquerade as ordinary
/// notes while never spelling out the real secret verbatim.
///
/// The returned buffer is `Zeroizing` and wiped on drop.
fn extract_secret(raw: &[u8]) -> Zeroizing<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    let lines: Vec<&str> = text.lines().collect();
    // 1st from end = last line, so 12th from end = index len-12.
    let idx = lines.len().saturating_sub(12);
    let line = lines.get(idx).copied().unwrap_or("").trim();
    // Take the last whitespace-delimited word, then drop its final `-word`.
    let word = line.split_whitespace().last().unwrap_or("");
    let secret = match word.rfind('-') {
        Some(i) => &word[..i],
        None => word,
    };
    Zeroizing::new(secret.as_bytes().to_vec())
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

/// Resolve the seed file: config value (absolute, ~, or relative to the
/// mountpoint), defaulting to `<mnt>/.common-seed`.
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
        None => mnt.join(".common-seed"),
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
