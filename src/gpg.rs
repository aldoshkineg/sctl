//! First-class gpg secret-key preloading into gpg-agent after a mount.
//!
//! After the `.gnupg` container is mounted, sctl can preset the secret-key
//! passphrases for every enrolled primary key into the (freshly started)
//! gpg-agent via `gpg-preset-passphrase`, so the user is not prompted on every
//! mount.
//!
//! In backend mode the passphrases come from the secret backend via
//! `secret::resolve_secret` for each secret that opts in with `gpg_preset`;
//! secrets without `gpg_preset` are left for gpg to prompt interactively.

use crate::config::{Config, Secret};
use crate::procfs;
use crate::secret;
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Preset passphrases for all enrolled secret keys in the secret's gnupg home.
///
/// - With `gpg_preset`: resolve each primary key's passphrase from the backend
///   and preset it (plus its subkeys) into gpg-agent. Best-effort: individual
///   failures are warnings.
/// - Without `gpg_preset`: no-op — gpg prompts interactively.
pub fn preset(cfg: &Config, secret: &Secret) -> Result<()> {
    if !secret.gpg_preset {
        // Not backend-managed: nothing to preload automatically.
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

    // Load the whole backend map once; only keys actually enrolled are preset.
    // Keys the user skipped at `install` are simply absent from the map and are
    // silently left for gpg to prompt on demand.
    let map = secret::resolve_all(cfg)?;
    let bin = preset_bin()?;
    let mut count = 0usize;
    for (fpr, _uid, grips) in &keys {
        let id = secret::composite_key("gpg", &secret::gpg_id_tail(&secret.name, fpr));
        let Some(pass) = map.get(&id) else {
            continue; // not enrolled (skipped at install)
        };
        for g in grips {
            match run_preset(&bin, g, pass.as_slice()) {
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
        // Preload a secret if it opts into preset, or if it is backend-managed
        // (gpg_preset): this gpg home is managed by the secret backend, so
        // `install` enrolls its passphrase and `mount` preloads it; the
        // mechanism (tpm or escrow) is selected by `secret_backend`.
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

/// Collect `(primary_fpr, primary_uid, [keygrip, ...])` triples for every
/// secret key in a gpg home. Each primary key's list includes its own keygrip
/// plus every subkey's keygrip (they share the primary key's passphrase, which
/// is what we preset). `primary_uid` is the key's first user-id
/// (`Name <email>`), used for human-readable prompts during `install`.
pub fn keys_with_keygrips(home: &Path) -> Result<Vec<(String, String, Vec<String>)>> {
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

    let mut keys: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut cur: Option<(String, Option<String>, Vec<String>)> = None;
    let mut pending_uid: Option<String> = None;
    let mut in_primary = false;
    let mut got_primary_fpr = false;

    for line in text.lines() {
        if line.starts_with("sec:") {
            if let Some(c) = cur.take() {
                keys.push(to_triple(c));
            }
            in_primary = true;
            got_primary_fpr = false;
            cur = None;
            pending_uid = None;
        } else if line.starts_with("ssb:") {
            // Subkey block: its grips belong to the current primary key.
            in_primary = false;
        } else if line.starts_with("uid:") && in_primary {
            let Some(u) = line.split(':').nth(9) else {
                continue;
            };
            if u.is_empty() {
                continue;
            }
            match cur.as_mut() {
                Some((_, uid @ None, _)) => *uid = Some(u.to_string()),
                Some(_) => {}
                None => pending_uid = Some(u.to_string()),
            }
        } else if line.starts_with("fpr:") && in_primary && !got_primary_fpr {
            if let Some(f) = line.split(':').nth(9) {
                let uid = pending_uid.take();
                cur = Some((f.to_string(), uid, Vec::new()));
                got_primary_fpr = true;
            }
        } else if line.starts_with("grp:") {
            let Some((_, _, grips)) = cur.as_mut() else {
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
        keys.push(to_triple(c));
    }
    Ok(keys)
}

/// Finalize a `(fpr, Option<uid>, grips)` accumulator into a `(fpr, uid, grips)`
/// triple, defaulting a missing uid to an empty string.
fn to_triple(c: (String, Option<String>, Vec<String>)) -> (String, String, Vec<String>) {
    (c.0, c.1.unwrap_or_default(), c.2)
}

/// Verify a gpg key passphrase for real: cache the candidate via
/// `gpg-preset-passphrase` and then export the secret key through the agent.
/// `gpg-preset-passphrase --preset` alone only *caches* the passphrase (a typo
/// is accepted silently), so we must exercise the key: exporting the secret key
/// forces the agent to decrypt it with the cached passphrase, which fails on a
/// wrong passphrase. On success the passphrase is left cached (avoids a later
/// prompt). `fpr` selects the key; `keygrip` is the primary key's grip to cache.
pub fn verify_passphrase(home: &Path, fpr: &str, keygrip: &str, passphrase: &[u8]) -> Result<()> {
    Command::new("gpgconf")
        .arg("--homedir")
        .arg(home)
        .arg("--launch")
        .arg("gpg-agent")
        .output()
        .context("launching gpg-agent")?;
    let bin = preset_bin()?;
    run_preset(&bin, keygrip, passphrase)?;

    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .arg("--batch")
        .arg("--yes")
        .arg("--output")
        .arg("/dev/null")
        .arg("--export-secret-keys")
        .arg(fpr)
        .output()
        .context("running gpg to verify the passphrase")?;
    if !out.status.success() {
        bail!(
            "gpg passphrase verification failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
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
