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
            match run_preset(&bin, &mnt, g, pass.as_slice()) {
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
fn ensure_agent(home: &Path) {
    // Spawn (if not already running) a `gpg-agent` dedicated to `home` and point
    // `GNUPGHOME` at it, so subsequent `gpg` calls for that home talk to an agent
    // that actually serves it. Best-effort: failures are ignored because the
    // caller still works if the agent is already reachable another way.
    // `gpgconf --launch` honors GNUPGHOME, which we set to `home` so the spawned
    // agent actually serves this (non-default) homedir.
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", home)
        .arg("--launch")
        .arg("gpg-agent")
        .output();
}

pub fn keys_with_keygrips(home: &Path) -> Result<Vec<(String, String, Vec<String>)>> {
    // Discover secret keys WITHOUT consulting the gpg-agent. On runners that
    // ship a pre-started (default) gpg-agent, `gpg --list-secret-keys` asks that
    // agent which refuses to serve a custom homedir and reports no secret keys.
    // We instead read the *public* key listing (no agent needed) for the
    // primary/subkey structure and keygrips, then keep only the keygrips whose
    // secret material actually exists on disk in this home
    // (`private-keys-v1.d/<keygrip>.key`). This works on any machine/runner
    // regardless of a pre-existing agent.
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--with-keygrip")
        .arg("--list-keys")
        .output()
        .context("running gpg --list-keys")?;
    if !out.status.success() {
        bail!("gpg --list-keys failed for {}", home.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let private_dir = home.join("private-keys-v1.d");
    let has_secret = |g: &str| private_dir.join(format!("{g}.key")).exists();

    struct Prim {
        fpr: String,
        uid: String,
        grips: Vec<String>,
    }
    let mut prims: Vec<Prim> = Vec::new();
    let mut cur: Option<Prim> = None;
    let mut in_primary = false;
    let mut cur_fpr: Option<String> = None;

    for line in text.lines() {
        if line.starts_with("pub:") {
            if let Some(p) = cur.take() {
                prims.push(p);
            }
            in_primary = true;
            cur = Some(Prim {
                fpr: String::new(),
                uid: String::new(),
                grips: Vec::new(),
            });
        } else if line.starts_with("sub:") {
            in_primary = false;
        } else if line.starts_with("uid:") && in_primary {
            if let Some(u) = line.split(':').nth(9)
                && !u.is_empty()
                && let Some(p) = cur.as_mut()
                && p.uid.is_empty()
            {
                p.uid = u.to_string();
            }
        } else if line.starts_with("fpr:") {
            cur_fpr = line.split(':').nth(9).map(|s| s.to_string());
        } else if line.starts_with("grp:")
            && let (Some(fpr), Some(g)) = (cur_fpr.take(), line.split(':').nth(9))
            && !g.is_empty()
            && has_secret(g)
            && let Some(p) = cur.as_mut()
        {
            if in_primary && p.fpr.is_empty() {
                p.fpr = fpr;
            }
            p.grips.push(g.to_string());
        }
    }
    if let Some(p) = cur.take() {
        prims.push(p);
    }

    let keys: Vec<(String, String, Vec<String>)> = prims
        .into_iter()
        .filter(|p| !p.grips.is_empty())
        .map(|p| (p.fpr, p.uid, p.grips))
        .collect();
    Ok(keys)
}

/// Verify a gpg key passphrase for real: decrypt the secret key with the
/// candidate passphrase through loopback pinentry. This exercises the key
/// directly (so a typo fails) and needs no gpg-agent cache, which makes it work
/// for any homedir — including the non-default paths used in tests, where the
/// agent cache would not be consulted. The passphrase is written to a 0600 temp
/// file so it never appears on the command line. `fpr` selects the key;
/// `keygrip` is accepted for API symmetry but unused here.
pub fn verify_passphrase(home: &Path, fpr: &str, _keygrip: &str, passphrase: &[u8]) -> Result<()> {
    // Write the candidate passphrase to a 0600 temp file (never exposed via ps).
    let passfile =
        crate::passfile::from_bytes(passphrase).context("writing gpg passphrase to temp file")?;
    ensure_agent(home);
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(home)
        .env("GNUPGHOME", home)
        .arg("--batch")
        .arg("--yes")
        .arg("--pinentry-mode=loopback")
        .arg("--passphrase-file")
        .arg(passfile.path())
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
/// `GNUPGHOME` is set explicitly so the preset lands in the *same* agent that
/// the (custom-homedir) `gpg` export below talks to — otherwise the passphrase
/// would be cached in the default agent and the export would still prompt.
fn run_preset(bin: &Path, home: &Path, keygrip: &str, passphrase: &[u8]) -> Result<()> {
    let mut child = Command::new(bin)
        .arg("--preset")
        .arg(keygrip)
        .env("GNUPGHOME", home)
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
