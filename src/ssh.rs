//! First-class ssh secret-key preloading into ssh-agent after a mount.
//!
//! Mirrors [`crate::gpg`]: after the secret's cleartext directory (e.g. `~/.ssh`)
//! is mounted, sctl can preset the enrolled key passphrases into `ssh-agent` via
//! `ssh-add`, so the user is never prompted on mount.
//!
//! In backend mode the passphrases come from the secret backend via
//! `secret::resolve_secret` for each secret that opts in with `ssh_preset`;
//! secrets without `ssh_preset` are left for ssh to prompt interactively.
//!
//! Key identity is the stable `SHA256:...` fingerprint from `ssh-keygen -l`
//! (independent of the passphrase), so re-enrolling after a passphrase change
//! keeps the same map key.

use crate::config::{Config, Secret};
use crate::secret;
use anyhow::{Context, Result, bail};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One discovered ssh private key in a directory.
#[derive(Debug)]
pub struct SshKey {
    /// Stable `SHA256:...` fingerprint (from `ssh-keygen -l`).
    pub fingerprint: String,
    /// Key comment (`-C`), for human-readable prompts at `install`.
    pub comment: String,
    /// Absolute path to the private key file.
    pub path: PathBuf,
}

/// Collect every ssh private key in `dir` as `(fingerprint, comment, path)`.
///
/// Files are probed with `ssh-keygen -l -f`; only those that report a valid
/// private-key fingerprint are returned. Public keys (`*.pub`), `known_hosts`,
/// `authorized_keys`, `config` and other non-key files are skipped, so a real
/// `~/.ssh` can be scanned directly.
pub fn keys_in_dir(dir: &Path) -> Result<Vec<SshKey>> {
    let mut out = Vec::new();
    let mut entries =
        std::fs::read_dir(dir).with_context(|| format!("reading ssh dir {}", dir.display()))?;
    while let Some(entry) = entries.next().transpose()? {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_non_key(name) {
            continue;
        }
        let Some(key) = inspect_key(&path)? else {
            continue; // not a private key (public file, config, etc.)
        };
        out.push(key);
    }
    Ok(out)
}

/// Names that are never ssh private keys; skip them before probing.
fn is_non_key(name: &str) -> bool {
    if name.ends_with(".pub")
        || name.ends_with(".crt")
        || name.ends_with(".cert")
        || name.ends_with(".old")
        || name.ends_with(".bak")
    {
        return true;
    }
    matches!(
        name,
        "known_hosts"
            | "known_hosts2"
            | "authorized_keys"
            | "authorized_keys2"
            | "config"
            | "rc"
            | "environment"
            | "id_ed25519_sk"
    )
}

/// Probe `path` with `ssh-keygen -l -f` and, if it is a private key, return its
/// `(fingerprint, comment, path)`. Non-keys (or unreadable files) yield `None`.
fn inspect_key(path: &Path) -> Result<Option<SshKey>> {
    let out = Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(path)
        .output()
        .context("running ssh-keygen -l")?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Format: "<bits> <SHA256:...> <comment> (<type>)"
    let mut fields = text.split_whitespace();
    let _bits = fields.next();
    let Some(fpr) = fields.next() else {
        return Ok(None);
    };
    if !fpr.starts_with("SHA256:") {
        return Ok(None);
    }
    let comment = fields.next().unwrap_or("").to_string();
    Ok(Some(SshKey {
        fingerprint: fpr.to_string(),
        comment,
        path: path.to_path_buf(),
    }))
}

/// Verify an ssh key passphrase for real: extract the public key through
/// `ssh-keygen -y` with the candidate passphrase. A wrong passphrase fails the
/// command (so a typo is caught at `install`, not at the next `mount`). The
/// passphrase is passed via `-P` on the command line here (the only ssh-keygen
/// interface for passphrase verification); `install` itself receives it through
/// `--ssh-pass` and never prints it.
pub fn verify_passphrase(_dir: &Path, key_path: &Path, passphrase: &[u8]) -> Result<()> {
    let pass = std::str::from_utf8(passphrase).context("ssh passphrase is not valid UTF-8")?;
    let out = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-P")
        .arg(pass)
        .arg("-f")
        .arg(key_path)
        .output()
        .with_context(|| format!("running ssh-keygen -y for {}", key_path.display()))?;
    if !out.status.success() {
        bail!(
            "ssh passphrase verification failed for {}:\n{}",
            key_path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Preset passphrases for all enrolled ssh keys into `ssh-agent`.
///
/// - With `ssh_preset`: resolve each key's passphrase from the backend and add
///   the key to `ssh-agent` (via `ssh-add`, passphrase fed through
///   `SSH_ASKPASS`). Best-effort: individual failures are warnings.
/// - Without `ssh_preset`: no-op — ssh prompts interactively.
/// - When `SSH_AUTH_SOCK` is unset, ssh-agent is unavailable; we skip with a
///   warning (the mount still succeeds).
pub fn preset(cfg: &Config, secret: &Secret) -> Result<()> {
    if !secret.ssh_preset {
        return Ok(());
    }
    let Some(sock) = ssh_auth_sock() else {
        eprintln!(
            "warning: ssh preset: SSH_AUTH_SOCK not set; skipping ssh agent preload for '{}'",
            secret.name
        );
        return Ok(());
    };

    let mnt = secret.mountpoint(&cfg.home);
    let keys = match keys_in_dir(&mnt) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("warning: ssh preset: {}", e);
            return Ok(());
        }
    };
    if keys.is_empty() {
        eprintln!(
            "warning: ssh preset: no ssh keys found for '{}' at {}",
            secret.name,
            mnt.display()
        );
        return Ok(());
    }

    let map = secret::resolve_all(cfg)?;
    let mut count = 0usize;
    for key in &keys {
        let id = secret::composite_key("ssh", &secret::ssh_id_tail(&secret.name, &key.fingerprint));
        let Some(pass) = map.get(&id) else {
            continue; // not enrolled (skipped at install)
        };
        match run_add(&key.path, pass.as_slice(), &sock) {
            Ok(()) => count += 1,
            Err(e) => eprintln!(
                "warning: ssh preset failed for {} ({}): {e:#}",
                key.fingerprint, key.comment
            ),
        }
    }

    if count > 0 {
        println!("ssh: added {count} key(s) to agent");
    }
    Ok(())
}

/// The ssh-agent socket from `SSH_AUTH_SOCK`, if set.
fn ssh_auth_sock() -> Option<PathBuf> {
    std::env::var_os("SSH_AUTH_SOCK")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Add `key_path` to `ssh-agent`, supplying `passphrase` via the `SSH_ASKPASS`
/// mechanism (there is no stdin/argument passphrase API for `ssh-add`). The
/// passphrase is passed through an environment variable to a throwaway askpass
/// script, so it never lands in a command line or on-disk file.
fn run_add(key_path: &Path, passphrase: &[u8], sock: &Path) -> Result<()> {
    let pass = std::str::from_utf8(passphrase).context("ssh passphrase is not valid UTF-8")?;

    let script = tempfile::Builder::new()
        .prefix("sctl-askpass-")
        .suffix(".sh")
        .tempfile()
        .context("creating ssh askpass script")?;
    std::fs::write(
        script.path(),
        "#!/bin/sh\nexec printf '%s\\n' \"$SCTL_SSH_PASS\"\n",
    )
    .context("writing ssh askpass script")?;
    let mut perms = std::fs::metadata(script.path())?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(script.path(), perms)?;

    let status = Command::new("ssh-add")
        .arg(key_path)
        .env("SSH_ASKPASS", script.path())
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .env("SSH_AUTH_SOCK", sock)
        .env("SCTL_SSH_PASS", pass)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("spawning ssh-add")?;
    if !status.success() {
        bail!("ssh-add exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command as ProcCommand;

    fn have_ssh() -> bool {
        ProcCommand::new("ssh-keygen")
            .arg("--help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn gen_key(dir: &Path, name: &str, pass: &str) {
        let mut c = ProcCommand::new("ssh-keygen");
        c.args(["-t", "ed25519", "-f"])
            .arg(dir.join(name))
            .args(["-N", pass, "-C", name]);
        let out = c.output().expect("spawn ssh-keygen");
        assert!(
            out.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn discovers_and_verifies_keys() {
        if !have_ssh() {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::create_dir_all(p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();

        gen_key(p, "id_ed25519_a", "topsecret");
        gen_key(p, "id_ed25519_b", "otherpass");

        let keys = keys_in_dir(p).unwrap();
        assert_eq!(keys.len(), 2, "expected 2 private keys:\n{keys:?}");
        for k in &keys {
            assert!(k.fingerprint.starts_with("SHA256:"));
            // Wrong passphrase (the fingerprint bytes) must fail verification.
            assert!(verify_passphrase(p, &k.path, k.fingerprint.as_bytes()).is_err());
        }

        // Correct passphrase verifies; wrong one fails.
        let a = keys.iter().find(|k| k.comment == "id_ed25519_a").unwrap();
        assert!(verify_passphrase(p, &a.path, b"topsecret").is_ok());
        assert!(verify_passphrase(p, &a.path, b"wrong").is_err());

        // Public key and config files must be ignored.
        fs::write(p.join("config"), "Host *\n").unwrap();
        fs::write(p.join("known_hosts"), "example.com\n").unwrap();
        let keys2 = keys_in_dir(p).unwrap();
        assert_eq!(keys2.len(), 2, "non-key files must be skipped");
    }
}
