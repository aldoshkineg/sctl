//! Shared GnuPG test fixture: an isolated GNUPGHOME with several master keys
//! (each carrying `sign` + `auth`/ssh subkeys).
//!
//! Shells out to the system `gpg` binary. The
//! helpers are gated behind [`have_gpg`]; when `gpg` is missing the calling
//! test skips instead of failing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// One discovered GnuPG primary (master) key.
pub struct GpgKey {
    pub fpr: String,
    pub has_sign: bool,
    pub has_auth: bool,
}

/// An isolated GnuPG home containing generated master keys.
pub struct GpgHome {
    // `TempDir` is held only to own the directory for the fixture's lifetime;
    // it is never read directly, hence the underscore-prefixed name.
    pub _dir: TempDir,
    pub home: PathBuf,
    pub keys: Vec<GpgKey>,
}

fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Public gate: is the `gpg` binary available for fixtures/tests?
pub fn have_gpg() -> bool {
    have("gpg")
}

/// Public gate: is the `ssh-keygen` binary available for fixtures/tests?
pub fn have_ssh() -> bool {
    have("ssh-keygen")
}

/// Generate `n` ssh key pairs (ed25519) at an explicit `dir` path (used by e2e
/// tests where the directory must live exactly at a secret's mountpoint), all
/// sharing `pass`. Mirrors [`gen_gpg_home_at`]'s intent for ssh.
pub fn gen_ssh_home_at(dir: &std::path::Path, n: usize, pass: &str) {
    assert!(
        have_ssh(),
        "ssh-keygen binary not found; fixture unavailable"
    );
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    for i in 0..n {
        let name = format!("id_ed25519_{i}");
        let mut c = Command::new("ssh-keygen");
        c.args(["-t", "ed25519", "-f"])
            .arg(dir.join(&name))
            .args(["-N", pass, "-C", &name]);
        let out = c.output().expect("spawn ssh-keygen");
        assert!(
            out.status.success(),
            "ssh-keygen failed for {name}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn gpg(home: &PathBuf) -> Command {
    let mut c = Command::new("gpg");
    c.arg("--homedir").arg(home).arg("--batch");
    c
}

fn run(home: &PathBuf, args: &[&str]) {
    let mut c = gpg(home);
    c.args(args);
    let out = c.output().expect("spawn gpg");
    assert!(
        out.status.success(),
        "gpg {:?} failed:\n{}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// List `--with-colons` output for the secret keys in `home`.
fn list_colons(home: &PathBuf) -> String {
    let mut c = gpg(home);
    c.args(["--with-colons", "--list-secret-keys"]);
    let out = c.output().expect("spawn gpg");
    assert!(out.status.success(), "gpg list failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Parse primary fprs (one per `sec` record).
fn primary_fprs(home: &PathBuf) -> Vec<String> {
    let text = list_colons(home);
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with("sec") {
            continue;
        }
        let Some(fpr_line) = lines.get(i + 1) else {
            continue;
        };
        if !fpr_line.starts_with("fpr:") {
            continue;
        }
        let f = fpr_line.split(':').nth(9).unwrap_or("").to_string();
        if !f.is_empty() {
            out.push(f);
        }
    }
    out
}

/// Discover all master keys with their subkey capabilities.
fn collect_keys(home: &PathBuf) -> Vec<GpgKey> {
    let text = list_colons(home);
    let mut keys: Vec<GpgKey> = Vec::new();
    let mut cur: Option<GpgKey> = None;
    for line in text.lines() {
        if line.starts_with("sec") {
            if let Some(k) = cur.take() {
                keys.push(k);
            }
            cur = Some(GpgKey {
                fpr: String::new(),
                has_sign: false,
                has_auth: false,
            });
            continue;
        }
        if line.starts_with("ssb") {
            let usage = line.split(':').nth(11).unwrap_or("");
            if let Some(k) = cur.as_mut() {
                if usage.contains('s') {
                    k.has_sign = true;
                }
                if usage.contains('a') {
                    k.has_auth = true;
                }
            }
            continue;
        }
        if !line.starts_with("fpr") {
            continue;
        }
        let Some(k) = cur.as_mut() else {
            continue;
        };
        if !k.fpr.is_empty() {
            continue;
        }
        k.fpr = line
            .trim_end_matches(':')
            .split(':')
            .nth(9)
            .unwrap_or("")
            .to_string();
    }
    if let Some(k) = cur.take() {
        keys.push(k);
    }
    keys
}

/// Generate a gpg home at an explicit `home` path (used by e2e tests where the
/// home must live exactly at a secret's mountpoint). Same key layout as
/// [`gen_gpg_home`]: `n` RSA primary keys, each carrying a `sign` and an
/// `auth` (ssh) subkey — a real primary/subkey hierarchy. All keys share `pass`.
pub fn gen_gpg_home_at(home: &PathBuf, n: usize, pass: &str) {
    assert!(have_gpg(), "gpg binary not found; fixture unavailable");
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        home.join("gpg-agent.conf"),
        "allow-loopback-pinentry\nallow-preset-passphrase\n",
    )
    .unwrap();
    fs::write(home.join("gpg.conf"), "pinentry-mode loopback\n").unwrap();

    for i in 0..n {
        let uid = format!("Test User {i} <test{i}@example.com>");
        // Primary: cert+sign.
        run(
            home,
            &[
                "--yes",
                "--pinentry-mode=loopback",
                "--passphrase",
                pass,
                "--quick-generate-key",
                &uid,
                "rsa3072",
                "sign,cert",
                "0",
            ],
        );
        let fpr = primary_fprs(home).pop().expect("primary fpr");
        // sign subkey
        run(
            home,
            &[
                "--yes",
                "--pinentry-mode=loopback",
                "--passphrase",
                pass,
                "--quick-add-key",
                &fpr,
                "rsa2048",
                "sign",
                "0",
            ],
        );
        // auth (ssh) subkey
        run(
            home,
            &[
                "--yes",
                "--pinentry-mode=loopback",
                "--passphrase",
                pass,
                "--quick-add-key",
                &fpr,
                "rsa2048",
                "auth",
                "0",
            ],
        );
    }
}

/// Create an isolated GNUPGHOME with `n` master RSA keys, each carrying a
/// `sign` subkey and an `auth` (ssh) subkey. All keys share `pass`.
pub fn gen_gpg_home(n: usize, pass: &str) -> GpgHome {
    let dir = TempDir::new().expect("tempdir");
    let home = dir.path().join("gnupg");
    gen_gpg_home_at(&home, n, pass);
    let keys = collect_keys(&home);
    GpgHome {
        _dir: dir,
        home,
        keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture itself: 5 primaries, each with sign + auth subkeys.
    #[test]
    fn fixture_builds_gpg_hierarchy() {
        if !have_gpg() {
            eprintln!("skipping: gpg not available");
            return;
        }
        let home = gen_gpg_home(5, "fixture-pass");
        assert!(home.home.exists(), "gpg home dir must exist");
        assert_eq!(home.keys.len(), 5, "expected 5 primary keys");
        for k in &home.keys {
            assert!(k.has_sign, "primary must carry a sign subkey");
            assert!(k.has_auth, "primary must carry an auth subkey");
        }
    }

    /// The ssh fixture: `n` key pairs, all sharing one passphrase.
    #[test]
    fn fixture_builds_ssh_home() {
        if !have_ssh() {
            eprintln!("skipping: ssh-keygen not available");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ssh");
        gen_ssh_home_at(&p, 3, "fixture-ssh-pass");
        assert!(p.join("id_ed25519_0").is_file(), "ssh key 0 missing");
        assert!(p.join("id_ed25519_0.pub").is_file(), "ssh pub 0 missing");
        assert!(p.join("id_ed25519_2").is_file(), "ssh key 2 missing");

        // The lib's discovery must see the generated keys (and ignore .pub).
        let keys = sctl::ssh::keys_in_dir(&p).unwrap();
        assert_eq!(keys.len(), 3, "expected 3 ssh private keys");
        for k in &keys {
            assert!(k.fingerprint.starts_with("SHA256:"));
        }
    }
}
