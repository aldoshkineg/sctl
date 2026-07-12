//! Shared GnuPG test fixture: an isolated GNUPGHOME with several master keys
//! (each carrying `sign` + `auth`/ssh subkeys).
//!
//! Shells out to the system `gpg` binary (per docs/SECRETS.md §12). The
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

/// Create an isolated GNUPGHOME with `n` master RSA keys, each carrying a
/// `sign` subkey and an `auth` (ssh) subkey. All keys share `pass`.
pub fn gen_gpg_home(n: usize, pass: &str) -> GpgHome {
    assert!(have_gpg(), "gpg binary not found; fixture unavailable");
    let dir = TempDir::new().expect("tempdir");
    let home = dir.path().join("gnupg");
    fs::create_dir_all(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
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
            &home,
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
        let fpr = primary_fprs(&home).pop().expect("primary fpr");
        // sign subkey
        run(
            &home,
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
            &home,
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

    let keys = collect_keys(&home);
    GpgHome {
        _dir: dir,
        home,
        keys,
    }
}
