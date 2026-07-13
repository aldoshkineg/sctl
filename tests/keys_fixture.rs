//! Key-generation fixtures: several GnuPG master keys with sign + ssh (auth)
//! subkeys (via the shared `common` module), and a set of SSH keys in multiple
//! formats generated locally below.

mod common;

use common::gen_gpg_home;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn gpg_master_keys_have_sign_and_auth_subkeys() {
    if !common::have_gpg() {
        eprintln!("gpg not present; skipping gpg fixture test");
        return;
    }
    let home = gen_gpg_home(2, "fixture-passphrase");
    assert!(home.home.is_dir());
    assert_eq!(home.keys.len(), 2, "expected 2 master keys");

    for k in &home.keys {
        assert!(!k.fpr.is_empty(), "empty fingerprint");
        assert!(
            k.has_sign,
            "master key {} is missing a 'sign' subkey",
            k.fpr
        );
        assert!(
            k.has_auth,
            "master key {} is missing an 'auth' (ssh) subkey",
            k.fpr
        );
    }
}

/// One generated SSH key.
struct SshKey {
    key_type: &'static str,
    private: PathBuf,
    public: PathBuf,
}

/// An isolated directory containing generated SSH keys.
struct SshDir {
    // `TempDir` is held only for the directory's lifetime; never read directly.
    _dir: TempDir,
    keys: Vec<SshKey>,
}

fn have_ssh() -> bool {
    Command::new("ssh-keygen")
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn ssh_keys_in_multiple_formats() {
    if !have_ssh() {
        eprintln!("ssh-keygen not present; skipping ssh fixture test");
        return;
    }
    let ssh = gen_ssh_dir("fixture-passphrase");
    let types: Vec<&str> = ssh.keys.iter().map(|k| k.key_type).collect();

    assert!(types.contains(&"rsa"), "missing rsa key");
    assert!(types.contains(&"ecdsa"), "missing ecdsa key");
    assert!(types.contains(&"ed25519"), "missing ed25519 key");

    for k in &ssh.keys {
        assert!(k.private.is_file(), "private key missing: {:?}", k.private);
        assert!(k.public.is_file(), "public key missing: {:?}", k.public);
        // Verify the passphrase actually unlocks the key.
        let out = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-P")
            .arg("fixture-passphrase")
            .arg("-f")
            .arg(&k.private)
            .output()
            .expect("spawn ssh-keygen -y");
        assert!(
            out.status.success(),
            "ssh-keygen -y failed for {}: {}",
            k.key_type,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Create an isolated directory with RSA, ECDSA and Ed25519 SSH keys (all
/// sharing `pass`).
fn gen_ssh_dir(pass: &str) -> SshDir {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().to_path_buf();
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

    let specs: &[(&str, &str, &str)] = &[
        ("rsa", "4096", "id_rsa"),
        ("ecdsa", "521", "id_ecdsa"),
        ("ed25519", "", "id_ed25519"),
    ];

    let mut keys = Vec::new();
    for (t, bits, name) in specs {
        let private = path.join(name);
        let mut c = Command::new("ssh-keygen");
        c.arg("-t").arg(t);
        if !bits.is_empty() {
            c.arg("-b").arg(bits);
        }
        c.args(["-f", private.to_str().unwrap(), "-N", pass, "-C", name]);
        let out = c.output().expect("spawn ssh-keygen");
        assert!(
            out.status.success(),
            "ssh-keygen -t {t} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let public = private.with_extension("pub");
        keys.push(SshKey {
            key_type: t,
            private,
            public,
        });
    }
    SshDir { _dir: dir, keys }
}
