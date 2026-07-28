//! Full end-to-end tests driving the real `sctl` binary through the secret
//! lifecycle: `install` -> `check` -> `mount` (from the enrolled backend) ->
//! `recovery` -> `umount`.
//!
//! `install` is fully non-interactive (so the binary can be exercised as a black
//! box): it reads `CRYPT_PASS` and `SCTL_MASTER_PASS` from the environment, takes
//! the gpg passphrase from `--gpg-pass NAME=PASSWORD` (verified via gpg-agent,
//! no tty — see `src/install.rs` / `src/passfile.rs`), and answers the "use
//! encryption for gpg keys?" prompt with `--yes`.
//!
//! Gating:
//! - The escrow `install`/`check`/`recovery` path needs no TPM or FUSE and runs
//!   in CI.
//! - The `mount`/`umount` steps need `gocryptfs` + `fusermount3`.
//! - The TPM variants need a TPM device (`/dev/tpmrm0`) and the `tss` group.

use assert_cmd::Command;
use base64::Engine;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

mod common;

/// Serialize gocryptfs-backed tests: parallel FUSE mounts are flaky.
static MOUNT_LOCK: Mutex<()> = Mutex::new(());

fn mount_guard() -> MutexGuard<'static, ()> {
    MOUNT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new(config: &str) -> Sandbox {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::create_dir_all(p.join("cfg/state")).unwrap();
        fs::create_dir_all(p.join("enc")).unwrap();
        fs::create_dir_all(p.join("runtime")).unwrap();
        let cfg = config.replace("$ENC", p.join("enc").to_str().unwrap());
        fs::write(p.join("cfg/config.toml"), cfg).unwrap();
        Sandbox { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Command with `CRYPT_PASS` set (used for `init` and non-backend paths).
    fn cmd(&self) -> Command {
        let mut c = self.base_cmd();
        c.env("CRYPT_PASS", "testpassword123");
        c
    }

    /// Command with `CRYPT_PASS` **unset** — proves the backend resolves the
    /// gocryptfs password instead of falling back to the env override.
    fn cmd_no_crypt(&self) -> Command {
        let mut c = self.base_cmd();
        c.env_remove("CRYPT_PASS");
        c
    }

    fn base_cmd(&self) -> Command {
        let p = self.dir.path();
        let mut c = Command::cargo_bin("sctl").unwrap();
        c.env("HOME", p)
            .env("SCTL_CONFIG", p.join("cfg/config.toml"))
            .env("SCTL_CONFIG_DIR", p.join("cfg"))
            .env("SCTL_STATE_DIR", p.join("cfg/state"))
            .env("XDG_RUNTIME_DIR", p.join("runtime"))
            .env("SCTL_COLOR", "never")
            .env("SCTL_MASTER_PASS", "test-master-pass");
        c
    }

    fn mnt(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

fn have_gocryptfs() -> bool {
    which("gocryptfs").is_some() && which("fusermount3").is_some()
}

fn is_mounted(p: &Path) -> bool {
    let content = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let target = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    content.lines().any(|l| {
        l.split_whitespace()
            .nth(4)
            .map(|mp| Path::new(mp) == target)
            .unwrap_or(false)
    })
}

fn tpm_available() -> bool {
    if !Path::new("/dev/tpmrm0").exists() {
        return false;
    }
    let gid = fs::read_to_string("/etc/group").ok().and_then(|g| {
        g.lines()
            .find(|l| l.starts_with("tss:"))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<u32>().ok())
    });
    let Some(gid) = gid else {
        return false;
    };
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Groups:"))
                .map(|l| l["Groups:".len()..].to_string())
        })
        .map(|g| g.split_whitespace().any(|x| x.parse::<u32>() == Ok(gid)))
        .unwrap_or(false)
}

const ESCROW_BASE: &str = r#"
[settings]
default_idle = "10m"
enc_root = "$ENC"
secret_backend = "escrow"

[secrets.vault]
path = ".vault"
"#;

const TPM_BASE: &str = r#"
[settings]
default_idle = "10m"
enc_root = "$ENC"
secret_backend = "tpm"

[secrets.vault]
path = ".vault"
"#;

/// `gpg_preset` variant of the escrow base: the secret's gpg home (`.gnupg`) is
/// generated with real keys by the test before `install`.
const GPG_BASE: &str = r#"
[settings]
default_idle = "10m"
enc_root = "$ENC"
secret_backend = "escrow"

[secrets.vault]
path = ".gnupg"
gpg_preset = true
"#;

/// Extract the base64 value for `key` from `sctl recovery` stdout.
fn recovery_value(stdout: &str, key: &str) -> String {
    stdout
        .lines()
        .find(|l| l.starts_with(key))
        .unwrap_or_else(|| panic!("recovery output missing {key}:\n{stdout}"))
        .split_once(" = ")
        .unwrap_or_else(|| panic!("malformed recovery line for {key}"))
        .1
        .to_string()
}

// --- escrow: install / check / recovery (no TPM, no FUSE) -----------------

#[test]
fn escrow_install_then_check_initialized() {
    let sb = Sandbox::new(ESCROW_BASE);
    sb.cmd().arg("install").assert().success();
    assert!(
        sb.path().join("cfg/sctl-escrow.age").is_file(),
        "escrow file written"
    );

    // After enrollment `check` must report the backend as healthy. The
    // "not initialized" volume warning is expected (we never ran `init`).
    sb.cmd()
        .arg("check")
        .assert()
        .success()
        .stdout(predicates::str::contains("vault"))
        .stdout(predicates::str::contains("escrow file present"))
        .stdout(predicates::str::contains("escrow decrypt self-test ok"));
}

#[test]
fn escrow_install_then_recovery_roundtrip() {
    let sb = Sandbox::new(ESCROW_BASE);
    sb.cmd().arg("install").assert().success();

    let out = sb
        .cmd()
        .args(["recovery", "--filter", "gocryptfs:"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    let b64 = recovery_value(&text, "gocryptfs:__shared__");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("recovery value is valid base64");
    assert_eq!(decoded, b"testpassword123");
}

#[test]
fn escrow_install_then_mount_resolves_from_backend() {
    if !have_gocryptfs() {
        eprintln!("skipping: gocryptfs/fusermount3 not installed");
        return;
    }
    let _guard = mount_guard();
    let sb = Sandbox::new(ESCROW_BASE);

    sb.cmd().args(["init", "vault"]).assert().success();
    assert!(sb.path().join("enc/vault/gocryptfs.conf").is_file());

    // Enroll the secret, then mount WITHOUT CRYPT_PASS: the password must come
    // from the escrow backend, not the env fallback.
    sb.cmd().arg("install").assert().success();
    sb.cmd_no_crypt()
        .args(["mount", "vault"])
        .assert()
        .success();
    assert!(is_mounted(&sb.mnt(".vault")));

    sb.cmd_no_crypt()
        .args(["umount", "vault"])
        .assert()
        .success();
    assert!(!is_mounted(&sb.mnt(".vault")));
}

// --- gpg_preset: non-interactive install via --gpg-pass --------------------

#[test]
fn gpg_preset_install_enrolls_all_keys() {
    if !common::have_gpg() {
        eprintln!("skipping: gpg not available");
        return;
    }
    // gpg 2.5 keeps a single global "flat" agent at /run/user/<uid>. The keys
    // below are generated into a *temporary* gpg home; if the ambient agent was
    // started under the real $HOME it refuses to serve a different homedir, so
    // `gpg --list-secret-keys` (used by `sctl install`) returns nothing and the
    // install fails. Killing the agent lets a fresh one spawn that serves this
    // sandbox's home. Best-effort: ignored if no agent is running.
    let _ = std::process::Command::new("gpgconf")
        .args(["--kill", "gpg-agent"])
        .output();
    let sb = Sandbox::new(GPG_BASE);
    // Generate a real gpg home at the secret's mountpoint: 5 primary keys, each
    // carrying sign + auth subkeys (a primary/subkey hierarchy). All share one
    // passphrase, as `--gpg-pass` supplies a single passphrase per gpg home.
    let gpg_pass = "gpg-top-secret";
    let gpg_home = sb.path().join(".gnupg");
    common::gen_gpg_home_at(&gpg_home, 5, gpg_pass);

    // Fully non-interactive: gocryptfs key via CRYPT_PASS, gpg passphrase via
    // --gpg-pass, master passphrase via SCTL_MASTER_PASS, confirm via --yes.
    sb.cmd()
        .args([
            "install",
            "--yes",
            "--gpg-pass",
            &format!("vault={gpg_pass}"),
        ])
        .assert()
        .success();

    // `recovery` must list one gpg entry per primary key (5) plus the shared
    // gocryptfs key — proving the passphrases were enrolled through the binary.
    let out = sb
        .cmd()
        .args(["recovery"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    let gpg_entries = text.lines().filter(|l| l.starts_with("gpg:vault:")).count();
    assert_eq!(gpg_entries, 5, "expected 5 gpg entries, got:\n{text}");
    assert!(
        text.lines().any(|l| l.starts_with("gocryptfs:__shared__")),
        "missing gocryptfs shared key:\n{text}"
    );
}

// --- tpm: install / check / recovery --------------------------------------

#[test]
fn tpm_install_then_check_initialized() {
    if !tpm_available() {
        eprintln!("skipping: TPM (with tss group) not available");
        return;
    }
    let sb = Sandbox::new(TPM_BASE);
    sb.cmd().arg("install").assert().success();
    assert!(
        sb.path().join("cfg/state/tpm/dek.priv").is_file(),
        "DEK sealed"
    );
    assert!(sb.path().join("cfg/state/tpm/dek.pub").is_file());
    assert!(sb.path().join("cfg/state/tpm/map.age").is_file());
    // TPM also writes an escrow backup for recovery.
    assert!(sb.path().join("cfg/sctl-escrow.age").is_file());

    sb.cmd()
        .arg("check")
        .assert()
        .success()
        .stdout(predicates::str::contains("vault"))
        .stdout(predicates::str::contains("TPM DEK and map present"))
        .stdout(predicates::str::contains("desync check ok"));
}

#[test]
fn tpm_install_then_recovery_roundtrip() {
    if !tpm_available() {
        eprintln!("skipping: TPM (with tss group) not available");
        return;
    }
    let sb = Sandbox::new(TPM_BASE);
    sb.cmd().arg("install").assert().success();

    let out = sb
        .cmd()
        .args(["recovery", "--filter", "gocryptfs:"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    let b64 = recovery_value(&text, "gocryptfs:__shared__");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("recovery value is valid base64");
    assert_eq!(decoded, b"testpassword123");
}

#[test]
fn tpm_install_then_mount_resolves_from_backend() {
    if !tpm_available() || !have_gocryptfs() {
        eprintln!("skipping: TPM (with tss group) and/or gocryptfs not available");
        return;
    }
    let _guard = mount_guard();
    let sb = Sandbox::new(TPM_BASE);

    sb.cmd().args(["init", "vault"]).assert().success();

    sb.cmd().arg("install").assert().success();
    sb.cmd_no_crypt()
        .args(["mount", "vault"])
        .assert()
        .success();
    assert!(is_mounted(&sb.mnt(".vault")));

    sb.cmd_no_crypt()
        .args(["umount", "vault"])
        .assert()
        .success();
    assert!(!is_mounted(&sb.mnt(".vault")));
}

/// Shared lifecycle: enroll the backend, mount a secret resolving the
/// gocryptfs password from the backend (no `CRYPT_PASS`), then verify `status`
/// reflects mounted/unmounted and `toggle` flips the mount state. `needs_tpm`
/// selects the TPM gating in addition to gocryptfs.
fn status_toggle_lifecycle(base: &str, needs_tpm: bool) {
    if !have_gocryptfs() || (needs_tpm && !tpm_available()) {
        eprintln!(
            "skipping: gocryptfs{} not available",
            if needs_tpm { " / TPM" } else { "" }
        );
        return;
    }
    let _guard = mount_guard();
    let sb = Sandbox::new(base);

    sb.cmd().args(["init", "vault"]).assert().success();
    sb.cmd().arg("install").assert().success();

    // Mount resolves the password from the backend, not CRYPT_PASS.
    sb.cmd_no_crypt()
        .args(["mount", "vault"])
        .assert()
        .success();
    assert!(is_mounted(&sb.mnt(".vault")));
    sb.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("mounted"));

    // toggle off -> unmounted, status reflects it.
    sb.cmd().args(["toggle", "vault"]).assert().success();
    assert!(!is_mounted(&sb.mnt(".vault")));
    sb.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("unmounted"));

    // toggle on -> mounted again.
    sb.cmd().args(["toggle", "vault"]).assert().success();
    assert!(is_mounted(&sb.mnt(".vault")));

    sb.cmd().args(["umount", "vault"]).assert().success();
}

#[test]
fn escrow_install_mount_status_toggle() {
    status_toggle_lifecycle(ESCROW_BASE, false);
}

#[test]
fn tpm_install_mount_status_toggle() {
    status_toggle_lifecycle(TPM_BASE, true);
}
