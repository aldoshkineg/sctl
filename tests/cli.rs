//! End-to-end CLI tests in an isolated sandbox (own HOME/config/backends).
//! Mount tests auto-skip when gocryptfs/fusermount3 are unavailable.

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new(config: &str) -> Sandbox {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        fs::create_dir_all(p.join("cfg/state")).unwrap();
        fs::create_dir_all(p.join("enc")).unwrap();
        fs::write(p.join("cfg/key"), b"testpassword123").unwrap();
        let cfg = config.replace("$ENC", p.join("enc").to_str().unwrap());
        let cfg = cfg.replace("$KEY", p.join("cfg/key").to_str().unwrap());
        fs::write(p.join("cfg/config.toml"), cfg).unwrap();
        Sandbox { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn cmd(&self) -> Command {
        let p = self.dir.path();
        let mut c = Command::cargo_bin("sctl").unwrap();
        c.env("HOME", p)
            .env("SCTL_CONFIG", p.join("cfg/config.toml"))
            .env("SCTL_CONFIG_DIR", p.join("cfg"))
            .env("SCTL_STATE_DIR", p.join("cfg/state"))
            .env("SCTL_COLOR", "never");
        c
    }

    fn mnt(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
}

fn have(bin: &str) -> bool {
    which(bin).is_some()
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
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

const BASE: &str = r#"
[settings]
default_idle = "10m"
enc_root = "$ENC"
keyfile = "$KEY"

[secrets.gpg]
path = ".gnupg"

[secrets.pass]
path = ".password-store"
depends = ["gpg"]

[secrets.mail]
path = ".local/share/mail"
depends = ["gpg", "pass"]
idle = "30s"
"#;

#[test]
fn help_and_version() {
    let sb = Sandbox::new(BASE);
    sb.cmd().arg("--help").assert().success();
    sb.cmd().arg("--version").assert().success();
}

#[test]
fn unknown_secret_errors() {
    let sb = Sandbox::new(BASE);
    sb.cmd()
        .args(["mount", "nope"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown secret"));
}

#[test]
fn status_lists_all() {
    let sb = Sandbox::new(BASE);
    sb.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("gpg"))
        .stdout(predicates::str::contains("DEPENDS"));
}

#[test]
fn cycle_is_rejected() {
    let cfg = r#"
[settings]
enc_root = "$ENC"
keyfile = "$KEY"
[secrets.a]
path = "a"
depends = ["b"]
[secrets.b]
path = "b"
depends = ["a"]
"#;
    let sb = Sandbox::new(cfg);
    sb.cmd()
        .args(["mount", "a"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cycle"));
}

#[test]
fn completions_generate() {
    let sb = Sandbox::new(BASE);
    sb.cmd()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicates::str::contains("#compdef sctl"));
}

// --- lifecycle (needs gocryptfs + fusermount3) ----------------------------

#[test]
fn mount_pulls_dependencies_and_cascades() {
    if !have("gocryptfs") || !have("fusermount3") {
        eprintln!("skipping: gocryptfs/fusermount3 not installed");
        return;
    }
    let sb = Sandbox::new(BASE);

    sb.cmd().args(["init", "all"]).assert().success();
    assert!(sb.path().join("enc/gpg/gocryptfs.conf").exists());

    // Mounting mail must pull gpg + pass first.
    sb.cmd().args(["mount", "mail"]).assert().success();
    assert!(is_mounted(&sb.mnt(".gnupg")));
    assert!(is_mounted(&sb.mnt(".password-store")));
    assert!(is_mounted(&sb.mnt(".local/share/mail")));

    // Unmounting a needed dependency is refused.
    sb.cmd()
        .args(["umount", "gpg"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("required by mounted"));
    assert!(is_mounted(&sb.mnt(".gnupg")));

    // Smart cascade: umount mail also unmounts pass + gpg.
    sb.cmd().args(["umount", "mail"]).assert().success();
    assert!(!is_mounted(&sb.mnt(".local/share/mail")));
    assert!(!is_mounted(&sb.mnt(".password-store")));
    assert!(!is_mounted(&sb.mnt(".gnupg")));
}

#[test]
fn no_idle_shows_never() {
    if !have("gocryptfs") || !have("fusermount3") {
        eprintln!("skipping: gocryptfs/fusermount3 not installed");
        return;
    }
    let sb = Sandbox::new(BASE);
    sb.cmd().args(["init", "gpg"]).assert().success();
    sb.cmd()
        .args(["mount", "gpg", "--no-idle"])
        .assert()
        .success();
    sb.cmd()
        .arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("never"));
    sb.cmd().args(["umount", "gpg"]).assert().success();
}

#[test]
fn shared_dependency_is_kept() {
    if !have("gocryptfs") || !have("fusermount3") {
        eprintln!("skipping: gocryptfs/fusermount3 not installed");
        return;
    }
    // Two independent consumers of gpg.
    let cfg = r#"
[settings]
enc_root = "$ENC"
keyfile = "$KEY"
[secrets.gpg]
path = ".gnupg"
[secrets.mail]
path = ".local/share/mail"
depends = ["gpg"]
[secrets.chat]
path = ".local/share/chat"
depends = ["gpg"]
"#;
    let sb = Sandbox::new(cfg);
    sb.cmd().args(["init", "all"]).assert().success();
    sb.cmd().args(["mount", "mail", "chat"]).assert().success();
    // Unmount only mail; chat still needs gpg -> gpg kept.
    sb.cmd().args(["umount", "mail"]).assert().success();
    assert!(!is_mounted(&sb.mnt(".local/share/mail")));
    assert!(is_mounted(&sb.mnt(".gnupg")));
    assert!(is_mounted(&sb.mnt(".local/share/chat")));
    sb.cmd().args(["umount", "all"]).assert().success();
}
