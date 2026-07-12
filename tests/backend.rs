//! Behavioral end-to-end test for the TPM/escrow secret backend.
//!
//! Uses the shared gpg fixture (tests/common) to enroll a real gpg home via
//! `install::build_map` + `finalize`, then verifies that `recovery::read_map`
//! and `secret::resolve_secret` return the same secret material — i.e. the
//! single-writer invariant (docs §2) holds and there is no desync between the
//! escrow container and (for the tpm backend) the TPM blobs.

mod common;

use sctl::config::{Config, Secret, SecretBackend};
use sctl::install::{ConstProvider, build_map, finalize};
use sctl::recovery;
use sctl::secret;
use std::path::Path;
use std::path::PathBuf;

const MASTER: &str = "test-master-pass";
const G: &[u8] = b"shared-gocryptfs-key-material-bytes";
const PASS: &str = "fixture-key-passphrase";

/// Build a config pointing at an isolated gpg home (fixture) with a shared
/// gocryptfs key adopted from `keyfile`.
fn cfg_for(
    backend: SecretBackend,
    state_dir: &Path,
    keyfile: &Path,
    escrow_file: &Path,
    gpg_home: &Path,
) -> Config {
    let mut secrets = std::collections::BTreeMap::new();
    secrets.insert(
        "gpg".to_string(),
        Secret {
            name: "gpg".to_string(),
            rel_path: gpg_home.to_string_lossy().into_owned(),
            idle: None,
            depends: vec![],
            gpg: true,
            gpg_preset: true,
            auto_kill: vec![],
            kill_busy: false,
            kill_busy_after: None,
            pre_mount: vec![],
            post_mount: vec![],
            pre_unmount: vec![],
            post_unmount: vec![],
        },
    );
    Config {
        home: PathBuf::from("/"),
        state_dir: state_dir.to_path_buf(),
        stray_dir: state_dir.join("stray"),
        enc_root: state_dir.join("enc"),
        keyfile: keyfile.to_path_buf(),
        default_idle: None,
        secret_backend: Some(backend),
        escrow_file: escrow_file.to_path_buf(),
        master_passphrase_file: None,
        tpm_pcr: false,
        secrets,
    }
}

fn tpm_available() -> bool {
    if !Path::new("/dev/tpmrm0").exists() {
        return false;
    }
    let gid = std::fs::read_to_string("/etc/group").ok().and_then(|g| {
        g.lines()
            .find(|l| l.starts_with("tss:"))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<u32>().ok())
    });
    let Some(gid) = gid else {
        return false;
    };
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Groups:"))
                .map(|l| l["Groups:".len()..].to_string())
        })
        .map(|g| g.split_whitespace().any(|x| x.parse::<u32>() == Ok(gid)))
        .unwrap_or(false)
}

#[test]
fn install_recovery_roundtrip_escrow() {
    // Skip gracefully if gpg is unavailable (mirrors fixture gate).
    if !common::have_gpg() {
        eprintln!("skipping: gpg not available");
        return;
    }
    unsafe {
        std::env::set_var("SCTL_MASTER_PASS", MASTER);
    }

    let home = common::gen_gpg_home(1, PASS);
    assert!(
        home.keys[0].has_sign && home.keys[0].has_auth,
        "fixture key missing expected subkeys"
    );
    let fpr = home.keys[0].fpr.clone();

    let dir = std::env::temp_dir().join(format!("sctl-beh-escrow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let keyfile = dir.join("key");
    std::fs::write(&keyfile, G).unwrap();
    let escrow_file = dir.join("sctl-escrow.age");

    let cfg = cfg_for(
        SecretBackend::Escrow,
        &dir,
        &keyfile,
        &escrow_file,
        &home.home,
    );

    let map = build_map(&cfg, &ConstProvider { pass: PASS }, &[]).unwrap();
    assert_eq!(map.get("gocryptfs:__shared__").unwrap().as_slice(), G);
    assert_eq!(
        map.get(&format!("gpg:gpg:{fpr}")).unwrap().as_slice(),
        PASS.as_bytes()
    );

    finalize(&cfg, &map).unwrap();
    assert!(escrow_file.is_file(), "escrow file written");

    // recovery returns the exact same material (single-writer invariant).
    let recovered = recovery::read_map(&cfg).unwrap();
    assert_eq!(recovered.len(), map.len());
    assert_eq!(recovered.get("gocryptfs:__shared__").unwrap().as_slice(), G);
    assert_eq!(
        recovered.get(&format!("gpg:gpg:{fpr}")).unwrap().as_slice(),
        PASS.as_bytes()
    );
}

#[test]
fn install_resolve_secret_tpm_no_desync() {
    if !common::have_gpg() || !tpm_available() {
        eprintln!("skipping: gpg or TPM (with tss group) not available");
        return;
    }
    unsafe {
        std::env::set_var("SCTL_MASTER_PASS", MASTER);
    }

    let home = common::gen_gpg_home(1, PASS);
    assert!(
        home.keys[0].has_sign && home.keys[0].has_auth,
        "fixture key missing expected subkeys"
    );
    let fpr = home.keys[0].fpr.clone();

    let dir = std::env::temp_dir().join(format!("sctl-beh-tpm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let keyfile = dir.join("key");
    std::fs::write(&keyfile, G).unwrap();
    let escrow_file = dir.join("sctl-escrow.age");

    let cfg = cfg_for(SecretBackend::Tpm, &dir, &keyfile, &escrow_file, &home.home);

    let map = build_map(&cfg, &ConstProvider { pass: PASS }, &[]).unwrap();
    finalize(&cfg, &map).unwrap();
    assert!(
        escrow_file.is_file(),
        "escrow file written alongside TPM blobs"
    );

    // TPM-backed resolution returns the enrolled secrets.
    let g = secret::resolve_secret(&cfg, "gocryptfs", "__shared__").unwrap();
    assert_eq!(g.as_slice(), G);
    let p = secret::resolve_secret(&cfg, "gpg", &format!("gpg:{fpr}")).unwrap();
    assert_eq!(p.as_slice(), PASS.as_bytes());

    // The escrow container (recovery path) holds the same values: no desync.
    let recovered = recovery::read_map(&cfg).unwrap();
    assert_eq!(recovered.get("gocryptfs:__shared__").unwrap().as_slice(), G);
    assert_eq!(
        recovered.get(&format!("gpg:gpg:{fpr}")).unwrap().as_slice(),
        PASS.as_bytes()
    );
}
