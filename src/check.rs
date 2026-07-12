//! `check` command: validate config, backends, permissions and dependencies.

use crate::config::{Config, SecretBackend};
use crate::escrow;
use crate::secret;
use crate::table;
use crate::tpm;
use anyhow::Context;
use owo_colors::Style;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[derive(PartialEq)]
enum Level {
    Ok,
    Warn,
    Err,
}

/// Run all checks. Returns true if any error-level problem was found.
pub fn run(cfg: &Config) -> bool {
    let mut errors = 0usize;
    let mut warns = 0usize;
    let mut report = |level: Level, msg: String| {
        let (tag, style) = match level {
            Level::Ok => ("ok  ", Style::new().green()),
            Level::Warn => ("warn", Style::new().yellow()),
            Level::Err => ("err ", Style::new().red().bold()),
        };
        match level {
            Level::Warn => warns += 1,
            Level::Err => errors += 1,
            Level::Ok => {}
        }
        println!("  {} {}", table::paint(tag, style), msg);
    };

    // enc_root
    if cfg.enc_root.is_dir() {
        report(
            Level::Ok,
            format!("enc_root exists: {}", cfg.enc_root.display()),
        );
    } else {
        report(
            Level::Err,
            format!("enc_root missing: {}", cfg.enc_root.display()),
        );
    }

    // keyfile (only meaningful in legacy mode)
    check_keyfile(&cfg.keyfile, &mut report);

    // Backend-specific checks + desync detection.
    check_backend(cfg, &mut report);

    // per-secret checks
    let mut mountpoints: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for s in cfg.secrets.values() {
        // dependency references (also validated at load, re-report clearly)
        for d in &s.depends {
            if !cfg.secrets.contains_key(d) {
                report(
                    Level::Err,
                    format!("secret '{}' depends on unknown '{}'", s.name, d),
                );
            }
        }
        // backend init state
        let enc = s.enc_dir(&cfg.enc_root);
        if enc.join("gocryptfs.conf").exists() {
            report(Level::Ok, format!("secret '{}' initialized", s.name));
            check_mode(&enc, 0o077, &format!("backend {}", s.name), &mut report);
        } else if enc.exists() {
            report(
                Level::Warn,
                format!(
                    "secret '{}' backend exists but not initialized: {}",
                    s.name,
                    enc.display()
                ),
            );
        } else {
            report(
                Level::Warn,
                format!(
                    "secret '{}' not initialized (run: sctl init {})",
                    s.name, s.name
                ),
            );
        }
        // duplicate mountpoint detection
        let mp = s.mountpoint(&cfg.home).display().to_string();
        if let Some(other) = mountpoints.insert(mp.clone(), s.name.clone()) {
            report(
                Level::Err,
                format!(
                    "secrets '{}' and '{}' share mountpoint {}",
                    other, s.name, mp
                ),
            );
        }
    }

    // orphan backends: enc_root subdirs not referenced by any secret
    let known: BTreeSet<String> = cfg.secrets.values().map(|s| s.safe()).collect();
    if let Ok(entries) = std::fs::read_dir(&cfg.enc_root) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                let name = e.file_name().to_string_lossy().to_string();
                if !known.contains(&name) {
                    report(
                        Level::Warn,
                        format!(
                            "orphan backend (no matching secret): {}",
                            e.path().display()
                        ),
                    );
                }
            }
        }
    }

    println!();
    if errors == 0 && warns == 0 {
        println!(
            "{}",
            table::paint("all checks passed", Style::new().green().bold())
        );
    } else {
        println!("{errors} error(s), {warns} warning(s)");
    }
    errors > 0
}

/// Backend presence + self-tests. Also runs the desync detector (§7.3).
fn check_backend(cfg: &Config, report: &mut dyn FnMut(Level, String)) {
    match cfg.secret_backend {
        None => report(
            Level::Warn,
            "secret_backend not set: legacy mode (plaintext keyfile, manual gpg)".to_string(),
        ),
        Some(SecretBackend::Tpm) => check_tpm(cfg, report),
        Some(SecretBackend::Escrow) => check_escrow(cfg, report),
    }
}

/// TPM backend: tools, device, group, and per-secret blob presence.
fn check_tpm(cfg: &Config, report: &mut dyn FnMut(Level, String)) {
    // tpm2-tools presence.
    if Command::new("tpm2_createprimary")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        report(Level::Ok, "tpm2-tools present".to_string());
    } else {
        report(
            Level::Warn,
            "tpm2-tools not found (install app-crypt/tpm2-tools)".to_string(),
        );
    }

    // /dev/tpmrm0 resource manager.
    if Path::new("/dev/tpmrm0").exists() {
        report(Level::Ok, "/dev/tpmrm0 present".to_string());
    } else if Path::new("/dev/tpm0").exists() {
        report(
            Level::Warn,
            "/dev/tpmrm0 absent; /dev/tpm0 present (no RM)".to_string(),
        );
    } else {
        report(
            Level::Err,
            "no TPM device (/dev/tpmrm0, /dev/tpm0)".to_string(),
        );
    }

    // user in tss group.
    if user_in_group("tss") {
        report(Level::Ok, "user is in group 'tss'".to_string());
    } else {
        report(
            Level::Warn,
            "user not in group 'tss' (TPM access denied without root)".to_string(),
        );
    }

    // Per-secret TPM blob presence.
    let ids = enrolled_ids(cfg);
    let mut missing = Vec::new();
    for id in &ids {
        if !tpm::exists(id, cfg) {
            missing.push(id.clone());
        }
    }
    if missing.is_empty() {
        report(Level::Ok, "all TPM blobs present".to_string());
    } else {
        report(
            Level::Err,
            format!(
                "missing TPM blobs: {} (run `sctl install`)",
                missing.join(", ")
            ),
        );
    }

    // Desync vs escrow (if escrow file also present).
    if cfg.escrow_file.is_file() {
        check_desync(cfg, &ids, report);
    }
}

/// Escrow backend: file presence, master passphrase availability, self-test.
fn check_escrow(cfg: &Config, report: &mut dyn FnMut(Level, String)) {
    if !cfg.escrow_file.is_file() {
        report(
            Level::Err,
            format!("escrow file missing: {}", cfg.escrow_file.display()),
        );
        return;
    }
    report(
        Level::Ok,
        format!("escrow file present: {}", cfg.escrow_file.display()),
    );

    // Master passphrase availability (env/file/prompt); report only, since
    // prompting during check is intrusive.
    let have = std::env::var_os("SCTL_MASTER_PASS").is_some()
        || cfg
            .master_passphrase_file
            .as_ref()
            .is_some_and(|p| p.is_file());
    if have {
        report(Level::Ok, "master passphrase available".to_string());
    } else {
        report(
            Level::Warn,
            "master passphrase not provided (env/file); will prompt at use".to_string(),
        );
    }

    // Self-test: decrypt the escrow container with the master passphrase.
    let master = match secret::read_master_passphrase_noninteractive(cfg) {
        Ok(m) => m,
        Err(e) => {
            report(Level::Warn, format!("escrow self-test skipped: {e:#}"));
            return;
        }
    };
    let bytes = match read_escrow_bytes(cfg) {
        Ok(b) => b,
        Err(e) => {
            report(Level::Err, format!("escrow self-test FAILED: {e:#}"));
            return;
        }
    };
    match escrow::open(&bytes, &master) {
        Ok(map) => report(
            Level::Ok,
            format!("escrow decrypt self-test ok ({} entries)", map.len()),
        ),
        Err(e) => report(Level::Err, format!("escrow self-test FAILED: {e:#}")),
    }
}

/// DESYNC detector (docs §2/§7.3). In TPM mode the mount path reads from the
/// TPM, so the primary check is **TPM → escrow**: every enrolled TPM blob must
/// match its escrow counterpart, and a TPM blob with no escrow entry (stale or
/// orphaned) is reported. We also catch the reverse (escrow entry whose TPM
/// blob diverges). A mismatch means mount or recovery would yield a stale
/// secret.
fn check_desync(cfg: &Config, ids: &[String], report: &mut dyn FnMut(Level, String)) {
    let master = match secret::read_master_passphrase_noninteractive(cfg) {
        Ok(m) => m,
        Err(e) => {
            report(
                Level::Warn,
                format!("desync check skipped (no master): {e:#}"),
            );
            return;
        }
    };
    let bytes = match read_escrow_bytes(cfg) {
        Ok(b) => b,
        Err(e) => {
            report(
                Level::Err,
                format!("desync check: cannot read escrow: {e:#}"),
            );
            return;
        }
    };
    let escrow_map = match escrow::open(&bytes, &master) {
        Ok(m) => m,
        Err(e) => {
            report(
                Level::Err,
                format!("desync check: escrow undecryptable: {e:#}"),
            );
            return;
        }
    };

    // Universe of ids to compare: enrolled TPM ids (config-derived) ∪ escrow keys.
    let mut union: std::collections::BTreeSet<String> = ids.iter().cloned().collect();
    union.extend(escrow_map.keys().cloned());

    let mut mismatches = Vec::new();
    let mut checked = 0usize;
    let mut tpm_only = Vec::new();
    let mut escrow_only = Vec::new();
    for id in &union {
        let tpm_present = tpm::exists(id, cfg);
        let esc = escrow_map.get(id);
        match (tpm_present, esc) {
            (true, Some(esc_val)) => match tpm::unseal(id, cfg) {
                Ok(tpm_val) => {
                    if tpm_val.as_slice() == esc_val.as_slice() {
                        checked += 1;
                    } else {
                        mismatches.push(id.clone());
                    }
                }
                Err(e) => report(
                    Level::Warn,
                    format!("desync check: TPM unseal failed for {id}: {e:#}"),
                ),
            },
            (true, None) => tpm_only.push(id.clone()),
            (false, Some(_)) => escrow_only.push(id.clone()),
            (false, None) => {}
        }
    }

    if !mismatches.is_empty() {
        report(
            Level::Err,
            format!(
                "DESYNC: TPM and escrow disagree for: {} — re-run `sctl install`",
                mismatches.join(", ")
            ),
        );
    }
    if !tpm_only.is_empty() {
        report(
            Level::Err,
            format!(
                "TPM blobs without escrow counterpart (stale/orphan): {} — re-run `sctl install`",
                tpm_only.join(", ")
            ),
        );
    }
    if !escrow_only.is_empty() {
        report(
            Level::Warn,
            format!(
                "escrow entries without TPM blob (mount will fail): {}",
                escrow_only.join(", ")
            ),
        );
    }
    if mismatches.is_empty() && tpm_only.is_empty() {
        if checked > 0 {
            report(
                Level::Ok,
                format!("desync check ok ({checked} entries matched)"),
            );
        } else {
            report(
                Level::Warn,
                "desync check: no overlapping TPM/escrow entries".to_string(),
            );
        }
    }
}

/// All secret ids that `install` should enroll into the TPM: the shared
/// gocryptfs key plus every `tpm_gpg` gpg home's primary-key ids.
fn enrolled_ids(cfg: &Config) -> Vec<String> {
    let mut ids = vec!["gocryptfs:__shared__".to_string()];
    for s in cfg.secrets.values() {
        if !s.tpm_gpg {
            continue;
        }
        let home = s.mountpoint(&cfg.home);
        if !home.exists() {
            continue;
        }
        if let Ok(fprs) = crate::gpg::list_primary_fprs(&home) {
            for fpr in fprs {
                ids.push(secret::composite_key(
                    "gpg",
                    &secret::gpg_id_tail(&s.name, &fpr),
                ));
            }
        }
    }
    ids
}

fn read_escrow_bytes(cfg: &Config) -> anyhow::Result<Vec<u8>> {
    std::fs::read(&cfg.escrow_file)
        .with_context(|| format!("reading escrow file {}", cfg.escrow_file.display()))
}

/// Whether the current user belongs to `group` (via /etc/group + /proc/self).
fn user_in_group(group: &str) -> bool {
    let gid = std::fs::read_to_string("/etc/group").ok().and_then(|g| {
        g.lines()
            .find(|l| l.starts_with(&format!("{group}:")))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<u32>().ok())
    });
    let Some(gid) = gid else {
        return false;
    };
    let groups = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Groups:"))
                .map(|l| l["Groups:".len()..].to_string())
        });
    groups
        .map(|g| g.split_whitespace().any(|x| x.parse::<u32>() == Ok(gid)))
        .unwrap_or(false)
}

fn check_keyfile(keyfile: &Path, report: &mut dyn FnMut(Level, String)) {
    if !keyfile.exists() {
        report(
            Level::Warn,
            format!("keyfile absent (will prompt): {}", keyfile.display()),
        );
        return;
    }
    report(Level::Ok, format!("keyfile present: {}", keyfile.display()));
    check_mode(keyfile, 0o177, "keyfile", report);
}

/// Warn if any bit in `mask` is set on the path's mode.
fn check_mode(path: &Path, mask: u32, what: &str, report: &mut dyn FnMut(Level, String)) {
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & mask != 0 {
            report(
                Level::Warn,
                format!("{what} is too permissive: {:o} ({})", mode, path.display()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Secret, SecretBackend};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn cfg_with_gpg(name: &str, home: PathBuf, tpm_gpg: bool) -> Config {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            name.to_string(),
            Secret {
                name: name.to_string(),
                rel_path: home.to_string_lossy().into_owned(),
                idle: None,
                depends: vec![],
                gpg: true,
                gpg_preset: true,
                tpm_gpg,
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
            home: PathBuf::from("/h"),
            state_dir: PathBuf::from("/c/state"),
            stray_dir: PathBuf::from("/c/stray"),
            enc_root: PathBuf::from("/c/enc"),
            keyfile: PathBuf::from("/c/key"),
            default_idle: None,
            secret_backend: Some(SecretBackend::Tpm),
            escrow_file: PathBuf::from("/c/escrow.age"),
            master_passphrase_file: None,
            tpm_pcr: false,
            secrets,
        }
    }

    #[test]
    fn enrolled_ids_gocryptfs_only() {
        let cfg = cfg_with_gpg("gpg", PathBuf::from("/no/such/home"), false);
        assert_eq!(enrolled_ids(&cfg), vec!["gocryptfs:__shared__".to_string()]);
    }

    #[test]
    fn enrolled_ids_skips_missing_home() {
        // tpm_gpg enabled but the gpg home is absent: only the shared key is
        // enrolled (matches `build_map`, which bails on a missing home).
        let cfg = cfg_with_gpg("gpg", PathBuf::from("/no/such/home"), true);
        assert_eq!(enrolled_ids(&cfg), vec!["gocryptfs:__shared__".to_string()]);
    }
}
