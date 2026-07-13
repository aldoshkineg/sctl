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
        SecretBackend::Tpm => check_tpm(cfg, report),
        SecretBackend::Escrow => check_escrow(cfg, report),
    }
}

/// TPM backend: tools, device, group, and sealed DEK + DEK-encrypted map.
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

    // TPM enrollment: sealed DEK + DEK-encrypted map present.
    if !tpm::dek_exists(cfg) {
        report(
            Level::Err,
            "TPM DEK not enrolled (run `sctl install`)".to_string(),
        );
    } else if !cfg.tpm_map_file().is_file() {
        report(
            Level::Err,
            format!(
                "TPM map missing: {} (run `sctl install`)",
                cfg.tpm_map_file().display()
            ),
        );
    } else {
        report(Level::Ok, "TPM DEK and map present".to_string());
        check_mode(&cfg.tpm_map_file(), 0o077, "TPM map", report);
    }

    // Desync vs escrow (if escrow file also present).
    if cfg.escrow_file.is_file() {
        check_desync(cfg, report);
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
    check_mode(&cfg.escrow_file, 0o077, "escrow file", report);

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

/// DESYNC detector (docs §2/§7.3). Both backends now hold the *whole* secret
/// map in one age container (escrow wrapped by the master passphrase, TPM
/// wrapped by the sealed DEK). This compares the two decrypted maps key-by-key:
/// a value mismatch, or a key present in only one, means `mount` (TPM) and
/// recovery (escrow) would disagree — re-run `sctl install`.
fn check_desync(cfg: &Config, report: &mut dyn FnMut(Level, String)) {
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

    // The TPM map (DEK-unwrapped) is the daily-mount source of truth.
    let tpm_map = match secret::resolve_all(cfg) {
        Ok(m) => m,
        Err(e) => {
            report(
                Level::Err,
                format!("desync check: cannot read TPM map: {e:#}"),
            );
            return;
        }
    };

    let mut union: std::collections::BTreeSet<&String> = escrow_map.keys().collect();
    union.extend(tpm_map.keys());

    let mut mismatches = Vec::new();
    let mut tpm_only = Vec::new();
    let mut escrow_only = Vec::new();
    let mut checked = 0usize;
    for id in union {
        match (tpm_map.get(id), escrow_map.get(id)) {
            (Some(t), Some(e)) => {
                if t.as_slice() == e.as_slice() {
                    checked += 1;
                } else {
                    mismatches.push(id.clone());
                }
            }
            (Some(_), None) => tpm_only.push(id.clone()),
            (None, Some(_)) => escrow_only.push(id.clone()),
            (None, None) => {}
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
                "TPM map entries without escrow counterpart: {} — re-run `sctl install`",
                tpm_only.join(", ")
            ),
        );
    }
    if !escrow_only.is_empty() {
        report(
            Level::Warn,
            format!(
                "escrow entries without TPM counterpart (mount will fail): {}",
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
    use std::os::unix::fs::PermissionsExt;

    /// `check_mode` flags group/other-accessible secret files.
    #[test]
    fn check_mode_flags_loose_perms() {
        let dir = std::env::temp_dir().join("sctl-check-mode-test");
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("secret");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut levels = Vec::new();
        {
            let mut report = |lvl: Level, _msg: String| levels.push(lvl);
            check_mode(&f, 0o077, "secret", &mut report);
        }
        assert!(levels.contains(&Level::Warn));

        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut levels = Vec::new();
        {
            let mut report = |lvl: Level, _msg: String| levels.push(lvl);
            check_mode(&f, 0o077, "secret", &mut report);
        }
        // check_mode is silent on acceptable perms (no Warn emitted).
        assert!(!levels.contains(&Level::Warn));
    }
}
