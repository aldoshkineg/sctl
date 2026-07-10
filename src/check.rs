//! `check` command: validate config, backends, permissions and dependencies.

use crate::config::Config;
use crate::table;
use owo_colors::Style;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

    // keyfile
    check_keyfile(&cfg.keyfile, &mut report);

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

fn check_keyfile<F: FnMut(Level, String)>(keyfile: &Path, report: &mut F) {
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
fn check_mode<F: FnMut(Level, String)>(path: &Path, mask: u32, what: &str, report: &mut F) {
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
