//! Background watcher: force-unmount secrets stuck in `busy` past their
//! `kill_busy_after` threshold. Driven either as a resident loop (`sctl watch`)
//! or as a single pass (`sctl watch --once`, e.g. from cron).

use crate::config::Config;
use crate::procfs::{busy_pids, is_mounted};
use crate::state;
use crate::umount::{UmountOpts, umount_one};
use anyhow::Result;
use std::thread;
use std::time::Duration;

/// How often the resident watcher polls (the user asked for ~once a minute).
pub const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// Default busy timeout when a secret enables `kill_busy` without specifying
/// `kill_busy_after` (10 minutes).
const DEFAULT_KILL_BUSY_AFTER: u64 = 600;

/// One polling pass: for every mounted secret with `kill_busy`, track how long
/// it has been busy and force-unmount once the threshold is exceeded.
pub fn one_pass(cfg: &Config) -> Result<()> {
    for secret in cfg.secrets.values() {
        if !secret.kill_busy {
            continue;
        }
        let safe = secret.safe();
        // A secret mounted with `--no-idle` (or SCTL_NO_IDLE) opted out of all
        // automatic unmounting, including the busy watcher; never force-unmount
        // it. Drop any stale busy marker so it does not linger.
        if state::idle_disabled(&cfg.state_dir, &safe) {
            state::clear_busy(&cfg.state_dir, &safe);
            continue;
        }
        let mnt = secret.mountpoint(&cfg.home);

        if !is_mounted(&mnt) {
            state::clear_busy(&cfg.state_dir, &safe);
            continue;
        }
        let pids = busy_pids(&mnt);
        if pids.is_empty() {
            state::clear_busy(&cfg.state_dir, &safe);
            continue;
        }

        let threshold = secret
            .kill_busy_after
            .as_deref()
            .and_then(state::duration_to_secs)
            .unwrap_or(DEFAULT_KILL_BUSY_AFTER);
        let now = state::now_secs();

        // First time we see it busy: just remember the moment, wait for the
        // threshold on subsequent passes.
        let since = match state::busy_since(&cfg.state_dir, &safe) {
            Some(s) => s,
            None => {
                state::mark_busy(&cfg.state_dir, &safe, now)?;
                continue;
            }
        };

        if now - since >= threshold as i64 {
            eprintln!(
                "{}: busy {}s (>= {}s threshold) -> force unmount",
                secret.name,
                now - since,
                threshold
            );
            let opts = UmountOpts {
                force: true,
                lazy: false,
                notify: true,
            };
            if let Err(e) = umount_one(cfg, secret, opts) {
                eprintln!("error: force unmount of {} failed: {e:#}", secret.name);
            }
            state::clear_busy(&cfg.state_dir, &safe);
        }
    }
    Ok(())
}

/// Resident loop: run `one_pass` every `WATCH_INTERVAL` until there is nothing
/// left to watch, then exit (a later `mount` respawns the watcher).
pub fn run(cfg: &Config) -> Result<()> {
    loop {
        one_pass(cfg)?;
        if !any_kill_busy_mounted(cfg) {
            break;
        }
        thread::sleep(WATCH_INTERVAL);
    }
    Ok(())
}

/// True if at least one `kill_busy` secret is currently mounted.
fn any_kill_busy_mounted(cfg: &Config) -> bool {
    cfg.secrets
        .values()
        .any(|s| s.kill_busy && is_mounted(&s.mountpoint(&cfg.home)))
}
