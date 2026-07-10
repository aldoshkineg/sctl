//! `umount` operation with busy detection and interactive process killing.

use crate::config::{Config, Secret};
use crate::notify::notify;
use crate::procfs::{busy_pids, is_mounted, proc_info};
use crate::state;
use crate::sys;
use crate::table::{self, Cell};
use anyhow::{Result, bail};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use owo_colors::Style;
use std::path::Path;
use std::time::Duration;

/// Options controlling an unmount.
#[derive(Debug, Clone, Copy, Default)]
pub struct UmountOpts {
    /// Kill blocking processes without asking.
    pub force: bool,
    /// Lazy unmount (`fusermount -u -z`).
    pub lazy: bool,
    pub notify: bool,
}

/// Unmount a single secret's container.
pub fn umount_one(cfg: &Config, secret: &Secret, opts: UmountOpts) -> Result<()> {
    let _lock = crate::lock::acquire(&cfg.state_dir, &secret.safe(), &secret.name)?;
    let mnt = secret.mountpoint(&cfg.home);
    if !is_mounted(&mnt) {
        println!("{}: not mounted", secret.name);
        return Ok(());
    }
    if secret.gpg {
        sys::gpg_kill();
    }
    sys::run_hooks("pre_unmount", &secret.pre_unmount)?;

    let pids = busy_pids(&mnt);
    if !pids.is_empty() {
        handle_busy(secret, &mnt, &pids, opts)?;
    }

    sys::fuse_unmount(&mnt, opts.lazy)?;
    println!("unmounted: {}", secret.name);
    notify(opts.notify, &format!("Unmounted {}", secret.name));
    state::clear(&cfg.state_dir, &secret.safe());
    sys::run_hooks("post_unmount", &secret.post_unmount)?;
    Ok(())
}

/// Decide what to do about processes holding the mount busy.
///
/// Policy: if every holder's process name is in the secret's `auto_kill` list,
/// they are killed silently. If any *other* process holds the mount, nothing is
/// killed - the list is printed and `--force` is required. `--force` kills all.
fn handle_busy(secret: &Secret, mnt: &Path, pids: &[i32], opts: UmountOpts) -> Result<()> {
    let infos = proc_info(pids);
    // Map pid -> comm for classification (missing => unknown => "other").
    let comm_of = |pid: i32| -> Option<String> {
        infos.iter().find(|i| i.pid == pid).map(|i| i.comm.clone())
    };
    let is_auto = |pid: i32| -> bool {
        match comm_of(pid) {
            Some(comm) => secret.auto_kill.iter().any(|k| k == &comm),
            None => false,
        }
    };
    let others: Vec<i32> = pids.iter().copied().filter(|&p| !is_auto(p)).collect();

    if opts.force {
        eprintln!(
            "{}: --force killing {} process(es) holding {}",
            secret.name,
            pids.len(),
            mnt.display()
        );
        print_proc_table(&infos, pids);
        kill_pids(pids)?;
    } else if others.is_empty() {
        // Every holder is whitelisted -> kill silently.
        let names: Vec<String> = infos
            .iter()
            .map(|i| format!("{}({})", i.comm, i.pid))
            .collect();
        eprintln!("{}: auto-killing {}", secret.name, names.join(" "));
        kill_pids(pids)?;
    } else {
        // Non-whitelisted holder present -> refuse, show the list.
        eprintln!(
            "{} is busy ({} process{} holding {}):",
            secret.name,
            pids.len(),
            if pids.len() == 1 { "" } else { "es" },
            mnt.display()
        );
        print_proc_table(&infos, pids);
        notify(
            opts.notify,
            &format!("Busy: {} unmount skipped", secret.name),
        );
        bail!(
            "{} is busy; rerun with --force to kill (pids: {})",
            secret.name,
            join_pids(pids)
        );
    }

    // Re-check; if still busy and not lazy, error out.
    let remaining = busy_pids(mnt);
    if !remaining.is_empty() && !opts.lazy {
        bail!(
            "{} still busy after kill (pids: {})",
            secret.name,
            join_pids(&remaining)
        );
    }
    Ok(())
}

fn print_proc_table(infos: &[crate::procfs::ProcInfo], pids: &[i32]) {
    let red = Style::new().red();
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    if infos.is_empty() {
        for pid in pids {
            rows.push(vec![
                Cell::styled(pid.to_string(), red),
                Cell::plain("?"),
                Cell::plain("?"),
            ]);
        }
    } else {
        for i in infos {
            rows.push(vec![
                Cell::styled(i.pid.to_string(), red),
                Cell::plain(i.user.clone()),
                Cell::plain(i.comm.clone()),
            ]);
        }
    }
    eprintln!("{}", table::render(&["PID", "USER", "COMMAND"], &rows));
}

/// SIGTERM the processes, wait briefly, then SIGKILL any survivors.
fn kill_pids(pids: &[i32]) -> Result<()> {
    for &pid in pids {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    // Wait up to ~3s for graceful exit.
    for _ in 0..30 {
        if pids.iter().all(|&p| !alive(p)) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for &pid in pids {
        if alive(pid) {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    Ok(())
}

fn alive(pid: i32) -> bool {
    // signal 0 => existence check
    kill(Pid::from_raw(pid), None).is_ok()
}

fn join_pids(pids: &[i32]) -> String {
    pids.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}
