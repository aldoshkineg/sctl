mod check;
mod cli;
mod config;
mod deps;
mod gpg;
mod lock;
mod mount;
mod notify;
mod passfile;
mod procfs;
mod state;
mod status;
mod sys;
mod table;
mod umount;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use cli::{Cli, Command};
use config::Config;
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::process::ExitCode;

fn main() -> ExitCode {
    table::init_color(Some(std::io::stdout().is_terminal()));
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Command::Check => {
            let cfg = Config::load()?;
            Ok(exit(check::run(&cfg)))
        }
        Command::Status { notify } => {
            let cfg = Config::load()?;
            status::run(&cfg, notify);
            Ok(ExitCode::SUCCESS)
        }
        Command::Init { names } => {
            let cfg = Config::load()?;
            let targets = expand_all(&cfg, &names);
            let mut failed = false;
            for name in targets {
                let secret = match cfg.get(&name) {
                    Ok(s) => s.clone(),
                    Err(e) => {
                        eprintln!("error: {e:#}");
                        failed = true;
                        continue;
                    }
                };
                if let Err(e) = mount::init_one(&cfg, &secret) {
                    eprintln!("error: {e:#}");
                    failed = true;
                }
            }
            Ok(exit(failed))
        }
        Command::Mount { names, opts } => {
            let cfg = Config::load()?;
            let requested = expand_all(&cfg, &names);
            if opts.dry_run {
                print_mount_plan(&cfg, &requested)?;
                return Ok(ExitCode::SUCCESS);
            }
            let mopts = mount::MountOpts {
                no_idle: opts.no_idle,
                notify: opts.notify,
            };
            Ok(exit(do_mount(&cfg, &requested, mopts)?))
        }
        Command::Umount { names, opts } => {
            let cfg = Config::load()?;
            let mounted = mounted_set(&cfg);
            let requested = resolve_umount_names(&cfg, &names, &mounted);
            if opts.dry_run {
                print_umount_plan(&cfg, &requested, &mounted)?;
                return Ok(ExitCode::SUCCESS);
            }
            let uopts = umount::UmountOpts {
                force: opts.force,
                lazy: opts.lazy,
                notify: opts.notify,
            };
            Ok(exit(do_umount(&cfg, &requested, &mounted, uopts)?))
        }
        Command::Toggle { names, opts } => {
            let cfg = Config::load()?;
            let mounted = mounted_set(&cfg);
            // Validate names exist up front.
            for n in &names {
                cfg.get(n)?;
            }
            let to_mount: Vec<String> = names
                .iter()
                .filter(|n| !mounted.contains(*n))
                .cloned()
                .collect();
            let to_umount: Vec<String> = names
                .iter()
                .filter(|n| mounted.contains(*n))
                .cloned()
                .collect();

            if opts.dry_run {
                if !to_mount.is_empty() {
                    print_mount_plan(&cfg, &to_mount)?;
                }
                if !to_umount.is_empty() {
                    print_umount_plan(&cfg, &to_umount, &mounted)?;
                }
                return Ok(ExitCode::SUCCESS);
            }

            let mut failed = false;
            if !to_mount.is_empty() {
                let mopts = mount::MountOpts {
                    no_idle: opts.no_idle,
                    notify: opts.notify,
                };
                failed |= do_mount(&cfg, &to_mount, mopts)?;
            }
            if !to_umount.is_empty() {
                let uopts = umount::UmountOpts {
                    force: opts.force,
                    lazy: opts.lazy,
                    notify: opts.notify,
                };
                failed |= do_umount(&cfg, &to_umount, &mounted, uopts)?;
            }
            Ok(exit(failed))
        }
    }
}

fn do_mount(cfg: &Config, requested: &[String], opts: mount::MountOpts) -> Result<bool> {
    let order = deps::mount_order(cfg, requested)?;
    let mut failed = false;
    for name in order {
        let secret = cfg.get(&name)?.clone();
        if let Err(e) = mount::mount_one(cfg, &secret, opts) {
            eprintln!("error: {e:#}");
            failed = true;
        }
    }
    Ok(failed)
}

fn do_umount(
    cfg: &Config,
    requested: &[String],
    mounted: &BTreeSet<String>,
    opts: umount::UmountOpts,
) -> Result<bool> {
    let plan = deps::umount_plan(cfg, requested, mounted)?;
    let mut failed = false;
    for (blocked, blockers) in &plan.blocked {
        eprintln!(
            "error: {blocked} is required by mounted: {} (unmount them first or include them)",
            blockers.join(", ")
        );
        failed = true;
    }
    for name in plan.order {
        let secret = cfg.get(&name)?.clone();
        if let Err(e) = umount::umount_one(cfg, &secret, opts) {
            eprintln!("error: {e:#}");
            failed = true;
        }
    }
    Ok(failed)
}

fn print_mount_plan(cfg: &Config, requested: &[String]) -> Result<()> {
    let order = deps::mount_order(cfg, requested)?;
    let mounted = mounted_set(cfg);
    let reqset: BTreeSet<&String> = requested.iter().collect();
    println!("mount plan (dry-run):");
    for name in order {
        let tag = if mounted.contains(&name) {
            "already mounted, skip"
        } else if reqset.contains(&name) {
            "mount"
        } else {
            "mount (dependency)"
        };
        println!("  {name}  [{tag}]");
    }
    Ok(())
}

fn print_umount_plan(cfg: &Config, requested: &[String], mounted: &BTreeSet<String>) -> Result<()> {
    let plan = deps::umount_plan(cfg, requested, mounted)?;
    let reqset: BTreeSet<&String> = requested.iter().collect();
    println!("umount plan (dry-run):");
    for (blocked, blockers) in &plan.blocked {
        println!(
            "  {blocked}  [blocked: required by {}]",
            blockers.join(", ")
        );
    }
    for name in &plan.order {
        let tag = if reqset.contains(name) {
            "unmount"
        } else {
            "unmount (cascade: unused dependency)"
        };
        println!("  {name}  [{tag}]");
    }
    if plan.order.is_empty() && plan.blocked.is_empty() {
        println!("  (nothing to unmount)");
    }
    Ok(())
}

/// Resolve requested names for unmount, expanding `all` to mounted secrets.
fn resolve_umount_names(cfg: &Config, names: &[String], mounted: &BTreeSet<String>) -> Vec<String> {
    if names.iter().any(|n| n == "all") {
        cfg.all_names()
            .into_iter()
            .filter(|n| mounted.contains(n))
            .collect()
    } else {
        names.to_vec()
    }
}

/// Expand `all` to every configured secret, else de-duplicate preserving order.
fn expand_all(cfg: &Config, names: &[String]) -> Vec<String> {
    if names.iter().any(|n| n == "all") {
        return cfg.all_names();
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for n in names {
        if seen.insert(n.clone()) {
            out.push(n.clone());
        }
    }
    out
}

/// Set of currently mounted secret names.
fn mounted_set(cfg: &Config) -> BTreeSet<String> {
    cfg.secrets
        .values()
        .filter(|s| procfs::is_mounted(&s.mountpoint(&cfg.home)))
        .map(|s| s.name.clone())
        .collect()
}

fn exit(failed: bool) -> ExitCode {
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
