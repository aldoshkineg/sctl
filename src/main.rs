mod cli;
mod config;
mod deps;
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
            // Pull in dependencies, deps-first.
            let order = deps::mount_order(&cfg, &requested)?;
            let mopts = mount::MountOpts {
                no_idle: opts.no_idle,
                notify: opts.notify,
            };
            let mut failed = false;
            for name in order {
                let secret = cfg.get(&name)?.clone();
                if let Err(e) = mount::mount_one(&cfg, &secret, mopts) {
                    eprintln!("error: {e:#}");
                    failed = true;
                }
            }
            Ok(exit(failed))
        }
        Command::Umount { names, opts } => {
            let cfg = Config::load()?;
            let mounted = mounted_set(&cfg);
            let requested = if names.iter().any(|n| n == "all") {
                // 'all' => every mounted secret
                cfg.all_names()
                    .into_iter()
                    .filter(|n| mounted.contains(n))
                    .collect()
            } else {
                names.clone()
            };
            let plan = deps::umount_plan(&cfg, &requested, &mounted)?;

            let mut failed = false;
            for (blocked, blockers) in &plan.blocked {
                eprintln!(
                    "error: {blocked} is required by mounted: {} (unmount them first or include them)",
                    blockers.join(", ")
                );
                failed = true;
            }
            let uopts = umount::UmountOpts {
                force: opts.force,
                lazy: opts.lazy,
                notify: opts.notify,
            };
            for name in plan.order {
                let secret = cfg.get(&name)?.clone();
                if let Err(e) = umount::umount_one(&cfg, &secret, uopts) {
                    eprintln!("error: {e:#}");
                    failed = true;
                }
            }
            Ok(exit(failed))
        }
    }
}

/// Expand `all` (if present) to every configured secret name, else return the
/// given names de-duplicated preserving order.
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
