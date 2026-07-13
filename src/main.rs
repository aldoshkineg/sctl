use anyhow::Result;
use clap::{CommandFactory, Parser};
use sctl::cli::{Cli, Command};
use sctl::config::Config;
use std::collections::BTreeSet;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

fn main() -> ExitCode {
    sctl::table::init_color(Some(std::io::stdout().is_terminal()));
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
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut cmd, name, &mut buf);
            let mut script = String::from_utf8_lossy(&buf).into_owned();
            if shell == clap_complete::Shell::Zsh {
                script = enhance_zsh(script);
            }
            print!("{script}");
            Ok(ExitCode::SUCCESS)
        }
        Command::ListSecrets => {
            // Best-effort: print secret names for completion, silent on error.
            if let Ok(cfg) = Config::load() {
                for name in cfg.all_names() {
                    println!("{name}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Version => {
            println!("sctl {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Command::Watch { once } => {
            let cfg = Config::load()?;
            if once {
                sctl::watch::one_pass(&cfg)?;
            } else {
                // Singleton: only one resident watcher may run at a time.
                match sctl::lock::acquire(&cfg.runtime_dir(), "watch", "watch") {
                    Ok(_lock) => sctl::watch::run(&cfg)?,
                    Err(_) => { /* another watcher already running */ }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Check => {
            let cfg = Config::load()?;
            Ok(exit(sctl::check::run(&cfg)))
        }
        Command::Install {
            names,
            gpg_pass,
            ssh_pass,
            yes,
        } => {
            let cfg = Config::load()?;
            sctl::install::run(
                &cfg,
                &sctl::install::InstallOpts {
                    names,
                    gpg_pass,
                    ssh_pass,
                    yes,
                },
            )?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Recovery { filter } => {
            let cfg = Config::load()?;
            sctl::recovery::run(&cfg, filter.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Status { notify } => {
            let cfg = Config::load()?;
            sctl::status::run(&cfg, notify);
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
                if let Err(e) = sctl::mount::init_one(&cfg, &secret) {
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
            let mopts = sctl::mount::MountOpts {
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
            let uopts = sctl::umount::UmountOpts {
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
                let mopts = sctl::mount::MountOpts {
                    no_idle: opts.no_idle,
                    notify: opts.notify,
                };
                failed |= do_mount(&cfg, &to_mount, mopts)?;
            }
            if !to_umount.is_empty() {
                let uopts = sctl::umount::UmountOpts {
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

fn do_mount(cfg: &Config, requested: &[String], opts: sctl::mount::MountOpts) -> Result<bool> {
    let order = sctl::deps::mount_order(cfg, requested)?;
    let mut failed = false;
    for name in order {
        let secret = cfg.get(&name)?.clone();
        if let Err(e) = sctl::mount::mount_one(cfg, &secret, opts) {
            eprintln!("error: {e:#}");
            failed = true;
        }
    }
    // Fork the resident watcher (singleton) if any secret opts into kill_busy.
    // A mount invoked with `--no-idle` opted out of all automatic unmounting,
    // so the watcher must not be launched for it.
    spawn_watcher_if_needed(cfg, opts.no_idle);
    Ok(failed)
}

/// Fork a detached `sctl watch` (singleton) when any secret enables `kill_busy`
/// and the mount was not `--no-idle`. The watcher self-exits when nothing is
/// left to watch and a later `mount` respawns it; the singleton lock prevents
/// duplicates.
fn spawn_watcher_if_needed(cfg: &Config, no_idle: bool) {
    if no_idle {
        return;
    }
    if !cfg.secrets.values().any(|s| s.kill_busy) {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("watch")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // Move into its own process group so the daemon survives the parent
        // mount command being interrupted (SIGINT to the foreground group no
        // longer reaches it). It still self-exits when nothing is mounted.
        #[cfg(unix)]
        cmd.process_group(0);
        let _ = cmd.spawn();
    }
}

fn do_umount(
    cfg: &Config,
    requested: &[String],
    mounted: &BTreeSet<String>,
    opts: sctl::umount::UmountOpts,
) -> Result<bool> {
    let plan = sctl::deps::umount_plan(cfg, requested, mounted)?;
    let mut failed = false;
    // With `--force`, a requested secret whose mounted dependents are not being
    // unmounted is unmounted anyway (the dependents are left mounted, broken).
    let mut to_unmount: Vec<String> = plan.order.clone();
    for (blocked, blockers) in &plan.blocked {
        if opts.force {
            eprintln!(
                "warning: {} is required by mounted: {} (--force: unmounting only {})",
                blocked,
                blockers.join(", "),
                blocked
            );
            if !to_unmount.contains(blocked) {
                to_unmount.push(blocked.clone());
            }
        } else {
            eprintln!(
                "error: {blocked} is required by mounted: {} (unmount them first or include them)",
                blockers.join(", ")
            );
            failed = true;
        }
    }
    for name in to_unmount {
        let secret = cfg.get(&name)?.clone();
        if let Err(e) = sctl::umount::umount_one(cfg, &secret, opts) {
            eprintln!("error: {e:#}");
            failed = true;
        }
    }
    Ok(failed)
}

fn print_mount_plan(cfg: &Config, requested: &[String]) -> Result<()> {
    let order = sctl::deps::mount_order(cfg, requested)?;
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
    let plan = sctl::deps::umount_plan(cfg, requested, mounted)?;
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
        .filter(|s| sctl::procfs::is_mounted(&s.mountpoint(&cfg.home)))
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

/// Patch clap's generated zsh completion to complete secret names dynamically
/// (from `sctl __list-secrets`) instead of falling back to `_default`.
fn enhance_zsh(mut s: String) -> String {
    // Drop the internal helper subcommand from the top-level suggestion list.
    s = s
        .lines()
        .filter(|l| !l.trim_start().starts_with("'__list-secrets:"))
        .collect::<Vec<_>>()
        .join("\n");
    s.push('\n');
    s = s.replace(
        "-- Secret name(s), or '\\''all'\\'':_default",
        "-- Secret name(s), or '\\''all'\\'':_sctl_secrets",
    );
    s = s.replace(
        "-- Secret name(s):_default",
        "-- Secret name(s):_sctl_secrets",
    );
    // A `Vec<String>` positional is emitted by clap as a zsh "rest" argument
    // (`*::`), which stops offering options (e.g. `--notify`) once a value has
    // been given. Demote it to a plain multiple positional (`*:`) so flags
    // remain completable after secret names: `sctl tg ssh --not` -> `--notify`.
    s = s.replace("'*::names", "'*:names");
    let helper = "\n\
_sctl_secrets() {\n\
    local -a _secrets\n\
    _secrets=(${(f)\"$(sctl __list-secrets 2>/dev/null)\"})\n\
    _values 'secret' all $_secrets\n\
}\n";
    let anchor = "autoload -U is-at-least\n";
    if let Some(pos) = s.find(anchor) {
        let idx = pos + anchor.len();
        s.insert_str(idx, helper);
    } else {
        s.push_str(helper);
    }
    s
}
