//! Command-line interface definition (clap derive).

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Debug, Parser)]
#[command(
    name = "sctl",
    about = "Config-driven gocryptfs secret mount manager",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create encrypted container(s) and migrate existing data
    #[command(visible_alias = "in")]
    Init {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Mount secret(s), pulling in dependencies (use 'all' for everything)
    #[command(visible_alias = "mo")]
    Mount {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        opts: MountFlags,
    },
    /// Unmount secret(s) with smart dependency cascade (use 'all')
    #[command(visible_alias = "um")]
    Umount {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        opts: UmountFlags,
    },
    /// Mount if unmounted, unmount if mounted (handy for keybindings)
    #[command(visible_alias = "tg")]
    Toggle {
        /// Secret name(s)
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        opts: ToggleFlags,
    },
    /// Validate config, backends, permissions and dependencies
    #[command(visible_alias = "ck")]
    Check,
    /// Show mount status (state, mountpoint, idle countdown)
    #[command(visible_alias = "st")]
    Status {
        /// Also send a desktop notification with the summary
        #[arg(long)]
        notify: bool,
    },
    /// Generate shell completions
    #[command(visible_alias = "cp")]
    Completions {
        /// Shell to generate for
        shell: Shell,
    },
    /// Print version information
    #[command(visible_alias = "ve")]
    Version,
    /// Background watcher: force-unmount secrets stuck busy past kill_busy_after
    #[command(visible_alias = "wa")]
    Watch {
        /// Run a single pass and exit (instead of the resident loop)
        #[arg(long)]
        once: bool,
    },
    /// (internal) list secret names for shell completion
    #[command(name = "__list-secrets", hide = true)]
    ListSecrets,
    /// Enroll all managed secrets into the backend (TPM seals + escrow)
    #[command(visible_alias = "inst")]
    Install {
        /// Restrict to these secret names (default: all managed secrets)
        #[arg(required = false)]
        names: Vec<String>,
    },
    /// Recover the secret map from the escrow container
    #[command(visible_alias = "rc")]
    Recovery {
        /// Only print entries whose key starts with this prefix (e.g. "gpg:")
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct MountFlags {
    /// Disable idle auto-unmount for this mount
    #[arg(long)]
    pub no_idle: bool,
    /// Send desktop notifications
    #[arg(long)]
    pub notify: bool,
    /// Show what would happen without doing it
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct UmountFlags {
    /// Kill processes holding the mount busy without prompting
    #[arg(long)]
    pub force: bool,
    /// Lazy unmount (detach now, clean up when free)
    #[arg(long)]
    pub lazy: bool,
    /// Send desktop notifications
    #[arg(long)]
    pub notify: bool,
    /// Show what would happen without doing it
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct ToggleFlags {
    /// Disable idle auto-unmount when mounting
    #[arg(long)]
    pub no_idle: bool,
    /// Kill processes holding a mount busy without prompting
    #[arg(long)]
    pub force: bool,
    /// Lazy unmount (detach now, clean up when free)
    #[arg(long)]
    pub lazy: bool,
    /// Send desktop notifications
    #[arg(long)]
    pub notify: bool,
    /// Show what would happen without doing it
    #[arg(long)]
    pub dry_run: bool,
}
