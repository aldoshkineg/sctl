//! Command-line interface definition (clap derive).

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Debug, Parser)]
#[command(
    name = "sctl",
    version,
    about = "Config-driven gocryptfs secret mount manager",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create encrypted container(s) and migrate existing data
    Init {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Mount secret(s), pulling in dependencies (use 'all' for everything)
    Mount {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        opts: MountFlags,
    },
    /// Unmount secret(s) with smart dependency cascade (use 'all')
    Umount {
        /// Secret name(s), or 'all'
        #[arg(required = true)]
        names: Vec<String>,
        #[command(flatten)]
        opts: UmountFlags,
    },
    /// Show mount status (state, mountpoint, idle countdown)
    Status {
        /// Also send a desktop notification with the summary
        #[arg(long)]
        notify: bool,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate for
        shell: Shell,
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
}
