//! sctl — config-driven gocryptfs secret mount manager.
//!
//! Library surface for the `sctl` binary. Modules are re-exported so they can
//! be exercised by `tests/` (e.g. behavioral install/recovery round-trips).

pub mod check;
pub mod cli;
pub mod config;
pub mod deps;
pub mod escrow;
pub mod gpg;
pub mod install;
pub mod lock;
pub mod mount;
pub mod notify;
pub mod passfile;
pub mod procfs;
pub mod rand;
pub mod recovery;
pub mod secret;
pub mod state;
pub mod status;
pub mod sys;
pub mod table;
pub mod tpm;
pub mod umount;
pub mod watch;
