//! Desktop notifications via `notify-send` (best-effort; never fails an op).

use crate::procfs::which;
use std::process::Command;

/// Send a desktop notification if enabled and `notify-send` is available.
/// Failures are intentionally swallowed so they can't abort a mount/unmount.
pub fn notify(enabled: bool, body: &str) {
    if !enabled || which("notify-send").is_none() {
        return;
    }
    let _ = Command::new("notify-send").arg("sctl").arg(body).status();
}
