//! Idle-timeout parsing/formatting and persisted idle-state files.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parse a duration like `30s`, `10m`, `1h` into seconds. Returns `None` if
/// malformed (so callers can treat it defensively).
pub fn duration_to_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last().unwrap() {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.parse::<u64>().ok().map(|n| n * mult)
}

/// Human-readable remaining time from seconds.
pub fn format_remaining(secs: i64) -> String {
    if secs <= 0 {
        return "due".to_string();
    }
    let mins = secs / 60;
    if mins >= 60 {
        format!("{}h{}m", mins / 60, mins % 60)
    } else if mins >= 1 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Record that `safe` was mounted now with the given idle value (`"none"` when
/// idle is disabled).
pub fn persist(state_dir: &Path, safe: &str, idle: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(state_dir.join(safe), format!("{} {}\n", now_secs(), idle))
}

/// Remove a persisted idle-state file (ignore if absent).
pub fn clear(state_dir: &Path, safe: &str) {
    let _ = std::fs::remove_file(state_dir.join(safe));
}

/// Record that `safe` first became busy now (epoch seconds).
pub fn mark_busy(state_dir: &Path, safe: &str, epoch: i64) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(state_dir.join(format!("{safe}.busy")), format!("{epoch}\n"))
}

/// Epoch when `safe` first became busy, if recorded.
pub fn busy_since(state_dir: &Path, safe: &str) -> Option<i64> {
    let raw = std::fs::read_to_string(state_dir.join(format!("{safe}.busy"))).ok()?;
    raw.trim().parse::<i64>().ok()
}

/// Forget a recorded busy state (ignore if absent).
pub fn clear_busy(state_dir: &Path, safe: &str) {
    let _ = std::fs::remove_file(state_dir.join(format!("{safe}.busy")));
}

/// True if `safe` was mounted with idle disabled (i.e. `--no-idle` or
/// `SCTL_NO_IDLE`). Such a secret opted out of all automatic unmounting,
/// including the busy watcher.
pub fn idle_disabled(state_dir: &Path, safe: &str) -> bool {
    let raw = match std::fs::read_to_string(state_dir.join(safe)) {
        Ok(c) => c,
        Err(_) => return false,
    };
    raw.split_whitespace().nth(1) == Some("none")
}

/// Countdown status shown in the `UNMOUNT IN` column.
#[derive(Debug, PartialEq, Eq)]
pub enum Countdown {
    /// Not mounted.
    NotMounted,
    /// Mounted but no state file (mounted by something else).
    Unknown,
    /// Mounted with idle disabled.
    Never,
    /// Idle timer likely elapsed but still mounted (recent activity resets it).
    Busy,
    /// Estimated remaining time.
    Remaining(String),
}

impl Countdown {
    pub fn text(&self) -> String {
        match self {
            Countdown::NotMounted => "-".into(),
            Countdown::Unknown => "?".into(),
            Countdown::Never => "never".into(),
            Countdown::Busy => "busy".into(),
            Countdown::Remaining(s) => s.clone(),
        }
    }
}

/// Compute the countdown for a mount given its persisted state.
pub fn countdown(state_dir: &Path, safe: &str, mounted: bool) -> Countdown {
    if !mounted {
        return Countdown::NotMounted;
    }
    let raw = match std::fs::read_to_string(state_dir.join(safe)) {
        Ok(c) => c,
        Err(_) => return Countdown::Unknown,
    };
    let mut it = raw.split_whitespace();
    let epoch: i64 = match it.next().and_then(|s| s.parse().ok()) {
        Some(e) => e,
        None => return Countdown::Unknown,
    };
    let idle = it.next().unwrap_or("");
    if idle == "none" {
        return Countdown::Never;
    }
    match duration_to_secs(idle) {
        Some(d) => {
            let rem = epoch + d as i64 - now_secs();
            if rem <= 0 {
                Countdown::Busy
            } else {
                Countdown::Remaining(format_remaining(rem))
            }
        }
        None => Countdown::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_durations() {
        assert_eq!(duration_to_secs("30s"), Some(30));
        assert_eq!(duration_to_secs("10m"), Some(600));
        assert_eq!(duration_to_secs("1h"), Some(3600));
        assert_eq!(duration_to_secs("45"), Some(45));
        assert_eq!(duration_to_secs("garbage!!"), None);
        assert_eq!(duration_to_secs(""), None);
    }

    #[test]
    fn format() {
        assert_eq!(format_remaining(0), "due");
        assert_eq!(format_remaining(30), "30s");
        assert_eq!(format_remaining(600), "10m");
        assert_eq!(format_remaining(3720), "1h2m");
    }

    #[test]
    fn idle_disabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!idle_disabled(dir.path(), "gpg"));
        persist(dir.path(), "gpg", "none").unwrap();
        assert!(idle_disabled(dir.path(), "gpg"));
        persist(dir.path(), "gpg", "5m").unwrap();
        assert!(!idle_disabled(dir.path(), "gpg"));
    }
}
