//! `/proc`-based helpers: mountpoint detection and process info; `fuser` wrapper.

use std::path::Path;
use std::process::Command;

/// Return true if `path` is a mountpoint, by scanning `/proc/self/mountinfo`.
pub fn is_mounted(path: &Path) -> bool {
    let target = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => path.to_path_buf(),
    };
    let content = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in content.lines() {
        // Field 5 (1-indexed) is the mount point.
        if let Some(mp) = line.split_whitespace().nth(4) {
            let mp = unescape_mountinfo(mp);
            if Path::new(&mp) == target {
                return true;
            }
        }
    }
    false
}

/// mountinfo escapes space/tab/newline/backslash as octal (\040 etc.).
fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(code as char);
            i += 4;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Info about a process holding a mount busy.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: i32,
    pub user: String,
    pub comm: String,
}

/// Return PIDs using the given mount, via `fuser -m`. Empty if `fuser` is
/// missing or nothing holds the mount.
pub fn busy_pids(mnt: &Path) -> Vec<i32> {
    if which("fuser").is_none() {
        return Vec::new();
    }
    let out = match Command::new("fuser").arg("-m").arg(mnt).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    // fuser prints PIDs (possibly with access-type letters) across stdout/stderr.
    let mut pids: Vec<i32> = Vec::new();
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&out.stdout));
    text.push(' ');
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    for tok in text.split_whitespace() {
        let digits: String = tok.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pid) = digits.parse::<i32>()
            && !pids.contains(&pid)
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

/// Resolve process info for PIDs from `/proc/<pid>/{comm,status}`.
pub fn proc_info(pids: &[i32]) -> Vec<ProcInfo> {
    pids.iter()
        .filter_map(|&pid| {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()?
                .trim()
                .to_string();
            let user = uid_of(pid)
                .and_then(username)
                .unwrap_or_else(|| "?".to_string());
            Some(ProcInfo { pid, user, comm })
        })
        .collect()
}

fn uid_of(pid: i32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn username(uid: u32) -> Option<String> {
    use nix::unistd::{Uid, User};
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

/// Locate an executable in PATH.
pub fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_spaces() {
        assert_eq!(unescape_mountinfo(r"/mnt/a\040b"), "/mnt/a b");
        assert_eq!(unescape_mountinfo("/plain"), "/plain");
    }

    #[test]
    fn root_is_mounted() {
        assert!(is_mounted(Path::new("/")));
    }
}
