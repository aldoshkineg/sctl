//! `status` command: colored, aligned table of all secrets.

use crate::config::Config;
use crate::notify::notify;
use crate::procfs::is_mounted;
use crate::state::{self, Countdown};
use crate::table::{self, Cell};
use owo_colors::Style;

/// Print the status table. Cleans stale state files for unmounted secrets.
pub fn run(cfg: &Config, do_notify: bool) {
    let show_deps = cfg.secrets.values().any(|s| !s.depends.is_empty());

    let mut headers = vec!["NAME", "STATE", "MOUNTPOINT", "UNMOUNT IN"];
    if show_deps {
        headers.push("DEPENDS");
    }

    let red = Style::new().red().bold();
    let dim = Style::new().dimmed();
    let blue = Style::new().blue();

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let mut summary = String::new();

    for secret in cfg.secrets.values() {
        let mnt = secret.mountpoint(&cfg.home);
        let mounted = is_mounted(&mnt);
        let safe = secret.safe();
        if !mounted {
            state::clear(&cfg.runtime_dir(), &safe);
        }
        let cd = state::countdown(&cfg.runtime_dir(), &safe, mounted);

        let state_cell = if mounted {
            Cell::styled("mounted", red)
        } else {
            Cell::styled("unmounted", dim)
        };
        let cd_style = match cd {
            Countdown::Busy => Some(Style::new().red()),
            Countdown::Never => Some(blue),
            _ => None,
        };
        let cd_text = cd.text();
        let cd_cell = match cd_style {
            Some(s) => Cell::styled(cd_text.clone(), s),
            None => Cell::plain(cd_text.clone()),
        };

        let mut row = vec![
            Cell::plain(secret.name.clone()),
            state_cell,
            Cell::plain(mnt.display().to_string()),
            cd_cell,
        ];
        if show_deps {
            row.push(Cell::plain(if secret.depends.is_empty() {
                "-".to_string()
            } else {
                secret.depends.join(",")
            }));
        }
        rows.push(row);

        summary.push_str(&format!(
            "{}: {} ({})\n",
            secret.name,
            if mounted { "mounted" } else { "unmounted" },
            cd_text
        ));
    }

    println!("{}", table::render(&headers, &rows));
    notify(do_notify, summary.trim_end());
}
