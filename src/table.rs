//! Terminal color handling and aligned table rendering.

use owo_colors::{OwoColorize, Style};
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static COLOR: AtomicBool = AtomicBool::new(false);

/// Decide whether to emit ANSI colors, honoring `NO_COLOR` and `SCTL_COLOR`.
pub fn init_color(stdout_is_tty: Option<bool>) {
    let enabled = match std::env::var("SCTL_COLOR").as_deref() {
        Ok("always") => true,
        Ok("never") => false,
        _ => {
            if std::env::var_os("NO_COLOR").is_some() {
                false
            } else {
                stdout_is_tty.unwrap_or_else(|| std::io::stdout().is_terminal())
            }
        }
    };
    COLOR.store(enabled, Ordering::Relaxed);
}

fn color_enabled() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Apply a style only when color is enabled.
pub fn paint(text: &str, style: Style) -> String {
    if color_enabled() {
        text.style(style).to_string()
    } else {
        text.to_string()
    }
}

/// A cell: its plain text plus an optional style.
pub struct Cell {
    pub text: String,
    pub style: Option<Style>,
}

impl Cell {
    pub fn plain<S: Into<String>>(text: S) -> Cell {
        Cell {
            text: text.into(),
            style: None,
        }
    }
    pub fn styled<S: Into<String>>(text: S, style: Style) -> Cell {
        Cell {
            text: text.into(),
            style: Some(style),
        }
    }
}

/// Render a table with dynamically sized columns. Widths are computed on the
/// plain text so ANSI codes never break alignment.
pub fn render(headers: &[&str], rows: &[Vec<Cell>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.text.chars().count());
        }
    }

    let mut out = String::new();
    // header (bold)
    let header_cells: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i]))
        .collect();
    out.push_str(&paint(&join(&header_cells), Style::new().bold()));
    out.push('\n');

    for row in rows {
        let mut line_cells: Vec<String> = Vec::with_capacity(cols);
        for (i, cell) in row.iter().enumerate() {
            let padded = pad(&cell.text, widths[i]);
            match cell.style {
                Some(style) => line_cells.push(paint(&padded, style)),
                None => line_cells.push(padded),
            }
        }
        out.push_str(&join(&line_cells));
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn join(cells: &[String]) -> String {
    cells.join("  ").trim_end().to_string()
}
