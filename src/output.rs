//! Output formatting: human (colored), JSON, and table modes.

use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use console::style;
use owo_colors::OwoColorize;

/// Output format selected by the user.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum Format {
    /// Colored, human-friendly output (default).
    #[default]
    Human,
    /// JSON output for scripting.
    Json,
    /// ASCII table output.
    Table,
}

/// Print a success message to stderr.
pub fn success(msg: &str) {
    eprintln!("  {} {msg}", style("OK").green().bold());
}

/// Print a warning message to stderr.
pub fn warning(msg: &str) {
    eprintln!("  {} {msg}", style("WARN").yellow().bold());
}

/// Print an error message to stderr.
pub fn error(msg: &str) {
    eprintln!("  {} {msg}", style("ERR").red().bold());
}

/// Print a labelled status line to stderr.
pub fn status(label: &str, msg: &str) {
    eprintln!("{} {msg}", style(format!("{label:>12}")).cyan().bold());
}

/// Build a styled table.
pub fn styled_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

/// Format a score with colour coding.
pub fn format_score(score: Option<u8>) -> String {
    match score {
        Some(s) if s >= 80 => format!("{}", s.to_string().green()),
        Some(s) if s >= 50 => format!("{}", s.to_string().yellow()),
        Some(s) => format!("{}", s.to_string().red()),
        None => style("--").dim().to_string(),
    }
}

/// Return a comfy_table Cell for a score (correct width for table layout).
pub fn score_cell(score: Option<u8>) -> Cell {
    match score {
        Some(s) if s >= 80 => Cell::new(s).fg(Color::Green),
        Some(s) if s >= 50 => Cell::new(s).fg(Color::Yellow),
        Some(s) => Cell::new(s).fg(Color::Red),
        None => Cell::new("--").fg(Color::DarkGrey),
    }
}

/// Format an analysis status string with colour.
pub fn format_status(status: &str) -> String {
    match status {
        "success" => style(status).green().to_string(),
        "pending" => style(status).dim().to_string(),
        "in-progress" => style(status).cyan().to_string(),
        "canceled" => style(status).yellow().to_string(),
        "error" => style(status).red().to_string(),
        other => other.to_string(),
    }
}

/// Return a comfy_table Cell for a status (correct width for table layout).
pub fn status_cell(status: &str) -> Cell {
    match status {
        "success" => Cell::new(status).fg(Color::Green),
        "pending" => Cell::new(status).fg(Color::DarkGrey),
        "in-progress" => Cell::new(status).fg(Color::Cyan),
        "canceled" => Cell::new(status).fg(Color::Yellow),
        "error" => Cell::new(status).fg(Color::Red),
        other => Cell::new(other),
    }
}
