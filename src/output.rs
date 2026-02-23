//! Output formatting: human (colored), JSON, and table modes.

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

/// Format a score with colour coding.
pub fn format_score(score: Option<u8>) -> String {
    match score {
        Some(s) if s >= 80 => format!("{}", s.to_string().green()),
        Some(s) if s >= 50 => format!("{}", s.to_string().yellow()),
        Some(s) => format!("{}", s.to_string().red()),
        None => style("--").dim().to_string(),
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
