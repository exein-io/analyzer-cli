//! Analyzer CLI — a command-line interface for Exein Analyzer.
//!
//! Scan firmware and container images for vulnerabilities, generate SBOMs,
//! check CRA compliance, and more.

mod client;
mod commands;
mod config;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::output::Format;

/// Exein Analyzer CLI — firmware & container security scanning.
///
/// Scan images for CVEs, generate SBOMs, check CRA compliance, and more.
/// Get started with `analyzer login` or set ANALYZER_API_KEY.
#[derive(Parser)]
#[command(
    name = "analyzer",
    version,
    about,
    long_about = None,
    propagate_version = true,
    arg_required_else_help = true,
)]
struct Cli {
    /// API key (overrides config file and ANALYZER_API_KEY env var).
    #[arg(long, global = true, env = "ANALYZER_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Base URL for the Analyzer API.
    #[arg(long, global = true, env = "ANALYZER_URL")]
    url: Option<String>,

    /// Config profile to use.
    #[arg(long, global = true, env = "ANALYZER_PROFILE")]
    profile: Option<String>,

    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    format: Format,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Authenticate and save your API key.
    Login {
        /// Server URL to authenticate against.
        #[arg(long)]
        url: Option<String>,
        /// Profile name to save credentials under.
        #[arg(long)]
        profile: Option<String>,
    },

    /// Show your current identity and configuration.
    Whoami,

    /// Manage configuration (show, set, get).
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Manage objects (devices / products).
    #[command(subcommand)]
    Object(ObjectCommand),

    /// Manage scans and analysis results.
    #[command(subcommand)]
    Scan(ScanCommand),

    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

// -- Config subcommands -------------------------------------------------------

#[derive(Subcommand)]
enum ConfigCommand {
    /// Show all configuration.
    Show,
    /// Set a config value (url, api-key, default-profile).
    Set {
        key: String,
        value: String,
        /// Profile to modify.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Get a config value.
    Get {
        key: String,
        /// Profile to read from.
        #[arg(long)]
        profile: Option<String>,
    },
}

// -- Object subcommands -------------------------------------------------------

#[derive(Subcommand)]
enum ObjectCommand {
    /// List all objects.
    List,
    /// Create a new object.
    New {
        /// Name for the object.
        name: String,
        /// Optional description.
        #[arg(short, long)]
        description: Option<String>,
        /// Tags for the object.
        #[arg(short, long)]
        tags: Vec<String>,
    },
    /// Delete an object by ID.
    Delete {
        /// Object UUID.
        id: Uuid,
    },
}

// -- Scan subcommands ---------------------------------------------------------

#[derive(Subcommand)]
enum ScanCommand {
    /// Create a new scan.
    New {
        /// Object ID to scan against.
        #[arg(short, long = "object")]
        object_id: Uuid,

        /// Path to the firmware / container image file.
        #[arg(short = 'f', long = "file")]
        file: PathBuf,

        /// Image type: linux, docker, idf.
        #[arg(short = 't', long = "type")]
        scan_type: String,

        /// Analysis types to run (e.g. info cve software-bom malware).
        /// If omitted, all available analyses for the scan type are run.
        #[arg(short = 'a', long = "analysis", num_args = 1..)]
        analyses: Vec<String>,

        /// Wait for the scan to finish before returning.
        #[arg(short, long)]
        wait: bool,

        /// Poll interval when waiting (e.g. "2s", "500ms").
        #[arg(long, value_parser = humantime::parse_duration, default_value = "2s")]
        interval: Duration,

        /// Maximum wait time (e.g. "10m", "120s").
        #[arg(long, value_parser = humantime::parse_duration, default_value = "10m")]
        timeout: Duration,
    },

    /// Delete a scan.
    Delete {
        /// Scan UUID.
        id: Uuid,
    },

    /// Cancel a running scan.
    Cancel {
        /// Scan UUID.
        id: Uuid,
    },

    /// Show scan status.
    Status {
        /// Scan UUID.
        #[arg(short, long = "scan")]
        scan_id: Uuid,
    },

    /// Show the security score.
    Score {
        /// Scan UUID.
        #[arg(short, long = "scan")]
        scan_id: Uuid,
    },

    /// Download the PDF report.
    Report {
        /// Scan UUID.
        #[arg(short, long = "scan")]
        scan_id: Uuid,

        /// Output file path.
        #[arg(short, long)]
        output: PathBuf,

        /// Wait for scan completion first.
        #[arg(short, long)]
        wait: bool,

        /// Poll interval when waiting.
        #[arg(long, value_parser = humantime::parse_duration, default_value = "2s")]
        interval: Duration,

        /// Maximum wait time.
        #[arg(long, value_parser = humantime::parse_duration, default_value = "10m")]
        timeout: Duration,
    },

    /// Download the SBOM (CycloneDX JSON).
    Sbom {
        /// Scan UUID.
        #[arg(short, long = "scan")]
        scan_id: Uuid,

        /// Output file path.
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Download the CRA compliance report (PDF).
    CraReport {
        /// Scan UUID.
        #[arg(short, long = "scan")]
        scan_id: Uuid,

        /// Output file path.
        #[arg(short, long)]
        output: PathBuf,

        /// Wait for scan completion first.
        #[arg(short, long)]
        wait: bool,

        /// Poll interval when waiting.
        #[arg(long, value_parser = humantime::parse_duration, default_value = "2s")]
        interval: Duration,

        /// Maximum wait time.
        #[arg(long, value_parser = humantime::parse_duration, default_value = "10m")]
        timeout: Duration,
    },

    /// List available scan types and analysis options.
    Types,
}

// =============================================================================

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        output::error(&format!("{e:#}"));
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn run(cli: Cli) -> Result<()> {
    // Extract auth fields before moving cli.command
    let api_key = cli.api_key;
    let url = cli.url;
    let profile = cli.profile;
    let format = cli.format;

    match cli.command {
        // -- Auth (no API key required) -----------------------------------
        Command::Login {
            url: login_url,
            profile: login_profile,
        } => commands::auth::run_login(login_url.as_deref(), login_profile.as_deref()).await,

        Command::Whoami => {
            commands::auth::run_whoami(api_key.as_deref(), url.as_deref(), profile.as_deref())
        }

        // -- Config (no API key required) ---------------------------------
        Command::Config(cmd) => match cmd {
            ConfigCommand::Show => commands::config::run_show(),
            ConfigCommand::Set {
                key,
                value,
                profile: p,
            } => commands::config::run_set(&key, &value, p.as_deref()),
            ConfigCommand::Get { key, profile: p } => commands::config::run_get(&key, p.as_deref()),
        },

        // -- Completions (no API key required) ----------------------------
        Command::Completions { shell } => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(shell, &mut cmd, "analyzer", &mut std::io::stdout());
            Ok(())
        }

        // -- Commands that need an authenticated client -------------------
        Command::Object(cmd) => {
            let client = make_client(api_key.as_deref(), url.as_deref(), profile.as_deref())?;
            match cmd {
                ObjectCommand::List => commands::object::run_list(&client, format).await,
                ObjectCommand::New {
                    name,
                    description,
                    tags,
                } => commands::object::run_new(&client, name, description, tags, format).await,
                ObjectCommand::Delete { id } => commands::object::run_delete(&client, id).await,
            }
        }

        Command::Scan(cmd) => {
            let client = make_client(api_key.as_deref(), url.as_deref(), profile.as_deref())?;
            match cmd {
                ScanCommand::New {
                    object_id,
                    file,
                    scan_type,
                    analyses,
                    wait,
                    interval,
                    timeout,
                } => {
                    commands::scan::run_new(
                        &client, object_id, file, scan_type, analyses, format, wait, interval,
                        timeout,
                    )
                    .await
                }
                ScanCommand::Delete { id } => commands::scan::run_delete(&client, id).await,
                ScanCommand::Cancel { id } => commands::scan::run_cancel(&client, id).await,
                ScanCommand::Status { scan_id } => {
                    commands::scan::run_status(&client, scan_id, format).await
                }
                ScanCommand::Score { scan_id } => {
                    commands::scan::run_score(&client, scan_id, format).await
                }
                ScanCommand::Report {
                    scan_id,
                    output,
                    wait,
                    interval,
                    timeout,
                } => {
                    commands::scan::run_report(&client, scan_id, output, wait, interval, timeout)
                        .await
                }
                ScanCommand::Sbom { scan_id, output } => {
                    commands::scan::run_sbom(&client, scan_id, output).await
                }
                ScanCommand::CraReport {
                    scan_id,
                    output,
                    wait,
                    interval,
                    timeout,
                } => {
                    commands::scan::run_cra_report(
                        &client, scan_id, output, wait, interval, timeout,
                    )
                    .await
                }
                ScanCommand::Types => commands::scan::run_types(&client, format).await,
            }
        }
    }
}

fn make_client(
    api_key: Option<&str>,
    url: Option<&str>,
    profile: Option<&str>,
) -> Result<AnalyzerClient> {
    let cfg = config::resolve(api_key, url, profile)?;
    AnalyzerClient::new(cfg.url, &cfg.api_key)
}
