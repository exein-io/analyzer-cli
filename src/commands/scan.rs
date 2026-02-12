//! Scan management commands.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use console::style;
use indicatif::ProgressBar;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::{AnalysisStatus, AnalysisStatusEntry, ScanTypeRequest};
use crate::output::{self, Format, format_score, format_status, score_cell, status_cell, styled_table};

/// Create a new scan.
pub async fn run_new(
    client: &AnalyzerClient,
    object_id: Uuid,
    file: PathBuf,
    scan_type: String,
    analyses: Vec<String>,
    format: Format,
    wait: bool,
    interval: Duration,
    timeout: Duration,
) -> Result<()> {
    // If no analyses specified, fetch all available for this scan type.
    let analyses = if analyses.is_empty() {
        let types = client.get_scan_types().await?;
        let matching = types
            .iter()
            .find(|t| t.image_type == scan_type);
        match matching {
            Some(t) => t.analyses.iter().map(|a| a.analysis_type.clone()).collect(),
            None => bail!(
                "unknown scan type '{scan_type}'. Run `analyzer scan types` to see available types."
            ),
        }
    } else {
        analyses
    };

    let req = ScanTypeRequest {
        scan_type: scan_type.clone(),
        analyses: analyses.clone(),
    };

    let resp = client.create_scan(object_id, &file, &req).await?;

    match format {
        Format::Json if !wait => {
            println!("{}", serde_json::json!({ "id": resp.id }));
        }
        _ if !wait => {
            output::success(&format!("Scan {} created", style(resp.id).bold()));
            eprintln!(
                "\n  Check status:\n    {} {} --scan {}",
                style("analyzer").bold(),
                style("scan status").cyan(),
                resp.id,
            );
        }
        _ => {}
    }

    if wait {
        let status = wait_for_completion(client, resp.id, interval, timeout).await?;
        print_status(resp.id, &status, format)?;
    }

    Ok(())
}

/// Delete a scan.
pub async fn run_delete(client: &AnalyzerClient, id: Uuid) -> Result<()> {
    client.delete_scan(id).await?;
    output::success(&format!("Deleted scan {id}"));
    Ok(())
}

/// Cancel a running scan.
pub async fn run_cancel(client: &AnalyzerClient, id: Uuid) -> Result<()> {
    client.cancel_scan(id).await?;
    output::success(&format!("Cancelled scan {id}"));
    Ok(())
}

/// Show scan status.
pub async fn run_status(client: &AnalyzerClient, scan_id: Uuid, format: Format) -> Result<()> {
    let status = client.get_scan_status(scan_id).await?;
    print_status(scan_id, &status, format)
}

/// Download the PDF report.
pub async fn run_report(
    client: &AnalyzerClient,
    scan_id: Uuid,
    output_path: PathBuf,
    wait: bool,
    interval: Duration,
    timeout: Duration,
) -> Result<()> {
    if wait {
        wait_for_completion(client, scan_id, interval, timeout).await?;
    }
    output::status("Downloading", "PDF report...");
    let bytes = client.download_report(scan_id).await?;
    tokio::fs::write(&output_path, &bytes).await?;
    output::success(&format!("Report saved to {}", output_path.display()));
    Ok(())
}

/// Download the SBOM.
pub async fn run_sbom(
    client: &AnalyzerClient,
    scan_id: Uuid,
    output_path: PathBuf,
) -> Result<()> {
    output::status("Downloading", "SBOM...");
    let bytes = client.download_sbom(scan_id).await?;
    tokio::fs::write(&output_path, &bytes).await?;
    output::success(&format!("SBOM saved to {}", output_path.display()));
    Ok(())
}

/// Download the CRA compliance report.
pub async fn run_cra_report(
    client: &AnalyzerClient,
    scan_id: Uuid,
    output_path: PathBuf,
    wait: bool,
    interval: Duration,
    timeout: Duration,
) -> Result<()> {
    if wait {
        wait_for_completion(client, scan_id, interval, timeout).await?;
    }
    output::status("Downloading", "CRA compliance report...");
    let bytes = client.download_cra_report(scan_id).await?;
    tokio::fs::write(&output_path, &bytes).await?;
    output::success(&format!("CRA report saved to {}", output_path.display()));
    Ok(())
}

/// Show the security score for a scan.
pub async fn run_score(client: &AnalyzerClient, scan_id: Uuid, format: Format) -> Result<()> {
    let score = client.get_scan_score(scan_id).await?;

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(&score)?)?
            );
        }
        Format::Human | Format::Table => {
            eprintln!(
                "\n  {} {}",
                style("Overall Score:").bold(),
                format_score(score.score)
            );
            if !score.scores.is_empty() {
                let mut table = styled_table();
                table.set_header(vec!["Analysis", "Score"]);
                for s in &score.scores {
                    table.add_row(vec![
                        comfy_table::Cell::new(&s.analysis_type),
                        score_cell(Some(s.score)),
                    ]);
                }
                eprintln!("{table}");
            }
        }
    }
    Ok(())
}

/// List available scan types.
pub async fn run_types(client: &AnalyzerClient, format: Format) -> Result<()> {
    let types = client.get_scan_types().await?;

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(&types)?)?
            );
        }
        Format::Human | Format::Table => {
            for st in &types {
                eprintln!("\n  {}", style(&st.image_type).bold().underlined());
                for a in &st.analyses {
                    let marker = if a.default {
                        style(" (default)").dim().to_string()
                    } else {
                        String::new()
                    };
                    eprintln!("    - {}{marker}", a.analysis_type);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn print_status(
    scan_id: Uuid,
    status: &crate::client::models::ScanStatus,
    format: Format,
) -> Result<()> {
    match format {
        Format::Json => {
            let mut map = serde_json::Map::new();
            map.insert("id".into(), serde_json::to_value(scan_id)?);
            map.insert(
                "status".into(),
                serde_json::to_value(status.status.to_string())?,
            );
            for (key, val) in &status.analyses {
                if let Ok(entry) = serde_json::from_value::<AnalysisStatusEntry>(val.clone()) {
                    let mut m = serde_json::Map::new();
                    m.insert("id".into(), serde_json::to_value(entry.id)?);
                    m.insert("status".into(), serde_json::to_value(entry.status.to_string())?);
                    map.insert(key.clone(), serde_json::Value::Object(m));
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(map))?
            );
        }
        Format::Human | Format::Table => {
            eprintln!(
                "\n  {} {} ({})",
                style("Scan").bold(),
                scan_id,
                format_status(&status.status.to_string()),
            );

            let mut table = styled_table();
            table.set_header(vec!["Analysis", "Status"]);
            for (key, val) in &status.analyses {
                if let Ok(entry) = serde_json::from_value::<AnalysisStatusEntry>(val.clone()) {
                    table.add_row(vec![
                        comfy_table::Cell::new(key),
                        status_cell(&entry.status.to_string()),
                    ]);
                }
            }
            if table.row_count() > 0 {
                eprintln!("{table}");
            }
        }
    }
    Ok(())
}

/// Poll scan status until completion, error, or timeout.
async fn wait_for_completion(
    client: &AnalyzerClient,
    scan_id: Uuid,
    interval: Duration,
    timeout: Duration,
) -> Result<crate::client::models::ScanStatus> {
    let deadline = tokio::time::Instant::now() + timeout;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        indicatif::ProgressStyle::with_template("  {spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["   ", ".  ", ".. ", "...", " ..", "  .", "   "]),
    );
    spinner.enable_steady_tick(Duration::from_millis(120));
    spinner.set_message("Waiting for scan to complete...");

    loop {
        let status = client.get_scan_status(scan_id).await?;

        match status.status {
            AnalysisStatus::Success => {
                spinner.finish_and_clear();
                output::success("Scan completed successfully!");
                return Ok(status);
            }
            AnalysisStatus::Error => {
                spinner.finish_and_clear();
                bail!("Scan failed with error status");
            }
            AnalysisStatus::Canceled => {
                spinner.finish_and_clear();
                bail!("Scan was cancelled");
            }
            _ => {
                let mut parts = Vec::new();
                for (key, val) in &status.analyses {
                    if let Ok(entry) =
                        serde_json::from_value::<AnalysisStatusEntry>(val.clone())
                    {
                        let icon = match entry.status {
                            AnalysisStatus::Success => "done",
                            AnalysisStatus::InProgress => "running",
                            AnalysisStatus::Pending => "queued",
                            _ => "?",
                        };
                        parts.push(format!("{key}: {icon}"));
                    }
                }
                spinner.set_message(format!("Analyzing... [{}]", parts.join(", ")));
            }
        }

        if tokio::time::Instant::now() >= deadline {
            spinner.finish_and_clear();
            bail!(
                "Timed out waiting for scan to complete ({}s)",
                timeout.as_secs()
            );
        }

        tokio::time::sleep(interval).await;
    }
}
