//! Scan management commands.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use console::style;
use indicatif::ProgressBar;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::{AnalysisStatus, AnalysisStatusEntry, ScanTypeRequest};
use crate::output::{
    self, Format, format_score, format_status, score_cell, severity_cell, status_cell, styled_table,
};

/// List all scans.
pub async fn run_list(client: &AnalyzerClient, format: Format) -> Result<()> {
    let scans = client.list_scans().await?;

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(&scans)?)?
            );
        }
        Format::Human | Format::Table => {
            if scans.is_empty() {
                output::status("Scans", "None found. Create one with: analyzer scan new");
                return Ok(());
            }

            let mut table = styled_table();
            table.set_header(vec!["ID", "File", "Type", "Score", "Created"]);
            // Prevent the ID column from wrapping so UUIDs stay on one line.
            if let Some(col) = table.column_mut(0) {
                col.set_constraint(comfy_table::ColumnConstraint::ContentWidth);
            }

            for scan in &scans {
                let score = scan.score.as_ref().and_then(|s| s.score);

                table.add_row(vec![
                    comfy_table::Cell::new(scan.id),
                    comfy_table::Cell::new(&scan.image.file_name),
                    comfy_table::Cell::new(scan.image_type.as_deref().unwrap_or("-")),
                    score_cell(score),
                    comfy_table::Cell::new(scan.created.format("%Y-%m-%d %H:%M")),
                ]);
            }

            println!("{table}");
            output::status("Total", &format!("{} scan(s)", scans.len()));
        }
    }
    Ok(())
}

/// Create a new scan.
#[allow(clippy::too_many_arguments)]
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
        let matching = types.iter().find(|t| t.image_type == scan_type);
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
pub async fn run_sbom(client: &AnalyzerClient, scan_id: Uuid, output_path: PathBuf) -> Result<()> {
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

/// Show results for a specific analysis within a scan.
#[allow(clippy::too_many_arguments)]
pub async fn run_show(
    client: &AnalyzerClient,
    scan_id: Uuid,
    analysis: &str,
    page: u32,
    per_page: u32,
    sort_by: &str,
    sort_ord: &str,
    format: Format,
) -> Result<()> {
    // Resolve the analysis name to its UUID via the scan status.
    let status = client.get_scan_status(scan_id).await?;
    let entry_value = status.analyses.get(analysis).ok_or_else(|| {
        let available: Vec<&String> = status.analyses.keys().collect();
        anyhow::anyhow!(
            "analysis '{}' not found in scan. Available: {}",
            analysis,
            available
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let entry: crate::client::models::AnalysisStatusEntry =
        serde_json::from_value(entry_value.clone())?;

    let results = client
        .get_analysis_results(scan_id, entry.id, page, per_page, sort_by, sort_ord)
        .await?;

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        Format::Human | Format::Table => {
            // The API returns { "findings": [...], "filters": {...} }.
            // Extract the findings array for table rendering.
            let items = results
                .get("findings")
                .and_then(|v| v.as_array())
                .or_else(|| results.as_array());

            match items {
                Some(arr) if !arr.is_empty() => {
                    if let Some(first) = arr.first().and_then(|v| v.as_object()) {
                        let columns = build_columns(first);

                        let mut table = styled_table();
                        table.set_header(&columns);

                        for item in arr {
                            if let Some(obj) = item.as_object() {
                                let row: Vec<comfy_table::Cell> = columns
                                    .iter()
                                    .map(|col| {
                                        let text = match obj.get(col) {
                                            Some(serde_json::Value::String(s)) => s.clone(),
                                            Some(serde_json::Value::Null) => "-".to_string(),
                                            Some(v) => v.to_string(),
                                            None => "-".to_string(),
                                        };
                                        style_cell(col, text)
                                    })
                                    .collect();
                                table.add_row(row);
                            }
                        }

                        println!("{table}");
                        output::status("Total", &format!("{} result(s)", arr.len()));
                    } else {
                        println!("{}", serde_json::to_string_pretty(&results)?);
                    }
                }
                Some(_) => {
                    output::status("Results", "No results found for this analysis.");
                }
                None => {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            }
        }
    }
    Ok(())
}

// TODO: each analysis type should have its own column layout (ordering, hidden
// fields, primary field after severity, etc.) instead of using a generic renderer.

/// Build column list: severity first (if present), then the rest.
fn build_columns(first: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut cols = Vec::with_capacity(first.len());
    if first.contains_key("severity") {
        cols.push("severity".to_string());
    }
    for key in first.keys() {
        if key != "severity" {
            cols.push(key.clone());
        }
    }
    cols
}

/// Style a cell: severity gets colour + bold, everything else plain.
fn style_cell(col: &str, text: String) -> comfy_table::Cell {
    if col == "severity" {
        severity_cell(&text).add_attribute(comfy_table::Attribute::Bold)
    } else {
        comfy_table::Cell::new(text)
    }
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
                    m.insert(
                        "status".into(),
                        serde_json::to_value(entry.status.to_string())?,
                    );
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
                    if let Ok(entry) = serde_json::from_value::<AnalysisStatusEntry>(val.clone()) {
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
