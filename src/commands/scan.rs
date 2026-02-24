//! Scan management commands.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use console::style;
use indicatif::ProgressBar;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::{
    AnalysisStatus, AnalysisStatusEntry, AnalysisType, CapabilityFinding, ComplianceReport,
    ComplianceType, CryptoFinding, CveFinding, HardeningFinding, IdfSymbolFinding, IdfTaskFinding,
    KernelFinding, MalwareFinding, PasswordFinding, ResultsQuery, SbomComponent, ScanTypeRequest,
};
use crate::output::{self, Format, format_score, format_status};

/// Resolve a scan ID from either an explicit --scan or an --object flag.
/// When --object is used, fetches the object and returns its last scan ID.
pub async fn resolve_scan_id(
    client: &AnalyzerClient,
    scan_id: Option<Uuid>,
    object_id: Option<Uuid>,
) -> Result<Uuid> {
    if let Some(sid) = scan_id {
        return Ok(sid);
    }
    if let Some(oid) = object_id {
        let object = client.get_object(oid).await?;
        let scan = object
            .last_scan
            .ok_or_else(|| anyhow::anyhow!("object {oid} has no scans yet"))?;
        return Ok(scan.status.id);
    }
    bail!("either --scan or --object must be provided")
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
                "\n  Check status:\n    {} {} --object {}",
                style("analyzer").bold(),
                style("scan status").cyan(),
                object_id,
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

/// Download a compliance report.
pub async fn run_compliance_report(
    client: &AnalyzerClient,
    scan_id: Uuid,
    ct: ComplianceType,
    output_path: PathBuf,
    wait: bool,
    interval: Duration,
    timeout: Duration,
) -> Result<()> {
    if wait {
        wait_for_completion(client, scan_id, interval, timeout).await?;
    }
    output::status(
        "Downloading",
        &format!("{} compliance report...", ct.display_name()),
    );
    let bytes = client.download_compliance_report(scan_id, ct).await?;
    tokio::fs::write(&output_path, &bytes).await?;
    output::success(&format!(
        "{} report saved to {}",
        ct.display_name(),
        output_path.display()
    ));
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
                eprintln!();
                eprintln!(
                    "  {:<20}  {}",
                    style("Analysis").underlined(),
                    style("Score").underlined(),
                );
                for s in &score.scores {
                    let score_str = format!("{:<5}", s.score);
                    let score_styled = if s.score >= 80 {
                        style(score_str).green().to_string()
                    } else if s.score >= 50 {
                        style(score_str).yellow().to_string()
                    } else {
                        style(score_str).red().to_string()
                    };
                    eprintln!("  {:<20}  {}", s.analysis_type, score_styled);
                }
            }
            eprintln!();
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

            let entries: Vec<_> = status
                .analyses
                .iter()
                .filter_map(|(key, val)| {
                    serde_json::from_value::<AnalysisStatusEntry>(val.clone())
                        .ok()
                        .map(|e| (key.clone(), e))
                })
                .collect();

            if !entries.is_empty() {
                eprintln!();
                eprintln!(
                    "  {:<20}  {}",
                    style("Analysis").underlined(),
                    style("Status").underlined(),
                );
                for (key, entry) in &entries {
                    eprintln!(
                        "  {:<20}  {}",
                        key,
                        format_status(&entry.status.to_string()),
                    );
                }
            }
            eprintln!();
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

// ===========================================================================
// Overview
// ===========================================================================

/// Show scan overview.
pub async fn run_overview(client: &AnalyzerClient, scan_id: Uuid, format: Format) -> Result<()> {
    let overview = client.get_scan_overview(scan_id).await?;

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&overview)?);
        }
        Format::Human | Format::Table => {
            eprintln!("\n  {} {}\n", style("Scan Overview").bold(), scan_id);

            if let Some(cve) = &overview.cve {
                let c = &cve.counts;
                eprintln!("  {} ({})", style("CVE Vulnerabilities").bold(), cve.total);
                eprintln!(
                    "    Critical: {}  High: {}  Medium: {}  Low: {}  Unknown: {}",
                    style(c.critical).red(),
                    style(c.high).red(),
                    style(c.medium).yellow(),
                    style(c.low).green(),
                    style(c.unknown).dim(),
                );
            }
            if let Some(m) = &overview.malware {
                eprintln!("  {}: {}", style("Malware Detections").bold(), m.count);
            }
            if let Some(p) = &overview.password_hash {
                eprintln!("  {}: {}", style("Password Issues").bold(), p.count);
            }
            if let Some(h) = &overview.hardening {
                let c = &h.counts;
                eprintln!("  {} ({})", style("Hardening Issues").bold(), h.total);
                eprintln!(
                    "    High: {}  Medium: {}  Low: {}",
                    style(c.high).red(),
                    style(c.medium).yellow(),
                    style(c.low).green(),
                );
            }
            if let Some(cap) = &overview.capabilities {
                eprintln!(
                    "  {} ({} executables)",
                    style("Capabilities").bold(),
                    cap.executable_count
                );
                let c = &cap.counts;
                eprintln!(
                    "    Critical: {}  High: {}  Medium: {}  Low: {}",
                    style(c.critical).red(),
                    style(c.high).red(),
                    style(c.medium).yellow(),
                    style(c.low).green(),
                );
            }
            if let Some(cr) = &overview.crypto {
                eprintln!(
                    "  {}: {} certs, {} public keys, {} private keys",
                    style("Crypto").bold(),
                    cr.certificates,
                    cr.public_keys,
                    cr.private_keys,
                );
            }
            if let Some(sbom) = &overview.software_bom {
                eprintln!(
                    "  {}: {} components",
                    style("Software BOM").bold(),
                    sbom.count
                );
            }
            if let Some(k) = &overview.kernel {
                eprintln!("  {}: {} configs", style("Kernel").bold(), k.count);
            }
            if let Some(s) = &overview.symbols {
                eprintln!("  {}: {}", style("Symbols").bold(), s.count);
            }
            if let Some(t) = &overview.tasks {
                eprintln!("  {}: {}", style("Tasks").bold(), t.count);
            }
            if let Some(so) = &overview.stack_overflow {
                if let Some(method) = &so.method {
                    eprintln!("  {}: {}", style("Stack Overflow").bold(), method);
                }
            }
            eprintln!();
        }
    }
    Ok(())
}

// ===========================================================================
// Results
// ===========================================================================

/// Resolve an analysis type name to its UUID by fetching the scan metadata.
async fn resolve_analysis_id(
    client: &AnalyzerClient,
    scan_id: Uuid,
    analysis_type: &AnalysisType,
) -> Result<Uuid> {
    let scan = client.get_scan(scan_id).await?;
    let api_name = analysis_type.api_name();

    for entry in &scan.analysis {
        if entry.entry_type.analyses.iter().any(|a| a == api_name) {
            return Ok(entry.id);
        }
    }

    let available: Vec<_> = scan
        .analysis
        .iter()
        .flat_map(|e| e.entry_type.analyses.iter())
        .collect();
    bail!(
        "analysis type '{}' not found in scan. Available: {}",
        api_name,
        available
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Browse analysis results.
pub async fn run_results(
    client: &AnalyzerClient,
    scan_id: Uuid,
    analysis_type: AnalysisType,
    page: Option<u32>,
    per_page: Option<u32>,
    search: Option<String>,
    format: Format,
) -> Result<()> {
    let analysis_id = resolve_analysis_id(client, scan_id, &analysis_type).await?;

    let page = page.unwrap_or(1);
    let per_page = per_page.unwrap_or(25);
    let query = ResultsQuery {
        page,
        per_page,
        sort_by: analysis_type.default_sort_by().to_string(),
        sort_ord: "asc".to_string(),
        search,
    };

    let results = client
        .get_analysis_results(scan_id, analysis_id, &query)
        .await?;

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        Format::Human | Format::Table => {
            let all_values: Vec<&serde_json::Value> = results.findings.iter().collect();

            if all_values.is_empty() {
                eprintln!("\n  No findings.\n");
                return Ok(());
            }

            match analysis_type {
                AnalysisType::Cve => render_cve_table(&all_values)?,
                AnalysisType::PasswordHash => render_password_table(&all_values)?,
                AnalysisType::Malware => render_malware_table(&all_values)?,
                AnalysisType::Hardening => render_hardening_table(&all_values)?,
                AnalysisType::Capabilities => render_capabilities_table(&all_values)?,
                AnalysisType::Crypto => render_crypto_table(&all_values)?,
                AnalysisType::SoftwareBom => render_sbom_table(&all_values)?,
                AnalysisType::Kernel => render_kernel_table(&all_values)?,
                AnalysisType::Symbols => render_symbols_table(&all_values)?,
                AnalysisType::Tasks => render_tasks_table(&all_values)?,
                AnalysisType::Info => render_info(&all_values)?,
                AnalysisType::StackOverflow => render_info(&all_values)?,
            }

            let total_pages = results.total_findings.div_ceil(per_page as u64);
            eprintln!(
                "\n  Page {}/{} ({} total) — use --page N to navigate\n",
                page, total_pages, results.total_findings,
            );
        }
    }
    Ok(())
}

fn render_cve_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<8}  {:<15}  {:<5}  {:<14}  {:<20}  {}",
        style("Severity").underlined(),
        style("CVE ID").underlined(),
        style("Score").underlined(),
        style("Vendor").underlined(),
        style("Product").underlined(),
        style("Summary").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<CveFinding>((*val).clone()) {
            let score_str = f
                .cvss
                .as_ref()
                .and_then(|c| c.v3.as_ref().or(c.v2.as_ref()))
                .and_then(|d| d.base_score)
                .map(|s| format!("{s:.1}"))
                .unwrap_or_default();
            let sev = format_severity(f.severity.as_deref().unwrap_or("unknown"), 8);
            let product = f
                .products
                .first()
                .and_then(|p| p.product.as_deref())
                .unwrap_or("-");
            let summary = f.summary.as_deref().unwrap_or("");
            let summary_trunc = if summary.len() > 40 {
                format!("{}...", &summary[..37])
            } else {
                summary.to_string()
            };
            eprintln!(
                "  {}  {:<15}  {:<5}  {:<14}  {:<20}  {}",
                sev,
                f.cveid.as_deref().unwrap_or("-"),
                score_str,
                truncate_str(f.vendor.as_deref().unwrap_or("-"), 14),
                truncate_str(product, 20),
                summary_trunc,
            );
        }
    }
    Ok(())
}

fn render_password_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<8}  {:<20}  {}",
        style("Severity").underlined(),
        style("Username").underlined(),
        style("Password").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<PasswordFinding>((*val).clone()) {
            let sev = format_severity(f.severity.as_deref().unwrap_or("unknown"), 8);
            eprintln!(
                "  {}  {:<20}  {}",
                sev,
                f.username.as_deref().unwrap_or("-"),
                f.password.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

fn render_malware_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<30}  {:<40}  {}",
        style("Filename").underlined(),
        style("Description").underlined(),
        style("Engine").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<MalwareFinding>((*val).clone()) {
            eprintln!(
                "  {:<30}  {:<40}  {}",
                truncate_str(f.filename.as_deref().unwrap_or("-"), 30),
                truncate_str(f.description.as_deref().unwrap_or("-"), 40),
                f.detection_engine.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

fn render_hardening_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<8}  {:<30}  {:<6}  {:<3}  {:<7}  {:<7}  {}",
        style("Severity").underlined(),
        style("Filename").underlined(),
        style("Canary").underlined(),
        style("NX").underlined(),
        style("PIE").underlined(),
        style("RELRO").underlined(),
        style("Fortify").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<HardeningFinding>((*val).clone()) {
            let sev = format_severity(f.severity.as_deref().unwrap_or("unknown"), 8);
            eprintln!(
                "  {}  {:<30}  {}  {}  {:<7}  {:<7}  {}",
                sev,
                truncate_str(f.filename.as_deref().unwrap_or("-"), 30),
                format_bool(f.canary.unwrap_or(false), 6),
                format_bool(f.nx.unwrap_or(false), 3),
                f.pie.as_deref().unwrap_or("-"),
                f.relro.as_deref().unwrap_or("-"),
                format_bool(f.fortify.unwrap_or(false), 7),
            );
        }
    }
    Ok(())
}

fn render_capabilities_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<30}  {:<8}  {:<9}  {}",
        style("Filename").underlined(),
        style("Severity").underlined(),
        style("Behaviors").underlined(),
        style("Syscalls").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<CapabilityFinding>((*val).clone()) {
            let sev = format_severity(f.level.as_deref().unwrap_or("unknown"), 8);
            eprintln!(
                "  {:<30}  {}  {:<9}  {}",
                truncate_str(f.filename.as_deref().unwrap_or("-"), 30),
                sev,
                f.behaviors.len(),
                f.syscalls.len(),
            );
        }
    }
    Ok(())
}

/// Format a severity string with color and fixed-width padding.
fn format_severity(severity: &str, width: usize) -> String {
    let padded = format!("{:<width$}", severity.to_uppercase(), width = width);
    match severity.to_lowercase().as_str() {
        "critical" => style(padded).red().bold().to_string(),
        "high" => style(padded).red().to_string(),
        "medium" => style(padded).yellow().to_string(),
        "low" => style(padded).green().to_string(),
        _ => style(padded).dim().to_string(),
    }
}

/// Truncate a string to max chars, adding "..." if needed.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        format!("{:<width$}", s, width = max)
    }
}

/// Format a boolean as colored Yes/No with fixed-width padding.
fn format_bool(val: bool, width: usize) -> String {
    if val {
        style(format!("{:<width$}", "Yes", width = width))
            .green()
            .to_string()
    } else {
        style(format!("{:<width$}", "No", width = width))
            .red()
            .to_string()
    }
}

fn render_crypto_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<14}  {:<20}  {:<20}  {:<8}  {}",
        style("Type").underlined(),
        style("Filename").underlined(),
        style("Path").underlined(),
        style("Key Size").underlined(),
        style("Aux").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<CryptoFinding>((*val).clone()) {
            let aux = if f.aux.is_empty() {
                "-".to_string()
            } else {
                f.aux.join(", ")
            };
            eprintln!(
                "  {:<14}  {:<20}  {:<20}  {:<8}  {}",
                truncate_str(f.crypto_type.as_deref().unwrap_or("-"), 14),
                truncate_str(f.filename.as_deref().unwrap_or("-"), 20),
                truncate_str(f.parent.as_deref().unwrap_or("-"), 20),
                f.pubsz.map(|s| s.to_string()).as_deref().unwrap_or("-"),
                truncate_str(&aux, 30),
            );
        }
    }
    Ok(())
}

fn render_sbom_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<30}  {:<14}  {:<12}  {}",
        style("Name").underlined(),
        style("Version").underlined(),
        style("Type").underlined(),
        style("Licenses").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<SbomComponent>((*val).clone()) {
            let licenses = f
                .licenses
                .iter()
                .filter_map(|l| {
                    l.get("license")
                        .and_then(|lic| lic.get("id").or_else(|| lic.get("name")))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "  {:<30}  {:<14}  {:<12}  {}",
                truncate_str(f.name.as_deref().unwrap_or("-"), 30),
                truncate_str(f.version.as_deref().unwrap_or("-"), 14),
                f.component_type.as_deref().unwrap_or("-"),
                if licenses.is_empty() { "-" } else { &licenses },
            );
        }
    }
    Ok(())
}

fn render_kernel_table(values: &[&serde_json::Value]) -> Result<()> {
    for val in values {
        if let Ok(f) = serde_json::from_value::<KernelFinding>((*val).clone()) {
            if let Some(file) = &f.file {
                eprintln!("\n  {} {}", style("Kernel Config:").bold(), file);
            }
            if let Some(score) = f.score {
                eprintln!("  Score: {}", score);
            }
            eprintln!();
            eprintln!(
                "  {:<40}  {}",
                style("Feature").underlined(),
                style("Status").underlined(),
            );
            for feat in &f.features {
                eprintln!("  {:<40}  {}", feat.name, format_bool(feat.enabled, 8),);
            }
        }
    }
    Ok(())
}

fn render_symbols_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<40}  {:<12}  {}",
        style("Name").underlined(),
        style("Type").underlined(),
        style("Bind").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<IdfSymbolFinding>((*val).clone()) {
            eprintln!(
                "  {:<40}  {:<12}  {}",
                truncate_str(f.symbol_name.as_deref().unwrap_or("-"), 40),
                f.symbol_type.as_deref().unwrap_or("-"),
                f.symbol_bind.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

fn render_tasks_table(values: &[&serde_json::Value]) -> Result<()> {
    eprintln!();
    eprintln!(
        "  {:<30}  {}",
        style("Name").underlined(),
        style("Function").underlined(),
    );
    for val in values {
        if let Ok(f) = serde_json::from_value::<IdfTaskFinding>((*val).clone()) {
            eprintln!(
                "  {:<30}  {}",
                truncate_str(f.task_name.as_deref().unwrap_or("-"), 30),
                f.task_fn.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}

fn render_info(values: &[&serde_json::Value]) -> Result<()> {
    for val in values {
        eprintln!("\n{}", serde_json::to_string_pretty(val)?);
    }
    Ok(())
}

// ===========================================================================
// Compliance
// ===========================================================================

/// Show compliance check results.
pub async fn run_compliance(
    client: &AnalyzerClient,
    scan_id: Uuid,
    ct: ComplianceType,
    format: Format,
) -> Result<()> {
    let report = client.get_compliance(scan_id, ct).await?;

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Format::Human | Format::Table => {
            render_compliance_human(&report, ct);
        }
    }
    Ok(())
}

fn render_compliance_human(report: &ComplianceReport, ct: ComplianceType) {
    let c = &report.checks;
    eprintln!(
        "\n  {} — {}\n",
        style(format!("{} Compliance Report", ct.display_name())).bold(),
        &report.name,
    );
    eprintln!(
        "  {} passed  {} failed  {} unknown  {} N/A  ({} total)\n",
        style(c.passed).green(),
        style(c.failed).red(),
        style(c.unknown).yellow(),
        style(c.not_applicable).dim(),
        c.total,
    );

    for section in &report.sections {
        eprintln!(
            "  {} ({})",
            style(&section.label).bold(),
            section.policy_ref
        );

        for sub in &section.sub_sections {
            eprintln!("    {}", style(&sub.label).underlined());
            eprintln!();
            eprintln!(
                "    {:<8}  {:<16}  {}",
                style("ID").underlined(),
                style("Status").underlined(),
                style("Description").underlined(),
            );
            for req in &sub.requirements {
                let effective_status = req
                    .overwritten_status
                    .as_deref()
                    .unwrap_or(&req.analyzer_status);
                let desc = if req.description.len() > 60 {
                    format!("{}...", &req.description[..57])
                } else {
                    req.description.clone()
                };
                eprintln!(
                    "    {:<8}  {}  {}",
                    req.id,
                    format_compliance_status(effective_status, 16),
                    desc,
                );
            }
            eprintln!();
        }
    }
}

/// Format a compliance status string with color and fixed-width padding.
fn format_compliance_status(status: &str, width: usize) -> String {
    let normalized = status
        .to_lowercase()
        .replace("analyzer-", "")
        .replace("analyzer_", "");
    let padded = format!("{:<width$}", status, width = width);
    match normalized.as_str() {
        "passed" => style(padded).green().to_string(),
        "failed" => style(padded).red().to_string(),
        "unknown" => style(padded).yellow().to_string(),
        "not_applicable" | "not-applicable" | "notapplicable" => style(padded).dim().to_string(),
        _ => padded,
    }
}
