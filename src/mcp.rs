//! MCP (Model Context Protocol) server mode.
//!
//! When the CLI is invoked with `--mcp`, this module runs an MCP server over
//! stdio, exposing Analyzer operations as structured tools for AI assistants.

use std::path::{Path, PathBuf};

use anyhow::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::{ErrorData as McpError, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::{
    AnalysisType, ComplianceType, CreateObject, ResultsQuery, ScanTypeRequest,
};
use crate::config::ConfigFile;

// ===========================================================================
// Parameter structs (serde + schemars for MCP tool schemas)
// ===========================================================================

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateObjectParams {
    /// Name for the new object.
    name: String,
    /// Optional description.
    description: Option<String>,
    /// Optional tags.
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ObjectIdParam {
    /// Object UUID.
    object_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CreateScanParams {
    /// Object UUID to scan against.
    object_id: String,
    /// Path to the firmware or container image file.
    file_path: String,
    /// Image type: "linux", "docker", or "idf".
    scan_type: String,
    /// Analysis types to run (e.g. ["cve", "software-bom"]).
    /// If omitted, all available analyses for the scan type are run.
    analyses: Option<Vec<String>>,
}

/// Identifies a scan — either by scan UUID directly, or by object UUID
/// (which resolves to the object's most recent scan).
#[derive(Debug, Deserialize, JsonSchema)]
struct ScanOrObjectParam {
    /// Scan UUID. Provide either scan_id or object_id.
    scan_id: Option<String>,
    /// Object UUID — resolves to the object's most recent scan.
    object_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DownloadParams {
    /// Scan UUID. Provide either scan_id or object_id.
    scan_id: Option<String>,
    /// Object UUID — resolves to the object's most recent scan.
    object_id: Option<String>,
    /// Output file path. If omitted, saves to ~/.cache/analyzer/downloads/<scan_id>/.
    output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ComplianceDownloadParams {
    /// Scan UUID. Provide either scan_id or object_id.
    scan_id: Option<String>,
    /// Object UUID — resolves to the object's most recent scan.
    object_id: Option<String>,
    /// Compliance standard: "cra" (Cyber Resilience Act).
    compliance_type: String,
    /// Output file path. If omitted, saves to ~/.cache/analyzer/downloads/<scan_id>/.
    output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ComplianceParams {
    /// Scan UUID. Provide either scan_id or object_id.
    scan_id: Option<String>,
    /// Object UUID — resolves to the object's most recent scan.
    object_id: Option<String>,
    /// Compliance standard: "cra" (Cyber Resilience Act).
    compliance_type: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AnalysisResultsParams {
    /// Scan UUID. Provide either scan_id or object_id.
    scan_id: Option<String>,
    /// Object UUID — resolves to the object's most recent scan.
    object_id: Option<String>,
    /// Analysis type: cve, password-hash, malware, hardening, capabilities, crypto,
    /// software-bom, kernel, info, symbols, tasks, stack-overflow.
    analysis_type: String,
    /// Page number (default: 1).
    page: Option<u32>,
    /// Results per page (default: 25).
    per_page: Option<u32>,
    /// Search / filter string.
    search: Option<String>,
}

// ===========================================================================
// MCP server
// ===========================================================================

#[derive(Clone)]
pub struct AnalyzerMcp {
    client: AnalyzerClient,
    tool_router: ToolRouter<Self>,
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl AnalyzerMcp {
    fn new(client: AnalyzerClient) -> Self {
        Self {
            client,
            tool_router: Self::tool_router(),
        }
    }

    // -- Object tools ---------------------------------------------------------

    #[tool(
        description = "[Read] List all objects (devices/products) in your Analyzer account. Returns JSON array with id, name, description, tags, score (current and previous Exein Rating), and last scan info."
    )]
    async fn list_objects(&self) -> Result<CallToolResult, McpError> {
        match self.client.list_objects().await {
            Ok(page) => ok_json(&page.data),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "[Write] Create a new object (device / product).")]
    async fn create_object(
        &self,
        Parameters(p): Parameters<CreateObjectParams>,
    ) -> Result<CallToolResult, McpError> {
        let req = CreateObject {
            name: p.name,
            description: p.description,
            tags: p.tags.unwrap_or_default(),
        };
        match self.client.create_object(&req).await {
            Ok(obj) => ok_json(&obj),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Critical] Delete an object by its UUID. This permanently removes the object and all associated scans."
    )]
    async fn delete_object(
        &self,
        Parameters(p): Parameters<ObjectIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.object_id)?;
        match self.client.delete_object(id).await {
            Ok(()) => ok_text(format!("Deleted object {id}")),
            Err(e) => ok_err(e),
        }
    }

    // -- Scan tools -----------------------------------------------------------

    #[tool(
        description = "[Write] Create a new firmware/container scan. Uploads the image file and starts analysis. Returns the scan UUID. Image types: 'linux' (firmware), 'docker' (containers), 'idf' (ESP-IDF). If analyses are omitted, all defaults for the scan type are run. After creation, poll get_scan_status until completion (typically 1-10 min)."
    )]
    async fn create_scan(
        &self,
        Parameters(p): Parameters<CreateScanParams>,
    ) -> Result<CallToolResult, McpError> {
        let object_id = parse_uuid(&p.object_id)?;
        let file_path = PathBuf::from(&p.file_path);

        if !file_path.exists() {
            return ok_text(format!("Error: file not found: {}", p.file_path));
        }

        // Resolve analyses: if empty, use all defaults for this scan type.
        let analyses = match p.analyses {
            Some(a) if !a.is_empty() => a,
            _ => {
                let types = self.client.get_scan_types().await.map_err(|e| {
                    McpError::internal_error(format!("Failed to fetch scan types: {e:#}"), None)
                })?;
                match types.iter().find(|t| t.image_type == p.scan_type) {
                    Some(t) => t.analyses.iter().map(|a| a.analysis_type.clone()).collect(),
                    None => {
                        return ok_text(format!(
                            "Error: unknown scan type '{}'. Use get_scan_types to see available types.",
                            p.scan_type
                        ));
                    }
                }
            }
        };

        let req = ScanTypeRequest {
            scan_type: p.scan_type,
            analyses,
        };

        match self.client.create_scan(object_id, &file_path, &req).await {
            Ok(resp) => ok_json(&serde_json::json!({ "scan_id": resp.id })),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Get the current status of a scan and its individual analyses. Each analysis has a status: 'pending' (queued), 'in-progress' (running), 'success' (done), 'error' (failed), 'canceled'. The overall scan status reflects the aggregate. Poll this until all analyses reach a terminal state (success/error/canceled). Accepts scan_id or object_id (resolves to most recent scan)."
    )]
    async fn get_scan_status(
        &self,
        Parameters(p): Parameters<ScanOrObjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        match self.client.get_scan_status(id).await {
            Ok(status) => ok_json(&status),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Get the Exein Rating (security score) for a completed scan. Score is 0-100 where LOWER IS BETTER: 0 = no issues (best), 100 = worst. Returns overall score plus per-analysis breakdown (cve, hardening, kernel, malware, password-hash, capabilities). A score of 0 means clean/no issues found. Accepts scan_id or object_id."
    )]
    async fn get_scan_score(
        &self,
        Parameters(p): Parameters<ScanOrObjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        match self.client.get_scan_score(id).await {
            Ok(score) => ok_json(&score),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] List available scan types and their analysis options. Returns image types (linux, docker, idf) with available analyses. Each analysis shows whether it runs by default."
    )]
    async fn get_scan_types(&self) -> Result<CallToolResult, McpError> {
        match self.client.get_scan_types().await {
            Ok(types) => ok_json(&types),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Get a scan overview — summary of all analyses with finding counts by severity. Shows CVE counts (critical/high/medium/low), malware detections, password issues, hardening issues, capabilities risk levels, crypto assets, SBOM component count, kernel configs. Use this for a quick assessment before drilling into specific analysis results. Accepts scan_id or object_id."
    )]
    async fn get_scan_overview(
        &self,
        Parameters(p): Parameters<ScanOrObjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        match self.client.get_scan_overview(id).await {
            Ok(overview) => ok_json(&overview),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Browse paginated analysis results for a specific analysis type. Returns detailed findings: CVE entries with CVSS scores, malware detections, hardening flags per binary, capabilities with risk levels, crypto assets, SBOM components, kernel security features, etc. Supports pagination (page, per_page) and search filtering. Analysis types: cve, password-hash, malware, hardening, capabilities, crypto, software-bom, kernel, info, symbols, tasks, stack-overflow. Accepts scan_id or object_id."
    )]
    async fn get_analysis_results(
        &self,
        Parameters(p): Parameters<AnalysisResultsParams>,
    ) -> Result<CallToolResult, McpError> {
        let scan_id =
            resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;

        let analysis_type = AnalysisType::from_api_name(&p.analysis_type).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "Unknown analysis type: '{}'. Valid types: cve, password-hash, malware, hardening, capabilities, crypto, software-bom, kernel, info, symbols, tasks, stack-overflow",
                    p.analysis_type
                ),
                None,
            )
        })?;

        let analysis_id =
            crate::commands::scan::resolve_analysis_id(&self.client, scan_id, &analysis_type)
                .await
                .map_err(|e| McpError::invalid_params(format!("{e:#}"), None))?;

        let query = ResultsQuery {
            page: p.page.unwrap_or(1),
            per_page: p.per_page.unwrap_or(25),
            sort_by: analysis_type.default_sort_by().to_string(),
            sort_ord: "asc".to_string(),
            search: p.search,
        };

        match self
            .client
            .get_analysis_results(scan_id, analysis_id, &query)
            .await
        {
            Ok(results) => ok_json(&results),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Get compliance check results for a scan. Returns structured compliance data with sections, requirements, and pass/fail/unknown status for each check. Supported compliance types: 'cra' (EU Cyber Resilience Act). The result includes total/passed/failed/unknown/not-applicable counts. Accepts scan_id or object_id."
    )]
    async fn get_compliance(
        &self,
        Parameters(p): Parameters<ComplianceParams>,
    ) -> Result<CallToolResult, McpError> {
        let scan_id =
            resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        let ct = parse_compliance_type(&p.compliance_type)?;
        match self.client.get_compliance(scan_id, ct).await {
            Ok(report) => ok_json(&report),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Download the SBOM (Software Bill of Materials) in CycloneDX JSON format. Saves to disk and returns the full JSON inline. The SBOM lists all software components found in the image: name, version, type, purl (Package URL), and licenses. Use this to understand the software supply chain, identify outdated packages, or cross-reference with CVE results. Accepts scan_id or object_id."
    )]
    async fn download_sbom(
        &self,
        Parameters(p): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&id.to_string(), "sbom.json"),
        };
        match self.client.download_sbom(id).await {
            Ok(bytes) => {
                let save_msg = match save_to_path(&path, &bytes).await {
                    Ok(()) => format!("[Saved to {}]", path.display()),
                    Err(e) => format!("[Could not save to disk: {e}]"),
                };
                // Return the JSON content inline so the AI can read it
                let content = String::from_utf8_lossy(&bytes);
                ok_text(format!("{save_msg}\n\n{content}"))
            }
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Download the PDF security report for a completed scan. The report includes: Exein Rating, firmware details (OS, arch, kernel), executive summary with critical findings, CVE list by product and severity, binary hardening analysis, kernel security modules status, and remediation recommendations. Saves to disk (binary PDF) — returns the file path only. Accepts scan_id or object_id."
    )]
    async fn download_report(
        &self,
        Parameters(p): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&id.to_string(), "report.pdf"),
        };
        match self.client.download_report(id).await {
            Ok(bytes) => match save_to_path(&path, &bytes).await {
                Ok(()) => ok_text(format!("Report saved to {}", path.display())),
                Err(e) => ok_text(format!("Error writing file: {e}")),
            },
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "[Read] Download a compliance report PDF. Supported types: 'cra' (EU Cyber Resilience Act). Assesses firmware compliance with regulatory requirements. Saves to disk (binary PDF) — returns the file path only. Accepts scan_id or object_id."
    )]
    async fn download_compliance_report(
        &self,
        Parameters(p): Parameters<ComplianceDownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        let ct = parse_compliance_type(&p.compliance_type)?;
        let default_name = format!("{}_report.pdf", p.compliance_type);
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&id.to_string(), &default_name),
        };
        match self.client.download_compliance_report(id, ct).await {
            Ok(bytes) => match save_to_path(&path, &bytes).await {
                Ok(()) => ok_text(format!(
                    "{} report saved to {}",
                    ct.display_name(),
                    path.display()
                )),
                Err(e) => ok_text(format!("Error writing file: {e}")),
            },
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "[Write] Cancel a running scan. Accepts scan_id or object_id.")]
    async fn cancel_scan(
        &self,
        Parameters(p): Parameters<ScanOrObjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        match self.client.cancel_scan(id).await {
            Ok(()) => ok_text(format!("Cancelled scan {id}")),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "[Critical] Delete a scan permanently. Accepts scan_id or object_id.")]
    async fn delete_scan(
        &self,
        Parameters(p): Parameters<ScanOrObjectParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = resolve_scan(&self.client, p.scan_id.as_deref(), p.object_id.as_deref()).await?;
        match self.client.delete_scan(id).await {
            Ok(()) => ok_text(format!("Deleted scan {id}")),
            Err(e) => ok_err(e),
        }
    }

    // -- Info tools -----------------------------------------------------------

    #[tool(
        description = "[Read] Show the currently resolved configuration: active profile name, Analyzer API URL, and masked API key. Useful to verify which account and server you are connected to."
    )]
    async fn whoami(&self) -> Result<CallToolResult, McpError> {
        let config = ConfigFile::load().unwrap_or_default();
        let profile_name =
            std::env::var("ANALYZER_PROFILE").unwrap_or_else(|_| config.default_profile.clone());
        let prof = config.profile(Some(&profile_name));

        let url = std::env::var("ANALYZER_URL")
            .ok()
            .or_else(|| prof.url.clone())
            .unwrap_or_else(|| "https://analyzer.exein.io/api/".to_string());

        let key = std::env::var("ANALYZER_API_KEY")
            .ok()
            .or_else(|| prof.api_key.clone());

        let masked_key = match &key {
            Some(k) if k.len() > 8 => format!("{}...{}", &k[..4], &k[k.len() - 4..]),
            Some(k) => format!("{}...", &k[..k.len().min(4)]),
            None => "(not set)".to_string(),
        };

        ok_text(format!(
            "Profile: {profile_name}\nURL: {url}\nAPI Key: {masked_key}"
        ))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler
// ---------------------------------------------------------------------------

#[tool_handler]
impl ServerHandler for AnalyzerMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Exein Analyzer MCP server — scan firmware and container images for \
                 vulnerabilities, generate SBOMs, and check compliance.\n\
                 \n\
                 ## Tool Access Classification\n\
                 Each tool is tagged [Read], [Write], or [Critical]:\n\
                 - **[Read]**: Safe, no side effects — call freely.\n\
                 - **[Write]**: Creates or modifies state — confirm with the user before calling.\n\
                 - **[Critical]**: Destructive/irreversible — always confirm with the user.\n\
                 \n\
                 ## Identifying Scans\n\
                 Most tools accept either `scan_id` (scan UUID) or `object_id` (object UUID). \
                 When `object_id` is provided, the object's most recent scan is used automatically. \
                 This lets you go from object to results without looking up scan IDs.\n\
                 \n\
                 ## Quick Start\n\
                 1. `list_objects` — see existing objects (devices/products).\n\
                 2. `get_scan_types` — discover available image types and analyses.\n\
                 3. `create_object` — create an object if needed.\n\
                 4. `create_scan` — upload and scan (provide object_id, file path, scan type).\n\
                 5. `get_scan_status` — poll until all analyses reach 'success'.\n\
                 6. `get_scan_overview` — quick summary of all findings.\n\
                 7. `get_analysis_results` — drill into specific analysis types.\n\
                 8. `get_scan_score`, `download_sbom`, `download_report` — scores and artifacts.\n\
                 9. `get_compliance` — check regulatory compliance (e.g. CRA).\n\
                 \n\
                 ## Image Types\n\
                 - **linux**: Linux firmware (OpenWrt, Yocto, Buildroot). All analyses.\n\
                 - **docker**: Docker/OCI containers.\n\
                 - **idf**: ESP-IDF firmware. Subset of analyses (info, cve, software-bom).\n\
                 \n\
                 ## Analysis Types\n\
                 cve, software-bom, malware, crypto, hardening, password-hash, kernel, \
                 capabilities, info, symbols (IDF), tasks (IDF), stack-overflow (IDF).\n\
                 \n\
                 ## Exein Rating (Security Score)\n\
                 0-100 where **lower is better** (0 = no issues, 100 = worst). \
                 Score 0 means best possible result. The overall score is a weighted aggregate \
                 of per-analysis scores.\n\
                 \n\
                 ## Compliance\n\
                 Supported standard: 'cra' (EU Cyber Resilience Act). \
                 `get_compliance` returns structured pass/fail results. \
                 `download_compliance_report` downloads the PDF.\n\
                 \n\
                 ## Downloads\n\
                 PDFs and SBOMs save to `~/.cache/analyzer/downloads/<scan_id>/` by default. \
                 The SBOM is also returned inline as JSON. PDF reports return only the file path."
                    .into(),
            ),
        }
    }
}

// ===========================================================================
// Entry point
// ===========================================================================

/// Start the MCP server over stdio.
pub async fn serve(
    api_key: Option<String>,
    url: Option<String>,
    profile: Option<String>,
) -> Result<()> {
    let cfg = crate::config::resolve(api_key.as_deref(), url.as_deref(), profile.as_deref())?;
    let client = AnalyzerClient::new(cfg.url, &cfg.api_key)?;
    let server = AnalyzerMcp::new(client);

    let service = server
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;

    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

fn parse_uuid(s: &str) -> Result<Uuid, McpError> {
    s.parse::<Uuid>()
        .map_err(|_| McpError::invalid_params(format!("Invalid UUID: {s}"), None))
}

fn parse_compliance_type(s: &str) -> Result<ComplianceType, McpError> {
    ComplianceType::from_name(s).ok_or_else(|| {
        McpError::invalid_params(
            format!("Unknown compliance type: '{s}'. Supported: cra"),
            None,
        )
    })
}

/// Resolve a scan ID from optional scan_id / object_id string params.
async fn resolve_scan(
    client: &AnalyzerClient,
    scan_id: Option<&str>,
    object_id: Option<&str>,
) -> Result<Uuid, McpError> {
    let scan_uuid = scan_id.map(parse_uuid).transpose()?;
    let object_uuid = object_id.map(parse_uuid).transpose()?;
    crate::commands::scan::resolve_scan_id(client, scan_uuid, object_uuid)
        .await
        .map_err(|e| McpError::invalid_params(format!("{e:#}"), None))
}

fn ok_json<T: serde::Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| McpError::internal_error(format!("JSON serialization error: {e}"), None))?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
}

fn ok_text(msg: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(msg)]))
}

fn ok_err(e: anyhow::Error) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(format!(
        "Error: {e:#}"
    ))]))
}

/// Build a path like `~/.cache/analyzer/downloads/<scan_id>/<filename>`.
fn downloads_path(scan_id: &str, filename: &str) -> PathBuf {
    let base = dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("analyzer")
        .join("downloads")
        .join(scan_id);
    base.join(filename)
}

/// Create parent directories and write bytes to a file.
async fn save_to_path(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, bytes).await
}
