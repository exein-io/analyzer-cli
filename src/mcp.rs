//! MCP (Model Context Protocol) server mode.
//!
//! When the CLI is invoked with `--mcp`, this module runs an MCP server over
//! stdio, exposing Analyzer operations as structured tools for AI assistants.

use std::path::PathBuf;

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
use crate::client::models::{ComplianceType, CreateObject, ResultsQuery, ScanTypeRequest};
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

#[derive(Debug, Deserialize, JsonSchema)]
struct ScanIdParam {
    /// Scan UUID.
    scan_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DownloadParams {
    /// Scan UUID.
    scan_id: String,
    /// Output file path. If omitted, saves to ~/.cache/analyzer/downloads/<scan_id>/.
    output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ComplianceDownloadParams {
    /// Scan UUID.
    scan_id: String,
    /// Compliance standard: "cra" (Cyber Resilience Act).
    compliance_type: String,
    /// Output file path. If omitted, saves to ~/.cache/analyzer/downloads/<scan_id>/.
    output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ComplianceParams {
    /// Scan UUID.
    scan_id: String,
    /// Compliance standard: "cra" (Cyber Resilience Act).
    compliance_type: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AnalysisResultsParams {
    /// Scan UUID.
    scan_id: String,
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

#[derive(Debug, Deserialize, JsonSchema)]
struct ConfigureProfileParams {
    /// API key to save.
    api_key: String,
    /// Server URL (default: https://analyzer.exein.io/api/).
    url: Option<String>,
    /// Profile name (default: "default").
    profile: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ConfigGetParams {
    /// Config key to read: "url", "api-key", or "default-profile".
    key: String,
    /// Profile to read from.
    profile: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ConfigSetParams {
    /// Config key to set: "url", "api-key", or "default-profile".
    key: String,
    /// Value to set.
    value: String,
    /// Profile to modify.
    profile: Option<String>,
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

    #[tool(description = "List all objects (devices/products) in your Analyzer account. Returns JSON array with id, name, description, tags, score (current and previous Exein Rating), and last scan info.")]
    async fn list_objects(&self) -> Result<CallToolResult, McpError> {
        match self.client.list_objects().await {
            Ok(page) => ok_json(&page.data),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Create a new object (device / product).")]
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

    #[tool(description = "Delete an object by its UUID.")]
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
        description = "Create a new firmware/container scan. Uploads the image file and starts analysis. Returns the scan UUID. Image types: 'linux' (firmware), 'docker' (containers), 'idf' (ESP-IDF). If analyses are omitted, all defaults for the scan type are run. After creation, poll get_scan_status until completion (typically 1-10 min)."
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

    #[tool(description = "Get the current status of a scan and its individual analyses. Each analysis has a status: 'pending' (queued), 'in-progress' (running), 'success' (done), 'error' (failed), 'canceled'. The overall scan status reflects the aggregate. Poll this until all analyses reach a terminal state (success/error/canceled).")]
    async fn get_scan_status(
        &self,
        Parameters(p): Parameters<ScanIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        match self.client.get_scan_status(id).await {
            Ok(status) => ok_json(&status),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Get the Exein Rating (security score) for a completed scan. Score is 0-100 where LOWER IS BETTER: 0 = no issues (best), 100 = worst. Returns overall score plus per-analysis breakdown (cve, hardening, kernel, malware, password-hash, capabilities). A score of 0 means clean/no issues found. Use this to identify which areas need improvement — higher scores indicate worse security posture.")]
    async fn get_scan_score(
        &self,
        Parameters(p): Parameters<ScanIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        match self.client.get_scan_score(id).await {
            Ok(score) => ok_json(&score),
            Err(e) => ok_err(e),
        }
    }

    #[tool(
        description = "List available scan types and their analysis options. Returns image types (linux, docker, idf) with available analyses. Each analysis shows whether it runs by default."
    )]
    async fn get_scan_types(&self) -> Result<CallToolResult, McpError> {
        match self.client.get_scan_types().await {
            Ok(types) => ok_json(&types),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Get a scan overview — summary of all analyses with finding counts by severity. Shows CVE counts (critical/high/medium/low), malware detections, password issues, hardening issues, capabilities risk levels, crypto assets, SBOM component count, kernel configs. Use this for a quick assessment before drilling into specific analysis results.")]
    async fn get_scan_overview(
        &self,
        Parameters(p): Parameters<ScanIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        match self.client.get_scan_overview(id).await {
            Ok(overview) => ok_json(&overview),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Browse paginated analysis results for a specific analysis type. Returns detailed findings: CVE entries with CVSS scores, malware detections, hardening flags per binary, capabilities with risk levels, crypto assets, SBOM components, kernel security features, etc. Supports pagination (page, per_page) and search filtering. Analysis types: cve, password-hash, malware, hardening, capabilities, crypto, software-bom, kernel, info, symbols, tasks, stack-overflow.")]
    async fn get_analysis_results(
        &self,
        Parameters(p): Parameters<AnalysisResultsParams>,
    ) -> Result<CallToolResult, McpError> {
        let scan_id = parse_uuid(&p.scan_id)?;

        // Resolve the analysis type to its UUID
        let scan = self.client.get_scan(scan_id).await.map_err(|e| {
            McpError::internal_error(format!("Failed to fetch scan: {e:#}"), None)
        })?;

        let analysis_id = scan
            .analysis
            .iter()
            .find(|entry| entry.entry_type.analyses.iter().any(|a| a == &p.analysis_type))
            .map(|entry| entry.id);

        let analysis_id = match analysis_id {
            Some(id) => id,
            None => {
                let available: Vec<_> = scan
                    .analysis
                    .iter()
                    .flat_map(|e| e.entry_type.analyses.iter())
                    .collect();
                return ok_text(format!(
                    "Error: analysis type '{}' not found in scan. Available: {}",
                    p.analysis_type,
                    available.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
        };

        let query = ResultsQuery {
            page: p.page.unwrap_or(1),
            per_page: p.per_page.unwrap_or(25),
            sort_by: default_sort_by(&p.analysis_type).to_string(),
            sort_ord: "asc".to_string(),
            search: p.search,
        };

        match self.client.get_analysis_results(scan_id, analysis_id, &query).await {
            Ok(results) => ok_json(&results),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Get compliance check results for a scan. Returns structured compliance data with sections, requirements, and pass/fail/unknown status for each check. Supported compliance types: 'cra' (EU Cyber Resilience Act). The result includes total/passed/failed/unknown/not-applicable counts.")]
    async fn get_compliance(
        &self,
        Parameters(p): Parameters<ComplianceParams>,
    ) -> Result<CallToolResult, McpError> {
        let scan_id = parse_uuid(&p.scan_id)?;
        let ct = parse_compliance_type(&p.compliance_type)?;
        match self.client.get_compliance(scan_id, ct).await {
            Ok(report) => ok_json(&report),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Download the SBOM (Software Bill of Materials) in CycloneDX JSON format. Saves to disk and returns the full JSON inline. The SBOM lists all software components found in the image: name, version, type, purl (Package URL), and licenses. Use this to understand the software supply chain, identify outdated packages, or cross-reference with CVE results.")]
    async fn download_sbom(
        &self,
        Parameters(p): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&p.scan_id, "sbom.json"),
        };
        match self.client.download_sbom(id).await {
            Ok(bytes) => {
                // Save to disk for the user
                let save_msg = match save_to_path(&path, &bytes).await {
                    Ok(()) => format!("[Saved to {}]", path.display()),
                    Err(e) => format!("[Could not save to disk: {e}]"),
                };
                // Return the JSON content inline so Claude can read it
                let content = String::from_utf8_lossy(&bytes);
                ok_text(format!("{save_msg}\n\n{content}"))
            }
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Download the PDF security report for a completed scan. The report includes: Exein Rating, firmware details (OS, arch, kernel), executive summary with critical findings, CVE list by product and severity, binary hardening analysis, kernel security modules status, and remediation recommendations. Saves to disk (binary PDF) — returns the file path only.")]
    async fn download_report(
        &self,
        Parameters(p): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&p.scan_id, "report.pdf"),
        };
        match self.client.download_report(id).await {
            Ok(bytes) => match save_to_path(&path, &bytes).await {
                Ok(()) => ok_text(format!("Report saved to {}", path.display())),
                Err(e) => ok_text(format!("Error writing file: {e}")),
            },
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Download a compliance report PDF. Supported types: 'cra' (EU Cyber Resilience Act). Assesses firmware compliance with regulatory requirements. Saves to disk (binary PDF) — returns the file path only.")]
    async fn download_compliance_report(
        &self,
        Parameters(p): Parameters<ComplianceDownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        let ct = parse_compliance_type(&p.compliance_type)?;
        let default_name = format!("{}_report.pdf", p.compliance_type);
        let path = match &p.output_path {
            Some(p) => PathBuf::from(p),
            None => downloads_path(&p.scan_id, &default_name),
        };
        match self.client.download_compliance_report(id, ct).await {
            Ok(bytes) => match save_to_path(&path, &bytes).await {
                Ok(()) => ok_text(format!("{} report saved to {}", ct.display_name(), path.display())),
                Err(e) => ok_text(format!("Error writing file: {e}")),
            },
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Cancel a running scan.")]
    async fn cancel_scan(
        &self,
        Parameters(p): Parameters<ScanIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        match self.client.cancel_scan(id).await {
            Ok(()) => ok_text(format!("Cancelled scan {id}")),
            Err(e) => ok_err(e),
        }
    }

    #[tool(description = "Delete a scan.")]
    async fn delete_scan(
        &self,
        Parameters(p): Parameters<ScanIdParam>,
    ) -> Result<CallToolResult, McpError> {
        let id = parse_uuid(&p.scan_id)?;
        match self.client.delete_scan(id).await {
            Ok(()) => ok_text(format!("Deleted scan {id}")),
            Err(e) => ok_err(e),
        }
    }

    // -- Config tools ---------------------------------------------------------

    #[tool(
        description = "Configure an Analyzer profile with an API key and optional URL. Validates the key against the server before saving."
    )]
    async fn configure_profile(
        &self,
        Parameters(p): Parameters<ConfigureProfileParams>,
    ) -> Result<CallToolResult, McpError> {
        let profile_name = p.profile.as_deref().unwrap_or("default");
        let url = p
            .url
            .unwrap_or_else(|| "https://analyzer.exein.io/api/".to_string());

        // Validate the key
        let parsed_url: url::Url = url.parse().map_err(|_| {
            McpError::invalid_params(format!("Invalid URL: {url}"), None)
        })?;
        let client = AnalyzerClient::new(parsed_url, &p.api_key).map_err(|e| {
            McpError::internal_error(format!("Failed to create client: {e:#}"), None)
        })?;

        let validation = match client.health().await {
            Ok(_) => "Key validated successfully.",
            Err(_) => "Could not validate key (server may be unreachable). Saving anyway.",
        };

        // Save
        let mut config = ConfigFile::load().unwrap_or_default();
        let profile = config.profile_mut(profile_name);
        profile.api_key = Some(p.api_key);
        profile.url = Some(url.clone());
        config.save().map_err(|e| {
            McpError::internal_error(format!("Failed to save config: {e:#}"), None)
        })?;

        ok_text(format!(
            "{validation}\nProfile '{profile_name}' saved (URL: {url})."
        ))
    }

    #[tool(description = "Get a configuration value. Valid keys: url, api-key, default-profile.")]
    async fn config_get(
        &self,
        Parameters(p): Parameters<ConfigGetParams>,
    ) -> Result<CallToolResult, McpError> {
        let config = ConfigFile::load().unwrap_or_default();
        let profile_name = p.profile.as_deref().unwrap_or(&config.default_profile);
        let prof = config.profile(Some(profile_name));

        let value = match p.key.as_str() {
            "url" => prof.url.as_deref().unwrap_or("(not set)").to_string(),
            "api-key" | "api_key" => {
                if prof.api_key.is_some() {
                    "(set)".to_string()
                } else {
                    "(not set)".to_string()
                }
            }
            "default-profile" | "default_profile" => config.default_profile.clone(),
            other => {
                return ok_text(format!(
                    "Unknown config key: {other}. Valid keys: url, api-key, default-profile"
                ));
            }
        };

        ok_text(format!("{} = {}", p.key, value))
    }

    #[tool(description = "Set a configuration value. Valid keys: url, api-key, default-profile.")]
    async fn config_set(
        &self,
        Parameters(p): Parameters<ConfigSetParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut config = ConfigFile::load().unwrap_or_default();
        let profile_name = p.profile.as_deref().unwrap_or("default");
        let prof = config.profile_mut(profile_name);

        match p.key.as_str() {
            "url" => {
                let _: url::Url = p.value.parse().map_err(|_| {
                    McpError::invalid_params(format!("Invalid URL: {}", p.value), None)
                })?;
                prof.url = Some(p.value.clone());
            }
            "api-key" | "api_key" => {
                prof.api_key = Some(p.value.clone());
            }
            "default-profile" | "default_profile" => {
                config.default_profile = p.value.clone();
            }
            other => {
                return ok_text(format!(
                    "Unknown config key: {other}. Valid keys: url, api-key, default-profile"
                ));
            }
        }

        config.save().map_err(|e| {
            McpError::internal_error(format!("Failed to save config: {e:#}"), None)
        })?;

        ok_text(format!(
            "Set {} = {} (profile: {profile_name})",
            p.key, p.value
        ))
    }

    #[tool(description = "Show the currently resolved configuration: active profile name, Analyzer API URL, and masked API key. Useful to verify which account and server you are connected to.")]
    async fn whoami(&self) -> Result<CallToolResult, McpError> {
        let config = ConfigFile::load().unwrap_or_default();
        let profile_name = std::env::var("ANALYZER_PROFILE")
            .unwrap_or_else(|_| config.default_profile.clone());
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
                 ## Quick Start\n\
                 1. Call `list_objects` to see existing objects (devices/products).\n\
                 2. Call `get_scan_types` to discover available image types and analyses.\n\
                 3. Create an object with `create_object` if needed.\n\
                 4. Upload and scan with `create_scan` (provide object_id, file path, scan type).\n\
                 5. Poll `get_scan_status` until all analyses reach 'success' (or 'error').\n\
                 6. Use `get_scan_overview` for a quick summary of all findings.\n\
                 7. Drill down with `get_analysis_results` for specific analysis types.\n\
                 8. Retrieve scores and downloads: `get_scan_score`, `download_sbom`, \
                    `download_report`, `download_compliance_report`.\n\
                 9. Check compliance with `get_compliance` (e.g. CRA).\n\
                 \n\
                 ## Image Types\n\
                 - **linux**: Linux firmware images (e.g. OpenWrt, Yocto, Buildroot). Supports all analyses.\n\
                 - **docker**: Docker/OCI container images.\n\
                 - **idf**: ESP-IDF firmware images (Espressif IoT Development Framework). \
                   Supports a subset of analyses (info, cve, software-bom). \
                   Hardening and kernel-security checks are not applicable to bare-metal RTOS targets.\n\
                 \n\
                 ## Analysis Types\n\
                 - **info**: Extracts firmware metadata — OS, architecture, kernel version.\n\
                 - **cve**: CVE vulnerability scan powered by Kepler (Exein open-source tool using NIST NVD). \
                   Finds known vulnerabilities in software components. Results are grouped by product with \
                   severity breakdown: Critical, High, Medium, Low.\n\
                 - **software-bom**: Generates the Software Bill of Materials (SBOM) in CycloneDX JSON format. \
                   Lists all software components, versions, and licenses found in the image.\n\
                 - **malware**: Scans the filesystem for known malicious files (malware, trojans, etc.).\n\
                 - **crypto**: Cryptographic analysis — identifies certificates, public/private keys.\n\
                 - **hardening**: Binary hardening checks — verifies compiler security flags for each executable: \
                   Stack Canary, NX (non-executable stack), PIE (position-independent), RELRO (relocation read-only), \
                   Fortify Source. Reports weak binaries count.\n\
                 - **password-hash**: Detects hard-coded weak passwords in the firmware filesystem.\n\
                 - **kernel**: Checks kernel security modules: SECCOMP, SELINUX, APPARMOR, KASLR, \
                   STACKPROTECTOR, FORTIFYSOURCE, etc. Reports enabled/not-enabled status.\n\
                 - **capabilities**: Analyzes executable capabilities and syscalls, assigning risk levels.\n\
                 - **symbols** (IDF only): Lists symbols from ESP-IDF firmware.\n\
                 - **tasks** (IDF only): Lists RTOS tasks.\n\
                 - **stack-overflow** (IDF only): Stack overflow detection method.\n\
                 \n\
                 ## Exein Rating (Security Score)\n\
                 - Score is 0-100, where **lower is better** (0 = best, 100 = worst).\n\
                 - 0: Perfect — no issues found in this category.\n\
                 - 1-30: Good security posture.\n\
                 - 31-59: Mediocre — address higher-risk vulnerabilities.\n\
                 - 60-100: Poor — critical security issues require immediate attention.\n\
                 - The overall score is a weighted aggregate of individual analysis scores.\n\
                 - Per-analysis scores: malware=0 means clean (no malware), cve=100 means \
                   severe vulnerability exposure, hardening=50 means partial compiler protections, etc.\n\
                 - IMPORTANT: Do NOT interpret score 0 as 'bad'. Score 0 means the best possible result \
                   (no issues detected). Score 100 is the worst.\n\
                 \n\
                 ## Browsing Results\n\
                 - Use `get_scan_overview` first for a high-level summary of all analyses.\n\
                 - Then use `get_analysis_results` with a specific analysis_type to browse detailed findings.\n\
                 - Results are paginated (default 25 per page). Use page/per_page params to navigate.\n\
                 - Use the search param to filter results (e.g. search='openssl' for CVEs).\n\
                 \n\
                 ## Compliance\n\
                 - `get_compliance` returns structured compliance check results (pass/fail per requirement).\n\
                 - `download_compliance_report` downloads the full PDF compliance report.\n\
                 - Supported standard: 'cra' (EU Cyber Resilience Act).\n\
                 \n\
                 ## Scan Status\n\
                 - Each analysis within a scan has its own status: pending → in-progress → success | error | canceled.\n\
                 - The overall scan status reflects the aggregate of all analyses.\n\
                 - Scans typically take 1-10 minutes depending on image size and analyses requested.\n\
                 \n\
                 ## Downloaded Files\n\
                 - PDF reports and SBOMs are saved to `~/.cache/analyzer/downloads/<scan_id>/` by default.\n\
                 - The SBOM (download_sbom) is also returned inline as JSON so you can analyze it directly.\n\
                 - PDF reports (download_report, download_compliance_report) are binary files saved to disk — \
                   the tool returns only the file path. Use a filesystem MCP server to access them if needed.\n\
                 \n\
                 ## SBOM Format\n\
                 - Format: CycloneDX JSON (ECMA-424, 1st edition June 2024 / CycloneDX 1.6).\n\
                 - Also compatible with: SPDX 3.0.1 (on request via download_sbom parameters).\n\
                 - Key fields: `components[]` array with `name`, `version`, `type`, `purl` (Package URL), `licenses`.\n\
                 - Use the SBOM to understand the full software supply chain of the scanned image."
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
    match s.to_lowercase().as_str() {
        "cra" => Ok(ComplianceType::Cra),
        other => Err(McpError::invalid_params(
            format!("Unknown compliance type: '{other}'. Supported: cra"),
            None,
        )),
    }
}

/// Default sort-by field for a given analysis type API name.
fn default_sort_by(analysis_type: &str) -> &'static str {
    match analysis_type {
        "cve" | "password-hash" | "hardening" | "capabilities" => "severity",
        "malware" => "filename",
        "crypto" => "type",
        "software-bom" | "info" | "symbols" | "stack-overflow" => "name",
        "kernel" => "features",
        "tasks" => "function",
        _ => "name",
    }
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
async fn save_to_path(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, bytes).await
}
