//! Data models matching the Analyzer API JSON contract.
//!
//! These types are owned by the CLI and match the API's serialization format.
//! No dependency on the `analyzer-api` crate.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// === Pagination ===

#[derive(Debug, Deserialize)]
pub struct Page<T> {
    pub data: Vec<T>,
    #[allow(dead_code)]
    #[serde(default, rename = "_links")]
    pub links: PageLinks,
}

#[derive(Debug, Default, Deserialize)]
pub struct PageLinks {
    #[allow(dead_code)]
    pub next: Option<PageLink>,
}

#[derive(Debug, Deserialize)]
pub struct PageLink {
    #[allow(dead_code)]
    pub href: String,
}

// === Objects ===

#[derive(Debug, Serialize, Deserialize)]
pub struct Object {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    pub updated_on: Option<DateTime<Utc>>,
    pub created_on: DateTime<Utc>,
    pub score: Option<ObjectScore>,
    pub last_scan: Option<LastScan>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectScore {
    pub current: Option<ScoreEntry>,
    pub previous: Option<ScoreEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreEntry {
    pub scan_id: Uuid,
    pub created_on: DateTime<Utc>,
    pub value: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LastScan {
    pub status: ScanStatus,
    pub score: Option<ScanScore>,
}

#[derive(Debug, Serialize)]
pub struct CreateObject {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

// === Scans ===

#[derive(Debug, Deserialize)]
pub struct NewScanResponse {
    pub id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub image: ScanImage,
    pub created: DateTime<Utc>,
    pub analysis: Vec<AnalysisEntry>,
    pub image_type: Option<String>,
    pub info: Option<serde_json::Value>,
    pub score: Option<ScanScore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanImage {
    pub id: Uuid,
    pub file_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisEntry {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub entry_type: AnalysisEntryType,
    pub status: AnalysisStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisEntryType {
    #[serde(rename = "type")]
    pub analysis_type: String,
    pub analyses: Vec<String>,
}

// === Scan Status ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: Uuid,
    pub status: AnalysisStatus,
    #[serde(flatten)]
    pub analyses: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisStatus {
    Success,
    Pending,
    InProgress,
    Canceled,
    Error,
}

impl fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in-progress"),
            Self::Canceled => write!(f, "canceled"),
            Self::Error => write!(f, "error"),
        }
    }
}

// === Scan Score ===

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanScore {
    pub score: Option<u8>,
    pub scores: Vec<AnalysisScore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisScore {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub analysis_type: String,
    pub score: u8,
}

// === Scan Types ===

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiScanType {
    #[serde(rename = "type")]
    pub image_type: String,
    pub analyses: Vec<ApiAnalysisType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiAnalysisType {
    #[serde(rename = "type")]
    pub analysis_type: String,
    #[serde(default)]
    pub default: bool,
}

// === Scan Type for creating scans (multipart JSON field) ===

#[derive(Debug, Serialize)]
pub struct ScanTypeRequest {
    #[serde(rename = "type")]
    pub scan_type: String,
    pub analyses: Vec<String>,
}

// === Health ===

#[derive(Debug, Deserialize)]
pub struct HealthStatus {
    #[allow(dead_code)]
    pub healthy: bool,
}

// === Analysis Status Entry (for parsing flattened scan status) ===

#[derive(Debug, Deserialize)]
pub struct AnalysisStatusEntry {
    pub id: Uuid,
    pub status: AnalysisStatus,
}

// === Scan Overview ===

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanOverview {
    #[serde(default)]
    pub info: Option<serde_json::Value>,
    #[serde(default, rename = "password-hash")]
    pub password_hash: Option<CountOverview>,
    #[serde(default)]
    pub malware: Option<CountOverview>,
    #[serde(default)]
    pub hardening: Option<HardeningOverview>,
    #[serde(default)]
    pub cve: Option<CveOverview>,
    #[serde(default)]
    pub kernel: Option<CountOverview>,
    #[serde(default)]
    pub tasks: Option<CountOverview>,
    #[serde(default)]
    pub symbols: Option<CountOverview>,
    #[serde(default, rename = "software-bom")]
    pub software_bom: Option<SoftwareBomOverview>,
    #[serde(default)]
    pub capabilities: Option<CapabilitiesOverview>,
    #[serde(default)]
    pub crypto: Option<CryptoOverview>,
    #[serde(default, rename = "stack-overflow")]
    pub stack_overflow: Option<StackOverflowOverview>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CountOverview {
    pub count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveOverview {
    pub counts: CveSeverityCount,
    #[serde(default)]
    pub products: HashMap<String, u64>,
    pub total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveSeverityCount {
    #[serde(default)]
    pub critical: u64,
    #[serde(default)]
    pub high: u64,
    #[serde(default)]
    pub medium: u64,
    #[serde(default)]
    pub low: u64,
    #[serde(default)]
    pub unknown: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningOverview {
    pub counts: HardeningSeverityCount,
    pub total: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningSeverityCount {
    #[serde(default)]
    pub high: u64,
    #[serde(default)]
    pub medium: u64,
    #[serde(default)]
    pub low: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilitiesOverview {
    pub executable_count: u64,
    pub counts: RiskLevelCount,
    #[serde(default)]
    pub capabilities: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskLevelCount {
    #[serde(default)]
    pub critical: u64,
    #[serde(default)]
    pub high: u64,
    #[serde(default)]
    pub medium: u64,
    #[serde(default)]
    pub low: u64,
    #[serde(default)]
    pub none: u64,
    #[serde(default)]
    pub unknown: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoOverview {
    #[serde(default)]
    pub certificates: u64,
    #[serde(default)]
    pub public_keys: u64,
    #[serde(default)]
    pub private_keys: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoftwareBomOverview {
    pub count: u64,
    #[serde(default)]
    pub licenses: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StackOverflowOverview {
    pub method: Option<String>,
}

// === Analysis Results (paginated) ===

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResults {
    pub findings: Vec<serde_json::Value>,
    #[serde(rename = "total-findings")]
    pub total_findings: u64,
    #[serde(default)]
    pub filters: serde_json::Value,
}

/// Query parameters for the results endpoint.
pub struct ResultsQuery {
    pub page: u32,
    pub per_page: u32,
    pub sort_by: String,
    pub sort_ord: String,
    pub search: Option<String>,
}

// === Finding types ===

#[derive(Debug, Serialize, Deserialize)]
pub struct CveFinding {
    #[serde(default)]
    pub cveid: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub vector: Option<String>,
    #[serde(default)]
    pub cvss: Option<CvssScores>,
    #[serde(default)]
    pub products: Vec<CveProduct>,
    #[serde(default)]
    pub patch: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub problems: Vec<String>,
    #[serde(default)]
    pub published_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CvssScores {
    pub v3: Option<CvssDetail>,
    pub v2: Option<CvssDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CvssDetail {
    #[serde(default, alias = "baseScore")]
    pub base_score: Option<f64>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default, alias = "vectorString")]
    pub vector_string: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveProduct {
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordFinding {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MalwareFinding {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub detection_engine: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardeningFinding {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub canary: Option<bool>,
    #[serde(default)]
    pub nx: Option<bool>,
    #[serde(default)]
    pub pie: Option<String>,
    #[serde(default)]
    pub relro: Option<String>,
    #[serde(default)]
    pub fortify: Option<bool>,
    #[serde(default)]
    pub stripped: Option<bool>,
    #[serde(default)]
    pub suid: Option<bool>,
    #[serde(default)]
    pub execstack: Option<bool>,
    #[serde(default, rename = "type")]
    pub elf_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilityFinding {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub behaviors: Vec<CapabilityBehavior>,
    #[serde(default)]
    pub syscalls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CapabilityBehavior {
    #[serde(default, alias = "Description")]
    pub description: Option<String>,
    #[serde(default, alias = "ID")]
    pub id: Option<String>,
    #[serde(default, alias = "RiskLevel")]
    pub risk_level: Option<String>,
    #[serde(default, alias = "RiskScore")]
    pub risk_score: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoFinding {
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default, rename = "type")]
    pub crypto_type: Option<String>,
    #[serde(default)]
    pub subtype: Option<String>,
    #[serde(default)]
    pub pubsz: Option<u32>,
    #[serde(default)]
    pub aux: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, rename = "type")]
    pub component_type: Option<String>,
    #[serde(default, rename = "bom-ref")]
    pub bom_ref: Option<String>,
    #[serde(default)]
    pub licenses: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KernelFinding {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub score: Option<u32>,
    #[serde(default)]
    pub features: Vec<KernelFeature>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KernelFeature {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdfSymbolFinding {
    #[serde(default, rename = "symbol-name")]
    pub symbol_name: Option<String>,
    #[serde(default, rename = "symbol-type")]
    pub symbol_type: Option<String>,
    #[serde(default, rename = "symbol-bind")]
    pub symbol_bind: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdfTaskFinding {
    #[serde(default, rename = "task-name")]
    pub task_name: Option<String>,
    #[serde(default)]
    pub task_fn: Option<String>,
}

// === Compliance ===

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ComplianceReport {
    pub name: String,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    pub sections: Vec<ComplianceSection>,
    pub checks: ComplianceChecks,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ComplianceSection {
    pub label: String,
    pub policy_ref: String,
    pub sub_sections: Vec<ComplianceSubSection>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceSubSection {
    pub label: String,
    pub requirements: Vec<ComplianceRequirement>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ComplianceRequirement {
    pub id: String,
    pub description: String,
    pub policy_ref: String,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub advice: Option<String>,
    pub analyzer_status: String,
    #[serde(default)]
    pub overwritten_status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ComplianceChecks {
    pub total: u32,
    pub passed: u32,
    pub unknown: u32,
    pub failed: u32,
    pub not_applicable: u32,
}

// === Compliance Type enum (for CLI) ===

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ComplianceType {
    Cra,
}

impl ComplianceType {
    /// The API slug used in the compliance-check endpoint path.
    pub fn api_slug(&self) -> &'static str {
        match self {
            Self::Cra => "cyber-resilience-act",
        }
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Cra => "Cyber Resilience Act",
        }
    }
}

// === Analysis Type enum (for CLI) ===

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum AnalysisType {
    Cve,
    PasswordHash,
    Malware,
    Hardening,
    Capabilities,
    Crypto,
    SoftwareBom,
    Kernel,
    Info,
    Symbols,
    Tasks,
    StackOverflow,
}

impl AnalysisType {
    /// The API name used in the scan's analysis entries.
    pub fn api_name(&self) -> &'static str {
        match self {
            Self::Cve => "cve",
            Self::PasswordHash => "password-hash",
            Self::Malware => "malware",
            Self::Hardening => "hardening",
            Self::Capabilities => "capabilities",
            Self::Crypto => "crypto",
            Self::SoftwareBom => "software-bom",
            Self::Kernel => "kernel",
            Self::Info => "info",
            Self::Symbols => "symbols",
            Self::Tasks => "tasks",
            Self::StackOverflow => "stack-overflow",
        }
    }

    /// Default sort-by field for this analysis type.
    pub fn default_sort_by(&self) -> &'static str {
        match self {
            Self::Cve => "severity",
            Self::PasswordHash => "severity",
            Self::Malware => "filename",
            Self::Hardening => "severity",
            Self::Capabilities => "severity",
            Self::Crypto => "type",
            Self::SoftwareBom => "name",
            Self::Kernel => "features",
            Self::Info => "name",
            Self::Symbols => "name",
            Self::Tasks => "function",
            Self::StackOverflow => "name",
        }
    }
}
