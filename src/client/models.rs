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
    #[serde(default, rename = "_links")]
    pub links: PageLinks,
}

#[derive(Debug, Default, Deserialize)]
pub struct PageLinks {
    pub next: Option<String>,
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
    pub healthy: bool,
}

// === Analysis Status Entry (for parsing flattened scan status) ===

#[derive(Debug, Deserialize)]
pub struct AnalysisStatusEntry {
    pub id: Uuid,
    pub status: AnalysisStatus,
}
