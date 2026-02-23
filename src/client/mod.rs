//! Typed HTTP client for the Analyzer API.

pub mod models;

use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Result, bail};
use futures::Stream;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use reqwest::{Body, Client, header, multipart};
use tokio_util::io::ReaderStream;
use url::Url;
use uuid::Uuid;

use self::models::*;

static APP_USER_AGENT: &str = concat!("analyzer-cli/", env!("CARGO_PKG_VERSION"));

/// Analyzer API client.
#[derive(Debug, Clone)]
pub struct AnalyzerClient {
    client: Client,
    base_url: Url,
}

impl AnalyzerClient {
    /// Create a new client with the given base URL and API key.
    pub fn new(base_url: Url, api_key: &str) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {api_key}")
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid API key format"))?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .user_agent(APP_USER_AGENT)
            .build()?;

        Ok(Self { client, base_url })
    }

    // -- Health ---------------------------------------------------------------

    pub async fn health(&self) -> Result<HealthStatus> {
        let url = self.base_url.join("health")?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    // -- Objects --------------------------------------------------------------

    pub async fn list_objects(&self) -> Result<Page<Object>> {
        let url = self.base_url.join("objects/")?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_object(&self, id: Uuid) -> Result<Object> {
        let url = self.base_url.join(&format!("objects/{id}"))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn create_object(&self, req: &CreateObject) -> Result<Object> {
        let url = self.base_url.join("objects/")?;
        let resp = self.client.post(url).json(req).send().await?;
        Self::json(resp).await
    }

    pub async fn delete_object(&self, id: Uuid) -> Result<()> {
        let url = self.base_url.join(&format!("objects/{id}"))?;
        let resp = self.client.delete(url).send().await?;
        Self::empty(resp).await
    }

    // -- Scans ----------------------------------------------------------------

    #[allow(dead_code)]
    pub async fn list_scans(&self) -> Result<Vec<Scan>> {
        let url = self.base_url.join("scans/")?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_scan(&self, id: Uuid) -> Result<Scan> {
        let url = self.base_url.join(&format!("scans/{id}"))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    /// Upload a firmware image and create a new scan.
    ///
    /// Returns the scan response and a progress bar (already finished).
    pub async fn create_scan(
        &self,
        object_id: Uuid,
        file_path: &Path,
        scan_type: &ScanTypeRequest,
    ) -> Result<NewScanResponse> {
        let url = self.base_url.join("scans/")?;

        let file = tokio::fs::File::open(file_path).await?;
        let file_len = file.metadata().await?.len();

        // Set up progress bar
        let pb = ProgressBar::new(file_len);
        pb.set_style(
            ProgressStyle::with_template(
                "  {spinner:.green} Uploading [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )?
            .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).ok();
            })
            .progress_chars("=> "),
        );

        let pb_clone = pb.clone();
        let stream = ReaderStream::new(file);
        let stream = ProgressStream {
            inner: stream,
            progress_bar: pb_clone,
        };
        let body = Body::wrap_stream(stream);

        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("firmware.bin")
            .to_string();

        let part = multipart::Part::stream_with_length(body, file_len).file_name(filename);
        let analysis_json = serde_json::to_string(scan_type)?;

        let form = multipart::Form::new()
            .text("object_id", object_id.to_string())
            .text("analysis", analysis_json)
            .part("image", part);

        let resp = self.client.post(url).multipart(form).send().await?;
        pb.finish_and_clear();

        Self::json(resp).await
    }

    pub async fn delete_scan(&self, id: Uuid) -> Result<()> {
        let url = self.base_url.join(&format!("scans/{id}"))?;
        let resp = self.client.delete(url).send().await?;
        Self::empty(resp).await
    }

    pub async fn cancel_scan(&self, id: Uuid) -> Result<()> {
        let url = self.base_url.join(&format!("scans/{id}/cancel"))?;
        let resp = self.client.post(url).send().await?;
        Self::empty(resp).await
    }

    pub async fn get_scan_status(&self, id: Uuid) -> Result<ScanStatus> {
        let url = self.base_url.join(&format!("scans/{id}/status"))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_scan_score(&self, id: Uuid) -> Result<ScanScore> {
        let url = self.base_url.join(&format!("scans/{id}/score"))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_scan_types(&self) -> Result<Vec<ApiScanType>> {
        let url = self.base_url.join("scans/types")?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn download_report(&self, scan_id: Uuid) -> Result<bytes::Bytes> {
        let url = self.base_url.join(&format!("scans/{scan_id}/report"))?;
        let resp = self.client.get(url).send().await?;
        Self::bytes(resp).await
    }

    pub async fn download_sbom(&self, scan_id: Uuid) -> Result<bytes::Bytes> {
        let url = self.base_url.join(&format!("scans/{scan_id}/sbom"))?;
        let resp = self.client.get(url).send().await?;
        Self::bytes(resp).await
    }

    // -- Analysis Results & Compliance ----------------------------------------

    pub async fn get_scan_overview(&self, scan_id: Uuid) -> Result<ScanOverview> {
        let url = self.base_url.join(&format!("scans/{scan_id}/overview"))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_analysis_results(
        &self,
        scan_id: Uuid,
        analysis_id: Uuid,
        query: &ResultsQuery,
    ) -> Result<AnalysisResults> {
        let mut url = self
            .base_url
            .join(&format!("scans/{scan_id}/results/{analysis_id}"))?;
        url.query_pairs_mut()
            .append_pair("page", &query.page.to_string())
            .append_pair("per-page", &query.per_page.to_string())
            .append_pair("sort-by", &query.sort_by)
            .append_pair("sort-ord", &query.sort_ord);
        if let Some(search) = &query.search {
            url.query_pairs_mut().append_pair("search", search);
        }
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn get_compliance(
        &self,
        scan_id: Uuid,
        ct: ComplianceType,
    ) -> Result<ComplianceReport> {
        let url = self.base_url.join(&format!(
            "scans/{scan_id}/compliance-check/{}",
            ct.api_slug()
        ))?;
        let resp = self.client.get(url).send().await?;
        Self::json(resp).await
    }

    pub async fn download_compliance_report(
        &self,
        scan_id: Uuid,
        ct: ComplianceType,
    ) -> Result<bytes::Bytes> {
        let url = self.base_url.join(&format!(
            "scans/{scan_id}/compliance-check/{}/report",
            ct.api_slug()
        ))?;
        let resp = self.client.get(url).send().await?;
        Self::bytes(resp).await
    }

    // -- Response helpers -----------------------------------------------------

    async fn json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.json().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            bail!("API error (HTTP {status}): {body}");
        }
    }

    async fn empty(resp: reqwest::Response) -> Result<()> {
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            bail!("API error (HTTP {status}): {body}");
        }
    }

    async fn bytes(resp: reqwest::Response) -> Result<bytes::Bytes> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.bytes().await?)
        } else {
            let body = resp.text().await.unwrap_or_default();
            bail!("API error (HTTP {status}): {body}");
        }
    }
}

// ---------------------------------------------------------------------------
// Upload progress stream
// ---------------------------------------------------------------------------

/// Stream wrapper that updates a progress bar as bytes flow through.
struct ProgressStream<S> {
    inner: S,
    progress_bar: ProgressBar,
}

impl<S> Stream for ProgressStream<S>
where
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                self.progress_bar.inc(chunk.len() as u64);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                self.progress_bar.finish_and_clear();
                Poll::Ready(None)
            }
            other => other,
        }
    }
}
