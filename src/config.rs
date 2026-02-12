//! Configuration management for the Analyzer CLI.
//!
//! Config is loaded with this precedence (highest to lowest):
//! 1. CLI flags (`--api-key`, `--url`)
//! 2. Environment variables (`ANALYZER_API_KEY`, `ANALYZER_URL`)
//! 3. Config file (`~/.config/analyzer/config.toml`)
//! 4. Defaults

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

const CONFIG_DIR_NAME: &str = "analyzer";
const CONFIG_FILE_NAME: &str = "config.toml";
const DEFAULT_URL: &str = "https://analyzer.exein.io/api/";
const DEFAULT_PROFILE: &str = "default";

/// Resolved runtime configuration, ready to use.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub api_key: String,
    pub url: Url,
    #[allow(dead_code)]
    pub profile: String,
}

/// Top-level config file structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

/// A single named profile.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub api_key: Option<String>,
    pub url: Option<String>,
}

fn default_profile_name() -> String {
    DEFAULT_PROFILE.to_string()
}

impl ConfigFile {
    /// Path to the config file.
    pub fn path() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .context("could not determine config directory")?
            .join(CONFIG_DIR_NAME);
        Ok(dir.join(CONFIG_FILE_NAME))
    }

    /// Load from disk, returning defaults if the file is missing.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
    }

    /// Save to disk, creating parent directories as needed.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let contents = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Look up a profile by name, falling back to an empty profile.
    pub fn profile(&self, name: Option<&str>) -> &Profile {
        let name = name.unwrap_or(&self.default_profile);
        static EMPTY: Profile = Profile {
            api_key: None,
            url: None,
        };
        self.profiles.get(name).unwrap_or(&EMPTY)
    }

    /// Get or create a mutable profile.
    pub fn profile_mut(&mut self, name: &str) -> &mut Profile {
        self.profiles.entry(name.to_string()).or_default()
    }
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            default_profile: default_profile_name(),
            profiles: HashMap::new(),
        }
    }
}

/// Resolve the final configuration from all sources.
pub fn resolve(
    cli_api_key: Option<&str>,
    cli_url: Option<&str>,
    cli_profile: Option<&str>,
) -> Result<ResolvedConfig> {
    let config_file = ConfigFile::load().unwrap_or_default();

    let profile_name = cli_profile.map(String::from).unwrap_or_else(|| {
        std::env::var("ANALYZER_PROFILE").unwrap_or_else(|_| config_file.default_profile.clone())
    });

    let profile = config_file.profile(Some(&profile_name));

    // URL: flag > env > profile > default
    let url_str = cli_url
        .map(String::from)
        .or_else(|| std::env::var("ANALYZER_URL").ok())
        .or_else(|| profile.url.clone())
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    let url: Url = url_str
        .parse()
        .with_context(|| format!("invalid URL: {url_str}"))?;

    // API key: flag > env > profile
    let api_key = cli_api_key
        .map(String::from)
        .or_else(|| std::env::var("ANALYZER_API_KEY").ok())
        .or_else(|| profile.api_key.clone());

    let api_key = match api_key {
        Some(key) => key,
        None => anyhow::bail!(
            "no API key provided\n\n\
             Set it with one of:\n  \
             analyzer login\n  \
             analyzer --api-key <KEY> ...\n  \
             export ANALYZER_API_KEY=<KEY>"
        ),
    };

    Ok(ResolvedConfig {
        api_key,
        url,
        profile: profile_name,
    })
}
