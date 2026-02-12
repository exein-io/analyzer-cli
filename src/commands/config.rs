//! Configuration management commands.

use anyhow::Result;
use console::style;

use crate::config::ConfigFile;
use crate::output;

/// Show the current configuration.
pub fn run_show() -> Result<()> {
    let config = ConfigFile::load().unwrap_or_default();

    eprintln!(
        "{}",
        style("Analyzer CLI Configuration").bold().underlined()
    );
    eprintln!();
    eprintln!(
        "  {:>16}  {}",
        style("Default profile:").bold(),
        config.default_profile
    );

    if let Ok(path) = ConfigFile::path() {
        eprintln!("  {:>16}  {}", style("Config file:").bold(), path.display());
    }

    if config.profiles.is_empty() {
        eprintln!("\n  No profiles configured. Run: analyzer login");
    } else {
        eprintln!("\n  {}", style("Profiles:").bold());
        for (name, profile) in &config.profiles {
            let url = profile.url.as_deref().unwrap_or("(default)");
            let key_status = if profile.api_key.is_some() {
                "set"
            } else {
                "not set"
            };
            eprintln!(
                "    {} -- URL: {}, API key: {}",
                style(name).cyan(),
                url,
                key_status
            );
        }
    }
    Ok(())
}

/// Set a configuration value.
pub fn run_set(key: &str, value: &str, profile: Option<&str>) -> Result<()> {
    let mut config = ConfigFile::load().unwrap_or_default();
    let profile_name = profile.unwrap_or("default");
    let p = config.profile_mut(profile_name);

    match key {
        "url" => {
            let _: url::Url = value
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid URL: {value}"))?;
            p.url = Some(value.to_string());
        }
        "api-key" | "api_key" => {
            p.api_key = Some(value.to_string());
        }
        "default-profile" | "default_profile" => {
            config.default_profile = value.to_string();
        }
        other => {
            anyhow::bail!(
                "Unknown config key: {other}\n\nValid keys: url, api-key, default-profile"
            );
        }
    }

    config.save()?;
    output::success(&format!("Set {key} = {value} (profile: {profile_name})"));
    Ok(())
}

/// Get a configuration value.
pub fn run_get(key: &str, profile: Option<&str>) -> Result<()> {
    let config = ConfigFile::load().unwrap_or_default();
    let profile_name = profile.unwrap_or(&config.default_profile);
    let p = config.profile(Some(profile_name));

    let value = match key {
        "url" => p.url.as_deref().unwrap_or("(not set)"),
        "api-key" | "api_key" => {
            if p.api_key.is_some() {
                "(set)"
            } else {
                "(not set)"
            }
        }
        "default-profile" | "default_profile" => &config.default_profile,
        other => {
            anyhow::bail!(
                "Unknown config key: {other}\n\nValid keys: url, api-key, default-profile"
            );
        }
    };

    println!("{value}");
    Ok(())
}
