//! Authentication commands: login, whoami.

use anyhow::Result;
use console::style;

use crate::client::AnalyzerClient;
use crate::config::ConfigFile;
use crate::output;

/// Run the `login` command — prompt for API key, validate, save.
pub async fn run_login(url: Option<&str>, profile_name: Option<&str>) -> Result<()> {
    let profile_name = profile_name.unwrap_or("default");

    eprintln!();
    let banner = [
        r"                _        ",
        r"   _____  _____(_)_ __   ",
        r"  / _ \ \/ / _ \ | '_ \  ",
        r" |  __/>  <  __/ | | | | ",
        r"  \___/_/\_\___|_|_| |_| ",
    ];
    for line in &banner {
        eprintln!("  {}", style(line).cyan().bold());
    }
    eprintln!(
        "  {} {}",
        style(" analyzer").dim(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim()
    );
    eprintln!();
    eprintln!(
        "  {}",
        style(format!("Configuring profile '{profile_name}'")).dim()
    );
    eprintln!();

    let api_key = prompt_api_key()?;

    // Resolve URL from arg, existing config, or default
    let mut config = ConfigFile::load().unwrap_or_default();
    let existing_url = config.profile(Some(profile_name)).url.clone();
    let url = url
        .map(String::from)
        .or(existing_url)
        .unwrap_or_else(|| "https://analyzer.exein.io/api/".to_string());

    // Validate
    eprintln!();
    output::status("", "Validating API key...");
    let parsed_url: url::Url = url.parse()?;
    let client = AnalyzerClient::new(parsed_url, &api_key)?;

    match client.health().await {
        Ok(_) => output::success("Key accepted. You're in."),
        Err(e) => output::warning(&format!(
            "Could not validate key ({e}). Saving anyway — the server may be unreachable."
        )),
    }

    // Save
    let profile = config.profile_mut(profile_name);
    profile.api_key = Some(api_key);
    profile.url = Some(url);
    config.save()?;

    let path = ConfigFile::path()?;
    output::success(&format!("Config saved to {}", path.display()));
    eprintln!();
    eprintln!(
        "  {} Ready to hunt some vulns. Try:",
        style(">").green().bold()
    );
    eprintln!(
        "    {} {}       # list your objects",
        style("analyzer").bold(),
        style("object list").cyan()
    );
    eprintln!(
        "    {} {}        # available scan types",
        style("analyzer").bold(),
        style("scan types").cyan()
    );
    eprintln!(
        "    {} {}  # start a scan",
        style("analyzer").bold(),
        style("scan new -h").cyan()
    );
    eprintln!();

    Ok(())
}

/// Show current identity / configuration.
pub fn run_whoami(api_key: Option<&str>, url: Option<&str>, profile: Option<&str>) -> Result<()> {
    let config = ConfigFile::load().unwrap_or_default();
    let profile_name = profile
        .map(String::from)
        .or_else(|| std::env::var("ANALYZER_PROFILE").ok())
        .unwrap_or_else(|| config.default_profile.clone());

    let p = config.profile(Some(&profile_name));

    let resolved_url = url
        .map(String::from)
        .or_else(|| std::env::var("ANALYZER_URL").ok())
        .or_else(|| p.url.clone())
        .unwrap_or_else(|| "https://analyzer.exein.io/api/".to_string());

    let resolved_key = api_key
        .map(String::from)
        .or_else(|| std::env::var("ANALYZER_API_KEY").ok())
        .or_else(|| p.api_key.clone());

    let masked_key = match &resolved_key {
        Some(key) if key.len() > 8 => format!("{}...{}", &key[..4], &key[key.len() - 4..]),
        Some(key) => format!("{}...", &key[..key.len().min(4)]),
        None => "(not set)".to_string(),
    };

    eprintln!("{}", style("Analyzer CLI").bold().underlined());
    eprintln!();
    eprintln!("  {:>12}  {}", style("Profile:").bold(), profile_name);
    eprintln!("  {:>12}  {}", style("URL:").bold(), resolved_url);
    eprintln!("  {:>12}  {}", style("API Key:").bold(), masked_key);

    if let Ok(path) = ConfigFile::path() {
        eprintln!("  {:>12}  {}", style("Config:").bold(), path.display());
    }

    Ok(())
}

fn prompt_api_key() -> Result<String> {
    eprint!("  Enter your API key: ");
    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    if key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }
    Ok(key)
}
