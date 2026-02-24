//! Object management commands.

use anyhow::Result;
use console::style;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::CreateObject;
use crate::output::{self, Format};

/// List all objects.
pub async fn run_list(client: &AnalyzerClient, format: Format) -> Result<()> {
    let page = client.list_objects().await?;
    let objects = page.data;

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(&objects)?)?
            );
        }
        Format::Human | Format::Table => {
            if objects.is_empty() {
                output::status(
                    "Objects",
                    "None found. Create one with: analyzer object new <name>",
                );
                return Ok(());
            }

            eprintln!();
            eprintln!(
                "  {:<36}  {:<30}  {:<5}  {}",
                style("ID").underlined(),
                style("Name").underlined(),
                style("Score").underlined(),
                style("Description").underlined(),
            );
            for obj in &objects {
                let score = obj
                    .score
                    .as_ref()
                    .and_then(|s| s.current.as_ref())
                    .map(|s| s.value);

                let tags = if obj.tags.is_empty() {
                    String::new()
                } else {
                    obj.tags
                        .iter()
                        .map(|t| format!("[{}]", t))
                        .collect::<Vec<_>>()
                        .join(" ")
                };

                let desc = truncate(obj.description.as_deref().unwrap_or(""), 50);

                let score_str = match score {
                    Some(s) => format!("{:<5}", s),
                    None => format!("{:<5}", "--"),
                };
                eprintln!(
                    "  {}  {:<30}  {}  {}",
                    style(obj.id).cyan(),
                    truncate(&obj.name, 30),
                    match score {
                        Some(s) if s >= 80 => style(score_str).green(),
                        Some(s) if s >= 50 => style(score_str).yellow(),
                        Some(_) => style(score_str).red(),
                        None => style(score_str).dim(),
                    },
                    desc,
                );
                if !tags.is_empty() {
                    eprintln!("  {:<36}  {}", "", style(&tags).cyan());
                }
            }

            eprintln!();
            output::status("Total", &format!("{} object(s)", objects.len()));
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

/// Create a new object.
pub async fn run_new(
    client: &AnalyzerClient,
    name: String,
    description: Option<String>,
    tags: Vec<String>,
    format: Format,
) -> Result<()> {
    let req = CreateObject {
        name,
        description,
        tags,
    };
    let object = client.create_object(&req).await?;

    match format {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(&object)?)?
            );
        }
        Format::Human | Format::Table => {
            output::success(&format!("Created object '{}' ({})", object.name, object.id));
        }
    }
    Ok(())
}

/// Delete an object.
pub async fn run_delete(client: &AnalyzerClient, id: Uuid) -> Result<()> {
    client.delete_object(id).await?;
    output::success(&format!("Deleted object {id}"));
    Ok(())
}
