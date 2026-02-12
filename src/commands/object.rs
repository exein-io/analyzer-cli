//! Object management commands.

use anyhow::Result;
use uuid::Uuid;

use crate::client::AnalyzerClient;
use crate::client::models::CreateObject;
use crate::output::{self, Format, score_cell, styled_table};

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

            let mut table = styled_table();
            table.set_header(vec!["ID", "Name", "Description", "Score", "Tags"]);

            for obj in &objects {
                let score = obj
                    .score
                    .as_ref()
                    .and_then(|s| s.current.as_ref())
                    .map(|s| s.value);

                let tags = if obj.tags.is_empty() {
                    "-".to_string()
                } else {
                    obj.tags.join(", ")
                };

                table.add_row(vec![
                    comfy_table::Cell::new(obj.id),
                    comfy_table::Cell::new(&obj.name),
                    comfy_table::Cell::new(obj.description.as_deref().unwrap_or("-")),
                    score_cell(score),
                    comfy_table::Cell::new(tags),
                ]);
            }

            println!("{table}");
            output::status("Total", &format!("{} object(s)", objects.len()));
        }
    }
    Ok(())
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
