use anyhow::Result;
use rikitikitavi_models::ScanResults;
use std::path::Path;

/// Export scan findings as a CSV file.
pub fn export_csv(results: &ScanResults, path: &Path) -> Result<()> {
    tracing::info!(?path, "exporting CSV report");

    let mut out = String::from("severity,scanner,title,affected_ip,affected_port,cwe_id\n");
    for f in &results.findings {
        let ip = f
            .affected_ip
            .map_or_else(String::new, |ip| ip.to_string());
        let port = f
            .affected_port
            .map_or_else(String::new, |p| p.to_string());
        let cwe = f.cwe_id.as_deref().unwrap_or("");

        // Escape CSV fields that might contain commas or quotes
        out.push_str(&csv_escape(&f.severity.to_string()));
        out.push(',');
        out.push_str(&csv_escape(&f.scanner));
        out.push(',');
        out.push_str(&csv_escape(&f.title));
        out.push(',');
        out.push_str(&csv_escape(&ip));
        out.push(',');
        out.push_str(&csv_escape(&port));
        out.push(',');
        out.push_str(&csv_escape(cwe));
        out.push('\n');
    }

    std::fs::write(path, out)?;
    Ok(())
}

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
