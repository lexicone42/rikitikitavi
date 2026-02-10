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

    // ─── Property-based tests ─────────────────────────────────────────

    proptest::proptest! {
        /// CSV escape never panics on arbitrary input.
        #[test]
        fn prop_csv_escape_no_panic(input in proptest::prelude::any::<String>()) {
            let _ = csv_escape(&input);
        }

        /// Escaped output never contains unescaped commas outside of quoted fields.
        /// If the output is quoted (starts with `"`), that's correct escaping.
        /// If it's not quoted, it must not contain `,`, `"`, or `\n`.
        #[test]
        fn prop_csv_escape_well_formed(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            if escaped.starts_with('"') {
                // Quoted: must start and end with `"`, and inner `"` must be doubled
                assert!(escaped.ends_with('"'), "quoted field does not end with quote");
            } else {
                // Unquoted: must not contain special chars
                assert!(!escaped.contains(','), "unquoted field contains comma");
                assert!(!escaped.contains('"'), "unquoted field contains quote");
                assert!(!escaped.contains('\n'), "unquoted field contains newline");
            }
        }

        /// csv_escape preserves the original content (can be unescaped).
        /// For any input, stripping the CSV quoting should recover the original.
        #[test]
        fn prop_csv_escape_roundtrip(input in proptest::prelude::any::<String>()) {
            let escaped = csv_escape(&input);
            let recovered = if escaped.starts_with('"') && escaped.ends_with('"') {
                // Strip outer quotes and un-double inner quotes
                escaped[1..escaped.len()-1].replace("\"\"", "\"")
            } else {
                escaped
            };
            assert_eq!(recovered, input, "roundtrip failed for input: {input:?}");
        }
    }
}
