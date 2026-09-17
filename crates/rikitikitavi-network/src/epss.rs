//! EPSS (Exploit Prediction Scoring System) lookup via the FIRST.org API.
//! Scores are fetched on demand for the CVEs a scan produced, not embedded.
//! Best-effort: any failure yields an empty map.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

const EPSS_TIMEOUT: Duration = Duration::from_secs(8);
const EPSS_API: &str = "https://api.first.org/data/v1/epss";

#[derive(Deserialize)]
struct EpssResponse {
    data: Vec<EpssEntry>,
}

#[derive(Deserialize)]
struct EpssEntry {
    cve: String,
    /// The API returns the score as a decimal string, e.g. "0.94366".
    epss: String,
}

/// EPSS scores for `cves` as CVE ID → probability in `0.0..=1.0`.
/// Returns an empty map on empty input, network failure, or parse failure.
pub async fn fetch_epss_scores(cves: &[String]) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    if cves.is_empty() {
        return out;
    }

    let Ok(client) = reqwest::Client::builder().timeout(EPSS_TIMEOUT).build() else {
        return out;
    };

    for query in epss_queries(cves) {
        let resp = match client
            .get(format!("{EPSS_API}?cve={query}"))
            .header("User-Agent", "rikitikitavi")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "EPSS lookup failed (continuing without it)");
                return out;
            }
        };

        match resp.json::<EpssResponse>().await {
            Ok(parsed) => {
                for entry in parsed.data {
                    if let Ok(score) = entry.epss.parse::<f64>() {
                        out.insert(entry.cve, score);
                    }
                }
            }
            Err(e) => tracing::debug!(error = %e, "EPSS response parse failed"),
        }
    }

    out
}

/// The API returns at most `EPSS_BATCH` rows per request.
const EPSS_BATCH: usize = 100;

/// Deduplicated, sorted `cve` query values, at most `EPSS_BATCH` ids each.
fn epss_queries(cves: &[String]) -> Vec<String> {
    let mut unique: Vec<&str> = cves.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    unique.chunks(EPSS_BATCH).map(|c| c.join(",")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_dedupe_and_batch() {
        let cves: Vec<String> = (0..250)
            .map(|i| format!("CVE-2026-{:05}", i % 230))
            .collect();
        let q = epss_queries(&cves);
        assert_eq!(q.len(), 3);
        assert_eq!(q[0].split(',').count(), 100);
        assert_eq!(q[2].split(',').count(), 30);
        assert!(epss_queries(&[]).is_empty());
    }
}
