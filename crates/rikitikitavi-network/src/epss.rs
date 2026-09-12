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

    // Deduplicate; the API accepts a comma-separated `cve` list.
    let mut unique: Vec<&str> = cves.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    let url = format!("{EPSS_API}?cve={}", unique.join(","));

    let resp = match client
        .get(&url)
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

    out
}
