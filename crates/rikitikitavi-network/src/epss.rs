//! EPSS (Exploit Prediction Scoring System) lookup.
//!
//! EPSS gives the probability (0.0–1.0) that a CVE will be exploited in the next
//! 30 days. Combined with the embedded CISA KEV catalog (which says what *is*
//! being exploited now), it lets the report rank a wall of CVEs by real-world
//! exploitation likelihood rather than theoretical CVSS.
//!
//! The scores change daily and cover ~280k CVEs, so unlike KEV they are not
//! embedded — they are fetched on demand from FIRST.org's free, keyless API for
//! only the handful of CVEs a scan actually turned up. The lookup is
//! best-effort: it never fails a scan, returning an empty map when offline.

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

/// Look up EPSS exploitation-probability scores for a set of CVE IDs.
///
/// Returns a map of CVE ID → probability in `0.0..=1.0`. Best-effort: an empty
/// map is returned when the list is empty, the network is unavailable, or the
/// response cannot be parsed — a scan must keep working offline.
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
