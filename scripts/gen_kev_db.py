#!/usr/bin/env python3
"""Generate `kev_db.rs` from the CISA Known Exploited Vulnerabilities catalog.

The KEV catalog is the authoritative list of CVEs known to be exploited in the
wild. Membership is the single strongest "fix this now" signal, so we embed a
snapshot as a sorted static array for O(log n) binary-search lookup — the same
pattern as `oui_db.rs`.

Usage:
    python3 scripts/gen_kev_db.py > crates/rikitikitavi-analysis/src/kev_db.rs

Re-run periodically to refresh the snapshot (the catalog grows a few CVEs/week).
"""

import json
import sys
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def main() -> None:
    with urllib.request.urlopen(KEV_URL, timeout=60) as resp:
        catalog = json.load(resp)

    date_released = catalog.get("dateReleased", "unknown")
    version = catalog.get("catalogVersion", "unknown")
    # Deduplicate and sort so the array supports binary search.
    cves = sorted({v["cveID"].strip().upper() for v in catalog["vulnerabilities"]})

    out = sys.stdout
    out.write(f"""//! CISA Known Exploited Vulnerabilities (KEV) catalog — auto-generated.
//!
//! Source: <{KEV_URL}>
//! Catalog version: {version} | Released: {date_released}
//! Entries: {len(cves):,}
//!
//! Regenerate with `python3 scripts/gen_kev_db.py`. Membership means CISA has
//! evidence the CVE is being exploited in the wild — the strongest signal that a
//! finding should be fixed immediately.

/// The catalog version this snapshot was generated from.
pub const KEV_CATALOG_VERSION: &str = "{version}";

/// Whether `cve` (e.g. "CVE-2024-3400") is in the CISA KEV catalog.
///
/// Case-insensitive; O(log n) binary search over the sorted table.
#[must_use]
pub fn is_kev(cve: &str) -> bool {{
    let needle = cve.trim().to_ascii_uppercase();
    KEV_CVES.binary_search(&needle.as_str()).is_ok()
}}

/// Sorted list of CVE IDs known to be exploited in the wild.
#[rustfmt::skip]
static KEV_CVES: &[&str] = &[
""")

    for cve in cves:
        escaped = cve.replace("\\", "\\\\").replace('"', '\\"')
        out.write(f'    "{escaped}",\n')

    out.write("];\n")


if __name__ == "__main__":
    main()
