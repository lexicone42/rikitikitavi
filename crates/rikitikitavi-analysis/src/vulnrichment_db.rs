//! CISA Vulnrichment SSVC decision points — auto-generated.
//!
//! Source: <https://github.com/cisagov/vulnrichment> (branch `develop`, commit 3d608e158)
//! Licence: CC0-1.0 Universal (public domain dedication)
//! Snapshot: 2026-09-17 | Entries: 29 (active 13, poc 9, none 7)
//! Mode: workspace CVEs
//!
//! Regenerate with `uv run python scripts/gen_vulnrichment_db.py`.
//!
//! The `poc` tier is what KEV and EPSS cannot express: public exploit code
//! exists, exploitation in the wild has not been observed. `active` overlaps
//! KEV almost exactly; it is kept so the tier is total over the table.

/// SSVC Exploitation: evidence that a vulnerability is being exploited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exploitation {
    /// No public exploit code and no observed exploitation.
    None,
    /// Public proof-of-concept exploit code exists; no observed exploitation.
    Poc,
    /// Exploitation observed in the wild.
    Active,
}

/// SSVC Automatable: whether reconnaissance through exploitation can be automated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Automatable {
    /// Reliable automation of the first four kill-chain steps is not available.
    No,
    /// An attacker can automate the chain — the wormability signal.
    Yes,
}

/// SSVC Technical Impact: control gained over the vulnerable component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TechnicalImpact {
    /// Limited control, or information disclosure only.
    Partial,
    /// Total control of the vulnerable component.
    Total,
}

/// One CISA Vulnrichment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssvc {
    /// Normalised CVE id, e.g. `CVE-2024-6387`.
    pub cve: &'static str,
    /// Exploitation tier.
    pub exploitation: Exploitation,
    /// Automatable decision point; absent when the record carries no SSVC block.
    pub automatable: Option<Automatable>,
    /// Technical Impact decision point; absent when the record carries no SSVC block.
    pub technical_impact: Option<TechnicalImpact>,
    /// CISA-ADP CWE assignment; backfills findings that carry none.
    pub cwe: Option<&'static str>,
}

/// The Vulnrichment snapshot date this table was generated from.
pub const VULNRICHMENT_SNAPSHOT: &str = "2026-09-17";

/// Vulnrichment record for `cve` (e.g. "CVE-2024-6387"), if CISA enriched it.
///
/// Case-insensitive; O(log n) binary search over the sorted table.
#[must_use]
pub fn lookup_ssvc(cve: &str) -> Option<&'static Ssvc> {
    let needle = cve.trim().to_ascii_uppercase();
    SSVC_ENTRIES
        .binary_search_by(|entry| entry.cve.cmp(needle.as_str()))
        .ok()
        .map(|i| &SSVC_ENTRIES[i])
}

/// Records sorted by CVE id.
#[rustfmt::skip]
static SSVC_ENTRIES: &[Ssvc] = &[
    Ssvc { cve: "CVE-1999-0524", exploitation: Exploitation::None, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: Some("CWE-200") },
    Ssvc { cve: "CVE-2008-5161", exploitation: Exploitation::None, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: Some("CWE-329") },
    Ssvc { cve: "CVE-2014-0160", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Partial), cwe: Some("CWE-125") },
    Ssvc { cve: "CVE-2014-6271", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-78") },
    Ssvc { cve: "CVE-2017-0144", exploitation: Exploitation::Active, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2018-15473", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: Some("CWE-362") },
    Ssvc { cve: "CVE-2019-19781", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-22") },
    Ssvc { cve: "CVE-2021-33044", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-287") },
    Ssvc { cve: "CVE-2021-33045", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-287") },
    Ssvc { cve: "CVE-2021-34527", exploitation: Exploitation::Active, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2021-36260", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-78") },
    Ssvc { cve: "CVE-2021-41773", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2021-42013", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2021-44228", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2023-26048", exploitation: Exploitation::None, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2023-38408", exploitation: Exploitation::None, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-428") },
    Ssvc { cve: "CVE-2023-48795", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: Some("CWE-354") },
    Ssvc { cve: "CVE-2023-4966", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2024-1234", exploitation: Exploitation::None, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2024-3400", exploitation: Exploitation::Active, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2024-47076", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2024-47175", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2024-47176", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2024-51138", exploitation: Exploitation::None, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: Some("CWE-121") },
    Ssvc { cve: "CVE-2024-51977", exploitation: Exploitation::Poc, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2024-51978", exploitation: Exploitation::Poc, automatable: Some(Automatable::Yes), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2024-5678", exploitation: Exploitation::None, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Partial), cwe: None },
    Ssvc { cve: "CVE-2024-6387", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Total), cwe: None },
    Ssvc { cve: "CVE-2025-9961", exploitation: Exploitation::Poc, automatable: Some(Automatable::No), technical_impact: Some(TechnicalImpact::Total), cwe: None },
];

#[cfg(test)]
mod tests;
