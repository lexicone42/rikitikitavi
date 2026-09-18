//! OWASP `IoT` Top 10 (2018) taxonomy tagging (offline enrichment).
//!
//! Maps each finding to zero or more OWASP `IoT` Top 10 categories, primarily by CWE id and
//! secondarily by scanner id when a finding carries no CWE. Runs after exploit-intelligence
//! enrichment; the result is a `standards` tag list on each finding.
//!
//! Taxonomy source: OWASP `IoT` Top 10, 2018 edition
//! (<https://owasp.org/www-project-internet-of-things/>). Only the ten bare category
//! identifiers (`I1`–`I10`) are used; the labels below are this project's own concise factual
//! restatements, not OWASP's descriptive prose (which is CC-BY-SA and share-alike).

use rikitikitavi_models::Finding;

/// An OWASP `IoT` Top 10 (2018) category. The label is this project's own one-line restatement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IotCategory {
    /// I1 — weak, guessable, or hardcoded passwords and backdoor credentials.
    I1,
    /// I2 — unneeded or insecure network services.
    I2,
    /// I3 — insecure web, API, cloud, or mobile ecosystem interfaces.
    I3,
    /// I4 — missing secure firmware/software update mechanism.
    I4,
    /// I5 — use of insecure, outdated, or unmaintained components.
    I5,
    /// I6 — insufficient privacy protection for stored user data.
    I6,
    /// I7 — insecure data transfer or storage (missing or weak crypto).
    I7,
    /// I8 — lack of device management.
    I8,
    /// I9 — insecure default settings.
    I9,
    /// I10 — lack of physical hardening.
    I10,
}

impl IotCategory {
    /// The bare category identifier, e.g. `"I2"`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::I1 => "I1",
            Self::I2 => "I2",
            Self::I3 => "I3",
            Self::I4 => "I4",
            Self::I5 => "I5",
            Self::I6 => "I6",
            Self::I7 => "I7",
            Self::I8 => "I8",
            Self::I9 => "I9",
            Self::I10 => "I10",
        }
    }

    /// This project's own one-line factual label for the category.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::I1 => "Weak or hardcoded passwords",
            Self::I2 => "Insecure network services",
            Self::I3 => "Insecure ecosystem interfaces",
            Self::I4 => "Missing secure update mechanism",
            Self::I5 => "Outdated or vulnerable components",
            Self::I6 => "Insufficient privacy protection",
            Self::I7 => "Insecure data transfer or storage",
            Self::I8 => "Lack of device management",
            Self::I9 => "Insecure default settings",
            Self::I10 => "Lack of physical hardening",
        }
    }

    /// The stored tag, `"<id> <label>"`, e.g. `"I2 Insecure network services"`.
    #[must_use]
    pub fn tag(self) -> String {
        format!("{} {}", self.id(), self.label())
    }
}

/// The primary map: CWE id to OWASP `IoT` Top 10 category. `None` for CWEs with no natural home.
#[must_use]
pub const fn category_for_cwe(cwe: &str) -> Option<IotCategory> {
    Some(match cwe.as_bytes() {
        // I1 — passwords and backdoor credentials.
        b"CWE-798" | b"CWE-1392" | b"CWE-1393" => IotCategory::I1,
        // I2 — insecure or unneeded network services (missing auth/access control on a service,
        // spoofable channels, DoS, isolation and protection-mechanism failures).
        b"CWE-284" | b"CWE-287" | b"CWE-290" | b"CWE-306" | b"CWE-350" | b"CWE-400"
        | b"CWE-653" | b"CWE-693" | b"CWE-912" | b"CWE-923" => IotCategory::I2,
        // I3 — insecure web/API interfaces (injection, XSS, CSRF, CORS, clickjacking, exposed
        // methods, directory listing, cross-sphere resource transfer, cookie script exposure).
        b"CWE-22" | b"CWE-78" | b"CWE-79" | b"CWE-352" | b"CWE-470" | b"CWE-548" | b"CWE-669"
        | b"CWE-749" | b"CWE-942" | b"CWE-1004" | b"CWE-1021" => IotCategory::I3,
        // I4 — update/integrity verification failures.
        b"CWE-354" => IotCategory::I4,
        // I5 — outdated or vulnerable components (memory-safety CVEs, deserialization, races,
        // unmaintained third-party code).
        b"CWE-119" | b"CWE-120" | b"CWE-121" | b"CWE-125" | b"CWE-362" | b"CWE-416"
        | b"CWE-428" | b"CWE-502" | b"CWE-1104" => IotCategory::I5,
        // I6 — information exposure / privacy.
        b"CWE-200" => IotCategory::I6,
        // I7 — insecure data transfer or storage (cleartext transport, weak/broken crypto,
        // certificate and cookie transport flaws).
        b"CWE-295" | b"CWE-319" | b"CWE-324" | b"CWE-326" | b"CWE-327" | b"CWE-328"
        | b"CWE-329" | b"CWE-330" | b"CWE-614" => IotCategory::I7,
        // I9 — insecure default settings (missing hardening config, default init, permissions).
        b"CWE-16" | b"CWE-645" | b"CWE-732" | b"CWE-1188" => IotCategory::I9,
        _ => return None,
    })
}

/// The secondary map: scanner id to a category, used only when a finding carries no CWE.
///
/// Covers the network-posture scanners whose findings describe topology rather than a specific
/// weakness class, so a CWE is often absent.
#[must_use]
pub fn category_for_scanner(scanner: &str) -> Option<IotCategory> {
    match scanner {
        "credentials" | "kasa" | "tuya" => Some(IotCategory::I1),
        "arp" | "dhcp" | "dns" | "isolation" | "network" | "neighbor" | "exposure"
        | "mgmt-plane" | "modbus" | "mqtt" | "knx" | "tr069" => Some(IotCategory::I2),
        "wifi" | "passive-wifi" | "ssl" => Some(IotCategory::I7),
        "router" | "unifi" => Some(IotCategory::I9),
        _ => None,
    }
}

/// The category tags for one finding: CWE first, scanner id as a fallback.
#[must_use]
pub fn categories_for(finding: &Finding) -> Vec<String> {
    let cat = finding
        .cwe_id
        .as_deref()
        .and_then(category_for_cwe)
        .or_else(|| category_for_scanner(&finding.scanner));
    cat.map(|c| vec![c.tag()]).unwrap_or_default()
}

/// Tags every finding with its OWASP `IoT` Top 10 (2018) categories; returns the number tagged.
///
/// Idempotent: each finding's `standards` list is recomputed, not appended to.
pub fn enrich_standards(findings: &mut [Finding]) -> usize {
    let mut tagged = 0;
    for finding in findings.iter_mut() {
        finding.standards = categories_for(finding);
        if !finding.standards.is_empty() {
            tagged += 1;
        }
    }
    if tagged > 0 {
        tracing::info!(tagged, "OWASP IoT Top 10 (2018) tagging");
    }
    tagged
}

#[cfg(test)]
mod tests;
