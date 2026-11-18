//! Accepted-risk ledger (`--accept-file`).
//!
//! ```yaml
//! accepted:
//!   - fingerprint: "01a2b3c4d5e6f708"
//!     reason: Printer is on the isolated IoT VLAN
//!     accepted_on: 2026-11-01
//!     expires: 2027-02-01
//!     compensating: Inbound blocked at the gateway   # optional
//! ```

use anyhow::Context as _;
use chrono::NaiveDate;
use rikitikitavi_models::{AcceptedFinding, FindingFingerprint, ScanResults};
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::io::Read as _;
use std::path::Path;

/// Byte cap on an accept file.
pub const MAX_ACCEPT_FILE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    accepted: Vec<Entry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(deserialize_with = "fingerprint")]
    pub fingerprint: FindingFingerprint,
    pub reason: String,
    pub accepted_on: NaiveDate,
    pub expires: NaiveDate,
    #[serde(default)]
    pub compensating: Option<String>,
}

/// A quoted hex string. An unquoted value is rejected: YAML reads `0x1f`, `0017` and
/// `12_34` as numbers, which loses the digits that were written.
fn fingerprint<'de, D: Deserializer<'de>>(d: D) -> Result<FindingFingerprint, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Scalar {
        Text(String),
        Other(serde::de::IgnoredAny),
    }
    let Scalar::Text(text) = Scalar::deserialize(d)? else {
        return Err(serde::de::Error::custom(
            "fingerprint must be a quoted string, e.g. fingerprint: \"9b5e72351827da2a\"",
        ));
    };
    if text.trim().trim_start_matches("0x").len() > 16 {
        return Err(serde::de::Error::custom(format!(
            "fingerprint `{text}` is longer than 16 hex digits"
        )));
    }
    text.parse()
        .map_err(|_| serde::de::Error::custom(format!("invalid fingerprint `{text}`")))
}

#[derive(Debug, Clone)]
pub struct Ledger {
    pub entries: Vec<Entry>,
}

/// Read at most `cap` bytes of UTF-8 from `path`; larger files are an error.
pub fn read_capped(path: &Path, cap: u64, what: &str) -> anyhow::Result<String> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot read {what} file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {what} file {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= cap,
        "{what} file {} exceeds {cap} bytes",
        path.display()
    );
    String::from_utf8(bytes).with_context(|| format!("{what} file {} is not UTF-8", path.display()))
}

pub fn load(path: &Path) -> anyhow::Result<Ledger> {
    let text = read_capped(path, MAX_ACCEPT_FILE_BYTES, "accept")?;
    parse(&text).with_context(|| format!("invalid accept file {}", path.display()))
}

/// Unknown fields, an empty reason, `expires` before `accepted_on` and duplicate
/// fingerprints are errors.
pub fn parse(text: &str) -> anyhow::Result<Ledger> {
    let file: LedgerFile = serde_saphyr::from_str(text)?;
    let mut seen = HashSet::new();
    for e in &file.accepted {
        anyhow::ensure!(
            !e.reason.trim().is_empty(),
            "entry {} has an empty reason",
            e.fingerprint
        );
        anyhow::ensure!(
            e.expires >= e.accepted_on,
            "entry {} expires ({}) before it was accepted ({})",
            e.fingerprint,
            e.expires,
            e.accepted_on
        );
        anyhow::ensure!(
            seen.insert(e.fingerprint),
            "entry {} is listed twice",
            e.fingerprint
        );
    }
    Ok(Ledger {
        entries: file.accepted,
    })
}

/// Move findings matched by an unexpired entry from `findings` to `accepted`. An entry is
/// active through its `expires` date. Returns warnings for expired and unmatched entries.
pub fn apply(ledger: &Ledger, results: &mut ScanResults, today: NaiveDate) -> Vec<String> {
    let mut warnings = Vec::new();
    for e in &ledger.entries {
        if today > e.expires {
            warnings.push(format!(
                "Warning: accepted-risk entry {} (\"{}\") expired on {}; the finding is active again",
                e.fingerprint, e.reason, e.expires
            ));
            continue;
        }
        let (hit, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut results.findings)
            .into_iter()
            .partition(|f| f.fingerprint() == e.fingerprint);
        results.findings = rest;
        if hit.is_empty() {
            warnings.push(format!(
                "Warning: accepted-risk entry {} (\"{}\") matches no finding in this scan",
                e.fingerprint, e.reason
            ));
        }
        results
            .accepted
            .extend(hit.into_iter().map(|finding| AcceptedFinding {
                finding,
                fingerprint: e.fingerprint,
                reason: e.reason.clone(),
                accepted_on: e.accepted_on,
                expires: e.expires,
                compensating: e.compensating.clone(),
            }));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Finding;

    fn day(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    fn telnet() -> Finding {
        Finding::new("ports", "Telnet open", "d", Severity::High)
            .with_ip("10.0.0.5".parse().unwrap())
            .with_port(23)
    }

    fn entry_yaml(fp: &str, expires: &str) -> String {
        format!(
            "accepted:\n  - fingerprint: \"{fp}\"\n    reason: isolated VLAN\n    \
             accepted_on: 2026-11-01\n    expires: {expires}\n"
        )
    }

    #[test]
    fn parses_a_valid_entry() {
        let fp = telnet().fingerprint().to_string();
        let ledger = parse(&format!(
            "{}    compensating: inbound blocked\n",
            entry_yaml(&fp, "2027-02-01")
        ))
        .unwrap();
        assert_eq!(ledger.entries.len(), 1);
        let e = &ledger.entries[0];
        assert_eq!(e.fingerprint, telnet().fingerprint());
        assert_eq!(e.expires, day("2027-02-01"));
        assert_eq!(e.compensating.as_deref(), Some("inbound blocked"));
    }

    #[test]
    fn unquoted_numeric_fingerprint_is_rejected() {
        for fp in ["1234567890123456", "0x00000000000000aa", "0000000000001234"] {
            let err = parse(&format!(
                "accepted:\n  - fingerprint: {fp}\n    reason: r\n    \
                 accepted_on: 2026-11-01\n    expires: 2026-12-01\n"
            ))
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("quoted string"),
                "{fp}: {err:#}"
            );
        }
    }

    #[test]
    fn fails_closed() {
        let fp = telnet().fingerprint().to_string();
        let bad = [
            "accepted: [".to_owned(),
            format!("{}    owner: me\n", entry_yaml(&fp, "2027-01-01")),
            format!("{}extra: 1\n", entry_yaml(&fp, "2027-01-01")),
            entry_yaml(&fp, "2027-01-01").replace("    reason: isolated VLAN\n", ""),
            entry_yaml(&fp, "2027-01-01").replace("isolated VLAN", "\"  \""),
            entry_yaml(&fp, "2026-10-01"),
            entry_yaml(&fp, "not-a-date"),
            entry_yaml("xyz", "2027-01-01"),
            entry_yaml("00112233445566778899", "2027-01-01"),
            format!(
                "{}{}",
                entry_yaml(&fp, "2027-01-01"),
                entry_yaml(&fp, "2027-01-01").replace("accepted:\n", "")
            ),
            String::new(),
        ];
        for text in &bad {
            assert!(parse(text).is_err(), "accepted: {text:?}");
        }
    }

    #[test]
    fn oversize_and_missing_files_are_errors() {
        let dir = std::env::temp_dir().join(format!("rikitikitavi-accept-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.yaml");
        let cap = usize::try_from(MAX_ACCEPT_FILE_BYTES).unwrap();
        std::fs::write(&big, format!("# {}\naccepted: []\n", "x".repeat(cap))).unwrap();
        assert!(load(&big).unwrap_err().to_string().contains("exceeds"));
        assert!(load(&dir.join("missing.yaml")).is_err());
        let ok = dir.join("ok.yaml");
        std::fs::write(&ok, "accepted: []\n").unwrap();
        assert!(load(&ok).unwrap().entries.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn apply_moves_matches_and_warns_on_expired_and_unmatched() {
        let fp = telnet().fingerprint().to_string();
        let ledger = parse(&format!(
            "{}{}{}",
            entry_yaml(&fp, "2026-12-01"),
            entry_yaml("00000000000000aa", "2026-12-01").replace("accepted:\n", ""),
            entry_yaml("00000000000000bb", "2026-11-10").replace("accepted:\n", ""),
        ))
        .unwrap();
        let other = Finding::new("ssl", "Expired cert", "d", Severity::Medium);
        let mut results = ScanResults {
            findings: vec![telnet(), other],
            ..Default::default()
        };
        let warnings = apply(&ledger, &mut results, day("2026-12-01"));
        assert_eq!(results.findings.len(), 1);
        assert_eq!(results.accepted.len(), 1);
        assert_eq!(results.accepted[0].reason, "isolated VLAN");
        assert_eq!(warnings.len(), 2);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("00000000000000aa") && w.contains("matches no"))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("00000000000000bb") && w.contains("expired"))
        );
    }

    #[test]
    fn expired_entry_leaves_finding_active() {
        let fp = telnet().fingerprint().to_string();
        let ledger = parse(&entry_yaml(&fp, "2026-11-30")).unwrap();
        let mut results = ScanResults {
            findings: vec![telnet()],
            ..Default::default()
        };
        let warnings = apply(&ledger, &mut results, day("2026-12-01"));
        assert_eq!(results.findings.len(), 1);
        assert!(results.accepted.is_empty());
        assert!(warnings[0].contains(&fp) && warnings[0].contains("expired on 2026-11-30"));
    }

    proptest! {
        /// Every finding ends up in exactly one of `findings` / `accepted`.
        #[test]
        fn prop_apply_partitions_findings(
            ports in proptest::collection::vec(1_u16..50, 0..20),
            accept in proptest::collection::vec(1_u16..50, 0..10),
            expired in any::<bool>(),
        ) {
            let make = |p: u16| Finding::new("ports", "open", "d", Severity::Low)
                .with_ip("10.0.0.1".parse().unwrap())
                .with_port(p);
            let entries: Vec<Entry> = accept
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(|&p| Entry {
                    fingerprint: make(p).fingerprint(),
                    reason: "r".to_owned(),
                    accepted_on: day("2026-01-01"),
                    expires: day("2026-06-01"),
                    compensating: None,
                })
                .collect();
            let ledger = Ledger { entries };
            let mut results = ScanResults {
                findings: ports.iter().map(|&p| make(p)).collect(),
                ..Default::default()
            };
            let today = if expired { day("2026-06-02") } else { day("2026-06-01") };
            apply(&ledger, &mut results, today);
            prop_assert_eq!(results.findings.len() + results.accepted.len(), ports.len());
            if expired {
                prop_assert!(results.accepted.is_empty());
            }
            for f in &results.findings {
                prop_assert!(expired || !accept.contains(&f.affected_port.unwrap()));
            }
        }
    }
}
