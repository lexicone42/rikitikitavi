use super::*;
use proptest::prelude::*;

/// Table is strictly ascending bytewise: binary-search precondition, no duplicates.
#[test]
fn table_is_strictly_sorted() {
    assert!(SSVC_ENTRIES.windows(2).all(|w| w[0].cve < w[1].cve));
}

/// Every entry equals its own normalisation and has the `CVE-YYYY-NNNN+` shape.
#[test]
fn table_entries_are_normalised_cve_ids() {
    for entry in SSVC_ENTRIES {
        assert_eq!(entry.cve.trim().to_ascii_uppercase(), entry.cve);
        let Some((year, seq)) = entry
            .cve
            .strip_prefix("CVE-")
            .and_then(|rest| rest.split_once('-'))
        else {
            panic!("malformed entry {}", entry.cve);
        };
        assert!(
            year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()),
            "{}",
            entry.cve
        );
        assert!(
            seq.len() >= 4 && seq.bytes().all(|b| b.is_ascii_digit()),
            "{}",
            entry.cve
        );
    }
}

/// CWE values are `CWE-<digits>`, the form `Finding::cwe_id` and OCSF `analytic.uid` expect.
#[test]
fn cwe_values_are_well_formed() {
    for entry in SSVC_ENTRIES {
        let Some(cwe) = entry.cwe else { continue };
        let Some(digits) = cwe.strip_prefix("CWE-") else {
            panic!("malformed CWE {cwe}")
        };
        assert!(
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
            "{cwe}"
        );
    }
}

/// A row carries either both SSVC decision points or neither; a bare CWE row keeps
/// `Exploitation::None`.
#[test]
fn ssvc_decision_points_are_paired() {
    for entry in SSVC_ENTRIES {
        assert_eq!(
            entry.automatable.is_some(),
            entry.technical_impact.is_some(),
            "{}",
            entry.cve
        );
        if entry.automatable.is_none() {
            assert_eq!(entry.exploitation, Exploitation::None, "{}", entry.cve);
        }
    }
}

/// Spot checks against the upstream records, as of the 2026-09 snapshot.
#[test]
fn known_records_match_upstream() {
    // regreSSHion: public exploit, never observed in the wild — the `poc` tier's reason to exist.
    let regresshion = lookup_ssvc("CVE-2024-6387").expect("CVE-2024-6387");
    assert_eq!(regresshion.exploitation, Exploitation::Poc);
    assert_eq!(regresshion.technical_impact, Some(TechnicalImpact::Total));

    // Terrapin.
    assert_eq!(
        lookup_ssvc("CVE-2023-48795").map(|s| s.exploitation),
        Some(Exploitation::Poc)
    );

    // Log4Shell: active and automatable.
    let log4shell = lookup_ssvc("CVE-2021-44228").expect("CVE-2021-44228");
    assert_eq!(log4shell.exploitation, Exploitation::Active);
    assert_eq!(log4shell.automatable, Some(Automatable::Yes));

    // Heartbleed carries a CISA-ADP CWE, so it can backfill.
    assert_eq!(
        lookup_ssvc("CVE-2014-0160").and_then(|s| s.cwe),
        Some("CWE-125")
    );
}

/// Ids that exist only as test fixtures must never select a row: the generator
/// harvests production source plus `scripts/vulnrichment_extra_cves.txt`.
#[test]
fn test_fixture_cves_are_absent() {
    for cve in ["CVE-2024-1234", "CVE-2024-5678", "CVE-1999-0001"] {
        assert!(lookup_ssvc(cve).is_none(), "{cve}");
    }
}

#[test]
fn unknown_cve_is_absent() {
    assert!(lookup_ssvc("CVE-9999-99999").is_none());
    assert!(lookup_ssvc("").is_none());
    assert!(lookup_ssvc("not a cve").is_none());
}

#[test]
fn lookup_is_case_and_whitespace_insensitive() {
    assert_eq!(
        lookup_ssvc("  cve-2024-6387\n").map(|s| s.cve),
        Some("CVE-2024-6387")
    );
}

/// Every tier the table declares is reachable, so the enrichment arms are all exercised.
#[test]
fn all_tiers_present() {
    for tier in [Exploitation::None, Exploitation::Poc, Exploitation::Active] {
        assert!(
            SSVC_ENTRIES.iter().any(|e| e.exploitation == tier),
            "{tier:?} missing"
        );
    }
}

/// A table entry with random per-byte lowercasing and ASCII whitespace padding.
fn arb_mangled_entry() -> impl Strategy<Value = (String, &'static str)> {
    (0..SSVC_ENTRIES.len()).prop_flat_map(|i| {
        let cve = SSVC_ENTRIES[i].cve;
        (
            proptest::collection::vec(any::<bool>(), cve.len()),
            "[ \t\r\n]{0,3}",
            "[ \t\r\n]{0,3}",
        )
            .prop_map(move |(flips, lead, trail)| {
                let body: String = cve
                    .bytes()
                    .zip(flips)
                    .map(|(b, flip)| char::from(if flip { b.to_ascii_lowercase() } else { b }))
                    .collect();
                (format!("{lead}{body}{trail}"), cve)
            })
    })
}

fn arb_any_input() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "CVE-[0-9]{4}-[0-9]{4,7}",
        arb_mangled_entry().prop_map(|(s, _)| s),
    ]
}

proptest! {
    /// ASCII case and surrounding whitespace do not affect the row found.
    #[test]
    fn prop_case_and_whitespace_invariant((mangled, cve) in arb_mangled_entry()) {
        prop_assert_eq!(lookup_ssvc(&mangled).map(|s| s.cve), Some(cve));
    }

    /// Binary search agrees with a linear scan; never panics on arbitrary input.
    #[test]
    fn prop_agrees_with_linear_scan(s in arb_any_input()) {
        let needle = s.trim().to_ascii_uppercase();
        let linear = SSVC_ENTRIES.iter().find(|e| e.cve == needle);
        prop_assert_eq!(lookup_ssvc(&s), linear);
    }
}
