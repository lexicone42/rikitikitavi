use super::*;
use proptest::prelude::*;
use rikitikitavi_core::Severity;
use rikitikitavi_models::Finding;

/// Every CWE any scanner in the workspace emits, with the category it must map to.
/// Regenerate the left column with `grep -rhoE 'CWE-[0-9]+' crates/`.
const EMITTED_CWES: &[(&str, IotCategory)] = &[
    ("CWE-798", IotCategory::I1),
    ("CWE-1392", IotCategory::I1),
    ("CWE-1393", IotCategory::I1),
    ("CWE-284", IotCategory::I2),
    ("CWE-287", IotCategory::I2),
    ("CWE-290", IotCategory::I2),
    ("CWE-306", IotCategory::I2),
    ("CWE-350", IotCategory::I2),
    ("CWE-400", IotCategory::I2),
    ("CWE-653", IotCategory::I2),
    ("CWE-693", IotCategory::I2),
    ("CWE-912", IotCategory::I2),
    ("CWE-923", IotCategory::I2),
    ("CWE-22", IotCategory::I3),
    ("CWE-78", IotCategory::I3),
    ("CWE-79", IotCategory::I3),
    ("CWE-352", IotCategory::I3),
    ("CWE-470", IotCategory::I3),
    ("CWE-548", IotCategory::I3),
    ("CWE-669", IotCategory::I3),
    ("CWE-749", IotCategory::I3),
    ("CWE-942", IotCategory::I3),
    ("CWE-1004", IotCategory::I3),
    ("CWE-1021", IotCategory::I3),
    ("CWE-354", IotCategory::I4),
    ("CWE-119", IotCategory::I5),
    ("CWE-120", IotCategory::I5),
    ("CWE-121", IotCategory::I5),
    ("CWE-125", IotCategory::I5),
    ("CWE-362", IotCategory::I5),
    ("CWE-416", IotCategory::I5),
    ("CWE-428", IotCategory::I5),
    ("CWE-502", IotCategory::I5),
    ("CWE-1104", IotCategory::I5),
    ("CWE-200", IotCategory::I6),
    ("CWE-295", IotCategory::I7),
    ("CWE-319", IotCategory::I7),
    ("CWE-324", IotCategory::I7),
    ("CWE-326", IotCategory::I7),
    ("CWE-327", IotCategory::I7),
    ("CWE-328", IotCategory::I7),
    ("CWE-329", IotCategory::I7),
    ("CWE-330", IotCategory::I7),
    ("CWE-614", IotCategory::I7),
    ("CWE-16", IotCategory::I9),
    ("CWE-645", IotCategory::I9),
    ("CWE-732", IotCategory::I9),
    ("CWE-1188", IotCategory::I9),
];

#[test]
fn every_emitted_cwe_maps_to_the_expected_category() {
    for (cwe, expected) in EMITTED_CWES {
        assert_eq!(category_for_cwe(cwe), Some(*expected), "{cwe} mapped wrong");
    }
}

#[test]
fn placeholder_and_unknown_cwes_map_to_none() {
    // CWE-1 is the test-only placeholder used in other crates; deliberately unmapped.
    assert_eq!(category_for_cwe("CWE-1"), None);
    assert_eq!(category_for_cwe("CWE-99999"), None);
    assert_eq!(category_for_cwe("not-a-cwe"), None);
    assert_eq!(category_for_cwe(""), None);
}

#[test]
fn tag_is_id_space_label() {
    assert_eq!(IotCategory::I2.tag(), "I2 Insecure network services");
    assert_eq!(IotCategory::I1.id(), "I1");
    assert!(IotCategory::I7.tag().starts_with("I7 "));
}

#[test]
fn scanner_category_mappings_are_pinned() {
    // Each arm of category_for_scanner, so deleting one is caught.
    for scanner in ["credentials", "kasa", "tuya"] {
        assert_eq!(
            category_for_scanner(scanner),
            Some(IotCategory::I1),
            "{scanner}"
        );
    }
    for scanner in [
        "arp",
        "dhcp",
        "dns",
        "isolation",
        "network",
        "neighbor",
        "exposure",
        "mgmt-plane",
        "modbus",
        "mqtt",
        "knx",
        "tr069",
    ] {
        assert_eq!(
            category_for_scanner(scanner),
            Some(IotCategory::I2),
            "{scanner}"
        );
    }
    for scanner in ["wifi", "passive-wifi", "ssl"] {
        assert_eq!(
            category_for_scanner(scanner),
            Some(IotCategory::I7),
            "{scanner}"
        );
    }
    for scanner in ["router", "unifi"] {
        assert_eq!(
            category_for_scanner(scanner),
            Some(IotCategory::I9),
            "{scanner}"
        );
    }
    assert_eq!(category_for_scanner("some-unknown-scanner"), None);
}

#[test]
fn cwe_takes_priority_over_scanner() {
    // `credentials` scanner falls back to I1, but a CWE-319 finding is I7.
    let f = Finding::new("credentials", "t", "d", Severity::Low).with_cwe("CWE-319");
    assert_eq!(
        categories_for(&f),
        vec!["I7 Insecure data transfer or storage"]
    );
}

#[test]
fn scanner_fallback_used_when_no_cwe() {
    let f = Finding::new("isolation", "t", "d", Severity::Low);
    assert_eq!(categories_for(&f), vec!["I2 Insecure network services"]);
}

#[test]
fn unmapped_cwe_falls_back_to_scanner() {
    let f = Finding::new("ssl", "t", "d", Severity::Low).with_cwe("CWE-99999");
    assert_eq!(
        categories_for(&f),
        vec!["I7 Insecure data transfer or storage"]
    );
}

#[test]
fn finding_with_neither_gets_no_tag() {
    let f = Finding::new("some-unknown-scanner", "t", "d", Severity::Low);
    assert!(categories_for(&f).is_empty());
}

#[test]
fn enrich_counts_only_tagged_findings() {
    let mut findings = vec![
        Finding::new("ssl", "a", "d", Severity::Low).with_cwe("CWE-319"),
        Finding::new("some-unknown-scanner", "b", "d", Severity::Low),
        Finding::new("isolation", "c", "d", Severity::Low),
    ];
    assert_eq!(enrich_standards(&mut findings), 2);
    assert_eq!(
        findings[0].standards,
        vec!["I7 Insecure data transfer or storage"]
    );
    assert!(findings[1].standards.is_empty());
    assert_eq!(findings[2].standards, vec!["I2 Insecure network services"]);
}

#[test]
fn enrich_is_idempotent() {
    let mut findings = vec![Finding::new("ssl", "a", "d", Severity::Low).with_cwe("CWE-327")];
    enrich_standards(&mut findings);
    let once = findings[0].standards.clone();
    enrich_standards(&mut findings);
    assert_eq!(findings[0].standards, once);
    assert_eq!(once.len(), 1);
}

#[test]
fn old_scan_history_without_standards_still_loads() {
    // A finding serialized before the `standards` field existed must deserialize, defaulting empty.
    let legacy = r#"{"id":"00000000-0000-0000-0000-000000000000","scanner":"ssl","title":"t","description":"d","severity":"high","affected_ip":null,"affected_mac":null,"affected_hostname":null,"affected_port":null,"affected_service":null,"remediation":null,"cwe_id":"CWE-319","cve_ids":[],"references":[],"discovered_at":"2026-07-02T00:00:00Z"}"#;
    let mut parsed: Finding = serde_json::from_str(legacy).expect("legacy finding must load");
    assert!(parsed.standards.is_empty());

    // Enrichment then populates it, and it round-trips.
    enrich_standards(std::slice::from_mut(&mut parsed));
    assert_eq!(
        parsed.standards,
        vec!["I7 Insecure data transfer or storage"]
    );
    let json = serde_json::to_string(&parsed).unwrap();
    let back: Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.standards, parsed.standards);
}

#[test]
fn empty_standards_is_not_serialized() {
    let f = Finding::new("some-unknown-scanner", "t", "d", Severity::Low);
    let json = serde_json::to_string(&f).unwrap();
    assert!(
        !json.contains("standards"),
        "empty standards must be skipped"
    );
}

fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Low),
        Just(Severity::Medium),
        Just(Severity::High),
        Just(Severity::Critical),
    ]
}

fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        "[a-z-]{1,12}",
        "[a-zA-Z0-9 ]{1,20}",
        arb_severity(),
        proptest::option::of("CWE-[0-9]{1,5}"),
    )
        .prop_map(|(scanner, title, sev, cwe)| {
            let mut f = Finding::new(&scanner, &title, "d", sev);
            if let Some(cwe) = cwe {
                f = f.with_cwe(cwe);
            }
            f
        })
}

proptest! {
    /// Enrichment never panics and each finding gets at most one tag, always a known category id.
    #[test]
    fn prop_enrich_never_panics_and_tags_are_known(
        mut findings in proptest::collection::vec(arb_finding(), 0..16)
    ) {
        let known: Vec<String> = [
            IotCategory::I1, IotCategory::I2, IotCategory::I3, IotCategory::I4, IotCategory::I5,
            IotCategory::I6, IotCategory::I7, IotCategory::I8, IotCategory::I9, IotCategory::I10,
        ]
        .into_iter()
        .map(IotCategory::tag)
        .collect();

        let tagged = enrich_standards(&mut findings);
        let mut count = 0;
        for f in &findings {
            prop_assert!(f.standards.len() <= 1);
            for tag in &f.standards {
                prop_assert!(known.contains(tag), "unknown tag {tag:?}");
            }
            if !f.standards.is_empty() {
                count += 1;
            }
        }
        prop_assert_eq!(tagged, count);
    }

    /// Survey #10: enrichment is idempotent — a second pass returns the same count and
    /// leaves every finding's `standards` list byte-for-byte unchanged (guards against an
    /// append-instead-of-recompute regression).
    #[test]
    fn prop_enrich_is_idempotent(
        mut findings in proptest::collection::vec(arb_finding(), 0..16)
    ) {
        let first = enrich_standards(&mut findings);
        let snapshot: Vec<Vec<String>> = findings.iter().map(|f| f.standards.clone()).collect();
        let second = enrich_standards(&mut findings);
        let after: Vec<Vec<String>> = findings.iter().map(|f| f.standards.clone()).collect();
        prop_assert_eq!(second, first);
        prop_assert_eq!(after, snapshot);
    }
}
