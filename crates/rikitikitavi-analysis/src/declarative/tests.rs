use super::*;
use proptest::prelude::*;
use rikitikitavi_models::device::{OpenPort, PortProtocol};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn tcp(port: u16, service: Option<&str>, version: Option<&str>, banner: Option<&str>) -> OpenPort {
    OpenPort {
        port,
        protocol: PortProtocol::Tcp,
        service: service.map(str::to_owned),
        version: version.map(str::to_owned),
        banner: banner.map(str::to_owned),
    }
}

fn device_with(ports: Vec<OpenPort>) -> Device {
    let mut d = Device::new(ip("192.168.1.10"));
    d.open_ports = ports;
    d
}

#[test]
fn version_lt_orders_numerically_not_lexically() {
    assert!(version_lt("1.2.3", "1.10.0"));
    assert!(!version_lt("1.10.0", "1.2.3"));
    assert!(version_lt("1.20.4", "1.21.0"));
    assert!(!version_lt("2.0", "2.0.0"));
    assert!(version_lt("nginx/1.24.0", "1.25.0"));
    assert!(!version_lt("", ""));
}

#[test]
fn version_key_saturates_and_caps() {
    // Absurdly long numeric run must not panic; saturates to u64::MAX.
    let key = version_key(&"9".repeat(40));
    assert_eq!(key, vec![u64::MAX]);
    // More than MAX_VERSION_COMPONENTS groups are truncated.
    let many = (0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(".");
    assert_eq!(version_key(&many).len(), MAX_VERSION_COMPONENTS);
}

#[test]
fn port_open_predicate() {
    let rules = parse_rules(
        "rules:\n  - id: r1\n    title: Telnet open\n    severity: high\n    match:\n      - port_open: 23\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(23, Some("telnet"), None, None)]);
    let out = run_rules(&rules, &[dev], &[]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, Some(23));
    assert_eq!(out[0].scanner, SCANNER);
    // No match when the port is absent.
    let dev2 = device_with(vec![tcp(22, Some("ssh"), None, None)]);
    assert!(run_rules(&rules, &[dev2], &[]).is_empty());
}

#[test]
fn all_and_any_clauses() {
    let yaml = "\
rules:
  - id: cam-telnet
    title: Telnet on a camera
    severity: high
    match:
      all:
        - port_open: 23
      any:
        - device_type_is: camera
        - device_type_is: nvr
";
    let rules = parse_rules(yaml).unwrap();
    let mut cam = device_with(vec![tcp(23, Some("telnet"), None, None)]);
    cam.device_type = DeviceType::Camera;
    assert_eq!(run_rules(&rules, &[cam], &[]).len(), 1);

    // Right port, wrong type: any-clause fails.
    let mut printer = device_with(vec![tcp(23, Some("telnet"), None, None)]);
    printer.device_type = DeviceType::Printer;
    assert!(run_rules(&rules, &[printer], &[]).is_empty());
}

#[test]
fn banner_contains_scoped_and_unscoped() {
    let rules = parse_rules(
        "rules:\n  - id: b\n    title: Boa server\n    severity: medium\n    match:\n      - banner_contains: boa\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(80, Some("http"), None, Some("Server: Boa/0.94"))]);
    assert_eq!(run_rules(&rules, &[dev], &[]).len(), 1);

    let scoped = parse_rules(
        "rules:\n  - id: b\n    title: Boa on 8080\n    severity: medium\n    match:\n      - banner_contains: { port: 8080, text: boa }\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(80, Some("http"), None, Some("Server: Boa/0.94"))]);
    assert!(run_rules(&scoped, &[dev], &[]).is_empty());
}

#[test]
fn service_version_lt_predicate() {
    let rules = parse_rules(
        "rules:\n  - id: v\n    title: Old nginx\n    severity: medium\n    match:\n      - service_version_lt: { service: nginx, version: 1.25.0 }\n",
    )
    .unwrap();
    let old = device_with(vec![tcp(80, Some("nginx"), Some("1.24.0"), None)]);
    assert_eq!(run_rules(&rules, &[old], &[]).len(), 1);
    let current = device_with(vec![tcp(80, Some("nginx"), Some("1.27.0"), None)]);
    assert!(run_rules(&rules, &[current], &[]).is_empty());
    // No version parsed: no match.
    let unknown = device_with(vec![tcp(80, Some("nginx"), None, None)]);
    assert!(run_rules(&rules, &[unknown], &[]).is_empty());
}

#[test]
fn has_finding_matches_scanner_or_title() {
    let rules = parse_rules(
        "rules:\n  - id: h\n    title: Follow-up\n    severity: low\n    match:\n      - has_finding: telnet\n",
    )
    .unwrap();
    let dev = device_with(vec![]);
    let existing =
        vec![Finding::new("ports", "Telnet service exposed", "d", Severity::High).with_ip(dev.ip)];
    assert_eq!(
        run_rules(&rules, std::slice::from_ref(&dev), &existing).len(),
        1
    );
    // A finding on a different IP does not count.
    let other = vec![
        Finding::new("ports", "Telnet service exposed", "d", Severity::High)
            .with_ip(ip("10.0.0.9")),
    ];
    assert!(run_rules(&rules, &[dev], &other).is_empty());
}

#[test]
fn confidence_is_capped_at_probable() {
    let rules = parse_rules(
        "rules:\n  - id: c\n    title: T\n    severity: high\n    confidence: confirmed\n    match:\n      - port_open: 23\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(23, None, None, None)]);
    let out = run_rules(&rules, &[dev], &[]);
    assert_eq!(out[0].confidence, Confidence::Probable);
}

#[test]
fn confidence_defaults_to_inferred() {
    let rules = parse_rules(
        "rules:\n  - id: c\n    title: T\n    severity: high\n    match:\n      - port_open: 23\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(23, None, None, None)]);
    let out = run_rules(&rules, &[dev], &[]);
    assert_eq!(out[0].confidence, Confidence::Inferred);
}

#[test]
fn remediation_cwe_references_carried_through() {
    let yaml = "\
rules:
  - id: full
    title: Full finding
    severity: high
    cwe: CWE-319
    references: [https://example.test/adv]
    remediation:
      description: Disable it
      steps: [step one, step two]
      effort: 5 minutes
    match:
      - port_open: 23
";
    let rules = parse_rules(yaml).unwrap();
    let dev = device_with(vec![tcp(23, None, None, None)]);
    let f = &run_rules(&rules, &[dev], &[])[0];
    assert_eq!(f.cwe_id.as_deref(), Some("CWE-319"));
    assert_eq!(f.references, vec!["https://example.test/adv".to_owned()]);
    let rem = f.remediation.as_ref().unwrap();
    assert_eq!(rem.steps.len(), 2);
    assert_eq!(rem.effort.as_deref(), Some("5 minutes"));
}

#[test]
fn bare_list_file_form_parses() {
    let yaml = "\
- id: bare
  title: Bare list rule
  severity: low
  match:
    - port_open: 80
";
    let rules = parse_rules(yaml).unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn unknown_field_is_rejected() {
    let yaml = "rules:\n  - id: x\n    title: T\n    severity: low\n    typo_field: 1\n    match:\n      - port_open: 80\n";
    assert!(parse_rules(yaml).is_err());
}

#[test]
fn unknown_device_type_is_rejected() {
    let yaml = "rules:\n  - id: x\n    title: T\n    severity: low\n    match:\n      - device_type_is: toaster\n";
    assert!(parse_rules(yaml).is_err());
}

#[test]
fn empty_match_is_rejected() {
    let yaml = "rules:\n  - id: x\n    title: T\n    severity: low\n    match: []\n";
    assert!(parse_rules(yaml).is_err());
}

#[test]
fn over_long_pattern_is_rejected() {
    let long = "a".repeat(MAX_PATTERN_BYTES + 1);
    let yaml = format!(
        "rules:\n  - id: x\n    title: T\n    severity: low\n    match:\n      - banner_contains: {long}\n"
    );
    assert!(parse_rules(&yaml).is_err());
}

#[test]
fn too_many_rules_is_rejected() {
    let one = "  - id: r\n    title: T\n    severity: low\n    match:\n      - port_open: 1\n";
    let yaml = format!("rules:\n{}", one.repeat(MAX_RULES + 1));
    assert!(parse_rules(&yaml).is_err());
}

#[test]
fn shipped_example_rules_parse() {
    // Every example under examples/rules/ must load and validate.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/rules");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let rules = load_rules(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(!rules.is_empty(), "{}", path.display());
            count += 1;
        }
    }
    assert!(count >= 2, "expected the shipped example rule files");
}

#[test]
fn evaluate_rule_file_emits_matches() {
    let path = std::env::temp_dir().join(format!(
        "rikitikitavi_decl_{}_{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(
        &path,
        "rules:\n  - id: r1\n    title: Telnet open\n    severity: high\n    match:\n      - port_open: 23\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(23, Some("telnet"), None, None)]);
    let out = evaluate_rule_file(&path, &[dev], &[]).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, Some(23));
    assert_eq!(out[0].title, "Telnet open");
}

#[test]
fn device_type_is_predicate() {
    let rules = parse_rules(
        "rules:\n  - id: d\n    title: Camera\n    severity: low\n    match:\n      - device_type_is: camera\n",
    )
    .unwrap();
    let mut cam = device_with(vec![tcp(80, None, None, None)]);
    cam.device_type = DeviceType::Camera;
    assert_eq!(run_rules(&rules, &[cam], &[]).len(), 1);
    // A different device type must not match.
    let mut printer = device_with(vec![tcp(80, None, None, None)]);
    printer.device_type = DeviceType::Printer;
    assert!(run_rules(&rules, &[printer], &[]).is_empty());
}

#[test]
fn banner_contains_no_match_when_text_absent() {
    let rules = parse_rules(
        "rules:\n  - id: b\n    title: X\n    severity: low\n    match:\n      - banner_contains: zzznomatch\n",
    )
    .unwrap();
    // Port is open but none of service/version/banner contains the needle.
    let dev = device_with(vec![tcp(
        80,
        Some("http"),
        Some("1.0"),
        Some("Server: Boa"),
    )]);
    assert!(run_rules(&rules, &[dev], &[]).is_empty());
}

#[test]
fn banner_contains_matches_service_and_version_fields() {
    // Needle only in the service field: exercises the service arm of the OR.
    let svc = parse_rules(
        "rules:\n  - id: b\n    title: X\n    severity: low\n    match:\n      - banner_contains: nginx\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(80, Some("nginx"), None, None)]);
    assert_eq!(run_rules(&svc, &[dev], &[]).len(), 1);
    // Needle only in the version field: exercises the version arm of the OR.
    let ver = parse_rules(
        "rules:\n  - id: b\n    title: X\n    severity: low\n    match:\n      - banner_contains: beta7\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(80, Some("http"), Some("1.0-beta7"), None)]);
    assert_eq!(run_rules(&ver, &[dev], &[]).len(), 1);
}

#[test]
fn service_version_lt_respects_service_filter() {
    let rules = parse_rules(
        "rules:\n  - id: v\n    title: Old nginx\n    severity: medium\n    match:\n      - service_version_lt: { service: nginx, version: 2.0.0 }\n",
    )
    .unwrap();
    // Version is below the bound but the service is not nginx: filtered out.
    let apache = device_with(vec![tcp(80, Some("apache"), Some("1.0.0"), None)]);
    assert!(run_rules(&rules, &[apache], &[]).is_empty());
    // Matching service is kept.
    let nginx = device_with(vec![tcp(80, Some("nginx"), Some("1.0.0"), None)]);
    assert_eq!(run_rules(&rules, &[nginx], &[]).len(), 1);
}

#[test]
fn rule_port_from_scoped_banner_and_version() {
    // A scoped banner predicate names the port to stamp on the finding.
    let scoped = parse_rules(
        "rules:\n  - id: b\n    title: Boa\n    severity: low\n    match:\n      - banner_contains: { port: 8080, text: boa }\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(8080, Some("http"), None, Some("Boa/0.94"))]);
    let out = run_rules(&scoped, &[dev], &[]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, Some(8080));

    // service_version_lt with an explicit port likewise supplies the port.
    let ver = parse_rules(
        "rules:\n  - id: v\n    title: Old\n    severity: low\n    match:\n      - service_version_lt: { port: 8443, version: 2.0 }\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(8443, Some("nginx"), Some("1.0"), None)]);
    let out = run_rules(&ver, &[dev], &[]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, Some(8443));
}

#[test]
fn rule_port_none_when_ports_conflict() {
    // Two different ports named: no single port to attach.
    let rules = parse_rules(
        "rules:\n  - id: p\n    title: T\n    severity: low\n    match:\n      - port_open: 22\n      - port_open: 23\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(22, None, None, None), tcp(23, None, None, None)]);
    let out = run_rules(&rules, &[dev], &[]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, None);
}

#[test]
fn rule_port_set_when_ports_agree() {
    // Two predicates naming the same port: that port is stamped on the finding.
    let rules = parse_rules(
        "rules:\n  - id: p\n    title: T\n    severity: low\n    match:\n      - port_open: 23\n      - banner_contains: { port: 23, text: boa }\n",
    )
    .unwrap();
    let dev = device_with(vec![tcp(23, Some("telnet"), None, Some("Boa"))]);
    let out = run_rules(&rules, &[dev], &[]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].affected_port, Some(23));
}

fn arb_confidence() -> impl Strategy<Value = Confidence> {
    prop_oneof![
        Just(Confidence::Inferred),
        Just(Confidence::Probable),
        Just(Confidence::Confirmed),
    ]
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

/// A dotted-numeric version and its component vector, both of length `n`.
fn arb_same_len_versions() -> impl Strategy<Value = (Vec<u64>, Vec<u64>)> {
    (1usize..6).prop_flat_map(|n| {
        (
            proptest::collection::vec(0u64..1000, n),
            proptest::collection::vec(0u64..1000, n),
        )
    })
}

fn join_dotted(v: &[u64]) -> String {
    v.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn arb_dotted() -> impl Strategy<Value = String> {
    proptest::collection::vec(0u64..1000, 1..6).prop_map(|v| join_dotted(&v))
}

proptest! {
    /// Survey #1: no rule, not even one declaring `Confirmed`, can mint a `Confirmed`
    /// finding — confidence is clamped to at most `Probable`.
    #[test]
    fn prop_run_rules_never_emits_confirmed(
        severity in arb_severity(),
        confidence in proptest::option::of(arb_confidence()),
        port in any::<u16>(),
    ) {
        let rule = Rule {
            id: "p".to_owned(),
            title: "T".to_owned(),
            description: String::new(),
            severity,
            confidence,
            cwe: None,
            references: Vec::new(),
            remediation: None,
            match_expr: Match::List(vec![Predicate::PortOpen(port)]),
        };
        let dev = device_with(vec![tcp(port, None, None, None)]);
        let out = run_rules(std::slice::from_ref(&rule), &[dev], &[]);
        prop_assert_eq!(out.len(), 1);
        for f in &out {
            prop_assert!(f.confidence <= Confidence::Probable, "{:?}", f.confidence);
        }
    }

    /// Survey #2: `version_lt` is irreflexive.
    #[test]
    fn prop_version_lt_irreflexive(a in arb_dotted()) {
        prop_assert!(!version_lt(&a, &a));
    }

    /// Survey #2: `version_lt` is transitive.
    #[test]
    fn prop_version_lt_transitive(a in arb_dotted(), b in arb_dotted(), c in arb_dotted()) {
        if version_lt(&a, &b) && version_lt(&b, &c) {
            prop_assert!(version_lt(&a, &c), "{a} < {b} < {c}");
        }
    }

    /// Survey #2: for equal-length dotted-numeric strings, `version_lt` agrees with the
    /// lexicographic order of the numeric keys, and `version_key` recovers the components.
    #[test]
    fn prop_version_lt_agrees_with_key_order((a, b) in arb_same_len_versions()) {
        let sa = join_dotted(&a);
        let sb = join_dotted(&b);
        let expect = a < b;
        prop_assert_eq!(version_lt(&sa, &sb), expect);
        prop_assert_eq!(version_key(&sa), a);
        prop_assert_eq!(version_key(&sb), b);
    }

    /// Survey #2: `version_key` never exceeds the component cap, on any input.
    #[test]
    fn prop_version_key_is_bounded(s in ".{0,256}") {
        prop_assert!(version_key(&s).len() <= MAX_VERSION_COMPONENTS);
    }

    // The parser never panics on arbitrary text.
    #[test]
    fn parse_never_panics(s in ".{0,4096}") {
        let _ = parse_rules(&s);
    }

    // version_lt is total and antisymmetric on arbitrary bytes.
    #[test]
    fn version_lt_total(a in ".{0,64}", b in ".{0,64}") {
        let lt = version_lt(&a, &b);
        let gt = version_lt(&b, &a);
        prop_assert!(!(lt && gt));
    }

    // Evaluation never panics for any parsed rule against a fabricated device.
    #[test]
    fn eval_never_panics(port in any::<u16>(), needle in ".{0,32}") {
        let yaml = format!(
            "rules:\n  - id: p\n    title: T\n    severity: low\n    match:\n      any:\n        - port_open: {port}\n        - banner_contains: {needle:?}\n        - has_finding: {needle:?}\n"
        );
        if let Ok(rules) = parse_rules(&yaml) {
            let dev = device_with(vec![tcp(port, Some(&needle), Some(&needle), Some(&needle))]);
            let _ = run_rules(&rules, &[dev], &[]);
        }
    }
}
