use super::*;

use proptest::prelude::*;
use rikitikitavi_models::device::{OpenPort, PortProtocol};
use rikitikitavi_models::{Device, DeviceReportCard, DeviceType, Finding, MacAddr};
use std::net::{IpAddr, Ipv4Addr};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

fn card(n: u8, grade: Grade, status: DeviceStatus) -> DeviceReportCard {
    DeviceReportCard {
        ip: ip(n),
        mac: None,
        hostname: None,
        device_type: DeviceType::Unknown,
        grade,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        kev: 0,
        class_weighted: false,
        status,
        rationale: String::new(),
    }
}

fn sample() -> ScanResults {
    ScanResults {
        findings: vec![
            Finding::new("test", "critical", "d", Severity::Critical).with_ip(ip(1)),
            Finding {
                is_kev: true,
                ..Finding::new("test", "kev", "d", Severity::High).with_ip(ip(1))
            },
            Finding::new("test", "eol", "d", Severity::Medium)
                .with_ip(ip(2))
                .with_cwe("CWE-1104"),
        ],
        devices: vec![
            Device {
                mac: Some(MacAddr::new([0, 1, 2, 3, 4, 5])),
                vendor: Some("Example Inc".to_owned()),
                device_type: DeviceType::Camera,
                open_ports: vec![OpenPort {
                    port: 554,
                    protocol: PortProtocol::Tcp,
                    service: None,
                    version: None,
                    banner: None,
                }],
                ..Device::new(ip(1))
            },
            Device::new(ip(2)),
        ],
        report_cards: vec![
            card(1, Grade::F, DeviceStatus::New),
            card(2, Grade::B, DeviceStatus::Known),
        ],
        risk_score: 57.5,
        scan_duration_secs: 42,
        ..Default::default()
    }
}

/// Every sample line is `name[{labels}] value` with a finite value, and no
/// OpenMetrics-only construct appears. Returns the sample lines.
fn check_exposition(text: &str) -> Vec<(String, f64)> {
    let mut samples = Vec::new();
    for line in text.lines() {
        assert!(!line.is_empty(), "blank line in exposition");
        assert_ne!(line, "# EOF", "OpenMetrics terminator rejected by expfmt");
        if let Some(meta) = line.strip_prefix("# ") {
            assert!(
                meta.starts_with("HELP ") || meta.starts_with("TYPE "),
                "unexpected comment: {line}"
            );
            continue;
        }
        let (name_part, value_part) = line.rsplit_once(' ').expect("sample has a value");
        assert!(
            !name_part.contains("_created"),
            "OpenMetrics _created series"
        );
        let value: f64 = value_part.parse().expect("value parses as a float");
        assert!(value.is_finite());
        // A timestamp would leave a second field the collector rejects.
        assert!(
            !value_part.contains(' '),
            "sample carries a timestamp: {line}"
        );
        let name = name_part.split('{').next().unwrap().to_owned();
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':'),
            "illegal metric name: {name}"
        );
        if let Some(labels) = name_part.split_once('{') {
            assert!(labels.1.ends_with('}'), "unterminated label set: {line}");
        }
        samples.push((name_part.to_owned(), value));
    }
    samples
}

#[test]
fn sample_scan_renders_valid_exposition() {
    let text = render_prometheus(&sample());
    let samples = check_exposition(&text);
    assert!(!samples.is_empty());
}

#[test]
fn headers_precede_every_metric() {
    let text = render_prometheus(&sample());
    for (name, _) in check_exposition(&text) {
        let base = name.split('{').next().unwrap();
        assert!(
            text.contains(&format!("# TYPE {base} gauge")),
            "missing TYPE for {base}"
        );
        assert!(
            text.contains(&format!("# HELP {base} ")),
            "missing HELP for {base}"
        );
    }
}

#[test]
fn counts_match_the_results() {
    let text = render_prometheus(&sample());
    assert!(text.contains("rikitikitavi_devices 2"));
    assert!(text.contains("rikitikitavi_devices_new 1"));
    assert!(text.contains("rikitikitavi_kev_findings 1"));
    assert!(text.contains("rikitikitavi_eol_findings 1"));
    assert!(text.contains("rikitikitavi_poc_findings 0"));
    assert!(
        text.contains("rikitikitavi_findings{severity=\"critical\",confidence=\"probable\"} 1")
    );
    assert!(text.contains("rikitikitavi_devices_by_grade{grade=\"F\"} 1"));
    assert!(text.contains("rikitikitavi_device_grade{ip=\"10.0.0.1\"} 0"));
    assert!(text.contains("rikitikitavi_scan_duration_seconds 42"));
}

/// `_total` is reserved for counters; every series here is a snapshot gauge.
#[test]
fn no_gauge_carries_the_counter_suffix() {
    let text = render_prometheus(&sample());
    for (name, _) in check_exposition(&text) {
        let base = name.split('{').next().unwrap();
        assert!(!base.ends_with("_total"), "{base}");
    }
}

/// The `poc` tier is the one exploit signal KEV does not carry.
#[test]
fn poc_tier_findings_are_counted() {
    let mut results = sample();
    results.findings.push(
        Finding::new("test", "terrapin", "d", Severity::Medium)
            .with_ip(ip(2))
            .with_cve_ids(vec!["CVE-2023-48795".to_owned()]),
    );
    let text = render_prometheus(&results);
    check_exposition(&text);
    assert!(text.contains("rikitikitavi_poc_findings 1"));
}

#[test]
fn untracked_devices_emit_no_new_device_gauge() {
    let mut results = sample();
    for card in &mut results.report_cards {
        card.status = DeviceStatus::Untracked;
    }
    let text = render_prometheus(&results);
    assert!(!text.contains("devices_new"));
}

#[test]
fn not_assessed_devices_have_no_grade_sample() {
    let mut results = sample();
    results.report_cards[1].grade = Grade::NotAssessed;
    let text = render_prometheus(&results);
    check_exposition(&text);
    assert!(!text.contains("rikitikitavi_device_grade{ip=\"10.0.0.2\"}"));
    assert!(text.contains("rikitikitavi_devices_by_grade{grade=\"not_assessed\"} 1"));
}

#[test]
fn label_values_are_escaped() {
    let mut results = sample();
    results.devices[0].vendor = Some("a\"b\\c\nd\te".to_owned());
    let text = render_prometheus(&results);
    check_exposition(&text);
    assert!(text.contains(r#"vendor="a\"b\\c\nd e""#));
}

#[test]
fn empty_results_still_render() {
    let text = render_prometheus(&ScanResults::default());
    check_exposition(&text);
    assert!(text.contains("rikitikitavi_devices 0"));
}

#[test]
fn export_writes_the_file_and_leaves_no_temp() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rikitikitavi.prom");
    export_prometheus(&sample(), &path).unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    check_exposition(&body);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name() != "rikitikitavi.prom")
        .collect();
    assert!(leftovers.is_empty(), "temporary file left behind");
}

#[cfg(unix)]
#[test]
fn exported_file_is_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rikitikitavi.prom");
    export_prometheus(&sample(), &path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "node_exporter reads this as its own user");
}

#[test]
fn export_overwrites_an_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rikitikitavi.prom");
    std::fs::write(&path, "stale").unwrap();
    export_prometheus(&sample(), &path).unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains("stale"));
}

/// Any Unicode scalar values, including controls and quotes.
fn arb_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..16).prop_map(|c| c.into_iter().collect())
}

proptest! {
    /// Hostile identity strings never produce a document the collector would reject.
    #[test]
    fn prop_exposition_stays_parseable(
        vendor in arb_text(),
        hostname in arb_text(),
        title in arb_text(),
        duration in any::<u64>(),
    ) {
        let results = ScanResults {
            devices: vec![Device {
                vendor: Some(vendor),
                hostname: Some(hostname),
                ..Device::new(ip(9))
            }],
            findings: vec![Finding::new("s", &title, "d", Severity::Low).with_ip(ip(9))],
            scan_duration_secs: duration,
            ..Default::default()
        };
        let text = render_prometheus(&results);
        check_exposition(&text);
    }
}
