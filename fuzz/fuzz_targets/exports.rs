#![no_main]
//! Device-controlled text placed in every string field must not break out of any
//! export format. The marker `zqx` appears in no template.
use libfuzzer_sys::fuzz_target;
use rikitikitavi_models::{Device, Finding, Remediation, ScanResults};
use rikitikitavi_core::Severity;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let payload = format!("<zqx {text}\n# zqx\nzqx_metric 1\n|zqx|");
    let ip = std::net::IpAddr::from([10, 0, 0, 7]);

    let mut device = Device::new(ip);
    device.hostname = Some(payload.clone());
    device.vendor = Some(payload.clone());
    device.seen_by = vec![payload.clone()];
    let finding = Finding::new("ports", &payload, &payload, Severity::High)
        .with_ip(ip)
        .with_port(23)
        .with_service(&payload)
        .with_evidence(&payload)
        .with_remediation(Remediation {
            description: payload.clone(),
            steps: vec![payload.clone()],
            effort: Some(payload.clone()),
        });
    let results = ScanResults {
        devices: vec![device],
        findings: vec![finding],
        ..Default::default()
    };

    let html = rikitikitavi_export::html::render_html_report(&results);
    assert!(!html.contains("<zqx"), "raw tag in HTML");

    for md in [
        rikitikitavi_export::render_fix_plan(&results, Some(&payload)),
        rikitikitavi_export::render_segment_plan(&results, Some(&payload)),
    ] {
        assert!(
            !md.replace("\\<zqx", "").contains("<zqx"),
            "unescaped tag in Markdown"
        );
        assert!(
            !md.lines().any(|l| l.trim_start().starts_with("# zqx")),
            "injected Markdown heading"
        );
    }

    let prom = rikitikitavi_export::render_prometheus(&results);
    assert!(
        !prom.lines().any(|l| l.starts_with("zqx_metric")),
        "injected Prometheus sample"
    );

    let json = rikitikitavi_export::to_json_string(&results).expect("serializes");
    let back: ScanResults = serde_json::from_str(&json).expect("round-trips");
    assert_eq!(back.findings[0].title, payload);
    assert_eq!(back.devices[0].hostname.as_deref(), Some(payload.as_str()));
});
