//! Markdown fix-plan checklist: Do now / This weekend / Replace / Accepted.

use rikitikitavi_core::Severity;
use rikitikitavi_models::{AcceptedFinding, Finding, ScanResults};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

/// CWE tagged on end-of-life findings.
const EOL_CWE: &str = "CWE-1104";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bucket {
    DoNow,
    Weekend,
    Replace,
    NoFix,
    Skip,
}

fn is_eol(f: &Finding) -> bool {
    let title = f.title.to_ascii_lowercase();
    f.cwe_id.as_deref() == Some(EOL_CWE)
        || title.contains("end-of-life")
        || title.contains("end of life")
}

fn has_fix(f: &Finding) -> bool {
    f.remediation
        .as_ref()
        .is_some_and(|r| !r.description.trim().is_empty() || !r.steps.is_empty())
}

fn bucket(f: &Finding) -> Bucket {
    if f.severity == Severity::Info {
        Bucket::Skip
    } else if is_eol(f) {
        Bucket::Replace
    } else if !has_fix(f) {
        Bucket::NoFix
    } else if f.severity >= Severity::High {
        Bucket::DoNow
    } else {
        Bucket::Weekend
    }
}

/// Backslash-escapes Markdown punctuation; line breaks become spaces, other controls are dropped.
pub fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '|' | '!' | '~' | '{' | '}'
            | '&' | '(' | ')' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// `<url>` for a plain http(s) URL, escaped text otherwise.
fn reference(r: &str) -> String {
    let plain = (r.starts_with("https://") || r.starts_with("http://"))
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~:/?#@!$&'*+,;=%".contains(c));
    if plain {
        format!("<{r}>")
    } else {
        escape_md(r)
    }
}

fn location(ip: Option<IpAddr>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip @ IpAddr::V6(_)), Some(p)) => format!("[{ip}]:{p}"),
        (Some(ip), Some(p)) => format!("{ip}:{p}"),
        (Some(ip), None) => ip.to_string(),
        (None, Some(p)) => format!("port {p}"),
        (None, None) => "network".to_owned(),
    }
}

/// Device heading: report-card label (hostname, else IP), then device hostname, then IP.
fn heading(results: &ScanResults, ip: Option<IpAddr>) -> String {
    let Some(ip) = ip else {
        return "Network-wide".to_owned();
    };
    let label = results
        .report_cards
        .iter()
        .find(|c| c.ip == ip)
        .map(rikitikitavi_models::DeviceReportCard::label)
        .or_else(|| {
            results
                .devices
                .iter()
                .find(|d| d.ip == ip)
                .and_then(|d| d.hostname.clone())
        })
        .unwrap_or_else(|| ip.to_string());
    if label == ip.to_string() {
        ip.to_string()
    } else {
        format!("{} ({ip})", escape_md(&label))
    }
}

/// Grouped by IP (ascending, no-IP last); per group by severity desc, then fingerprint.
fn grouped<'a, T>(
    items: impl Iterator<Item = &'a T>,
    key: impl Fn(&T) -> &Finding,
) -> Vec<(Option<IpAddr>, Vec<&'a T>)>
where
    T: 'a,
{
    let mut map: BTreeMap<(bool, Option<IpAddr>), Vec<&T>> = BTreeMap::new();
    let mut seen = HashSet::new();
    for item in items {
        let f = key(item);
        if seen.insert((f.fingerprint(), f.affected_ip)) {
            map.entry((f.affected_ip.is_none(), f.affected_ip))
                .or_default()
                .push(item);
        }
    }
    map.into_iter()
        .map(|((_, ip), mut v)| {
            v.sort_by_key(|i| {
                let f = key(i);
                (std::cmp::Reverse(f.severity), f.fingerprint().value())
            });
            (ip, v)
        })
        .collect()
}

fn write_item(out: &mut String, f: &Finding) {
    let fp = f.fingerprint();
    let _ = write!(
        out,
        "- [ ] **{}** (`{}`, {})",
        escape_md(&f.title),
        location(f.affected_ip, f.affected_port),
        f.severity
    );
    if let Some(r) = f.remediation.as_ref() {
        if !r.description.trim().is_empty() {
            let _ = write!(out, ": {}", escape_md(&r.description));
        }
        out.push('\n');
        for (i, step) in r.steps.iter().enumerate() {
            let _ = writeln!(out, "  {}. {}", i + 1, escape_md(step));
        }
        if let Some(effort) = r.effort.as_deref() {
            let _ = writeln!(out, "  - Effort: {}", escape_md(effort));
        }
    } else {
        out.push('\n');
    }
    if !f.references.is_empty() {
        let refs: Vec<String> = f.references.iter().map(|r| reference(r)).collect();
        let _ = writeln!(out, "  - References: {}", refs.join(", "));
    }
    let _ = writeln!(out, "  - Verify: `rikitikitavi verify --finding {fp}`");
}

fn write_section(out: &mut String, title: &str, results: &ScanResults, items: &[&Finding]) {
    let _ = writeln!(out, "## {title}\n");
    if items.is_empty() {
        out.push_str("Nothing here.\n\n");
        return;
    }
    for (ip, group) in grouped(items.iter().copied(), |f| f) {
        let _ = writeln!(out, "### {}\n", heading(results, ip));
        for f in group {
            write_item(out, f);
        }
        out.push('\n');
    }
}

fn write_accepted(out: &mut String, results: &ScanResults) {
    out.push_str("## Accepted\n\n");
    if results.accepted.is_empty() {
        out.push_str("Nothing here.\n\n");
        return;
    }
    for (ip, group) in grouped(results.accepted.iter(), |a: &AcceptedFinding| &a.finding) {
        let _ = writeln!(out, "### {}\n", heading(results, ip));
        for a in group {
            let f = &a.finding;
            let _ = writeln!(
                out,
                "- **{}** (`{}`, {}, `{}`)",
                escape_md(&f.title),
                location(f.affected_ip, f.affected_port),
                f.severity,
                a.fingerprint
            );
            let _ = writeln!(
                out,
                "  - Reason: {} (accepted {}, expires {})",
                escape_md(&a.reason),
                a.accepted_on,
                a.expires
            );
            if let Some(c) = a.compensating.as_deref() {
                let _ = writeln!(out, "  - Compensating: {}", escape_md(c));
            }
        }
        out.push('\n');
    }
}

/// Render the plan. `generated` becomes one line under the title; everything else depends
/// only on the findings, devices and accepted entries.
pub fn render_fix_plan(results: &ScanResults, generated: Option<&str>) -> String {
    let mut out = String::from("# Fix plan\n\n");
    if let Some(line) = generated {
        let _ = writeln!(out, "{}\n", escape_md(line));
    }
    let pick = |b: Bucket| -> Vec<&Finding> {
        results.findings.iter().filter(|f| bucket(f) == b).collect()
    };
    write_section(&mut out, "Do now", results, &pick(Bucket::DoNow));
    write_section(&mut out, "This weekend", results, &pick(Bucket::Weekend));
    write_section(&mut out, "Replace", results, &pick(Bucket::Replace));
    write_accepted(&mut out, results);

    let no_fix = pick(Bucket::NoFix);
    if !no_fix.is_empty() {
        out.push_str("## No fix available\n\n");
        for (ip, group) in grouped(no_fix.into_iter(), |f| f) {
            for f in group {
                let _ = writeln!(
                    out,
                    "- {} (`{}`, {}, {}, `{}`)",
                    escape_md(&f.title),
                    location(ip, f.affected_port),
                    f.severity,
                    heading(results, ip),
                    f.fingerprint()
                );
            }
        }
        out.push('\n');
    }
    let info = pick(Bucket::Skip).len();
    if info > 0 {
        let _ = writeln!(out, "{info} informational finding(s) not listed.");
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

/// Write the plan with owner-only permissions.
pub fn export_fix_plan(
    results: &ScanResults,
    generated: Option<&str>,
    path: &Path,
) -> anyhow::Result<()> {
    rikitikitavi_core::fs::write_private(path, render_fix_plan(results, generated).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::{Device, Remediation};

    fn rem(desc: &str, steps: &[&str]) -> Remediation {
        Remediation {
            description: desc.to_owned(),
            steps: steps.iter().map(|s| (*s).to_owned()).collect(),
            effort: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fixture() -> ScanResults {
        let nas = ip("192.168.1.20");
        let cam = ip("192.168.1.30");
        let telnet = Finding::new("ports", "Telnet open", "d", Severity::Critical)
            .with_ip(nas)
            .with_port(23)
            .with_remediation(rem(
                "Disable Telnet",
                &["Open the admin UI", "Turn off Telnet"],
            ))
            .with_references(vec!["https://example.com/telnet".to_owned()]);
        let banner = Finding::new(
            "http_audit",
            "Admin panel <b>[click](http://evil)</b> *now*",
            "d",
            Severity::High,
        )
        .with_ip(cam)
        .with_port(80)
        .with_remediation(rem("Set a password", &[]));
        let weak = Finding::new("ssl", "Weak TLS", "d", Severity::Medium)
            .with_ip(nas)
            .with_port(443)
            .with_remediation(rem("Disable TLS 1.0", &[]));
        let eol = Finding::new(
            "services",
            "End-of-life Debian 9 on 192.168.1.20:22",
            "d",
            Severity::High,
        )
        .with_ip(nas)
        .with_port(22)
        .with_cwe(EOL_CWE);
        let nofix = Finding::new("rtsp", "RTSP stream open", "d", Severity::Medium)
            .with_ip(cam)
            .with_port(554);
        let info = Finding::new("ports", "SSH open", "d", Severity::Info).with_ip(nas);
        let upnp = Finding::new("upnp_igd", "UPnP IGD enabled", "d", Severity::Low)
            .with_remediation(rem("Turn off UPnP on the router", &[]));
        let accepted = Finding::new("snmp", "SNMP public community", "d", Severity::High)
            .with_ip(cam)
            .with_port(161);
        let devices = vec![
            Device::new(nas).with_hostname("nas.local"),
            Device::new(cam).with_hostname("cam_*evil*"),
        ];
        ScanResults {
            report_cards: rikitikitavi_analysis::grade_devices(&devices, &[]),
            devices,
            accepted: vec![AcceptedFinding {
                fingerprint: accepted.fingerprint(),
                finding: accepted,
                reason: "Camera VLAN blocks SNMP".to_owned(),
                accepted_on: "2026-11-01".parse().unwrap(),
                expires: "2027-02-01".parse().unwrap(),
                compensating: Some("ACL on gateway".to_owned()),
            }],
            findings: vec![info, nofix, upnp, eol, weak.clone(), banner, telnet, weak],
            ..Default::default()
        }
    }

    #[test]
    fn golden() {
        let rendered = render_fix_plan(&fixture(), None);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fix_plan/golden.md");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, &rendered).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rendered, expected, "set UPDATE_GOLDEN=1 to regenerate");
    }

    #[test]
    fn output_is_independent_of_finding_order_and_ids() {
        let a = fixture();
        let mut b = fixture();
        b.findings.reverse();
        assert_eq!(render_fix_plan(&a, None), render_fix_plan(&b, None));
    }

    #[test]
    fn generated_line_is_escaped_and_only_header() {
        let r = render_fix_plan(&ScanResults::default(), Some("Generated *now*"));
        assert!(r.contains("Generated \\*now\\*"));
        assert!(r.contains("## Do now\n\nNothing here."));
    }

    #[test]
    fn escape_neutralises_links_html_and_newlines() {
        let e = escape_md("[x](http://a) <img> # h\n- item `c`");
        assert!(!e.contains('\n'));
        for bad in ["[x]", "<img>", "`c`"] {
            assert!(!e.contains(bad), "{e}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn export_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.md");
        export_fix_plan(&fixture(), None, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    proptest! {
        /// No unescaped Markdown-significant character survives.
        #[test]
        fn prop_escape_leaves_no_bare_specials(s in "\\PC{0,64}") {
            let e = escape_md(&s);
            let mut chars = e.chars();
            while let Some(c) = chars.next() {
                prop_assert!(!c.is_control() || c == ' ');
                if c == '\\' {
                    prop_assert!(chars.next().is_some());
                } else {
                    let special = "`*_[]<>#|!~{}&()".contains(c);
                    prop_assert!(!special, "bare {:?} in {:?}", c, e);
                }
            }
        }
    }
}
