//! OVRS remediation template registry.
//!
//! Embedded YAML templates are parsed once (`OnceLock`); `get(id, params)`
//! returns an interpolated `Remediation`. `resolve(finding, device)` picks the
//! most specific product template whose typed `match` selectors fit.

use rikitikitavi_models::{Device, DeviceType, Finding, Remediation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OvrsTemplate {
    id: String,
    #[allow(dead_code)]
    version: String,
    summary: String,
    #[allow(dead_code)]
    description: String,
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<TemplateMetadata>,
    #[serde(default)]
    r#match: Option<TemplateMatch>,
    #[serde(default)]
    #[allow(dead_code)]
    parameters: Vec<ParameterDef>,
    steps: Vec<Step>,
    #[serde(default)]
    #[allow(dead_code)]
    preflight: Vec<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    validation: Vec<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    rollback: Option<serde_json::Value>,
    #[serde(default)]
    remediation: Option<RemediationHints>,
    #[serde(default)]
    #[allow(dead_code)]
    extensions: Option<serde_json::Value>,
}

/// Typed selectors. A list matches when any entry matches; every non-empty list
/// must match. `finding` holds finding-title prefixes; `vendor` and `product`
/// are case-insensitive substrings of `Device::vendor` and of
/// `Device::device_subtype` or `Device::hostname`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TemplateMatch {
    #[serde(default)]
    #[allow(dead_code)]
    resource_kinds: Vec<String>,
    #[serde(default)]
    finding: Vec<String>,
    #[serde(default)]
    vendor: Vec<String>,
    #[serde(default)]
    product: Vec<String>,
    #[serde(default)]
    device_type: Vec<String>,
    #[serde(default)]
    port: Vec<u16>,
}

impl TemplateMatch {
    const fn scopes_finding(&self) -> bool {
        !self.finding.is_empty() || !self.port.is_empty()
    }

    const fn scopes_device(&self) -> bool {
        !self.vendor.is_empty() || !self.product.is_empty() || !self.device_type.is_empty()
    }

    /// Number of non-empty selectors, or `None` when any of them fails.
    fn specificity(&self, finding: &Finding, device: &Device) -> Option<usize> {
        let contains = |hay: Option<&str>, needles: &[String]| {
            hay.is_some_and(|h| {
                let h = h.to_lowercase();
                needles.iter().any(|n| h.contains(&n.to_lowercase()))
            })
        };
        let checks = [
            (
                self.finding.is_empty(),
                self.finding
                    .iter()
                    .any(|p| finding.title.starts_with(p.as_str())),
            ),
            (
                self.vendor.is_empty(),
                contains(device.vendor.as_deref(), &self.vendor),
            ),
            (
                self.product.is_empty(),
                contains(device.device_subtype.as_deref(), &self.product)
                    || contains(device.hostname.as_deref(), &self.product),
            ),
            (
                self.device_type.is_empty(),
                self.device_type
                    .iter()
                    .any(|t| t == device.device_type.as_str()),
            ),
            (
                self.port.is_empty(),
                finding
                    .affected_port
                    .is_some_and(|p| self.port.contains(&p)),
            ),
        ];
        let mut score = 0;
        for (empty, hit) in checks {
            if empty {
                continue;
            }
            if !hit {
                return None;
            }
            score += 1;
        }
        Some(score)
    }
}

#[derive(Debug, Deserialize)]
struct TemplateMetadata {
    #[allow(dead_code)]
    owner: Option<String>,
    #[allow(dead_code)]
    visibility: Option<String>,
    #[allow(dead_code)]
    maturity: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ParameterDef {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    param_type: String,
    #[serde(default)]
    #[allow(dead_code)]
    required: bool,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    #[allow(dead_code)]
    id: String,
    kind: String,
    #[serde(default)]
    params: HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    depends_on: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemediationHints {
    #[allow(dead_code)]
    risk_level: Option<String>,
    #[allow(dead_code)]
    requires_reboot: Option<bool>,
    typical_duration_seconds: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    blast_radius_tags: Vec<String>,
    #[allow(dead_code)]
    change_type: Option<String>,
}

static REGISTRY: OnceLock<RemediationRegistry> = OnceLock::new();

struct RemediationRegistry {
    templates: HashMap<String, OvrsTemplate>,
}

fn init_registry() -> RemediationRegistry {
    let yaml_sources: &[&str] = &[
        include_str!("../templates/arp.yaml"),
        include_str!("../templates/credentials.yaml"),
        include_str!("../templates/database.yaml"),
        include_str!("../templates/device.yaml"),
        include_str!("../templates/dns.yaml"),
        include_str!("../templates/exposure.yaml"),
        include_str!("../templates/http_audit.yaml"),
        include_str!("../templates/isolation.yaml"),
        include_str!("../templates/mdns.yaml"),
        include_str!("../templates/mqtt.yaml"),
        include_str!("../templates/network.yaml"),
        include_str!("../templates/ports.yaml"),
        include_str!("../templates/products.yaml"),
        include_str!("../templates/router.yaml"),
        include_str!("../templates/rtsp.yaml"),
        include_str!("../templates/services.yaml"),
        include_str!("../templates/smb.yaml"),
        include_str!("../templates/snmp.yaml"),
        include_str!("../templates/ssl.yaml"),
        include_str!("../templates/unifi.yaml"),
        include_str!("../templates/upnp_igd.yaml"),
        include_str!("../templates/wifi.yaml"),
    ];

    let mut templates = HashMap::new();
    for source in yaml_sources {
        for document in yaml_documents(source) {
            let template: OvrsTemplate =
                serde_saphyr::from_str(&document).expect("embedded OVRS YAML must be valid");
            let id = template.id.clone();
            if let Some(m) = &template.r#match {
                validate_match(&id, m);
            }
            assert!(
                templates.insert(id.clone(), template).is_none(),
                "duplicate template ID: {id}"
            );
        }
    }

    RemediationRegistry { templates }
}

/// Panics on a selector set that `resolve` could apply too broadly or never.
fn validate_match(id: &str, m: &TemplateMatch) {
    assert_eq!(
        m.scopes_finding(),
        m.scopes_device(),
        "template {id}: product selectors need both a finding/port and a vendor/product/deviceType selector"
    );
    for t in &m.device_type {
        assert!(
            DeviceType::from_name(t).is_some(),
            "template {id}: unknown deviceType {t}"
        );
    }
}

/// Split a multi-document YAML stream on `---` separator lines; empty documents are dropped.
fn yaml_documents(source: &str) -> Vec<String> {
    let mut docs = vec![String::new()];
    for line in source.lines() {
        if line.trim_end() == "---" {
            docs.push(String::new());
        } else if let Some(doc) = docs.last_mut() {
            doc.push_str(line);
            doc.push('\n');
        }
    }
    docs.retain(|d| {
        d.lines()
            .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    });
    docs
}

/// Look up a remediation template by ID, applying parameter interpolation.
pub fn get(id: &str, params: &[(&str, &str)]) -> Option<Remediation> {
    let registry = REGISTRY.get_or_init(init_registry);
    registry.templates.get(id).map(|t| render(t, params))
}

/// Remediation for `finding` on `device`: the product template with the most
/// matching selectors (ties broken by lowest ID), else `finding.remediation`.
/// `{{ ip }}` and `{{ port }}` are interpolated.
pub fn resolve(finding: &Finding, device: &Device) -> Option<Remediation> {
    let registry = REGISTRY.get_or_init(init_registry);
    let best = registry
        .templates
        .values()
        .filter_map(|t| {
            let m = t.r#match.as_ref().filter(|m| m.scopes_device())?;
            m.specificity(finding, device).map(|score| (score, t))
        })
        .max_by(|(a, ta), (b, tb)| a.cmp(b).then_with(|| tb.id.cmp(&ta.id)));
    let Some((_, tmpl)) = best else {
        return finding.remediation.clone();
    };
    let ip = finding
        .affected_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let port = finding
        .affected_port
        .map(|p| p.to_string())
        .unwrap_or_default();
    Some(render(tmpl, &[("ip", &ip), ("port", &port)]))
}

fn render(tmpl: &OvrsTemplate, params: &[(&str, &str)]) -> Remediation {
    let steps: Vec<String> = tmpl
        .steps
        .iter()
        .filter(|s| s.kind == "manual.step")
        .filter_map(|s| s.params.get("text"))
        .filter_map(serde_json::Value::as_str)
        .map(|text| interpolate(text, params))
        .collect();

    let effort = tmpl
        .remediation
        .as_ref()
        .and_then(|r| r.typical_duration_seconds)
        .map(format_duration);

    Remediation {
        description: interpolate(&tmpl.summary, params),
        steps,
        effort,
    }
}

fn interpolate(template: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return template.to_owned();
    }
    let mut result = template.to_owned();
    for &(key, value) in params {
        result = result.replace(&format!("{{{{ {key} }}}}"), value);
    }
    result
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds} seconds")
    } else if seconds < 3600 {
        format!("{} minutes", seconds / 60)
    } else {
        format!("{} hour(s)", seconds / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Every template ID.
    const EXPECTED_IDS: &[&str] = &[
        "rikitikitavi.arp.spoofing-detected",
        "rikitikitavi.credentials.anonymous-ftp",
        "rikitikitavi.credentials.banner-disclosure",
        "rikitikitavi.credentials.class-default-advisory",
        "rikitikitavi.credentials.ftp-default-confirmed",
        "rikitikitavi.credentials.http-default-confirmed",
        "rikitikitavi.credentials.http-no-auth",
        "rikitikitavi.credentials.rdp-exposed",
        "rikitikitavi.credentials.smb-exposed",
        "rikitikitavi.credentials.telnet-default",
        "rikitikitavi.credentials.telnet-default-confirmed",
        "rikitikitavi.credentials.vsftpd-outdated",
        "rikitikitavi.database.elasticsearch-no-auth",
        "rikitikitavi.database.memcached-no-auth",
        "rikitikitavi.database.mongodb-no-auth",
        "rikitikitavi.database.mysql-exposed",
        "rikitikitavi.database.mysql-no-tls",
        "rikitikitavi.database.mysql-weak-auth",
        "rikitikitavi.database.postgresql-exposed",
        "rikitikitavi.database.redis-eol",
        "rikitikitavi.database.redis-no-auth",
        "rikitikitavi.device.unidentified",
        "rikitikitavi.dns.cross-validation-mismatch",
        "rikitikitavi.dns.dmarc-policy",
        "rikitikitavi.dns.dnssec-not-enforced",
        "rikitikitavi.dns.hijacking-detected",
        "rikitikitavi.dns.no-servers",
        "rikitikitavi.dns.spf-policy",
        "rikitikitavi.exposure.no-nat",
        "rikitikitavi.exposure.port-forwarded",
        "rikitikitavi.http_audit.admin-no-auth",
        "rikitikitavi.http_audit.cookie-flags",
        "rikitikitavi.http_audit.cors-permissive",
        "rikitikitavi.http_audit.csp-weak",
        "rikitikitavi.http_audit.dangerous-methods",
        "rikitikitavi.http_audit.default-page",
        "rikitikitavi.http_audit.directory-listing",
        "rikitikitavi.http_audit.missing-hsts",
        "rikitikitavi.http_audit.product-exposed",
        "rikitikitavi.http_audit.security-headers",
        "rikitikitavi.isolation.inter-vlan-routing",
        "rikitikitavi.isolation.large-flat-network",
        "rikitikitavi.mdns.file-sharing",
        "rikitikitavi.mdns.homekit",
        "rikitikitavi.mdns.http-advertised",
        "rikitikitavi.mdns.matter-window-open",
        "rikitikitavi.mdns.thread-border-router",
        "rikitikitavi.mdns.upnp-serial",
        "rikitikitavi.mqtt.anonymous-access",
        "rikitikitavi.network.apipa",
        "rikitikitavi.network.no-gateway",
        "rikitikitavi.ports.database-exposed",
        "rikitikitavi.ports.ftp-open",
        "rikitikitavi.ports.many-open",
        "rikitikitavi.ports.mqtt-unencrypted",
        "rikitikitavi.ports.printer-exposed",
        "rikitikitavi.ports.rdp-open",
        "rikitikitavi.ports.ssh-open",
        "rikitikitavi.ports.telnet-open",
        "rikitikitavi.ports.unencrypted-mail",
        "rikitikitavi.ports.upnp-exposed",
        "rikitikitavi.ports.vnc-open",
        "rikitikitavi.products.denon-avr-telnet",
        "rikitikitavi.products.dyson-mqtt",
        "rikitikitavi.products.gateway-ssh-open",
        "rikitikitavi.products.hue-bridge-self-signed",
        "rikitikitavi.products.unifi-console-openssh",
        "rikitikitavi.products.unifi-console-ssh",
        "rikitikitavi.router.admin-http-unencrypted",
        "rikitikitavi.router.ftp-enabled",
        "rikitikitavi.router.telnet-enabled",
        "rikitikitavi.router.upnp-enabled",
        "rikitikitavi.rtsp.no-auth",
        "rikitikitavi.services.dropbear-ssh",
        "rikitikitavi.services.eol-openssh",
        "rikitikitavi.services.eol-os",
        "rikitikitavi.services.lts-os",
        "rikitikitavi.services.mysql-exposed",
        "rikitikitavi.services.outdated-ssh",
        "rikitikitavi.services.outdated-web-server",
        "rikitikitavi.services.postgresql-exposed",
        "rikitikitavi.services.redis-no-auth",
        "rikitikitavi.services.smtp-no-auth",
        "rikitikitavi.services.smtp-no-starttls",
        "rikitikitavi.services.weak-ssh-algorithms",
        "rikitikitavi.smb.netbios-exposed",
        "rikitikitavi.smb.null-session",
        "rikitikitavi.smb.smbv1-enabled",
        "rikitikitavi.smb.unrecognized-445",
        "rikitikitavi.snmp.default-community",
        "rikitikitavi.ssl.cert-expired",
        "rikitikitavi.ssl.cert-expiring",
        "rikitikitavi.ssl.cert-hostname-mismatch",
        "rikitikitavi.ssl.cert-issue",
        "rikitikitavi.ssl.cert-self-signed",
        "rikitikitavi.ssl.cert-sha1-signature",
        "rikitikitavi.ssl.cert-weak-key",
        "rikitikitavi.ssl.excessive-validity",
        "rikitikitavi.ssl.sslv2v3-enabled",
        "rikitikitavi.ssl.tls10-enabled",
        "rikitikitavi.ssl.tls11-enabled",
        "rikitikitavi.ssl.weak-cipher-suite",
        "rikitikitavi.unifi.no-firewall-rules",
        "rikitikitavi.unifi.pmf",
        "rikitikitavi.upnp_igd.mapping",
        "rikitikitavi.wifi.deauth-flood",
        "rikitikitavi.wifi.default-ssid",
        "rikitikitavi.wifi.directed-probes",
        "rikitikitavi.wifi.hidden-ssid",
        "rikitikitavi.wifi.mac-randomization",
        "rikitikitavi.wifi.open-network",
        "rikitikitavi.wifi.rogue-ap",
        "rikitikitavi.wifi.wep-encryption",
        "rikitikitavi.wifi.wpa1-weak",
        "rikitikitavi.wifi.wps-enabled",
    ];

    #[test]
    fn test_all_templates_parse() {
        let registry = REGISTRY.get_or_init(init_registry);
        assert_eq!(registry.templates.len(), EXPECTED_IDS.len());
    }

    #[test]
    fn test_all_expected_templates_exist() {
        for id in EXPECTED_IDS {
            assert!(get(id, &[]).is_some(), "missing template: {id}");
        }
    }

    #[test]
    fn test_get_static_template() {
        let r = get("rikitikitavi.database.redis-no-auth", &[]).unwrap();
        assert_eq!(r.description, "Enable Redis authentication");
        assert_eq!(r.steps.len(), 4);
        assert!(r.steps[0].contains("requirepass"));
        assert_eq!(r.effort.as_deref(), Some("10 minutes"));
    }

    #[test]
    fn test_get_parameterized_template() {
        let r = get(
            "rikitikitavi.exposure.port-forwarded",
            &[("service", "SSH"), ("port", "22")],
        )
        .unwrap();
        assert!(
            r.description.contains("SSH"),
            "summary should be interpolated: {}",
            r.description
        );
        assert!(
            r.description.contains("22"),
            "summary should contain port: {}",
            r.description
        );
        assert!(r.steps[1].contains("22"), "step should be interpolated");
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        assert!(get("nonexistent.template.id", &[]).is_none());
    }

    #[test]
    fn test_interpolate_no_params() {
        let input = "Hello {{ world }}";
        assert_eq!(interpolate(input, &[]), input);
    }

    #[test]
    fn test_interpolate_multiple_params() {
        let input = "{{ a }} and {{ b }}";
        let result = interpolate(input, &[("a", "foo"), ("b", "bar")]);
        assert_eq!(result, "foo and bar");
    }

    #[test]
    fn test_interpolate_missing_param_preserved() {
        let input = "{{ a }} and {{ b }}";
        let result = interpolate(input, &[("a", "foo")]);
        assert_eq!(result, "foo and {{ b }}");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(59), "59 seconds");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1 minutes");
        assert_eq!(format_duration(300), "5 minutes");
        assert_eq!(format_duration(600), "10 minutes");
        assert_eq!(format_duration(3599), "59 minutes");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1 hour(s)");
        assert_eq!(format_duration(7200), "2 hour(s)");
    }

    fn finding(title: &str, port: u16) -> Finding {
        Finding::new("ports", title, "d", rikitikitavi_core::Severity::Medium)
            .with_ip("192.168.1.50".parse::<std::net::IpAddr>().unwrap())
            .with_port(port)
            .with_opt_remediation(get("rikitikitavi.ports.mqtt-unencrypted", &[]))
    }

    fn device(vendor: Option<&str>, device_type: DeviceType) -> Device {
        let mut d = Device::new("192.168.1.50".parse().unwrap());
        d.vendor = vendor.map(str::to_owned);
        d.device_type = device_type;
        d
    }

    #[test]
    fn resolve_dyson_mqtt_is_product_specific() {
        let f = finding("MQTT (unencrypted) open on 192.168.1.50:1883", 1883);
        let r = resolve(&f, &device(Some("Dyson"), DeviceType::IoT)).unwrap();
        assert!(r.description.contains("Dyson"));
        assert!(r.steps.iter().any(|s| s.contains("community")));
        assert!(r.steps.iter().any(|s| s.contains("192.168.1.50")));
        assert!(!r.steps.iter().any(|s| s.contains("8883")));
    }

    #[test]
    fn resolve_falls_back_to_finding_remediation() {
        let f = finding("MQTT (unencrypted) open on 192.168.1.50:1883", 1883);
        assert_eq!(
            resolve(&f, &device(Some("Espressif"), DeviceType::IoT)),
            f.remediation
        );
        assert_eq!(
            resolve(&f, &device(None, DeviceType::Unknown)),
            f.remediation
        );
        let other_port = finding("Open port 8080", 8080);
        assert_eq!(
            resolve(&other_port, &device(Some("Dyson"), DeviceType::IoT)),
            other_port.remediation
        );
    }

    #[test]
    fn resolve_denon_telnet_on_any_port_23_finding() {
        let r = resolve(
            &finding("Telnet open on 192.168.1.50:23", 23),
            &device(Some("D&M"), DeviceType::MediaPlayer),
        )
        .unwrap();
        assert!(r.steps.iter().any(|s| s.contains("Off In Standby")));
        assert!(r.steps.iter().any(|s| s.contains("IP Control")));
    }

    #[test]
    fn resolve_hue_self_signed_only() {
        let hue = device(Some("Signify"), DeviceType::Hub);
        let r = resolve(
            &finding("Self-signed certificate on 192.168.1.50:443", 443),
            &hue,
        )
        .unwrap();
        assert_eq!(r.description, "Update the Hue Bridge firmware");
        assert!(r.steps.iter().any(|s| s.contains("1971060010")));
        let validity = finding("Excessive certificate validity on 192.168.1.50:443", 443);
        assert_eq!(resolve(&validity, &hue), validity.remediation);
    }

    #[test]
    fn resolve_prefers_most_specific_template() {
        let ssh = finding("SSH open on 192.168.1.50:22", 22);
        let unifi = resolve(&ssh, &device(Some("Ubiquiti"), DeviceType::Router)).unwrap();
        assert!(
            unifi
                .steps
                .iter()
                .any(|s| s.contains("Control Plane > Console > SSH"))
        );
        let generic = resolve(&ssh, &device(Some("Netgear"), DeviceType::Router)).unwrap();
        assert!(generic.steps.iter().any(|s| s.contains("on port 22")));
        assert_eq!(
            resolve(&ssh, &device(Some("Ubiquiti"), DeviceType::AccessPoint)),
            ssh.remediation
        );
    }

    #[test]
    #[should_panic(expected = "product selectors need both")]
    fn validate_match_rejects_device_only_selectors() {
        let m = TemplateMatch {
            vendor: vec!["dyson".to_owned()],
            ..TemplateMatch::default()
        };
        validate_match("t", &m);
    }

    #[test]
    #[should_panic(expected = "unknown deviceType")]
    fn validate_match_rejects_unknown_device_type() {
        let m = TemplateMatch {
            port: vec![23],
            device_type: vec!["toaster".to_owned()],
            ..TemplateMatch::default()
        };
        validate_match("t", &m);
    }

    #[test]
    fn template_match_rejects_unknown_selector() {
        let r: Result<TemplateMatch, _> = serde_saphyr::from_str("vendr: [\"dyson\"]\n");
        assert!(r.is_err());
    }

    proptest! {
        #[test]
        fn prop_interpolate_no_panic(
            template in ".*",
            key in "[a-z]{1,10}",
            value in ".*",
        ) {
            let _ = interpolate(&template, &[(&key, &value)]);
        }

        #[test]
        fn prop_get_nonexistent_always_none(id in "[a-z.]{1,50}") {
            if !EXPECTED_IDS.contains(&id.as_str()) {
                assert!(get(&id, &[]).is_none());
            }
        }
    }
}
