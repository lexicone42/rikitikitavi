//! OVRS-compliant remediation template registry.
//!
//! Parses embedded YAML templates at runtime (once, via `OnceLock`) and
//! provides a `get(id, params)` API that scanners use instead of
//! hardcoding `Remediation` structs.

use rikitikitavi_models::Remediation;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

// ── OVRS serde types ────────────────────────────────────────────────

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
    #[allow(dead_code)]
    r#match: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    parameters: Vec<ParameterDef>,
    steps: Vec<Step>,
    #[serde(default)]
    #[allow(dead_code)]
    preflight: Vec<serde_yaml_ng::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    validation: Vec<serde_yaml_ng::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    rollback: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    remediation: Option<RemediationHints>,
    #[serde(default)]
    #[allow(dead_code)]
    extensions: Option<serde_yaml_ng::Value>,
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
    params: HashMap<String, serde_yaml_ng::Value>,
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

// ── Registry ────────────────────────────────────────────────────────

static REGISTRY: OnceLock<RemediationRegistry> = OnceLock::new();

struct RemediationRegistry {
    templates: HashMap<String, OvrsTemplate>,
}

fn init_registry() -> RemediationRegistry {
    let yaml_sources: &[&str] = &[
        include_str!("../templates/arp.yaml"),
        include_str!("../templates/credentials.yaml"),
        include_str!("../templates/database.yaml"),
        include_str!("../templates/dhcp.yaml"),
        include_str!("../templates/dns.yaml"),
        include_str!("../templates/exposure.yaml"),
        include_str!("../templates/http_audit.yaml"),
        include_str!("../templates/isolation.yaml"),
        include_str!("../templates/ports.yaml"),
        include_str!("../templates/router.yaml"),
        include_str!("../templates/services.yaml"),
        include_str!("../templates/smb.yaml"),
        include_str!("../templates/ssl.yaml"),
        include_str!("../templates/wifi.yaml"),
    ];

    let mut templates = HashMap::new();
    for source in yaml_sources {
        for document in serde_yaml_ng::Deserializer::from_str(source) {
            let template: OvrsTemplate = serde::Deserialize::deserialize(document)
                .expect("embedded OVRS YAML must be valid");
            let id = template.id.clone();
            assert!(
                templates.insert(id.clone(), template).is_none(),
                "duplicate template ID: {id}"
            );
        }
    }

    RemediationRegistry { templates }
}

// ── Public API ──────────────────────────────────────────────────────

/// Look up a remediation template by ID, applying parameter interpolation.
pub fn get(id: &str, params: &[(&str, &str)]) -> Option<Remediation> {
    let registry = REGISTRY.get_or_init(init_registry);
    let tmpl = registry.templates.get(id)?;

    let steps: Vec<String> = tmpl
        .steps
        .iter()
        .filter(|s| s.kind == "manual.step")
        .filter_map(|s| s.params.get("text"))
        .filter_map(serde_yaml_ng::Value::as_str)
        .map(|text| interpolate(text, params))
        .collect();

    let effort = tmpl
        .remediation
        .as_ref()
        .and_then(|r| r.typical_duration_seconds)
        .map(format_duration);

    Some(Remediation {
        description: interpolate(&tmpl.summary, params),
        steps,
        effort,
    })
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

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// All 54 expected template IDs.
    const EXPECTED_IDS: &[&str] = &[
        "rikitikitavi.arp.spoofing-detected",
        "rikitikitavi.credentials.anonymous-ftp",
        "rikitikitavi.credentials.http-no-auth",
        "rikitikitavi.credentials.telnet-default",
        "rikitikitavi.credentials.telnet-default-confirmed",
        "rikitikitavi.credentials.rdp-exposed",
        "rikitikitavi.credentials.smb-exposed",
        "rikitikitavi.database.redis-no-auth",
        "rikitikitavi.database.mongodb-no-auth",
        "rikitikitavi.database.mysql-exposed",
        "rikitikitavi.database.elasticsearch-no-auth",
        "rikitikitavi.database.memcached-no-auth",
        "rikitikitavi.database.postgresql-exposed",
        "rikitikitavi.dhcp.rogue-server",
        "rikitikitavi.dns.hijacking-detected",
        "rikitikitavi.dns.cross-validation-mismatch",
        "rikitikitavi.dns.dnssec-not-enforced",
        "rikitikitavi.exposure.port-forwarded",
        "rikitikitavi.http_audit.missing-hsts",
        "rikitikitavi.http_audit.directory-listing",
        "rikitikitavi.http_audit.admin-no-auth",
        "rikitikitavi.isolation.inter-vlan-routing",
        "rikitikitavi.isolation.large-flat-network",
        "rikitikitavi.ports.telnet-open",
        "rikitikitavi.ports.ftp-open",
        "rikitikitavi.ports.rdp-open",
        "rikitikitavi.ports.vnc-open",
        "rikitikitavi.ports.upnp-exposed",
        "rikitikitavi.ports.database-exposed",
        "rikitikitavi.ports.unencrypted-mail",
        "rikitikitavi.ports.mqtt-unencrypted",
        "rikitikitavi.router.admin-http-unencrypted",
        "rikitikitavi.router.telnet-enabled",
        "rikitikitavi.router.ftp-enabled",
        "rikitikitavi.router.upnp-enabled",
        "rikitikitavi.services.redis-no-auth",
        "rikitikitavi.services.mysql-exposed",
        "rikitikitavi.services.postgresql-exposed",
        "rikitikitavi.services.dropbear-ssh",
        "rikitikitavi.services.eol-openssh",
        "rikitikitavi.services.outdated-ssh",
        "rikitikitavi.smb.smbv1-enabled",
        "rikitikitavi.smb.null-session",
        "rikitikitavi.smb.netbios-exposed",
        "rikitikitavi.ssl.tls10-enabled",
        "rikitikitavi.ssl.tls11-enabled",
        "rikitikitavi.ssl.sslv2v3-enabled",
        "rikitikitavi.ssl.cert-expired",
        "rikitikitavi.ssl.cert-self-signed",
        "rikitikitavi.ssl.cert-weak-key",
        "rikitikitavi.wifi.open-network",
        "rikitikitavi.wifi.wep-encryption",
        "rikitikitavi.wifi.wpa1-weak",
        "rikitikitavi.wifi.wps-enabled",
    ];

    #[test]
    fn test_all_templates_parse() {
        let registry = REGISTRY.get_or_init(init_registry);
        assert_eq!(registry.templates.len(), 54);
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
