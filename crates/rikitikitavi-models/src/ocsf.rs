use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::Finding;

// ── Epoch-ms serialization for OCSF `timestamp_t` ──────────────────────

fn serialize_epoch_ms<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(dt.timestamp_millis())
}

fn deserialize_epoch_ms<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let millis = i64::deserialize(d)?;
    DateTime::from_timestamp_millis(millis)
        .ok_or_else(|| serde::de::Error::custom("invalid epoch milliseconds"))
}

// ── OCSF Vulnerability Finding (class 2002) ────────────────────────────

/// OCSF 1.1 Vulnerability Finding for Security Lake export.
///
/// Maps to OCSF class 2002 (`Vulnerability` Finding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfFinding {
    /// Always 2002 (Vulnerability Finding).
    pub class_uid: u32,
    /// Always "Vulnerability Finding".
    pub class_name: String,
    /// Always 2 (Findings).
    pub category_uid: u8,
    /// Always "Findings".
    pub category_name: String,
    /// Always 1 (Create).
    pub activity_id: u8,
    /// `class_uid` * 100 + `activity_id` = `200_201`.
    pub type_uid: u32,
    /// "Vulnerability Finding: Create".
    pub type_name: String,
    pub metadata: OcsfMetadata,
    pub severity_id: u8,
    pub severity: String,
    pub status_id: u8,
    pub finding_info: OcsfFindingInfo,
    pub remediation: Option<OcsfRemediation>,
    pub resources: Vec<OcsfResource>,
    /// Vulnerabilities (CVEs) associated with this finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<OcsfVulnerability>,
    /// Scan-level risk score (0.0 – 100.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    /// Finding timestamp as epoch milliseconds.
    #[serde(
        serialize_with = "serialize_epoch_ms",
        deserialize_with = "deserialize_epoch_ms"
    )]
    pub time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfMetadata {
    pub version: String,
    pub product: OcsfProduct,
    #[serde(
        serialize_with = "serialize_epoch_ms",
        deserialize_with = "deserialize_epoch_ms"
    )]
    pub logged_time: DateTime<Utc>,
    pub uid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfProduct {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfFindingInfo {
    pub uid: Uuid,
    pub title: String,
    pub desc: String,
    /// Scanner that produced this finding.
    pub product_uid: String,
    #[serde(
        serialize_with = "serialize_epoch_ms",
        deserialize_with = "deserialize_epoch_ms"
    )]
    pub created_time: DateTime<Utc>,
    /// CWE analytic mapping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytic: Option<OcsfAnalytic>,
}

/// Maps CWE to OCSF `finding_info.analytic`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfAnalytic {
    /// CWE identifier (e.g. "CWE-319").
    pub uid: String,
    /// CWE description.
    pub name: String,
    /// Always "Rule".
    pub r#type: String,
}

/// An OCSF vulnerability entry (CVE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfVulnerability {
    /// CVE identifier (e.g. "CVE-2024-1234").
    pub uid: String,
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<OcsfCve>,
}

/// CVE sub-object inside an `OcsfVulnerability`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfCve {
    pub uid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfRemediation {
    pub desc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfResource {
    pub uid: String,
    pub r#type: String,
    pub name: Option<String>,
}

impl From<&Finding> for OcsfFinding {
    #[allow(clippy::too_many_lines)]
    fn from(f: &Finding) -> Self {
        // ── Resources from IP / port / hostname ────────────────────
        let mut resources = Vec::new();
        if let Some(ip) = f.affected_ip {
            resources.push(OcsfResource {
                uid: ip.to_string(),
                r#type: "IP Address".to_owned(),
                name: f.affected_hostname.clone(),
            });
        }
        if let Some(port) = f.affected_port {
            resources.push(OcsfResource {
                uid: port.to_string(),
                r#type: "Port".to_owned(),
                name: f.affected_service.clone(),
            });
        }

        // ── CWE → analytic ────────────────────────────────────────
        let analytic = f.cwe_id.as_ref().map(|cwe| OcsfAnalytic {
            uid: cwe.clone(),
            name: cwe.clone(),
            r#type: "Rule".to_owned(),
        });

        // ── CVEs → vulnerabilities ────────────────────────────────
        let vulnerabilities: Vec<OcsfVulnerability> = f
            .cve_ids
            .iter()
            .map(|cve| OcsfVulnerability {
                uid: cve.clone(),
                desc: None,
                cve: Some(OcsfCve { uid: cve.clone() }),
            })
            .collect();

        Self {
            class_uid: 2002,
            class_name: "Vulnerability Finding".to_owned(),
            category_uid: 2,
            category_name: "Findings".to_owned(),
            activity_id: 1,
            type_uid: 200_201,
            type_name: "Vulnerability Finding: Create".to_owned(),
            metadata: OcsfMetadata {
                version: "1.1.0".to_owned(),
                product: OcsfProduct {
                    name: "Rikitikitavi".to_owned(),
                    vendor_name: "rikitikitavi".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                logged_time: Utc::now(),
                uid: Uuid::new_v4(),
            },
            severity_id: f.severity.ocsf_id(),
            severity: f.severity.to_string(),
            status_id: 1, // New
            finding_info: OcsfFindingInfo {
                uid: f.id,
                title: f.title.clone(),
                desc: f.description.clone(),
                product_uid: f.scanner.clone(),
                created_time: f.discovered_at,
                analytic,
            },
            remediation: f.remediation.as_ref().map(|r| OcsfRemediation {
                desc: r.description.clone(),
            }),
            resources,
            vulnerabilities,
            risk_score: None,
            time: f.discovered_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;

    #[test]
    fn test_ocsf_class_2002_fields() {
        let finding = Finding::new("test", "Test Finding", "A test", Severity::Medium);
        let ocsf = OcsfFinding::from(&finding);

        assert_eq!(ocsf.class_uid, 2002);
        assert_eq!(ocsf.class_name, "Vulnerability Finding");
        assert_eq!(ocsf.category_uid, 2);
        assert_eq!(ocsf.category_name, "Findings");
        assert_eq!(ocsf.activity_id, 1);
        assert_eq!(ocsf.type_uid, 200_201);
        assert_eq!(ocsf.type_name, "Vulnerability Finding: Create");
    }

    #[test]
    fn test_ocsf_from_finding_basic() {
        let finding = Finding::new("test", "Test Finding", "A test", Severity::Medium);
        let ocsf = OcsfFinding::from(&finding);

        assert_eq!(ocsf.severity_id, 3);
        assert_eq!(ocsf.severity, "MEDIUM");
        assert_eq!(ocsf.status_id, 1);
        assert_eq!(ocsf.finding_info.title, "Test Finding");
        assert_eq!(ocsf.finding_info.desc, "A test");
        assert_eq!(ocsf.finding_info.product_uid, "test");
    }

    #[test]
    fn test_ocsf_severity_mapping() {
        let cases = [
            (Severity::Info, 1_u8),
            (Severity::Low, 2),
            (Severity::Medium, 3),
            (Severity::High, 4),
            (Severity::Critical, 5),
        ];

        for (severity, expected_id) in cases {
            let finding = Finding::new("test", "t", "d", severity);
            let ocsf = OcsfFinding::from(&finding);
            assert_eq!(ocsf.severity_id, expected_id, "severity: {severity}");
        }
    }

    #[test]
    fn test_ocsf_with_remediation() {
        let finding = Finding::new("test", "Test", "Desc", Severity::High).with_remediation(
            crate::Remediation {
                description: "Fix it".to_owned(),
                steps: vec!["step 1".to_owned()],
                effort: Some("5 min".to_owned()),
            },
        );

        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.remediation.is_some());
        assert_eq!(ocsf.remediation.unwrap().desc, "Fix it");
    }

    #[test]
    fn test_ocsf_without_remediation() {
        let finding = Finding::new("test", "Test", "Desc", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.remediation.is_none());
    }

    #[test]
    fn test_ocsf_metadata() {
        let finding = Finding::new("scanner", "Title", "Desc", Severity::Info);
        let ocsf = OcsfFinding::from(&finding);

        assert_eq!(ocsf.metadata.version, "1.1.0");
        assert_eq!(ocsf.metadata.product.name, "Rikitikitavi");
        assert_eq!(ocsf.metadata.product.vendor_name, "rikitikitavi");
    }

    #[test]
    fn test_ocsf_cwe_analytic_mapping() {
        let finding =
            Finding::new("ssl", "Weak Cipher", "desc", Severity::High).with_cwe("CWE-327");
        let ocsf = OcsfFinding::from(&finding);

        let analytic = ocsf.finding_info.analytic.unwrap();
        assert_eq!(analytic.uid, "CWE-327");
        assert_eq!(analytic.name, "CWE-327");
        assert_eq!(analytic.r#type, "Rule");
    }

    #[test]
    fn test_ocsf_no_cwe_no_analytic() {
        let finding = Finding::new("test", "T", "D", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.finding_info.analytic.is_none());
    }

    #[test]
    fn test_ocsf_cve_vulnerabilities() {
        let mut finding = Finding::new("ssl", "Vuln", "desc", Severity::Critical);
        finding.cve_ids = vec!["CVE-2024-1234".to_owned(), "CVE-2024-5678".to_owned()];

        let ocsf = OcsfFinding::from(&finding);
        assert_eq!(ocsf.vulnerabilities.len(), 2);
        assert_eq!(ocsf.vulnerabilities[0].uid, "CVE-2024-1234");
        assert_eq!(
            ocsf.vulnerabilities[0].cve.as_ref().unwrap().uid,
            "CVE-2024-1234"
        );
        assert_eq!(ocsf.vulnerabilities[1].uid, "CVE-2024-5678");
    }

    #[test]
    fn test_ocsf_no_cves_empty_vulnerabilities() {
        let finding = Finding::new("test", "T", "D", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.vulnerabilities.is_empty());
    }

    #[test]
    fn test_ocsf_resource_from_ip_port() {
        let finding = Finding::new("ports", "Open SSH", "desc", Severity::Low)
            .with_ip("10.0.0.1".parse().unwrap())
            .with_port(22)
            .with_hostname("myrouter")
            .with_service("ssh");

        let ocsf = OcsfFinding::from(&finding);
        assert_eq!(ocsf.resources.len(), 2);

        // IP resource
        assert_eq!(ocsf.resources[0].uid, "10.0.0.1");
        assert_eq!(ocsf.resources[0].r#type, "IP Address");
        assert_eq!(ocsf.resources[0].name.as_deref(), Some("myrouter"));

        // Port resource
        assert_eq!(ocsf.resources[1].uid, "22");
        assert_eq!(ocsf.resources[1].r#type, "Port");
        assert_eq!(ocsf.resources[1].name.as_deref(), Some("ssh"));
    }

    #[test]
    fn test_ocsf_resource_ip_only() {
        let finding = Finding::new("ports", "Open", "d", Severity::Low)
            .with_ip("192.168.1.1".parse().unwrap());

        let ocsf = OcsfFinding::from(&finding);
        assert_eq!(ocsf.resources.len(), 1);
        assert_eq!(ocsf.resources[0].uid, "192.168.1.1");
        assert!(ocsf.resources[0].name.is_none());
    }

    #[test]
    fn test_ocsf_no_ip_no_resources() {
        let finding = Finding::new("network", "DNS Issue", "d", Severity::Info);
        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.resources.is_empty());
    }

    #[test]
    fn test_ocsf_epoch_ms_serialization() {
        let finding = Finding::new("test", "T", "D", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);

        let json = serde_json::to_value(&ocsf).unwrap();
        let time = json["time"].as_i64().unwrap();
        // Epoch ms should be in a reasonable range (after 2020, before 2100)
        assert!(time > 1_577_836_800_000, "time should be after 2020");
        assert!(time < 4_102_444_800_000, "time should be before 2100");

        let created_time = json["finding_info"]["created_time"].as_i64().unwrap();
        assert!(created_time > 1_577_836_800_000);

        let logged_time = json["metadata"]["logged_time"].as_i64().unwrap();
        assert!(logged_time > 1_577_836_800_000);
    }

    #[test]
    fn test_ocsf_epoch_ms_roundtrip() {
        let finding = Finding::new("test", "T", "D", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);

        let json = serde_json::to_string(&ocsf).unwrap();
        let recovered: OcsfFinding = serde_json::from_str(&json).unwrap();

        // Epoch-ms truncates sub-millisecond precision, but the roundtrip
        // should preserve millisecond-level accuracy.
        assert_eq!(
            ocsf.time.timestamp_millis(),
            recovered.time.timestamp_millis()
        );
    }

    #[test]
    fn test_ocsf_risk_score_default_none() {
        let finding = Finding::new("test", "T", "D", Severity::Low);
        let ocsf = OcsfFinding::from(&finding);
        assert!(ocsf.risk_score.is_none());
    }

    #[test]
    fn test_ocsf_product_uid_from_scanner() {
        let finding = Finding::new("wifi_scanner", "Weak WPA", "desc", Severity::High);
        let ocsf = OcsfFinding::from(&finding);
        assert_eq!(ocsf.finding_info.product_uid, "wifi_scanner");
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

    proptest! {
        /// Conversion never panics on arbitrary Finding and all invariants hold.
        #[test]
        fn prop_ocsf_conversion_invariants(
            scanner in "[a-z]{1,10}",
            title in "[a-zA-Z0-9 ]{1,30}",
            desc in "[a-zA-Z0-9 ]{1,60}",
            severity in arb_severity(),
        ) {
            let finding = Finding::new(&scanner, &title, &desc, severity);
            let ocsf = OcsfFinding::from(&finding);
            assert_eq!(ocsf.class_uid, 2002);
            assert_eq!(ocsf.category_uid, 2);
            assert_eq!(ocsf.activity_id, 1);
            assert_eq!(ocsf.type_uid, 200_201);
            assert!(ocsf.severity_id >= 1 && ocsf.severity_id <= 5);
            assert_eq!(ocsf.finding_info.product_uid, scanner);
        }

        /// JSON roundtrip preserves epoch-ms timestamps.
        #[test]
        fn prop_ocsf_json_roundtrip(
            scanner in "[a-z]{1,10}",
            title in "[a-zA-Z0-9 ]{1,30}",
            desc in "[a-zA-Z0-9 ]{1,60}",
            severity in arb_severity(),
        ) {
            let finding = Finding::new(&scanner, &title, &desc, severity);
            let ocsf = OcsfFinding::from(&finding);
            let json = serde_json::to_string(&ocsf).unwrap();
            let recovered: OcsfFinding = serde_json::from_str(&json).unwrap();
            assert_eq!(ocsf.time.timestamp_millis(), recovered.time.timestamp_millis());
            assert_eq!(ocsf.class_uid, recovered.class_uid);
            assert_eq!(ocsf.severity_id, recovered.severity_id);
        }
    }
}
