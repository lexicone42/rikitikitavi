use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Finding;

/// OCSF (Open Cybersecurity Schema Framework) finding for Security Lake export.
///
/// Maps to OCSF Detection Finding class (2004).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfFinding {
    pub metadata: OcsfMetadata,
    pub severity_id: u8,
    pub severity: String,
    pub status_id: u8,
    pub finding_info: OcsfFindingInfo,
    pub remediation: Option<OcsfRemediation>,
    pub resources: Vec<OcsfResource>,
    pub time: DateTime<Utc>,
    pub type_uid: u32,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfMetadata {
    pub version: String,
    pub product: OcsfProduct,
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
    pub created_time: DateTime<Utc>,
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
    fn from(f: &Finding) -> Self {
        Self {
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
                created_time: f.discovered_at,
            },
            remediation: f.remediation.as_ref().map(|r| OcsfRemediation {
                desc: r.description.clone(),
            }),
            resources: Vec::new(),
            time: f.discovered_at,
            type_uid: 200_401,
            type_name: "Detection Finding: Create".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;

    #[test]
    fn test_ocsf_from_finding_basic() {
        let finding = Finding::new("test", "Test Finding", "A test", Severity::Medium);
        let ocsf = OcsfFinding::from(&finding);

        assert_eq!(ocsf.severity_id, 3);
        assert_eq!(ocsf.severity, "MEDIUM");
        assert_eq!(ocsf.status_id, 1);
        assert_eq!(ocsf.finding_info.title, "Test Finding");
        assert_eq!(ocsf.finding_info.desc, "A test");
        assert_eq!(ocsf.type_uid, 200_401);
        assert_eq!(ocsf.type_name, "Detection Finding: Create");
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
        let finding = Finding::new("test", "Test", "Desc", Severity::High)
            .with_remediation(crate::Remediation {
                description: "Fix it".to_owned(),
                steps: vec!["step 1".to_owned()],
                effort: Some("5 min".to_owned()),
            });

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
        /// Conversion never panics on arbitrary Finding
        #[test]
        fn prop_ocsf_conversion_no_panic(
            scanner in "[a-z]{1,10}",
            title in "[a-zA-Z0-9 ]{1,30}",
            desc in "[a-zA-Z0-9 ]{1,60}",
            severity in arb_severity(),
        ) {
            let finding = Finding::new(&scanner, &title, &desc, severity);
            let ocsf = OcsfFinding::from(&finding);
            assert!(ocsf.severity_id >= 1 && ocsf.severity_id <= 5);
        }
    }
}
