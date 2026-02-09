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
