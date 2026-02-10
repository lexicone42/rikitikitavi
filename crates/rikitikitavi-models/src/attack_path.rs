use rikitikitavi_core::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An attack path — a chain of steps an attacker could follow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// Overall severity of this attack path.
    pub severity: Severity,
    /// Ordered steps in the attack chain.
    pub steps: Vec<AttackStep>,
    /// IDs of findings that contribute to this path.
    pub finding_ids: Vec<Uuid>,
}

/// A single step in an attack path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub order: u32,
    pub title: String,
    pub description: String,
    pub technique: Option<String>,
    pub difficulty: AttackDifficulty,
    /// Finding ID that enables this step, if any.
    pub finding_id: Option<Uuid>,
}

/// How difficult a particular attack step is to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackDifficulty {
    Trivial,
    Easy,
    Moderate,
    Hard,
    Expert,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_attack_path_json_roundtrip() {
        let path = AttackPath {
            id: Uuid::new_v4(),
            name: "Test Path".to_owned(),
            description: "A test attack path".to_owned(),
            severity: rikitikitavi_core::Severity::High,
            steps: vec![AttackStep {
                order: 1,
                title: "Step 1".to_owned(),
                description: "First step".to_owned(),
                technique: Some("T1078".to_owned()),
                difficulty: AttackDifficulty::Easy,
                finding_id: Some(Uuid::new_v4()),
            }],
            finding_ids: vec![Uuid::new_v4()],
        };

        let json = serde_json::to_string(&path).unwrap();
        let recovered: AttackPath = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.name, path.name);
        assert_eq!(recovered.steps.len(), 1);
    }

    #[test]
    fn test_attack_difficulty_serialization() {
        for (variant, expected) in [
            (AttackDifficulty::Trivial, "\"trivial\""),
            (AttackDifficulty::Easy, "\"easy\""),
            (AttackDifficulty::Moderate, "\"moderate\""),
            (AttackDifficulty::Hard, "\"hard\""),
            (AttackDifficulty::Expert, "\"expert\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let recovered: AttackDifficulty = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, variant);
        }
    }

    #[test]
    fn test_attack_step_roundtrip() {
        let step = AttackStep {
            order: 3,
            title: "Lateral movement".to_owned(),
            description: "Move to another host".to_owned(),
            technique: None,
            difficulty: AttackDifficulty::Moderate,
            finding_id: None,
        };

        let json = serde_json::to_string(&step).unwrap();
        let recovered: AttackStep = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.order, 3);
        assert!(recovered.technique.is_none());
        assert!(recovered.finding_id.is_none());
    }

    proptest! {
        /// AttackPath JSON roundtrip with arbitrary names
        #[test]
        fn prop_attack_path_roundtrip(name in "[a-zA-Z0-9 ]{1,30}", desc in "[a-zA-Z0-9 ]{1,60}") {
            let path = AttackPath {
                id: Uuid::new_v4(),
                name: name.clone(),
                description: desc.clone(),
                severity: rikitikitavi_core::Severity::Medium,
                steps: Vec::new(),
                finding_ids: Vec::new(),
            };
            let json = serde_json::to_string(&path).unwrap();
            let recovered: AttackPath = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered.name, name);
            assert_eq!(recovered.description, desc);
        }
    }
}
