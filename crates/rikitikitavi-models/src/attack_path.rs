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
