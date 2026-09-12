use rikitikitavi_core::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A ranked remediation action grouping all findings that share one fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityAction {
    /// Unique action ID.
    pub id: Uuid,
    /// Rank (1 = highest priority).
    pub rank: u32,
    /// Human-readable action title (from remediation description).
    pub title: String,
    /// Worst severity among grouped findings.
    pub severity: Severity,
    /// Number of distinct devices affected.
    pub affected_device_count: usize,
    /// Total number of findings this action addresses.
    pub finding_count: usize,
    /// Shared remediation steps.
    pub steps: Vec<String>,
    /// Estimated effort (e.g., "5 minutes").
    pub effort: Option<String>,
    /// IDs of the original findings grouped into this action.
    pub finding_ids: Vec<Uuid>,
}
