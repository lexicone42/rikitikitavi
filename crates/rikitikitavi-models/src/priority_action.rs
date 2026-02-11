use rikitikitavi_core::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A deduplicated, ranked remediation action derived from scan findings.
///
/// Multiple findings often share the same fix (e.g., "Upgrade TLS" applies
/// to every host still running TLS 1.0). `PriorityAction` groups these into
/// a single actionable item ranked by impact.
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
