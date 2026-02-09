use rikitikitavi_models::attack_path::{AttackDifficulty, AttackPath, AttackStep};
use rikitikitavi_models::finding::Finding;

use rikitikitavi_core::Severity;
use uuid::Uuid;

/// Generate attack paths by chaining related findings into plausible attack
/// scenarios an adversary could follow.
pub fn generate_attack_paths(findings: &[Finding]) -> Vec<AttackPath> {
    // TODO: Implement attack chain analysis
    // - Group findings by device
    // - Identify lateral movement opportunities
    // - Chain credential findings → access findings → privilege escalation
    // - Score each path by difficulty and impact
    tracing::info!(findings_count = findings.len(), "generating attack paths");

    // Placeholder: if we have a critical credential finding + any other high finding,
    // generate a sample path.
    let critical_creds = findings
        .iter()
        .find(|f| f.severity == Severity::Critical && f.scanner == "credentials");
    let high_finding = findings
        .iter()
        .find(|f| f.severity >= Severity::High && f.scanner != "credentials");

    let mut paths = Vec::new();

    if let (Some(cred), Some(other)) = (critical_creds, high_finding) {
        paths.push(AttackPath {
            id: Uuid::new_v4(),
            name: "Default Credentials to Network Compromise".to_owned(),
            description: format!(
                "Attacker exploits {} then leverages {}",
                cred.title, other.title
            ),
            severity: Severity::Critical,
            steps: vec![
                AttackStep {
                    order: 1,
                    title: cred.title.clone(),
                    description: cred.description.clone(),
                    technique: Some("T1078 - Valid Accounts".to_owned()),
                    difficulty: AttackDifficulty::Trivial,
                    finding_id: Some(cred.id),
                },
                AttackStep {
                    order: 2,
                    title: other.title.clone(),
                    description: other.description.clone(),
                    technique: None,
                    difficulty: AttackDifficulty::Easy,
                    finding_id: Some(other.id),
                },
            ],
            finding_ids: vec![cred.id, other.id],
        });
    }

    paths
}
