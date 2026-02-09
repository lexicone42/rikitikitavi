use rikitikitavi_core::Severity;
use rikitikitavi_models::Finding;

/// Calculate an aggregate risk score (0.0–100.0) from a set of findings.
///
/// The score weights critical findings heavily and accounts for the total
/// number of issues across all severity levels.
pub fn calculate_risk_score(findings: &[Finding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let mut score: f64 = 0.0;

    for finding in findings {
        score += match finding.severity {
            Severity::Critical => 25.0,
            Severity::High => 15.0,
            Severity::Medium => 8.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };
    }

    // Cap at 100
    score.min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_findings_zero_score() {
        assert!((calculate_risk_score(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_caps_at_100() {
        let findings: Vec<Finding> = (0..10)
            .map(|i| {
                Finding::new(
                    "test",
                    &format!("Critical Finding {i}"),
                    "desc",
                    Severity::Critical,
                )
            })
            .collect();
        let score = calculate_risk_score(&findings);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }
}
