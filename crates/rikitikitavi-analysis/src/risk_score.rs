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

    // ─── Property-based tests ─────────────────────────────────────────

    fn arb_severity() -> impl proptest::strategy::Strategy<Value = Severity> {
        proptest::prop_oneof![
            proptest::strategy::Just(Severity::Info),
            proptest::strategy::Just(Severity::Low),
            proptest::strategy::Just(Severity::Medium),
            proptest::strategy::Just(Severity::High),
            proptest::strategy::Just(Severity::Critical),
        ]
    }

    fn arb_finding() -> impl proptest::strategy::Strategy<Value = Finding> {
        use proptest::strategy::Strategy;
        arb_severity().prop_map(|sev| Finding::new("test", "title", "desc", sev))
    }

    proptest::proptest! {
        /// Risk score is always in [0.0, 100.0].
        #[test]
        fn prop_score_bounded(findings in proptest::collection::vec(arb_finding(), 0..50)) {
            let score = calculate_risk_score(&findings);
            assert!(score >= 0.0, "score {score} is negative");
            assert!(score <= 100.0, "score {score} exceeds 100");
        }

        /// Adding a finding never decreases the score (monotonicity).
        #[test]
        fn prop_score_monotonic(
            base in proptest::collection::vec(arb_finding(), 0..20),
            extra in arb_finding(),
        ) {
            let base_score = calculate_risk_score(&base);
            let mut extended = base;
            extended.push(extra);
            let ext_score = calculate_risk_score(&extended);
            assert!(ext_score >= base_score,
                "adding a finding decreased score from {base_score} to {ext_score}");
        }

        /// Higher severity findings produce >= score compared to lower severity ones.
        #[test]
        fn prop_critical_scores_more_than_info(count in 1_usize..5) {
            let critical_findings: Vec<Finding> = (0..count)
                .map(|_| Finding::new("test", "t", "d", Severity::Critical))
                .collect();
            let info_findings: Vec<Finding> = (0..count)
                .map(|_| Finding::new("test", "t", "d", Severity::Info))
                .collect();
            let crit_score = calculate_risk_score(&critical_findings);
            let info_score = calculate_risk_score(&info_findings);
            assert!(crit_score >= info_score,
                "{count} critical ({crit_score}) scored less than {count} info ({info_score})");
        }
    }
}
