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

/// Compute a letter grade and label from severity counts.
///
/// Returns `(grade_with_label, color_hint)` where `color_hint` is a CSS-friendly
/// color name that both the TUI and HTML report can map to their palette.
///
/// Grade scale:
/// - **F**: Any critical findings
/// - **D**: More than 2 high findings
/// - **C**: Any high findings
/// - **B**: More than 3 medium findings
/// - **A**: Otherwise
pub const fn risk_grade(
    critical: usize,
    high: usize,
    medium: usize,
) -> (&'static str, &'static str) {
    if critical > 0 {
        ("F  CRITICAL ISSUES", "critical")
    } else if high > 2 {
        ("D  Needs Attention", "high")
    } else if high > 0 {
        ("C  Fair", "medium")
    } else if medium > 3 {
        ("B  Good", "low")
    } else {
        ("A  Excellent", "info")
    }
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

    #[test]
    fn test_risk_grade_critical_is_f() {
        let (label, color) = risk_grade(1, 0, 0);
        assert!(label.starts_with('F'));
        assert_eq!(color, "critical");
    }

    #[test]
    fn test_risk_grade_clean_is_a() {
        let (label, color) = risk_grade(0, 0, 0);
        assert!(label.starts_with('A'));
        assert_eq!(color, "info");
    }

    #[test]
    fn test_risk_grade_high_is_d_or_c() {
        let (label_d, _) = risk_grade(0, 3, 0);
        assert!(label_d.starts_with('D'));
        let (label_c, _) = risk_grade(0, 1, 0);
        assert!(label_c.starts_with('C'));
    }

    #[test]
    fn test_risk_grade_medium_only_is_b() {
        let (label, color) = risk_grade(0, 0, 5);
        assert!(label.starts_with('B'));
        assert_eq!(color, "low");
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
