use rikitikitavi_core::Severity;
use rikitikitavi_models::Finding;

use crate::exploit_intel::ssvc_for;
use crate::vulnrichment_db::{Automatable, Exploitation};

/// Exploitability multiplier applied to a finding's severity weight.
///
/// KEV and SSVC `active` are the same claim (exploited in the wild) and score alike; `poc`
/// sits between that and nothing, a little higher when CISA also calls the chain automatable.
fn exploit_multiplier(finding: &Finding) -> f64 {
    if finding.is_kev {
        return 1.5;
    }
    match ssvc_for(finding).map(|s| (s.exploitation, s.automatable)) {
        Some((Exploitation::Active, _)) => 1.5,
        Some((Exploitation::Poc, Some(Automatable::Yes))) => 1.35,
        Some((Exploitation::Poc, _)) => 1.25,
        _ => 1.0,
    }
}

/// Aggregate risk score (0.0–100.0), capped at 100.
///
/// Sums per-severity weights (Critical 25, High 15, Medium 8, Low 3, Info 1) scaled by
/// [`exploit_multiplier`]: KEV or SSVC `active` ×1.5, automatable `poc` ×1.35, `poc` ×1.25.
pub fn calculate_risk_score(findings: &[Finding]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let mut score: f64 = 0.0;

    for finding in findings {
        let base = match finding.severity {
            Severity::Critical => 25.0,
            Severity::High => 15.0,
            Severity::Medium => 8.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };
        score += base * exploit_multiplier(finding);
    }

    score.min(100.0)
}

/// Letter grade from severity counts, as `(label, color_hint)`.
/// F: any critical; D: >2 high; C: any high; B: >3 medium; A: otherwise.
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

    fn finding_with_cve(sev: Severity, cve: &str) -> Finding {
        Finding::new("test", "t", "d", sev).with_cve_ids(vec![cve.to_owned()])
    }

    #[test]
    fn poc_scores_above_plain_and_below_kev() {
        let plain = calculate_risk_score(&[Finding::new("test", "t", "d", Severity::Medium)]);
        // regreSSHion: poc, not automatable.
        let poc = calculate_risk_score(&[finding_with_cve(Severity::Medium, "CVE-2024-6387")]);
        // Brother default password: poc, automatable.
        let wormable =
            calculate_risk_score(&[finding_with_cve(Severity::Medium, "CVE-2024-51978")]);
        let mut kev = Finding::new("test", "t", "d", Severity::Medium);
        kev.is_kev = true;
        let kev = calculate_risk_score(&[kev]);

        assert!(plain < poc, "{plain} < {poc}");
        assert!(poc < wormable, "{poc} < {wormable}");
        assert!(wormable < kev, "{wormable} < {kev}");
    }

    #[test]
    fn ssvc_active_scores_like_kev() {
        // Log4Shell is `active`; score it without the KEV flag set.
        let active = calculate_risk_score(&[finding_with_cve(Severity::Medium, "CVE-2021-44228")]);
        let mut kev = Finding::new("test", "t", "d", Severity::Medium);
        kev.is_kev = true;
        assert!((active - calculate_risk_score(&[kev])).abs() < f64::EPSILON);
    }

    #[test]
    fn exploitation_none_does_not_raise_the_score() {
        let plain = calculate_risk_score(&[Finding::new("test", "t", "d", Severity::Low)]);
        let none = calculate_risk_score(&[finding_with_cve(Severity::Low, "CVE-2023-38408")]);
        assert!((plain - none).abs() < f64::EPSILON);
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

    /// Grade letter as a rank: A=0 ... F=4.
    fn grade_rank(label: &str) -> u8 {
        match label.chars().next() {
            Some('A') => 0,
            Some('B') => 1,
            Some('C') => 2,
            Some('D') => 3,
            Some('F') => 4,
            other => panic!("unexpected grade letter {other:?}"),
        }
    }

    fn grade_of(findings: &[Finding]) -> (&'static str, &'static str) {
        let count = |sev: Severity| findings.iter().filter(|f| f.severity == sev).count();
        risk_grade(
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium),
        )
    }

    fn arb_kev_finding() -> impl proptest::strategy::Strategy<Value = Finding> {
        use proptest::strategy::Strategy;
        (arb_severity(), proptest::bool::ANY).prop_map(|(sev, is_kev)| {
            let mut finding = Finding::new("test", "title", "desc", sev);
            finding.is_kev = is_kev;
            finding
        })
    }

    proptest::proptest! {
        /// Grade never improves when any severity count grows.
        #[test]
        fn prop_grade_monotone_in_counts(
            critical in 0_usize..6,
            high in 0_usize..6,
            medium in 0_usize..8,
            dc in 0_usize..3,
            dh in 0_usize..3,
            dm in 0_usize..3,
        ) {
            let base = grade_rank(risk_grade(critical, high, medium).0);
            proptest::prop_assert!(grade_rank(risk_grade(critical + dc, high, medium).0) >= base);
            proptest::prop_assert!(grade_rank(risk_grade(critical, high + dh, medium).0) >= base);
            proptest::prop_assert!(grade_rank(risk_grade(critical, high, medium + dm).0) >= base);
            proptest::prop_assert!(
                grade_rank(risk_grade(critical + dc, high + dh, medium + dm).0) >= base
            );
        }

        /// Label letter and colour hint are paired one-to-one.
        #[test]
        fn prop_grade_label_color_paired(
            critical in 0_usize..4,
            high in 0_usize..6,
            medium in 0_usize..8,
        ) {
            let (label, color) = risk_grade(critical, high, medium);
            let expected = match grade_rank(label) {
                0 => "info",
                1 => "low",
                2 => "medium",
                3 => "high",
                _ => "critical",
            };
            proptest::prop_assert_eq!(color, expected);
        }

        /// Adding a finding never improves the grade nor lowers the score; a strictly
        /// worse grade comes with a strictly higher score unless already capped.
        #[test]
        fn prop_grade_and_score_agree_under_extension(
            base in proptest::collection::vec(arb_kev_finding(), 0..20),
            extra in arb_kev_finding(),
        ) {
            let base_grade = grade_rank(grade_of(&base).0);
            let base_score = calculate_risk_score(&base);
            let mut extended = base;
            extended.push(extra);
            let ext_grade = grade_rank(grade_of(&extended).0);
            let ext_score = calculate_risk_score(&extended);

            proptest::prop_assert!(ext_grade >= base_grade);
            proptest::prop_assert!(ext_score >= base_score);
            if ext_grade > base_grade {
                proptest::prop_assert!(ext_score > base_score || base_score >= 100.0);
            }
        }
    }
}
