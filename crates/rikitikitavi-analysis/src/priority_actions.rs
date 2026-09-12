use std::collections::HashMap;
use std::net::IpAddr;

use rikitikitavi_core::Severity;
use rikitikitavi_models::{Finding, PriorityAction};
use uuid::Uuid;

/// Severity to numeric weight for ranking.
const fn severity_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

/// Top 5 remediation groups by score.
///
/// Findings are grouped by `remediation.description` (no remediation: skipped) and each
/// group scored as `severity_weight * 100 + device_count * 10 + finding_count`.
pub fn generate_priority_actions(findings: &[Finding]) -> Vec<PriorityAction> {
    let mut groups: HashMap<String, GroupAccumulator> = HashMap::new();

    for finding in findings {
        let Some(remediation) = &finding.remediation else {
            continue;
        };

        let entry = groups
            .entry(remediation.description.clone())
            .or_insert_with(|| GroupAccumulator {
                steps: remediation.steps.clone(),
                effort: remediation.effort.clone(),
                max_severity: finding.severity,
                affected_ips: Vec::new(),
                finding_ids: Vec::new(),
            });

        if finding.severity > entry.max_severity {
            entry.max_severity = finding.severity;
        }

        // Deduplicated at scoring time.
        if let Some(ip) = finding.affected_ip {
            entry.affected_ips.push(ip);
        }

        entry.finding_ids.push(finding.id);

        // First non-empty steps/effort win.
        if entry.steps.is_empty() && !remediation.steps.is_empty() {
            entry.steps.clone_from(&remediation.steps);
        }
        if entry.effort.is_none() && remediation.effort.is_some() {
            entry.effort.clone_from(&remediation.effort);
        }
    }

    let mut scored: Vec<(String, GroupAccumulator, u32)> = groups
        .into_iter()
        .map(|(title, mut acc)| {
            acc.affected_ips.sort();
            acc.affected_ips.dedup();
            let device_count = acc.affected_ips.len();
            let finding_count = acc.finding_ids.len();
            let score = severity_weight(acc.max_severity) * 100
                + u32::try_from(device_count).unwrap_or(u32::MAX / 2) * 10
                + u32::try_from(finding_count).unwrap_or(u32::MAX / 2);
            (title, acc, score)
        })
        .collect();

    scored.sort_by_key(|entry| std::cmp::Reverse(entry.2));

    scored
        .into_iter()
        .take(5)
        .enumerate()
        .map(|(i, (title, acc, _score))| {
            let device_count = acc.affected_ips.len();
            PriorityAction {
                id: Uuid::new_v4(),
                rank: u32::try_from(i + 1).unwrap_or(1),
                title,
                severity: acc.max_severity,
                affected_device_count: device_count,
                finding_count: acc.finding_ids.len(),
                steps: acc.steps,
                effort: acc.effort,
                finding_ids: acc.finding_ids,
            }
        })
        .collect()
}

struct GroupAccumulator {
    steps: Vec<String>,
    effort: Option<String>,
    max_severity: Severity,
    affected_ips: Vec<IpAddr>,
    finding_ids: Vec<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::Remediation;
    use std::collections::HashSet;

    fn finding_with_remediation(
        title: &str,
        severity: Severity,
        ip: &str,
        remediation_desc: &str,
    ) -> Finding {
        Finding::new("test", title, "desc", severity)
            .with_ip(ip.parse().unwrap())
            .with_remediation(Remediation {
                description: remediation_desc.to_owned(),
                steps: vec!["Step 1".to_owned()],
                effort: Some("5 minutes".to_owned()),
            })
    }

    #[test]
    fn test_empty_findings_returns_empty() {
        let actions = generate_priority_actions(&[]);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_no_remediation_returns_empty() {
        let findings = vec![Finding::new("test", "No fix", "desc", Severity::High)];
        let actions = generate_priority_actions(&findings);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_single_finding_produces_one_action() {
        let findings = vec![finding_with_remediation(
            "Vuln 1",
            Severity::High,
            "192.168.1.1",
            "Upgrade firmware",
        )];
        let actions = generate_priority_actions(&findings);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].rank, 1);
        assert_eq!(actions[0].title, "Upgrade firmware");
        assert_eq!(actions[0].severity, Severity::High);
        assert_eq!(actions[0].affected_device_count, 1);
        assert_eq!(actions[0].finding_count, 1);
    }

    #[test]
    fn test_grouping_by_remediation_description() {
        let findings = vec![
            finding_with_remediation("Vuln A", Severity::Medium, "192.168.1.1", "Upgrade TLS"),
            finding_with_remediation("Vuln B", Severity::High, "192.168.1.2", "Upgrade TLS"),
            finding_with_remediation("Vuln C", Severity::Low, "192.168.1.3", "Disable UPnP"),
        ];
        let actions = generate_priority_actions(&findings);
        assert_eq!(actions.len(), 2);
        // Higher severity and more devices ranks first.
        assert_eq!(actions[0].title, "Upgrade TLS");
        assert_eq!(actions[0].severity, Severity::High);
        assert_eq!(actions[0].affected_device_count, 2);
        assert_eq!(actions[0].finding_count, 2);
    }

    #[test]
    fn test_max_five_actions() {
        let findings: Vec<Finding> = (0..10)
            .map(|i| {
                finding_with_remediation(
                    &format!("Vuln {i}"),
                    Severity::Medium,
                    &format!("192.168.1.{i}"),
                    &format!("Fix {i}"),
                )
            })
            .collect();
        let actions = generate_priority_actions(&findings);
        assert_eq!(actions.len(), 5);
        // Ranks 1..=5.
        for (i, action) in actions.iter().enumerate() {
            assert_eq!(action.rank, u32::try_from(i + 1).unwrap());
        }
    }

    #[test]
    fn test_severity_ranking() {
        let findings = vec![
            finding_with_remediation("Low vuln", Severity::Low, "10.0.0.1", "Low fix"),
            finding_with_remediation("Crit vuln", Severity::Critical, "10.0.0.2", "Critical fix"),
            finding_with_remediation("Med vuln", Severity::Medium, "10.0.0.3", "Medium fix"),
        ];
        let actions = generate_priority_actions(&findings);
        assert_eq!(actions[0].title, "Critical fix");
        assert_eq!(actions[1].title, "Medium fix");
        assert_eq!(actions[2].title, "Low fix");
    }

    #[test]
    fn test_device_deduplication() {
        let findings = vec![
            finding_with_remediation("Vuln A", Severity::High, "192.168.1.1", "Upgrade TLS"),
            finding_with_remediation("Vuln B", Severity::High, "192.168.1.1", "Upgrade TLS"),
        ];
        let actions = generate_priority_actions(&findings);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].affected_device_count, 1); // same IP, not double-counted
        assert_eq!(actions[0].finding_count, 2);
    }

    #[test]
    fn test_finding_ids_tracked() {
        let f1 = finding_with_remediation("V1", Severity::High, "10.0.0.1", "Fix X");
        let f2 = finding_with_remediation("V2", Severity::High, "10.0.0.2", "Fix X");
        let expected_ids = vec![f1.id, f2.id];
        let actions = generate_priority_actions(&[f1, f2]);
        assert_eq!(actions[0].finding_ids.len(), 2);
        for id in &expected_ids {
            assert!(actions[0].finding_ids.contains(id));
        }
    }

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ]
    }

    proptest! {
        /// generate_priority_actions never panics
        #[test]
        fn prop_no_panic(count in 0_usize..=20) {
            let findings: Vec<Finding> = (0..count)
                .map(|i| {
                    finding_with_remediation(
                        &format!("V{i}"),
                        Severity::Medium,
                        &format!("10.0.0.{}", i % 256),
                        &format!("Fix {}", i % 5),
                    )
                })
                .collect();
            let actions = generate_priority_actions(&findings);
            assert!(actions.len() <= 5);
        }

        /// Ranks are always 1..=N
        #[test]
        fn prop_ranks_sequential(count in 1_usize..=10) {
            let findings: Vec<Finding> = (0..count)
                .map(|i| {
                    finding_with_remediation(
                        &format!("V{i}"),
                        Severity::High,
                        &format!("10.0.{}.1", i % 256),
                        &format!("Fix {i}"),
                    )
                })
                .collect();
            let actions = generate_priority_actions(&findings);
            for (i, action) in actions.iter().enumerate() {
                assert_eq!(action.rank, u32::try_from(i + 1).unwrap());
            }
        }

        /// The max severity in each action is >= all grouped findings' severities
        #[test]
        fn prop_max_severity_correct(sev in arb_severity()) {
            let findings = vec![
                finding_with_remediation("A", Severity::Low, "10.0.0.1", "Fix"),
                finding_with_remediation("B", sev, "10.0.0.2", "Fix"),
            ];
            let actions = generate_priority_actions(&findings);
            assert_eq!(actions.len(), 1);
            assert!(actions[0].severity >= Severity::Low);
            assert!(actions[0].severity >= sev);
        }

        /// `severity_weight` is an order embedding of `Severity`.
        #[test]
        fn prop_severity_weight_order_embedding(a in arb_severity(), b in arb_severity()) {
            prop_assert_eq!(severity_weight(a).cmp(&severity_weight(b)), a.cmp(&b));
        }

        /// Actions are in non-increasing score order and each reflects exactly its group.
        #[test]
        fn prop_actions_ranked_and_consistent(
            findings in proptest::collection::vec(arb_maybe_remediated_finding(), 0..25)
        ) {
            let actions = generate_priority_actions(&findings);

            let groups: HashSet<&str> = findings
                .iter()
                .filter_map(|f| f.remediation.as_ref())
                .map(|r| r.description.as_str())
                .collect();
            prop_assert_eq!(actions.len(), groups.len().min(5));

            let score = |a: &PriorityAction| {
                severity_weight(a.severity) * 100
                    + u32::try_from(a.affected_device_count).unwrap() * 10
                    + u32::try_from(a.finding_count).unwrap()
            };
            for pair in actions.windows(2) {
                prop_assert!(score(&pair[0]) >= score(&pair[1]));
            }

            for action in &actions {
                let members: Vec<&Finding> = findings
                    .iter()
                    .filter(|f| action.finding_ids.contains(&f.id))
                    .collect();
                prop_assert_eq!(members.len(), action.finding_count);
                prop_assert_eq!(action.finding_ids.len(), action.finding_count);
                let same_group = members
                    .iter()
                    .all(|f| f.remediation.as_ref().is_some_and(|r| r.description == action.title));
                prop_assert!(same_group);
                prop_assert_eq!(action.severity, members.iter().map(|f| f.severity).max().unwrap());
                let ips: HashSet<_> = members.iter().filter_map(|f| f.affected_ip).collect();
                prop_assert_eq!(action.affected_device_count, ips.len());
            }
        }
    }

    fn arb_maybe_remediated_finding() -> impl Strategy<Value = Finding> {
        (arb_severity(), 1_u8..5_u8, 0_u8..7_u8, any::<bool>()).prop_map(
            |(sev, host, fix, remediated)| {
                let addr = format!("10.0.0.{host}");
                if remediated {
                    finding_with_remediation("V", sev, &addr, &format!("Fix {fix}"))
                } else {
                    Finding::new("test", "V", "desc", sev).with_ip(addr.parse().unwrap())
                }
            },
        )
    }
}
