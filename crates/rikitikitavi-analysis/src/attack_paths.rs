use rikitikitavi_models::attack_path::{AttackDifficulty, AttackPath, AttackStep};
use rikitikitavi_models::finding::Finding;

use rikitikitavi_core::Severity;
use uuid::Uuid;

/// Generate attack paths by chaining related findings into plausible attack
/// scenarios an adversary could follow.
///
/// Groups findings by device IP and identifies multi-step attack chains
/// such as credential exploitation → lateral movement → data exfiltration.
#[allow(clippy::too_many_lines)]
pub fn generate_attack_paths(findings: &[Finding]) -> Vec<AttackPath> {
    use std::collections::HashMap;

    tracing::info!(findings_count = findings.len(), "generating attack paths");
    let mut paths = Vec::new();

    // Group findings by affected IP
    let mut by_ip: HashMap<std::net::IpAddr, Vec<&Finding>> = HashMap::new();
    for f in findings {
        if let Some(ip) = f.affected_ip {
            by_ip.entry(ip).or_default().push(f);
        }
    }

    // ── Path 1: Default Credentials → Network Compromise ────────────
    let critical_creds = findings
        .iter()
        .find(|f| f.severity == Severity::Critical && f.scanner == "credentials");
    let high_finding = findings
        .iter()
        .find(|f| f.severity >= Severity::High && f.scanner != "credentials");

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

    // ── Path 2: Telnet/FTP → Default Credentials → Lateral Movement ─
    let telnet = findings
        .iter()
        .find(|f| f.scanner == "ports" && f.affected_port == Some(23));
    let smb = findings
        .iter()
        .find(|f| f.scanner == "ports" && f.affected_port == Some(445));

    if let (Some(tel), Some(s)) = (telnet, smb) {
        let mut step_findings = vec![tel.id, s.id];
        let mut steps = vec![
            AttackStep {
                order: 1,
                title: "Telnet cleartext access".to_owned(),
                description: "Attacker connects via Telnet and captures credentials \
                              transmitted in cleartext."
                    .to_owned(),
                technique: Some("T1021.001 - Remote Services: Telnet".to_owned()),
                difficulty: AttackDifficulty::Trivial,
                finding_id: Some(tel.id),
            },
            AttackStep {
                order: 2,
                title: "Credential harvest".to_owned(),
                description: "Captured credentials are used to authenticate.".to_owned(),
                technique: Some("T1078 - Valid Accounts".to_owned()),
                difficulty: AttackDifficulty::Easy,
                finding_id: None,
            },
            AttackStep {
                order: 3,
                title: "Lateral movement via SMB".to_owned(),
                description: "Attacker pivots to SMB shares using harvested \
                              credentials to access files on other devices."
                    .to_owned(),
                technique: Some("T1021.002 - Remote Services: SMB".to_owned()),
                difficulty: AttackDifficulty::Easy,
                finding_id: Some(s.id),
            },
        ];

        // If there's also anonymous FTP, prepend it
        if let Some(ftp) = findings.iter().find(|f| {
            f.scanner == "credentials" && f.title.to_lowercase().contains("anonymous ftp")
        }) {
            steps.insert(
                0,
                AttackStep {
                    order: 0,
                    title: "Anonymous FTP access".to_owned(),
                    description: "Attacker uploads tools via anonymous FTP.".to_owned(),
                    technique: Some("T1105 - Ingress Tool Transfer".to_owned()),
                    difficulty: AttackDifficulty::Trivial,
                    finding_id: Some(ftp.id),
                },
            );
            step_findings.push(ftp.id);
            // Re-number orders
            for (i, step) in steps.iter_mut().enumerate() {
                step.order = u32::try_from(i + 1).unwrap_or(0);
            }
        }

        paths.push(AttackPath {
            id: Uuid::new_v4(),
            name: "Cleartext Protocol to Lateral Movement".to_owned(),
            description: "Attacker uses cleartext protocols to capture credentials \
                          and pivot across the network via SMB."
                .to_owned(),
            severity: Severity::High,
            steps,
            finding_ids: step_findings,
        });
    }

    // ── Path 3: Self-signed cert → credential interception ──────────
    let self_signed = findings
        .iter()
        .find(|f| f.scanner == "ssl" && f.title.to_lowercase().contains("self-signed"));
    let router_admin = findings.iter().find(|f| {
        (f.scanner == "credentials" || f.scanner == "http_audit")
            && f.title.to_lowercase().contains("admin")
    });

    if let (Some(cert), Some(admin)) = (self_signed, router_admin) {
        paths.push(AttackPath {
            id: Uuid::new_v4(),
            name: "Certificate Weakness to Router Compromise".to_owned(),
            description: "Self-signed certificate on router enables MITM \
                          interception of admin credentials."
                .to_owned(),
            severity: Severity::High,
            steps: vec![
                AttackStep {
                    order: 1,
                    title: "MITM via self-signed certificate".to_owned(),
                    description: "Attacker performs ARP spoofing and presents \
                                  own certificate; user accepts because the \
                                  legitimate cert is also self-signed."
                        .to_owned(),
                    technique: Some("T1557.002 - LLMNR/mDNS Poisoning".to_owned()),
                    difficulty: AttackDifficulty::Moderate,
                    finding_id: Some(cert.id),
                },
                AttackStep {
                    order: 2,
                    title: "Router admin credential capture".to_owned(),
                    description: admin.description.clone(),
                    technique: Some("T1056 - Input Capture".to_owned()),
                    difficulty: AttackDifficulty::Easy,
                    finding_id: Some(admin.id),
                },
            ],
            finding_ids: vec![cert.id, admin.id],
        });
    }

    // ── Path 4: High-value targets (devices with 3+ findings) ───────
    for (ip, ip_findings) in &by_ip {
        let high_plus: Vec<&&Finding> = ip_findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .collect();

        if high_plus.len() >= 3 {
            let ids: Vec<Uuid> = high_plus.iter().map(|f| f.id).collect();
            let steps: Vec<AttackStep> = high_plus
                .iter()
                .enumerate()
                .map(|(i, f)| AttackStep {
                    order: u32::try_from(i + 1).unwrap_or(0),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    technique: None,
                    difficulty: AttackDifficulty::Easy,
                    finding_id: Some(f.id),
                })
                .collect();

            paths.push(AttackPath {
                id: Uuid::new_v4(),
                name: format!("High-value target: {ip}"),
                description: format!(
                    "Device {ip} has {} medium+ severity findings, making it \
                     a high-value target for attackers.",
                    high_plus.len()
                ),
                severity: Severity::High,
                steps,
                finding_ids: ids,
            });
        }
    }

    paths
}
