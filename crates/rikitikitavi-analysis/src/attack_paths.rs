use std::collections::BTreeMap;
use std::net::IpAddr;

use rikitikitavi_models::attack_path::{AttackDifficulty, AttackPath, AttackStep};
use rikitikitavi_models::finding::Finding;

use rikitikitavi_core::Severity;
use uuid::Uuid;

/// Builds attack paths from four fixed finding patterns.
/// Paths 1, 3 and 4 chain findings on the same device IP; path 2 matches network-wide.
pub fn generate_attack_paths(findings: &[Finding]) -> Vec<AttackPath> {
    tracing::info!(findings_count = findings.len(), "generating attack paths");
    let mut paths = Vec::new();

    let mut by_ip: BTreeMap<IpAddr, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if let Some(ip) = f.affected_ip {
            by_ip.entry(ip).or_default().push(f);
        }
    }

    for ip_findings in by_ip.values() {
        paths.extend(default_credentials_path(ip_findings));
    }

    paths.extend(cleartext_lateral_path(findings));

    for ip_findings in by_ip.values() {
        paths.extend(certificate_admin_path(ip_findings));
    }

    for (ip, ip_findings) in &by_ip {
        paths.extend(high_value_target_path(*ip, ip_findings));
    }

    paths
}

/// Path 1: critical credentials finding + any other High+ finding on the same host.
fn default_credentials_path(host: &[&Finding]) -> Option<AttackPath> {
    let cred = host
        .iter()
        .find(|f| f.severity == Severity::Critical && f.scanner == "credentials")?;
    let other = host
        .iter()
        .find(|f| f.severity >= Severity::High && f.scanner != "credentials")?;

    Some(AttackPath {
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
    })
}

/// Path 2: Telnet (23) + SMB (445) anywhere on the network, optionally preceded by anonymous FTP.
fn cleartext_lateral_path(findings: &[Finding]) -> Option<AttackPath> {
    let tel = findings
        .iter()
        .find(|f| f.scanner == "ports" && f.affected_port == Some(23))?;
    let s = findings
        .iter()
        .find(|f| f.scanner == "ports" && f.affected_port == Some(445))?;

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

    if let Some(ftp) = findings
        .iter()
        .find(|f| f.scanner == "credentials" && f.title.to_lowercase().contains("anonymous ftp"))
    {
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
        for (i, step) in steps.iter_mut().enumerate() {
            step.order = u32::try_from(i + 1).unwrap_or(0);
        }
    }

    Some(AttackPath {
        id: Uuid::new_v4(),
        name: "Cleartext Protocol to Lateral Movement".to_owned(),
        description: "Attacker uses cleartext protocols to capture credentials \
                      and pivot across the network via SMB."
            .to_owned(),
        severity: Severity::High,
        steps,
        finding_ids: step_findings,
    })
}

/// Path 3: self-signed cert + admin-interface finding on the same host.
fn certificate_admin_path(host: &[&Finding]) -> Option<AttackPath> {
    let cert = host
        .iter()
        .find(|f| f.scanner == "ssl" && f.title.to_lowercase().contains("self-signed"))?;
    let admin = host.iter().find(|f| {
        (f.scanner == "credentials" || f.scanner == "http_audit")
            && f.title.to_lowercase().contains("admin")
    })?;

    Some(AttackPath {
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
    })
}

/// Path 4: any device with 3+ Medium+ findings.
fn high_value_target_path(ip: IpAddr, host: &[&Finding]) -> Option<AttackPath> {
    let high_plus: Vec<&Finding> = host
        .iter()
        .copied()
        .filter(|f| f.severity >= Severity::Medium)
        .collect();

    if high_plus.len() < 3 {
        return None;
    }

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

    Some(AttackPath {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10));
    const HOST_B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 20));

    fn critical_creds(ip: IpAddr) -> Finding {
        Finding::new(
            "credentials",
            "Default credentials on admin panel",
            "desc",
            Severity::Critical,
        )
        .with_ip(ip)
    }

    fn high_ports(ip: IpAddr) -> Finding {
        Finding::new("ports", "Exposed RDP", "desc", Severity::High).with_ip(ip)
    }

    fn self_signed(ip: IpAddr) -> Finding {
        Finding::new("ssl", "Self-signed certificate", "desc", Severity::Medium).with_ip(ip)
    }

    fn admin_http(ip: IpAddr) -> Finding {
        Finding::new("http_audit", "Admin panel exposed", "desc", Severity::High).with_ip(ip)
    }

    fn by_name<'a>(paths: &'a [AttackPath], name: &str) -> Vec<&'a AttackPath> {
        paths.iter().filter(|p| p.name == name).collect()
    }

    #[test]
    fn default_credentials_path_requires_same_host() {
        let findings = vec![critical_creds(HOST_A), high_ports(HOST_B)];
        let paths = generate_attack_paths(&findings);
        assert!(by_name(&paths, "Default Credentials to Network Compromise").is_empty());
    }

    #[test]
    fn default_credentials_path_chains_same_host() {
        let cred = critical_creds(HOST_A);
        let other = high_ports(HOST_A);
        let findings = vec![cred.clone(), high_ports(HOST_B), other.clone()];
        let paths = generate_attack_paths(&findings);
        let matched = by_name(&paths, "Default Credentials to Network Compromise");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].finding_ids, vec![cred.id, other.id]);
    }

    #[test]
    fn default_credentials_path_ignores_findings_without_ip() {
        let findings = vec![
            Finding::new("credentials", "Default creds", "desc", Severity::Critical),
            high_ports(HOST_A),
        ];
        let paths = generate_attack_paths(&findings);
        assert!(by_name(&paths, "Default Credentials to Network Compromise").is_empty());
    }

    #[test]
    fn certificate_admin_path_requires_same_host() {
        let findings = vec![self_signed(HOST_A), admin_http(HOST_B)];
        let paths = generate_attack_paths(&findings);
        assert!(by_name(&paths, "Certificate Weakness to Router Compromise").is_empty());
    }

    #[test]
    fn certificate_admin_path_chains_same_host() {
        let cert = self_signed(HOST_B);
        let admin = admin_http(HOST_B);
        let findings = vec![self_signed(HOST_A), cert.clone(), admin.clone()];
        let paths = generate_attack_paths(&findings);
        let matched = by_name(&paths, "Certificate Weakness to Router Compromise");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].finding_ids, vec![cert.id, admin.id]);
    }

    #[test]
    fn one_path_per_matching_host() {
        let findings = vec![
            critical_creds(HOST_A),
            high_ports(HOST_A),
            critical_creds(HOST_B),
            high_ports(HOST_B),
        ];
        let paths = generate_attack_paths(&findings);
        assert_eq!(
            by_name(&paths, "Default Credentials to Network Compromise").len(),
            2
        );
    }

    #[test]
    fn cleartext_lateral_path_spans_hosts() {
        let findings = vec![
            Finding::new("ports", "Telnet", "desc", Severity::High)
                .with_ip(HOST_A)
                .with_port(23),
            Finding::new("ports", "SMB", "desc", Severity::Medium)
                .with_ip(HOST_B)
                .with_port(445),
        ];
        let paths = generate_attack_paths(&findings);
        assert_eq!(
            by_name(&paths, "Cleartext Protocol to Lateral Movement").len(),
            1
        );
    }

    #[test]
    fn high_value_target_needs_three_medium_plus_on_one_host() {
        let findings = vec![
            high_ports(HOST_A),
            self_signed(HOST_A),
            high_ports(HOST_B),
            self_signed(HOST_B),
            admin_http(HOST_B),
        ];
        let paths = generate_attack_paths(&findings);
        assert!(by_name(&paths, &format!("High-value target: {HOST_A}")).is_empty());
        assert_eq!(
            by_name(&paths, &format!("High-value target: {HOST_B}")).len(),
            1
        );
    }
}
