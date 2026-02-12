use anyhow::Result;
use chrono::Utc;
use futures::future::join_all;
use rikitikitavi_analysis::{calculate_risk_score, generate_attack_paths, generate_priority_actions};
use rikitikitavi_models::device::{OpenPort, PortProtocol};
use rikitikitavi_models::{Device, DeviceType, Finding, ScanContext, ScanResults};
use rikitikitavi_scanners::ScannerRegistry;
use std::net::IpAddr;
use std::time::Instant;

/// Perform network discovery and populate the scan context with gateway,
/// network CIDR, and discovered devices.
pub fn discover_network(ctx: &mut ScanContext) -> Vec<Device> {
    // Detect gateway
    if ctx.gateway.is_none() {
        match rikitikitavi_network::detect_gateway() {
            Ok(Some(gw)) => {
                tracing::info!(%gw, "detected default gateway");
                ctx.gateway = Some(gw);
            }
            Ok(None) => {
                tracing::warn!("could not detect default gateway");
            }
            Err(e) => {
                tracing::warn!("gateway detection failed: {e}");
            }
        }
    }

    // Detect network CIDR
    if ctx.target_network.is_none() {
        match rikitikitavi_network::detect_network() {
            Ok(Some(net)) => {
                tracing::info!(%net, "detected target network");
                ctx.target_network = Some(net);
            }
            Ok(None) => {
                tracing::warn!("could not detect target network");
            }
            Err(e) => {
                tracing::warn!("network detection failed: {e}");
            }
        }
    }

    // Read ARP cache and build device list
    let arp_entries = rikitikitavi_network::read_arp_cache().unwrap_or_default();
    let mut devices: Vec<Device> = arp_entries
        .iter()
        .map(|entry| {
            let mut dev = Device::new(entry.ip).with_mac(&entry.mac);
            // Tag the gateway device as Router
            if ctx.gateway == Some(entry.ip) {
                dev = dev.with_device_type(DeviceType::Router);
            }
            dev
        })
        .collect();

    // Ensure the gateway is in the device list even if not in ARP cache
    if let Some(gw) = ctx.gateway {
        if !devices.iter().any(|d| d.ip == gw) {
            devices.push(Device::new(gw).with_device_type(DeviceType::Router));
        }
    }

    tracing::info!(
        gateway = ?ctx.gateway,
        network = ?ctx.target_network,
        device_count = devices.len(),
        "network discovery complete"
    );

    devices
}

/// Orchestrate a full scan run across all applicable scanner modules.
///
/// The scan runs in two phases:
/// - **Phase 1 (Discovery)**: network, ports, device scanners populate
///   `discovered_devices` with IPs, open ports, and device types.
/// - **Phase 2 (Deep Analysis)**: remaining scanners run with enriched context,
///   adapting their checks based on what Phase 1 found.
#[allow(clippy::too_many_lines)]
pub async fn run_scan(ctx: &mut ScanContext) -> Result<ScanResults> {
    let start = Instant::now();
    let registry = ScannerRegistry::new();

    let scanners = ctx.config.modules.as_ref().map_or_else(
        // Run all scanners for this perspective
        || registry.for_perspective(ctx.perspective),
        // Only run specified modules
        |modules| {
            modules
                .iter()
                .filter_map(|id| registry.get(id))
                .collect::<Vec<_>>()
        },
    );

    // Split scanners into Phase 1 (discovery) and Phase 2 (deep analysis)
    let phase1_ids: &[&str] = &["network", "ports", "device"];
    let (phase1, phase2): (Vec<_>, Vec<_>) = scanners
        .into_iter()
        .partition(|s| phase1_ids.contains(&s.id()));

    let phase2_count = phase2.len();
    tracing::info!(
        perspective = %ctx.perspective,
        phase1_count = phase1.len(),
        phase2_count,
        "starting two-phase scan"
    );

    let mut all_findings = Vec::new();

    // ── Phase 1: Discovery ──────────────────────────────────────────
    tracing::info!("Phase 1: Discovery");
    for scanner in &phase1 {
        tracing::info!(
            scanner = scanner.id(),
            name = scanner.name(),
            "running Phase 1 scanner"
        );

        match scanner.scan(ctx).await {
            Ok(findings) => {
                tracing::info!(
                    scanner = scanner.id(),
                    findings_count = findings.len(),
                    "Phase 1 scanner completed"
                );
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(
                    scanner = scanner.id(),
                    error = %e,
                    "Phase 1 scanner failed, continuing"
                );
            }
        }
    }

    // ── Enrich context between phases ───────────────────────────────
    // Build Device list from Phase 1 findings (group open ports by IP)
    enrich_devices_from_findings(ctx, &all_findings);
    tracing::info!(
        discovered_devices = ctx.discovered_devices.len(),
        "enriched context with discovered devices"
    );

    // ── Phase 2: Deep Analysis (concurrent) ────────────────────────
    // Collect all open ports discovered in Phase 1 for smart filtering
    let discovered_ports: std::collections::HashSet<u16> = ctx
        .discovered_devices
        .iter()
        .flat_map(|d| d.open_ports.iter().map(|p| p.port))
        .collect();

    // Essential scanners that always run in Passive mode (they don't
    // depend on open ports and check fundamental network hygiene).
    let passive_essential: &[&str] = &[
        "credentials", "router", "wifi", "dns", "arp", "dhcp", "exposure",
    ];

    let phase2_filtered: Vec<_> = phase2
        .into_iter()
        .filter(|scanner| {
            let ports = scanner.relevant_ports();
            // If scanner declares relevant ports, skip if none were discovered
            if !ports.is_empty() && !ports.iter().any(|p| discovered_ports.contains(p)) {
                tracing::debug!(
                    scanner = scanner.id(),
                    "skipping — no relevant ports discovered"
                );
                return false;
            }
            // In Passive mode, only run essential scanners + port-dependent
            // scanners whose ports were found
            if ctx.config.intensity == rikitikitavi_models::config::ScanIntensity::Passive
                && !passive_essential.contains(&scanner.id())
                && ports.is_empty()
            {
                tracing::debug!(
                    scanner = scanner.id(),
                    "skipping — non-essential in quick scan"
                );
                return false;
            }
            true
        })
        .collect();

    let phase2_skipped = phase2_count - phase2_filtered.len();
    tracing::info!(
        "Phase 2: Deep Analysis ({} scanners, {} skipped, concurrent)",
        phase2_filtered.len(),
        phase2_skipped,
    );
    let phase2_results = join_all(phase2_filtered.iter().map(|scanner| async {
        tracing::info!(
            scanner = scanner.id(),
            name = scanner.name(),
            "running Phase 2 scanner"
        );
        (scanner.id(), scanner.scan(ctx).await)
    }))
    .await;

    for (id, result) in phase2_results {
        match result {
            Ok(findings) => {
                tracing::info!(
                    scanner = id,
                    findings_count = findings.len(),
                    "Phase 2 scanner completed"
                );
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(
                    scanner = id,
                    error = %e,
                    "Phase 2 scanner failed, continuing"
                );
            }
        }
    }

    // Deduplicate findings from Phase 1 + Phase 2 overlap
    let pre_dedup = all_findings.len();
    let all_findings = deduplicate_findings(all_findings);
    if all_findings.len() < pre_dedup {
        tracing::info!(
            before = pre_dedup,
            after = all_findings.len(),
            removed = pre_dedup - all_findings.len(),
            "deduplicated findings"
        );
    }

    // Generate attack paths if requested
    let attack_paths = if ctx.config.attack_paths {
        generate_attack_paths(&all_findings)
    } else {
        Vec::new()
    };

    let risk_score = calculate_risk_score(&all_findings);
    let priority_actions = generate_priority_actions(&all_findings);
    let duration = start.elapsed().as_secs();

    tracing::info!(
        total_findings = all_findings.len(),
        attack_paths = attack_paths.len(),
        priority_actions = priority_actions.len(),
        risk_score,
        duration_secs = duration,
        "scan complete"
    );

    Ok(ScanResults {
        findings: all_findings,
        devices: std::mem::take(&mut ctx.discovered_devices),
        attack_paths,
        priority_actions,
        risk_score,
        scan_duration_secs: duration,
        scanned_at: Utc::now(),
    })
}

/// Deduplicate findings that share the same `(affected_ip, affected_port)`.
///
/// When Phase 1 (ports) and Phase 2 (services, ssl, credentials, etc.) both
/// report on the same IP:port, keep the finding with the highest detail score.
/// Findings without both IP and port are never deduplicated.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashMap;

    let mut keyed: HashMap<(IpAddr, u16), Vec<Finding>> = HashMap::new();
    let mut unkeyed: Vec<Finding> = Vec::new();

    for finding in findings {
        if let (Some(ip), Some(port)) = (finding.affected_ip, finding.affected_port) {
            keyed.entry((ip, port)).or_default().push(finding);
        } else {
            unkeyed.push(finding);
        }
    }

    let mut result: Vec<Finding> = unkeyed;
    for (_key, mut group) in keyed {
        if group.len() == 1 {
            result.push(group.pop().expect("non-empty group"));
        } else {
            // Keep the finding with the highest detail score
            group.sort_by(|a, b| {
                let score_a = detail_score(a);
                let score_b = detail_score(b);
                score_b.cmp(&score_a).then_with(|| {
                    // Tiebreaker: prefer non-"ports" scanner (Phase 2 is deeper)
                    let a_is_ports = a.scanner == "ports";
                    let b_is_ports = b.scanner == "ports";
                    a_is_ports.cmp(&b_is_ports)
                })
            });
            result.push(group.swap_remove(0));
        }
    }

    // Re-sort by severity (descending) for consistent output
    result.sort_by(|a, b| b.severity.cmp(&a.severity));
    result
}

/// Score a finding by how much useful detail it contains.
fn detail_score(f: &Finding) -> u32 {
    let mut score = 0;
    if f.evidence.is_some() {
        score += 3;
    }
    if f.remediation.is_some() {
        score += 2;
    }
    if f.cwe_id.is_some() {
        score += 1;
    }
    if f.affected_service.is_some() {
        score += 1;
    }
    if f.description.len() > 100 {
        score += 1;
    }
    score
}

/// Enrich `ctx.discovered_devices` from Phase 1 scan findings.
///
/// Groups findings by IP address and extracts open ports, services, and
/// device metadata to build a rich device inventory that Phase 2 scanners
/// can use for adaptive scanning.
fn enrich_devices_from_findings(ctx: &mut ScanContext, findings: &[Finding]) {
    use std::collections::HashMap;

    // Index existing devices by IP (from discover_network)
    let mut device_map: HashMap<IpAddr, &mut Device> = ctx
        .discovered_devices
        .iter_mut()
        .map(|d| (d.ip, d))
        .collect();

    // Collect open ports from port-scanner findings
    for finding in findings {
        if finding.scanner != "ports" {
            continue;
        }
        let Some(ip) = finding.affected_ip else {
            continue;
        };
        let Some(port) = finding.affected_port else {
            continue;
        };

        if let Some(device) = device_map.get_mut(&ip) {
            // Avoid duplicate port entries
            if !device.open_ports.iter().any(|p| p.port == port) {
                device.open_ports.push(OpenPort {
                    port,
                    protocol: PortProtocol::Tcp,
                    service: finding.affected_service.clone(),
                    version: None,
                    banner: None,
                });
            }
        }
        // If the IP isn't in our device list yet (edge case), we don't create
        // a new device here — discover_network should have found it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_core::Severity;
    use rikitikitavi_models::Remediation;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn basic_finding(scanner: &str, sev: Severity, ip_addr: IpAddr, port: u16) -> Finding {
        Finding::new(scanner, "title", "short desc", sev)
            .with_ip(ip_addr)
            .with_port(port)
            .with_service("SVC")
    }

    #[test]
    fn test_dedup_keeps_more_detailed() {
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 23);
        let f2 = basic_finding("credentials", Severity::High, ip("10.0.0.1"), 23)
            .with_cwe("CWE-319")
            .with_remediation(Remediation {
                description: "Fix".to_owned(),
                steps: vec!["Do it".to_owned()],
                effort: None,
            });
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scanner, "credentials");
    }

    #[test]
    fn test_dedup_prefers_phase2() {
        // Same detail score, but prefer non-ports scanner
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 21)
            .with_cwe("CWE-319");
        let f2 = basic_finding("credentials", Severity::Medium, ip("10.0.0.1"), 21)
            .with_cwe("CWE-287");
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scanner, "credentials");
    }

    #[test]
    fn test_dedup_no_ip_no_dedup() {
        let f1 = Finding::new("network", "title1", "desc", Severity::Info);
        let f2 = Finding::new("network", "title2", "desc", Severity::Info);
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_different_ports() {
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 21);
        let f2 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 22);
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_evidence_wins() {
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 23)
            .with_cwe("CWE-319");
        let f2 = basic_finding("services", Severity::Medium, ip("10.0.0.1"), 23)
            .with_evidence("SSH-2.0-OpenSSH_8.9p1");
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        assert!(result[0].evidence.is_some());
    }

    #[test]
    fn test_dedup_empty() {
        let result = deduplicate_findings(Vec::new());
        assert!(result.is_empty());
    }

    #[test]
    fn test_dedup_preserves_unkeyed() {
        let f1 = Finding::new("network", "No IP finding", "desc", Severity::Info);
        let f2 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 23);
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 2);
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

    fn arb_finding_for_dedup() -> impl Strategy<Value = Finding> {
        (
            prop_oneof![Just("ports"), Just("services"), Just("credentials"), Just("smb")],
            arb_severity(),
            (0_u8..5_u8),
            (1_u16..100_u16),
            proptest::bool::ANY,
        )
            .prop_map(|(scanner, sev, host, port, has_ip)| {
                let mut f = Finding::new(scanner, "title", "description text here", sev);
                if has_ip {
                    f = f
                        .with_ip(format!("10.0.0.{host}").parse().unwrap())
                        .with_port(port);
                }
                f
            })
    }

    proptest! {
        #[test]
        fn prop_dedup_never_increases_count(
            findings in proptest::collection::vec(arb_finding_for_dedup(), 0..50)
        ) {
            let original_len = findings.len();
            let deduped = deduplicate_findings(findings);
            assert!(deduped.len() <= original_len);
        }
    }
}
