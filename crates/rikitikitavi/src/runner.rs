use anyhow::Result;
use chrono::Utc;
use futures::future::join_all;
use rikitikitavi_analysis::{
    calculate_risk_score, generate_attack_paths, generate_priority_actions,
};
use rikitikitavi_models::device::{OpenPort, PortProtocol};
use rikitikitavi_models::{Device, DeviceHint, DeviceType, Finding, ScanContext, ScanResults};
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
        "credentials",
        "router",
        "wifi",
        "dns",
        "arp",
        "dhcp",
        "exposure",
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

    // Enrich devices with hints from Phase 2 findings
    post_enrich_devices(&mut ctx.discovered_devices, &all_findings);

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

    // Propagate identification across devices sharing the same MAC address
    propagate_mac_siblings(&mut ctx.discovered_devices);

    // Deduplicate devices by IP, keeping the entry with the most metadata
    dedup_devices(&mut ctx.discovered_devices);

    // Ensure gateway remains classified as Router after all enrichment.
    // OUI hints may reclassify it (e.g. Ubiquiti → Switch), but the gateway
    // is by definition a router — it routes packets between networks.
    if let Some(gw_ip) = ctx.gateway {
        for device in &mut ctx.discovered_devices {
            if device.ip == gw_ip {
                device.device_type = DeviceType::Router;
            }
        }
    }

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
///
/// Within the same scanner, multiple findings per (IP, port) are kept
/// (e.g. ssl reports self-signed + excessive validity + cert details for one port).
/// Across different scanners, dedup keeps the finding with the best detail score
/// (e.g. ports + services + ssl all reporting something on port 443 → keep the
/// most detailed one from the deeper scanner).
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashMap;

    // Phase 1: Group by (IP, port, scanner) — keep all findings from the same scanner
    let mut by_scanner: HashMap<(IpAddr, u16, String), Vec<Finding>> = HashMap::new();
    let mut unkeyed: Vec<Finding> = Vec::new();

    for finding in findings {
        if let (Some(ip), Some(port)) = (finding.affected_ip, finding.affected_port) {
            let key = (ip, port, finding.scanner.clone());
            by_scanner.entry(key).or_default().push(finding);
        } else {
            unkeyed.push(finding);
        }
    }

    // Phase 2: For each (IP, port), pick the best scanner and keep all its findings.
    // If multiple scanners report on the same port, keep the deepest one.
    let mut by_port: HashMap<(IpAddr, u16), Vec<(String, Vec<Finding>)>> = HashMap::new();
    for ((ip, port, scanner), group) in by_scanner {
        by_port
            .entry((ip, port))
            .or_default()
            .push((scanner, group));
    }

    let mut result: Vec<Finding> = unkeyed;
    for (_key, scanner_groups) in by_port {
        if scanner_groups.len() == 1 {
            // Only one scanner reported on this port — keep all its findings
            result.extend(scanner_groups.into_iter().flat_map(|(_, f)| f));
        } else {
            // Multiple scanners on the same port — keep the best one
            let mut best_scanner = String::new();
            let mut best_score = 0_u32;
            for (scanner, group) in &scanner_groups {
                let max_score = group.iter().map(detail_score).max().unwrap_or(0);
                let is_ports = scanner == "ports";
                // Prefer non-ports scanners (Phase 2 deeper analysis)
                let adjusted = if is_ports { max_score } else { max_score + 1 };
                if adjusted > best_score {
                    best_score = adjusted;
                    scanner.clone_into(&mut best_scanner);
                }
            }
            for (scanner, group) in scanner_groups {
                if scanner == best_scanner {
                    result.extend(group);
                }
            }
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

/// Classify device type based on which ports are open.
fn classify_by_ports(open_ports: &[u16]) -> Option<DeviceType> {
    if open_ports.contains(&9100) || open_ports.contains(&631) {
        return Some(DeviceType::Printer);
    }
    if open_ports.contains(&554) || open_ports.contains(&8554) {
        return Some(DeviceType::Camera);
    }
    if open_ports.contains(&1883) || open_ports.contains(&8883) {
        return Some(DeviceType::IoT);
    }
    if open_ports.contains(&62078) {
        return Some(DeviceType::Phone);
    }
    if open_ports.contains(&5000) && open_ports.contains(&5001) {
        return Some(DeviceType::Nas);
    }
    if open_ports.contains(&8443) && open_ports.contains(&8880) {
        return Some(DeviceType::Server);
    }
    if open_ports.contains(&3689) || open_ports.contains(&5353) {
        return Some(DeviceType::MediaPlayer);
    }
    if open_ports.contains(&3389) {
        return Some(DeviceType::Desktop);
    }
    None
}

/// Enrich `ctx.discovered_devices` from Phase 1 scan findings.
///
/// Groups findings by IP address and extracts open ports, services, and
/// device metadata to build a rich device inventory that Phase 2 scanners
/// can use for adaptive scanning. Also applies device-scanner hints and
/// port-based classification.
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
        if finding.scanner == "ports" {
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
        }

        // Apply device-scanner hints (OUI vendor + device_type)
        if finding.scanner == "device" {
            if let (Some(ip), Some(hint)) = (finding.affected_ip, &finding.device_hint) {
                if let Some(device) = device_map.get_mut(&ip) {
                    if let Some(vendor) = &hint.vendor {
                        if device.vendor.is_none() {
                            vendor.clone_into(device.vendor.get_or_insert_with(String::new));
                        }
                    }
                    if let Some(dt) = hint.device_type {
                        if device.device_type == DeviceType::Unknown && dt != DeviceType::Unknown {
                            device.device_type = dt;
                        }
                    }
                }
            }
        }
    }

    // Port-based classification for devices still Unknown
    for device in &mut ctx.discovered_devices {
        if device.device_type == DeviceType::Unknown && !device.open_ports.is_empty() {
            let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
            if let Some(dt) = classify_by_ports(&ports) {
                device.device_type = dt;
            }
        }
    }
}

/// Clean up a hostname from mDNS/UPnP discovery.
///
/// Strips `.local` suffix and rejects UUID-style hostnames that aren't
/// human-readable (e.g. Chromecast device IDs).
fn clean_hostname(raw: &str) -> Option<String> {
    let cleaned = raw.strip_suffix(".local").unwrap_or(raw).trim();
    if cleaned.is_empty() {
        return None;
    }
    // Reject UUID-style hostnames (8-4-4-4-12 hex pattern)
    let hex_count = cleaned.chars().filter(char::is_ascii_hexdigit).count();
    let dash_count = cleaned.chars().filter(|c| *c == '-').count();
    let total = cleaned.len();
    // If >80% hex digits + dashes and has 4+ dashes, it's a UUID
    if dash_count >= 4 && (hex_count + dash_count) * 100 / total > 80 {
        return None;
    }
    Some(cleaned.to_owned())
}

/// Merge `DeviceHint` data from Phase 2 findings into devices.
///
/// Uses priority-based merging: higher-priority sources overwrite lower ones.
/// Priority (low → high): OUI (device scanner, priority=1), SSH banner (2),
/// mDNS service (3), `UPnP` description (4).
fn post_enrich_devices(devices: &mut [Device], findings: &[Finding]) {
    use std::collections::HashMap;

    // Collect all hints by IP, with priority
    let mut hints_by_ip: HashMap<IpAddr, Vec<(u8, &DeviceHint)>> = HashMap::new();

    for finding in findings {
        let Some(ip) = finding.affected_ip else {
            continue;
        };
        let Some(hint) = &finding.device_hint else {
            continue;
        };
        if hint.is_empty() {
            continue;
        }

        let priority = match finding.scanner.as_str() {
            "services" => 2,
            "mdns" => {
                // UPnP findings (have vendor) get higher priority than plain mDNS
                if hint.vendor.is_some() { 4 } else { 3 }
            }
            // "device" and any other scanner default to lowest priority
            _ => 1,
        };

        hints_by_ip.entry(ip).or_default().push((priority, hint));
    }

    if hints_by_ip.is_empty() {
        return;
    }

    let mut enriched_count = 0u32;
    for device in devices.iter_mut() {
        let Some(hints) = hints_by_ip.get(&device.ip) else {
            continue;
        };

        // Sort by priority (low first) so higher-priority overwrites
        let mut sorted: Vec<_> = hints.clone();
        sorted.sort_by_key(|(prio, _)| *prio);

        let mut changed = false;
        for (_, hint) in &sorted {
            if let Some(vendor) = &hint.vendor {
                vendor.clone_into(device.vendor.get_or_insert_with(String::new));
                changed = true;
            }
            if let Some(hostname) = &hint.hostname {
                if let Some(clean) = clean_hostname(hostname) {
                    if device.hostname.is_none() {
                        device.hostname = Some(clean);
                        changed = true;
                    }
                }
            }
            if let Some(dt) = hint.device_type {
                if dt != DeviceType::Unknown {
                    device.device_type = dt;
                    changed = true;
                }
            }
            if let Some(os) = &hint.os_guess {
                os.clone_into(device.os_guess.get_or_insert_with(String::new));
                changed = true;
            }
        }

        if changed {
            enriched_count += 1;
        }
    }

    if enriched_count > 0 {
        tracing::info!(enriched_count, "enriched devices from Phase 2 hints");
    }
}

/// Deduplicate devices by IP address.
///
/// When multiple entries share the same IP (e.g. from overlapping ARP
/// cache snapshots), keep the one with the richest metadata: prefer
/// entries with known `device_type`, then most open ports, then first
/// occurrence.
fn dedup_devices(devices: &mut Vec<Device>) {
    use std::collections::HashMap;

    let mut best: HashMap<IpAddr, usize> = HashMap::new();
    for (i, device) in devices.iter().enumerate() {
        best.entry(device.ip)
            .and_modify(|prev| {
                let prev_dev = &devices[*prev];
                let new_is_better =
                    // Prefer identified over unknown
                    (device.device_type != DeviceType::Unknown && prev_dev.device_type == DeviceType::Unknown)
                    // Prefer more open ports
                    || (device.device_type == prev_dev.device_type
                        && device.open_ports.len() > prev_dev.open_ports.len())
                    // Prefer having a hostname
                    || (device.device_type == prev_dev.device_type
                        && device.open_ports.len() == prev_dev.open_ports.len()
                        && device.hostname.is_some()
                        && prev_dev.hostname.is_none());
                if new_is_better {
                    *prev = i;
                }
            })
            .or_insert(i);
    }

    let mut keep: Vec<usize> = best.into_values().collect();
    keep.sort_unstable();
    *devices = keep.into_iter().map(|i| devices[i].clone()).collect();
}

/// Propagate identification across devices that share the same MAC address.
///
/// When the same physical device appears at multiple IPs (DHCP lease change,
/// dual-stack, etc.), one entry may have been identified while others remain
/// unknown. This copies `device_type`, `vendor`, `hostname`, and `os_guess`
/// from identified entries to their same-MAC siblings.
fn propagate_mac_siblings(devices: &mut [Device]) {
    use std::collections::HashMap;

    // Collect best-known info per MAC (using owned strings to avoid borrow issues)
    let mut mac_info: HashMap<String, (DeviceType, Option<String>, Option<String>, Option<String>)> =
        HashMap::new();

    for device in devices.iter() {
        let Some(mac) = device.mac.as_deref() else {
            continue;
        };
        let entry = mac_info.entry(mac.to_owned()).or_insert((
            DeviceType::Unknown,
            None,
            None,
            None,
        ));
        if device.device_type != DeviceType::Unknown && entry.0 == DeviceType::Unknown {
            entry.0 = device.device_type;
        }
        if entry.1.is_none() {
            entry.1.clone_from(&device.vendor);
        }
        if entry.2.is_none() {
            entry.2.clone_from(&device.hostname);
        }
        if entry.3.is_none() {
            entry.3.clone_from(&device.os_guess);
        }
    }

    // Apply best-known info back to all devices with matching MAC
    for device in devices.iter_mut() {
        let Some(mac) = device.mac.as_deref() else {
            continue;
        };
        if let Some((dt, vendor, hostname, os)) = mac_info.get(mac) {
            if device.device_type == DeviceType::Unknown && *dt != DeviceType::Unknown {
                device.device_type = *dt;
            }
            if device.vendor.is_none() {
                device.vendor.clone_from(vendor);
            }
            if device.hostname.is_none() {
                device.hostname.clone_from(hostname);
            }
            if device.os_guess.is_none() {
                device.os_guess.clone_from(os);
            }
        }
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
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 21).with_cwe("CWE-319");
        let f2 =
            basic_finding("credentials", Severity::Medium, ip("10.0.0.1"), 21).with_cwe("CWE-287");
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
        let f1 = basic_finding("ports", Severity::Medium, ip("10.0.0.1"), 23).with_cwe("CWE-319");
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

    #[test]
    fn test_classify_by_ports_printer() {
        assert_eq!(classify_by_ports(&[80, 443, 9100, 631]), Some(DeviceType::Printer));
    }

    #[test]
    fn test_classify_by_ports_camera() {
        assert_eq!(classify_by_ports(&[80, 554]), Some(DeviceType::Camera));
    }

    #[test]
    fn test_classify_by_ports_iot() {
        assert_eq!(classify_by_ports(&[1883]), Some(DeviceType::IoT));
    }

    #[test]
    fn test_classify_by_ports_nas() {
        assert_eq!(classify_by_ports(&[5000, 5001, 443]), Some(DeviceType::Nas));
    }

    #[test]
    fn test_classify_by_ports_phone() {
        assert_eq!(classify_by_ports(&[62078]), Some(DeviceType::Phone));
    }

    #[test]
    fn test_classify_by_ports_desktop() {
        assert_eq!(classify_by_ports(&[3389]), Some(DeviceType::Desktop));
    }

    #[test]
    fn test_classify_by_ports_none() {
        assert_eq!(classify_by_ports(&[80, 443]), None);
    }

    #[test]
    fn test_post_enrich_devices_upnp_overwrites_oui() {
        let mut devices = vec![
            Device::new(ip("192.168.1.220"))
                .with_mac("00:11:32:aa:bb:cc"),
        ];
        // Device scanner found vendor="Synology"
        devices[0].vendor = Some("Synology".to_owned());
        devices[0].device_type = DeviceType::Nas;

        let findings = vec![
            // UPnP finding with richer data
            Finding::new("mdns", "UPnP device: rudiger", "desc", Severity::Info)
                .with_ip(ip("192.168.1.220"))
                .with_device_hint(
                    DeviceHint::new()
                        .with_vendor("Synology Inc.")
                        .with_hostname("rudiger")
                        .with_model("DS418play")
                        .with_device_type(DeviceType::MediaPlayer), // UPnP MediaServer
                ),
        ];

        post_enrich_devices(&mut devices, &findings);

        // UPnP (priority 4) overwrites OUI vendor name
        assert_eq!(devices[0].vendor.as_deref(), Some("Synology Inc."));
        assert_eq!(devices[0].hostname.as_deref(), Some("rudiger"));
        // UPnP device_type overwrites
        assert_eq!(devices[0].device_type, DeviceType::MediaPlayer);
    }

    #[test]
    fn test_post_enrich_ssh_os_guess() {
        let mut devices = vec![
            Device::new(ip("192.168.1.10")),
        ];

        let findings = vec![
            Finding::new("services", "SSH on 10", "desc", Severity::Low)
                .with_ip(ip("192.168.1.10"))
                .with_device_hint(
                    DeviceHint::new().with_os_guess("Linux (Debian)"),
                ),
        ];

        post_enrich_devices(&mut devices, &findings);
        assert_eq!(devices[0].os_guess.as_deref(), Some("Linux (Debian)"));
    }

    #[test]
    fn test_post_enrich_priority_ordering() {
        let mut devices = vec![
            Device::new(ip("192.168.1.30")),
        ];

        let findings = vec![
            // mDNS hostname-only hint (priority 3)
            Finding::new("mdns", "AirPlay", "desc", Severity::Info)
                .with_ip(ip("192.168.1.30"))
                .with_device_hint(
                    DeviceHint::new()
                        .with_hostname("denon.local")
                        .with_device_type(DeviceType::MediaPlayer),
                ),
            // Device scanner OUI hint (priority 1)
            Finding::new("device", "LG device", "desc", Severity::Info)
                .with_ip(ip("192.168.1.30"))
                .with_device_hint(
                    DeviceHint::new()
                        .with_vendor("LG")
                        .with_device_type(DeviceType::Unknown),
                ),
        ];

        post_enrich_devices(&mut devices, &findings);

        // mDNS (priority 3) device_type overwrites OUI (priority 1)
        assert_eq!(devices[0].device_type, DeviceType::MediaPlayer);
        // OUI vendor is set (priority 1), not overwritten since mDNS has no vendor
        assert_eq!(devices[0].vendor.as_deref(), Some("LG"));
        // mDNS hostname is set
        assert_eq!(devices[0].hostname.as_deref(), Some("denon"));
    }

    #[test]
    fn test_post_enrich_empty_hints_ignored() {
        let mut devices = vec![
            Device::new(ip("192.168.1.1")),
        ];

        let findings = vec![
            Finding::new("ports", "Open port", "desc", Severity::Info)
                .with_ip(ip("192.168.1.1")),
        ];

        post_enrich_devices(&mut devices, &findings);
        assert!(devices[0].vendor.is_none());
        assert!(devices[0].hostname.is_none());
        assert_eq!(devices[0].device_type, DeviceType::Unknown);
    }

    #[test]
    fn test_clean_hostname_strips_local() {
        assert_eq!(clean_hostname("denon.local"), Some("denon".to_owned()));
        assert_eq!(
            clean_hostname("Kathryns-MacBook-Pro.local"),
            Some("Kathryns-MacBook-Pro".to_owned())
        );
    }

    #[test]
    fn test_clean_hostname_rejects_uuid() {
        assert_eq!(
            clean_hostname("3b7bb773-aa67-7879-b533-ffa93275bbd0.local"),
            None
        );
    }

    #[test]
    fn test_clean_hostname_keeps_friendly() {
        assert_eq!(
            clean_hostname("rudiger (DS418play)"),
            Some("rudiger (DS418play)".to_owned())
        );
        assert_eq!(
            clean_hostname("Hue Bridge (192.168.1.169)"),
            Some("Hue Bridge (192.168.1.169)".to_owned())
        );
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
            prop_oneof![
                Just("ports"),
                Just("services"),
                Just("credentials"),
                Just("smb")
            ],
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
