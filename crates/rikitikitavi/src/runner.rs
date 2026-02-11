use anyhow::Result;
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
    })
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
