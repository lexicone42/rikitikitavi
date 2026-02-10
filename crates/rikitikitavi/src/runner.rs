use anyhow::Result;
use rikitikitavi_analysis::{calculate_risk_score, generate_attack_paths};
use rikitikitavi_models::{Device, DeviceType, ScanContext, ScanResults};
use rikitikitavi_scanners::ScannerRegistry;
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
pub async fn run_scan(ctx: &ScanContext) -> Result<ScanResults> {
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

    tracing::info!(
        perspective = %ctx.perspective,
        scanner_count = scanners.len(),
        "starting scan"
    );

    let mut all_findings = Vec::new();

    for scanner in &scanners {
        tracing::info!(
            scanner = scanner.id(),
            name = scanner.name(),
            "running scanner"
        );

        match scanner.scan(ctx).await {
            Ok(findings) => {
                tracing::info!(
                    scanner = scanner.id(),
                    findings_count = findings.len(),
                    "scanner completed"
                );
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(
                    scanner = scanner.id(),
                    error = %e,
                    "scanner failed, continuing"
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
    let duration = start.elapsed().as_secs();

    tracing::info!(
        total_findings = all_findings.len(),
        attack_paths = attack_paths.len(),
        risk_score,
        duration_secs = duration,
        "scan complete"
    );

    Ok(ScanResults {
        findings: all_findings,
        devices: Vec::new(), // Devices are passed in separately by cmd_scan
        attack_paths,
        risk_score,
        scan_duration_secs: duration,
    })
}
