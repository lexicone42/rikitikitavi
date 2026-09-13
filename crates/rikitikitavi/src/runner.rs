use anyhow::Result;
use chrono::Utc;
use futures::future::join_all;
use rikitikitavi_analysis::{
    calculate_risk_score, generate_attack_paths, generate_priority_actions,
};
use rikitikitavi_core::Perspective;
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::device::{OpenPort, PortProtocol};
use rikitikitavi_models::{
    Device, DeviceHint, DeviceType, Finding, MacAddr, ScanContext, ScanResults,
};
use rikitikitavi_scanners::{Scanner, ScannerRegistry};
use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Scanners that run first and populate `discovered_devices`.
pub const PHASE1_IDS: [&str; 3] = ["network", "ports", "device"];

/// Phase-2 scanners that read the raw ARP cache when `discovered_devices` is empty.
const ARP_FALLBACK_IDS: [&str; 6] = [
    "credentials",
    "services",
    "smb",
    "snmp",
    "database",
    "mgmt-plane",
];

/// Detect gateway and target network into `ctx`; return devices from the ARP cache.
pub fn discover_network(ctx: &mut ScanContext) -> Vec<Device> {
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

    let arp_entries = rikitikitavi_network::read_arp_cache().unwrap_or_default();
    let mut devices: Vec<Device> = arp_entries
        .iter()
        .map(|entry| {
            let mut dev = Device::new(entry.ip).with_mac(&entry.mac);
            if ctx.gateway == Some(entry.ip) {
                dev = dev.with_device_type(DeviceType::Router);
            }
            dev
        })
        .collect();

    if let Some(gw) = ctx.gateway
        && !devices.iter().any(|d| d.ip == gw)
    {
        devices.push(Device::new(gw).with_device_type(DeviceType::Router));
    }

    tracing::info!(
        gateway = ?ctx.gateway,
        network = ?ctx.target_network,
        device_count = devices.len(),
        "network discovery complete"
    );

    devices
}

/// `targets` minus excluded IPs/CIDRs and `excluded_mac_ips`.
fn filter_sweep_targets(
    targets: Vec<IpAddr>,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
) -> Vec<IpAddr> {
    targets
        .into_iter()
        .filter(|ip| !exclusions.excludes_ip(*ip) && !excluded_mac_ips.contains(ip))
        .collect()
}

/// TCP-connect sweep of the target network, excluded hosts never probed; merges new
/// hosts into `ctx.discovered_devices`. Skipped at Passive intensity or without a
/// target network. Returns the number of hosts added.
pub async fn active_host_discovery(
    ctx: &mut ScanContext,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
) -> usize {
    use rikitikitavi_models::config::ScanIntensity;

    if !ctx.config.intensity.at_least(ScanIntensity::Active) {
        return 0;
    }
    let Some(network) = ctx.target_network else {
        return 0;
    };

    let targets = filter_sweep_targets(
        rikitikitavi_network::sweep::sweep_targets(&network),
        exclusions,
        excluded_mac_ips,
    );
    let found =
        rikitikitavi_network::sweep::tcp_sweep_hosts(targets, Duration::from_millis(400), 256)
            .await;

    let mut added = 0;
    for ip in found {
        if !ctx.discovered_devices.iter().any(|d| d.ip == ip) {
            let mut dev = Device::new(ip);
            if ctx.gateway == Some(ip) {
                dev = dev.with_device_type(DeviceType::Router);
            }
            ctx.discovered_devices.push(dev);
            added += 1;
        }
    }

    tracing::info!(added, "active TCP host sweep complete");
    added
}

/// Remove devices matched by `scan.excluded_networks` / `scan.excluded_devices`.
/// Returns the number removed.
pub fn apply_exclusions(devices: &mut Vec<Device>, exclusions: &ExclusionSet) -> usize {
    if exclusions.is_empty() {
        return 0;
    }
    let before = devices.len();
    devices.retain(|d| !exclusions.excludes_device(d));
    let removed = before - devices.len();
    if removed > 0 {
        tracing::info!(removed, "excluded devices dropped from discovery");
    }
    removed
}

/// ARP-cache discovery followed by the active TCP sweep; fills `ctx.discovered_devices`
/// with exclusions applied. Returns the number of hosts added by the sweep.
pub async fn discover_hosts(ctx: &mut ScanContext) -> Result<usize> {
    let exclusions = ctx.config.exclusions()?;
    ctx.discovered_devices = discover_network(ctx);
    apply_exclusions(&mut ctx.discovered_devices, &exclusions);
    let excluded_mac_ips = arp_ips_of_excluded_macs(&exclusions);
    let added = active_host_discovery(ctx, &exclusions, &excluded_mac_ips).await;
    if added > 0 {
        // The sweep's SYNs populate the ARP cache; MAC-less sweep hosts pick their MACs up here.
        let arp = rikitikitavi_network::read_arp_cache().unwrap_or_default();
        let filled = fill_macs_from_arp(&mut ctx.discovered_devices, &arp);
        tracing::info!(filled, "MACs filled from ARP cache after sweep");
        apply_exclusions(&mut ctx.discovered_devices, &exclusions);
    }
    Ok(added)
}

/// Set `mac` on MAC-less devices whose IP has a parseable ARP entry. Returns the count filled.
pub fn fill_macs_from_arp(devices: &mut [Device], arp: &[rikitikitavi_network::ArpEntry]) -> usize {
    let mut filled = 0;
    for dev in devices.iter_mut().filter(|d| d.mac.is_none()) {
        let mac = arp
            .iter()
            .find(|e| e.ip == dev.ip)
            .and_then(|e| e.mac.parse::<MacAddr>().ok());
        if mac.is_some() {
            dev.mac = mac;
            filled += 1;
        }
    }
    filled
}

/// ARP-cache IPs whose MAC is excluded.
fn arp_ips_of_excluded_macs(exclusions: &ExclusionSet) -> HashSet<IpAddr> {
    if exclusions.is_empty() {
        return HashSet::new();
    }
    rikitikitavi_network::read_arp_cache()
        .unwrap_or_default()
        .iter()
        .filter(|e| {
            e.mac
                .parse::<MacAddr>()
                .is_ok_and(|m| exclusions.excludes_mac(m))
        })
        .map(|e| e.ip)
        .collect()
}

/// `true` when the finding's IP is excluded directly or via `excluded_mac_ips`; `arp` findings are exempt.
fn is_excluded_finding(
    finding: &Finding,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
) -> bool {
    finding.scanner != "arp"
        && finding
            .affected_ip
            .is_some_and(|ip| exclusions.excludes_ip(ip) || excluded_mac_ips.contains(&ip))
}

/// Scanners resolved for a run.
pub struct ModuleSelection<'a> {
    pub scanners: Vec<&'a dyn Scanner>,
    /// Requested ids that do not support the perspective.
    pub skipped: Vec<&'static str>,
    /// Phase-1 ids added because a phase-2 module was requested.
    pub added: Vec<&'static str>,
}

/// Resolve `--modules` ids: dedupe, reject unknown, drop ids unsupported by `perspective`,
/// and prepend missing phase-1 scanners when any phase-2 scanner is requested.
pub fn select_modules<'a>(
    registry: &'a ScannerRegistry,
    modules: &[String],
    perspective: Perspective,
) -> Result<ModuleSelection<'a>> {
    let valid = || {
        registry
            .all()
            .iter()
            .map(|s| s.id())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut ids: Vec<&str> = Vec::new();
    for id in modules.iter().map(|m| m.trim()).filter(|m| !m.is_empty()) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        anyhow::bail!("no scanner modules selected; valid modules: {}", valid());
    }
    let unknown: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| registry.get(id).is_none())
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "unknown scanner module(s): {}; valid modules: {}",
            unknown.join(", "),
            valid()
        );
    }

    let supports = |s: &dyn Scanner| s.supported_perspectives().contains(&perspective);
    let mut scanners: Vec<&dyn Scanner> = Vec::new();
    let mut skipped = Vec::new();
    for scanner in ids.iter().filter_map(|id| registry.get(id)) {
        if supports(scanner) {
            scanners.push(scanner);
        } else {
            skipped.push(scanner.id());
        }
    }
    if scanners.is_empty() {
        anyhow::bail!(
            "none of the selected modules support the {perspective} perspective: {}",
            skipped.join(", ")
        );
    }

    let mut added = Vec::new();
    let (phase1, phase2): (Vec<_>, Vec<_>) = scanners
        .into_iter()
        .partition(|s| PHASE1_IDS.contains(&s.id()));
    let scanners = if phase2.is_empty() {
        phase1
    } else {
        let mut ordered: Vec<&dyn Scanner> = Vec::new();
        for id in PHASE1_IDS {
            if let Some(s) = phase1.iter().find(|s| s.id() == id) {
                ordered.push(*s);
            } else if let Some(s) = registry.get(id)
                && supports(s)
            {
                added.push(id);
                ordered.push(s);
            }
        }
        ordered.extend(phase2);
        ordered
    };
    Ok(ModuleSelection {
        scanners,
        skipped,
        added,
    })
}

/// Scanners for this run: the `--modules` selection, else all for the perspective.
pub fn plan_scanners<'a>(
    registry: &'a ScannerRegistry,
    ctx: &ScanContext,
) -> Result<ModuleSelection<'a>> {
    ctx.config.modules.as_ref().map_or_else(
        || {
            Ok(ModuleSelection {
                scanners: registry.for_perspective(ctx.perspective),
                skipped: Vec::new(),
                added: Vec::new(),
            })
        },
        |modules| select_modules(registry, modules, ctx.perspective),
    )
}

/// Info-level record of skipped and auto-added ids; `cmd_scan` prints the user-facing notices.
fn log_selection(selection: &ModuleSelection<'_>, perspective: Perspective) {
    if !selection.skipped.is_empty() {
        tracing::info!(
            %perspective,
            skipped = selection.skipped.join(", "),
            "modules skipped: not supported by this perspective"
        );
    }
    if !selection.added.is_empty() {
        tracing::info!(
            added = selection.added.join(", "),
            "phase-1 modules added so the requested modules have devices and ports"
        );
    }
}

/// Phase-2 scanners to run. Dropped: none of `relevant_ports()` discovered; non-essential
/// at Passive; `ARP_FALLBACK_IDS` when exclusions left `discovered_devices` empty; `router`
/// when the gateway is excluded.
fn filter_phase2<'a>(
    phase2: Vec<&'a dyn Scanner>,
    ctx: &ScanContext,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
) -> Vec<&'a dyn Scanner> {
    let discovered_ports: HashSet<u16> = ctx
        .discovered_devices
        .iter()
        .flat_map(|d| d.open_ports.iter().map(|p| p.port))
        .collect();

    // Scanners that run at Passive intensity even without matching open ports.
    let passive_essential: &[&str] = &[
        "credentials",
        "router",
        "wifi",
        "dns",
        "arp",
        "dhcp",
        "exposure",
    ];

    let all_excluded = !exclusions.is_empty() && ctx.discovered_devices.is_empty();
    let gateway_excluded = ctx
        .gateway
        .is_some_and(|gw| exclusions.excludes_ip(gw) || excluded_mac_ips.contains(&gw));

    phase2
        .into_iter()
        .filter(|scanner| {
            let id = scanner.id();
            if all_excluded && ARP_FALLBACK_IDS.contains(&id) {
                tracing::warn!(scanner = id, "skipping: no non-excluded devices discovered");
                return false;
            }
            if gateway_excluded && id == "router" {
                tracing::warn!(scanner = id, "skipping — gateway is excluded");
                return false;
            }
            let ports = scanner.relevant_ports();
            if !ports.is_empty() && !ports.iter().any(|p| discovered_ports.contains(p)) {
                tracing::debug!(scanner = id, "skipping — no relevant ports discovered");
                return false;
            }
            if ctx.config.intensity == rikitikitavi_models::config::ScanIntensity::Passive
                && !passive_essential.contains(&id)
                && ports.is_empty()
            {
                tracing::debug!(scanner = id, "skipping — non-essential in quick scan");
                return false;
            }
            true
        })
        .collect()
}

/// Bound `fut` to `limit`; `None` = unbounded.
async fn bounded<T>(limit: Option<Duration>, fut: impl Future<Output = Result<T>>) -> Result<T> {
    let Some(limit) = limit else {
        return fut.await;
    };
    match tokio::time::timeout(limit, fut).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!(
            "scan exceeded scan.timeout_seconds ({}s); raise it or set 0 to disable",
            limit.as_secs()
        ),
    }
}

/// Run one scanner under a timeout of 4x its estimated duration, clamped to 60-600 s.
async fn run_scanner_bounded(
    scanner: &dyn rikitikitavi_scanners::Scanner,
    ctx: &ScanContext,
) -> Result<Vec<Finding>, rikitikitavi_core::ScanError> {
    let budget = std::time::Duration::from_secs(
        scanner
            .estimated_duration_secs()
            .saturating_mul(4)
            .clamp(60, 600),
    );
    tokio::time::timeout(budget, scanner.scan(ctx))
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                scanner = scanner.id(),
                budget_secs = budget.as_secs(),
                "scanner exceeded its time budget, skipping"
            );
            Err(rikitikitavi_core::ScanError::Timeout {
                target: scanner.id().to_owned(),
            })
        })
}

/// Run all applicable scanners in two phases: `network`, `ports`, `device` run first
/// and populate `discovered_devices`; the remaining scanners then run concurrently.
/// Bounded by `scan.timeout_seconds` (0 = unbounded).
pub async fn run_scan(ctx: &mut ScanContext) -> Result<ScanResults> {
    let secs = ctx.config.timeout_seconds;
    let limit = (secs > 0).then(|| Duration::from_secs(secs));
    bounded(limit, run_scan_inner(ctx)).await
}

#[allow(clippy::too_many_lines)]
async fn run_scan_inner(ctx: &mut ScanContext) -> Result<ScanResults> {
    let start = Instant::now();
    let registry = ScannerRegistry::new();

    let exclusions = ctx.config.exclusions()?;
    apply_exclusions(&mut ctx.discovered_devices, &exclusions);
    let excluded_mac_ips = arp_ips_of_excluded_macs(&exclusions);

    let selection = plan_scanners(&registry, ctx)?;
    log_selection(&selection, ctx.perspective);

    let (phase1, phase2): (Vec<_>, Vec<_>) = selection
        .scanners
        .into_iter()
        .partition(|s| PHASE1_IDS.contains(&s.id()));

    let phase2_count = phase2.len();
    tracing::info!(
        perspective = %ctx.perspective,
        phase1_count = phase1.len(),
        phase2_count,
        "starting two-phase scan"
    );

    let mut all_findings = Vec::new();

    // Phase 1: discovery
    tracing::info!("Phase 1: Discovery");
    for scanner in &phase1 {
        tracing::info!(
            scanner = scanner.id(),
            name = scanner.name(),
            "running Phase 1 scanner"
        );

        match run_scanner_bounded(*scanner, ctx).await {
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

    enrich_devices_from_findings(ctx, &all_findings);
    tracing::info!(
        discovered_devices = ctx.discovered_devices.len(),
        "enriched context with discovered devices"
    );

    // Phase 2: deep analysis, concurrent
    let phase2_filtered = filter_phase2(phase2, ctx, &exclusions, &excluded_mac_ips);

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
        (scanner.id(), run_scanner_bounded(*scanner, ctx).await)
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

    if !exclusions.is_empty() {
        let before = all_findings.len();
        all_findings.retain(|f| !is_excluded_finding(f, &exclusions, &excluded_mac_ips));
        tracing::info!(
            removed = before - all_findings.len(),
            "dropped findings on excluded hosts"
        );
    }

    post_enrich_devices(&mut ctx.discovered_devices, &all_findings);

    let pre_dedup = all_findings.len();
    let mut all_findings = deduplicate_findings(all_findings);
    if all_findings.len() < pre_dedup {
        tracing::info!(
            before = pre_dedup,
            after = all_findings.len(),
            removed = pre_dedup - all_findings.len(),
            "deduplicated findings"
        );
    }

    // KEV before scoring.
    let kev_count = rikitikitavi_analysis::enrich_exploit_intelligence(&mut all_findings);
    if kev_count > 0 {
        tracing::info!(
            kev_count,
            "findings flagged as actively exploited (CISA KEV)"
        );
    }

    // EPSS lookup is best-effort; on failure findings keep `epss = None`.
    let all_cves: Vec<String> = all_findings
        .iter()
        .flat_map(|f| f.cve_ids.iter().cloned())
        .collect();
    if !all_cves.is_empty() {
        let scores = rikitikitavi_network::fetch_epss_scores(&all_cves).await;
        for finding in &mut all_findings {
            // A finding's EPSS is the highest score among its CVEs.
            if let Some(best) = finding
                .cve_ids
                .iter()
                .filter_map(|c| scores.get(c))
                .copied()
                .reduce(f64::max)
            {
                finding.epss = Some(best);
            }
        }
    }

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

    propagate_mac_siblings(&mut ctx.discovered_devices);

    dedup_devices(&mut ctx.discovered_devices);

    // Gateway is forced back to Router; OUI hints may have reclassified it.
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

/// Deduplicate findings keyed by `(affected_ip, affected_port)`.
///
/// Findings lacking IP or port are kept as-is. Per key, all findings from the scanner
/// with the highest `detail_score` are kept; non-`ports` scanners get +1 to that score.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashMap;

    // Group by (ip, port, scanner).
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

    // Per (ip, port), keep only the best scanner's group.
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
            result.extend(scanner_groups.into_iter().flat_map(|(_, f)| f));
        } else {
            let mut best_scanner = String::new();
            let mut best_score = 0_u32;
            for (scanner, group) in &scanner_groups {
                let max_score = group.iter().map(detail_score).max().unwrap_or(0);
                let is_ports = scanner == "ports";
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

    result.sort_by_key(|f| std::cmp::Reverse(f.severity));
    result
}

/// Score a finding by how much useful detail it contains.
const fn detail_score(f: &Finding) -> u32 {
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

/// Add open ports (from `ports` findings) and vendor/type hints (from `device` findings)
/// to `ctx.discovered_devices`, then classify still-Unknown devices by open ports.
fn enrich_devices_from_findings(ctx: &mut ScanContext, findings: &[Finding]) {
    use std::collections::HashMap;

    let mut device_map: HashMap<IpAddr, &mut Device> = ctx
        .discovered_devices
        .iter_mut()
        .map(|d| (d.ip, d))
        .collect();

    for finding in findings {
        if finding.scanner == "ports" {
            let Some(ip) = finding.affected_ip else {
                continue;
            };
            let Some(port) = finding.affected_port else {
                continue;
            };

            if let Some(device) = device_map.get_mut(&ip) {
                // skip duplicate port entries
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

        if finding.scanner == "device"
            && let (Some(ip), Some(hint)) = (finding.affected_ip, &finding.device_hint)
            && let Some(device) = device_map.get_mut(&ip)
        {
            if let Some(vendor) = &hint.vendor
                && device.vendor.is_none()
            {
                vendor.clone_into(device.vendor.get_or_insert_with(String::new));
            }
            if let Some(dt) = hint.device_type
                && device.device_type == DeviceType::Unknown
                && dt != DeviceType::Unknown
            {
                device.device_type = dt;
            }
        }
    }

    for device in &mut ctx.discovered_devices {
        if device.device_type == DeviceType::Unknown && !device.open_ports.is_empty() {
            let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
            if let Some(dt) = classify_by_ports(&ports) {
                device.device_type = dt;
            }
        }
    }
}

/// Strip a `.local` suffix; return `None` for empty or UUID-style hostnames.
fn clean_hostname(raw: &str) -> Option<String> {
    let cleaned = raw.strip_suffix(".local").unwrap_or(raw).trim();
    if cleaned.is_empty() {
        return None;
    }
    let hex_count = cleaned.chars().filter(char::is_ascii_hexdigit).count();
    let dash_count = cleaned.chars().filter(|c| *c == '-').count();
    let total = cleaned.len();
    // UUID heuristic: 4+ dashes and >80% hex digits or dashes.
    if dash_count >= 4 && (hex_count + dash_count) * 100 / total > 80 {
        return None;
    }
    Some(cleaned.to_owned())
}

/// Merge `DeviceHint`s from findings into devices; higher priority overwrites lower.
/// Priority: `device`/other = 1, `services` = 2, `mdns` = 3, `mdns` with vendor (`UPnP`) = 4.
fn post_enrich_devices(devices: &mut [Device], findings: &[Finding]) {
    use std::collections::HashMap;

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
                // `mdns` hints carrying a vendor come from UPnP.
                if hint.vendor.is_some() { 4 } else { 3 }
            }
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

        let mut sorted: Vec<_> = hints.clone();
        sorted.sort_by_key(|(prio, _)| *prio);

        let mut changed = false;
        for (_, hint) in &sorted {
            if let Some(vendor) = &hint.vendor {
                vendor.clone_into(device.vendor.get_or_insert_with(String::new));
                changed = true;
            }
            if let Some(hostname) = &hint.hostname
                && let Some(clean) = clean_hostname(hostname)
                && device.hostname.is_none()
            {
                device.hostname = Some(clean);
                changed = true;
            }
            if let Some(dt) = hint.device_type
                && dt != DeviceType::Unknown
            {
                device.device_type = dt;
                changed = true;
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

/// Deduplicate devices by IP. Per IP keep, in order of preference: known `device_type`,
/// more open ports, a hostname, first occurrence.
fn dedup_devices(devices: &mut Vec<Device>) {
    use std::collections::HashMap;

    let mut best: HashMap<IpAddr, usize> = HashMap::new();
    for (i, device) in devices.iter().enumerate() {
        best.entry(device.ip)
            .and_modify(|prev| {
                let prev_dev = &devices[*prev];
                let new_is_better =
                    // known type beats Unknown
                    (device.device_type != DeviceType::Unknown && prev_dev.device_type == DeviceType::Unknown)
                    // then more open ports
                    || (device.device_type == prev_dev.device_type
                        && device.open_ports.len() > prev_dev.open_ports.len())
                    // then having a hostname
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

/// Copy `device_type`, `vendor`, `hostname`, and `os_guess` between devices sharing a MAC
/// (same host seen at several IPs). Only fills fields that are unset/Unknown.
fn propagate_mac_siblings(devices: &mut [Device]) {
    use std::collections::HashMap;

    // Keyed by canonical `MacAddr` so textual MAC variants merge.
    let mut mac_info: HashMap<
        rikitikitavi_models::MacAddr,
        (DeviceType, Option<String>, Option<String>, Option<String>),
    > = HashMap::new();

    for device in devices.iter() {
        let Some(mac) = device.mac else {
            continue;
        };
        let entry = mac_info
            .entry(mac)
            .or_insert((DeviceType::Unknown, None, None, None));
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

    for device in devices.iter_mut() {
        let Some(mac) = device.mac else {
            continue;
        };
        if let Some((dt, vendor, hostname, os)) = mac_info.get(&mac) {
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

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn ids(selection: &ModuleSelection<'_>) -> Vec<&'static str> {
        selection.scanners.iter().map(|s| s.id()).collect()
    }

    #[test]
    fn select_modules_rejects_unknown_ids() {
        let registry = ScannerRegistry::new();
        let Err(err) = select_modules(
            &registry,
            &owned(&["ports", "nope"]),
            Perspective::Unauthenticated,
        ) else {
            panic!("unknown id must error");
        };
        let msg = err.to_string();
        assert!(msg.starts_with("unknown scanner module(s): nope;"), "{msg}");
        assert!(
            msg.contains("valid modules: network, ports, device,"),
            "{msg}"
        );
    }

    #[test]
    fn select_modules_rejects_empty_selection() {
        let registry = ScannerRegistry::new();
        assert!(select_modules(&registry, &[], Perspective::Unauthenticated).is_err());
        assert!(
            select_modules(&registry, &owned(&["", " "]), Perspective::Unauthenticated).is_err()
        );
    }

    #[test]
    fn select_modules_adds_phase1_for_phase2_request() {
        let registry = ScannerRegistry::new();
        let sel = select_modules(
            &registry,
            &owned(&["dns", " ports"]),
            Perspective::Unauthenticated,
        )
        .unwrap();
        assert_eq!(ids(&sel), ["network", "ports", "device", "dns"]);
        assert_eq!(sel.added, ["network", "device"]);
        assert!(sel.skipped.is_empty());
    }

    #[test]
    fn select_modules_phase1_only_keeps_requested_order() {
        let registry = ScannerRegistry::new();
        let sel = select_modules(
            &registry,
            &owned(&["device", "ports", "device"]),
            Perspective::Unauthenticated,
        )
        .unwrap();
        assert_eq!(ids(&sel), ["device", "ports"]);
        assert!(sel.added.is_empty());
    }

    #[test]
    fn select_modules_dedupes_repeated_ids() {
        let registry = ScannerRegistry::new();
        let sel = select_modules(
            &registry,
            &owned(&["dns", "dns", "ports", "dns"]),
            Perspective::Unauthenticated,
        )
        .unwrap();
        assert_eq!(ids(&sel), ["network", "ports", "device", "dns"]);
    }

    #[test]
    fn select_modules_skips_unsupported_perspective() {
        let registry = ScannerRegistry::new();
        let sel = select_modules(
            &registry,
            &owned(&["neighbor", "ports"]),
            Perspective::Unauthenticated,
        )
        .unwrap();
        assert_eq!(ids(&sel), ["ports"]);
        assert_eq!(sel.skipped, ["neighbor"]);

        let Err(err) = select_modules(
            &registry,
            &owned(&["neighbor"]),
            Perspective::Unauthenticated,
        ) else {
            panic!("all-skipped selection must error");
        };
        assert_eq!(
            err.to_string(),
            "none of the selected modules support the unauthenticated perspective: neighbor"
        );
    }

    #[test]
    fn select_modules_never_adds_phase1_unsupported_by_perspective() {
        let registry = ScannerRegistry::new();
        let sel = select_modules(&registry, &owned(&["neighbor"]), Perspective::Neighbor).unwrap();
        assert_eq!(ids(&sel), ["neighbor"]);
        assert!(sel.added.is_empty());
    }

    fn ctx_with(modules: Option<Vec<String>>, perspective: Perspective) -> ScanContext {
        ScanContext {
            target_network: None,
            gateway: None,
            perspective,
            network_mode: rikitikitavi_core::NetworkMode::Auto,
            config: rikitikitavi_models::config::ScanConfig {
                modules,
                ..Default::default()
            },
            discovered_devices: Vec::new(),
        }
    }

    #[test]
    fn plan_scanners_without_modules_uses_perspective_set() {
        let registry = ScannerRegistry::new();
        let ctx = ctx_with(None, Perspective::Authenticated);
        let sel = plan_scanners(&registry, &ctx).unwrap();
        assert_eq!(
            sel.scanners.len(),
            registry.for_perspective(Perspective::Authenticated).len()
        );
        assert!(sel.skipped.is_empty() && sel.added.is_empty());
    }

    #[test]
    fn plan_scanners_with_modules_selects() {
        let registry = ScannerRegistry::new();
        let ctx = ctx_with(Some(owned(&["ports"])), Perspective::Unauthenticated);
        assert_eq!(ids(&plan_scanners(&registry, &ctx).unwrap()), ["ports"]);
    }

    #[test]
    fn apply_exclusions_removes_by_ip_cidr_and_mac() {
        let exclusions = ExclusionSet::parse(
            &owned(&["10.0.9.0/24"]),
            &owned(&["10.0.0.5", "aa:bb:cc:dd:ee:ff"]),
        )
        .unwrap();
        let mut devices = vec![
            Device::new(ip("10.0.0.5")),
            Device::new(ip("10.0.0.6")).with_mac("AA:BB:CC:DD:EE:FF"),
            Device::new(ip("10.0.9.7")),
            Device::new(ip("10.0.0.8")).with_mac("00:11:22:33:44:55"),
        ];
        assert_eq!(apply_exclusions(&mut devices, &exclusions), 3);
        let left: Vec<IpAddr> = devices.iter().map(|d| d.ip).collect();
        assert_eq!(left, [ip("10.0.0.8")]);
        assert_eq!(apply_exclusions(&mut devices, &ExclusionSet::default()), 0);
    }

    #[test]
    fn excluded_findings_detected_by_ip_and_mac_ip() {
        let exclusions = ExclusionSet::parse(&owned(&["10.0.9.0/24"]), &[]).unwrap();
        let mac_ips: HashSet<IpAddr> = HashSet::from([ip("10.0.0.6")]);
        let by_cidr = basic_finding("ports", Severity::Low, ip("10.0.9.1"), 22);
        let by_mac = basic_finding("ports", Severity::Low, ip("10.0.0.6"), 22);
        let kept = basic_finding("ports", Severity::Low, ip("10.0.0.7"), 22);
        let no_ip = Finding::new("network", "t", "d", Severity::Info);
        let arp = Finding::new("arp", "t", "d", Severity::High).with_ip(ip("10.0.9.1"));
        assert!(is_excluded_finding(&by_cidr, &exclusions, &mac_ips));
        assert!(is_excluded_finding(&by_mac, &exclusions, &mac_ips));
        assert!(!is_excluded_finding(&kept, &exclusions, &mac_ips));
        assert!(!is_excluded_finding(&no_ip, &exclusions, &mac_ips));
        assert!(!is_excluded_finding(&arp, &exclusions, &mac_ips));
    }

    fn phase2_ids(
        ctx: &ScanContext,
        exclusions: &ExclusionSet,
        excluded_mac_ips: &HashSet<IpAddr>,
    ) -> Vec<&'static str> {
        let registry = ScannerRegistry::new();
        let phase2: Vec<&dyn Scanner> = registry
            .for_perspective(ctx.perspective)
            .into_iter()
            .filter(|s| !PHASE1_IDS.contains(&s.id()))
            .collect();
        filter_phase2(phase2, ctx, exclusions, excluded_mac_ips)
            .iter()
            .map(|s| s.id())
            .collect()
    }

    #[test]
    fn arp_fallback_ids_are_registered_scanner_ids() {
        let registry = ScannerRegistry::new();
        for id in ARP_FALLBACK_IDS {
            assert!(registry.get(id).is_some(), "{id} is not a scanner id");
        }
    }

    #[test]
    fn filter_sweep_targets_never_lists_excluded_hosts() {
        let exclusions =
            ExclusionSet::parse(&owned(&["10.0.0.4/31"]), &owned(&["10.0.0.2"])).unwrap();
        let mac_ips = HashSet::from([ip("10.0.0.6")]);

        let all = rikitikitavi_network::sweep::sweep_targets(&"10.0.0.0/29".parse().unwrap());
        let targets = filter_sweep_targets(all.clone(), &exclusions, &mac_ips);

        assert_eq!(all.len(), 6);
        assert_eq!(targets.len(), all.len() - 4);
        for excluded in ["10.0.0.2", "10.0.0.4", "10.0.0.5", "10.0.0.6"] {
            assert!(
                !targets.contains(&ip(excluded)),
                "{excluded} in {targets:?}"
            );
        }
        assert_eq!(
            filter_sweep_targets(all.clone(), &ExclusionSet::default(), &HashSet::new()),
            all
        );
    }

    #[test]
    fn filter_phase2_skips_arp_fallback_when_all_devices_excluded() {
        let mut ctx = ctx_with(None, Perspective::Unauthenticated);
        ctx.config.excluded_devices = owned(&["10.0.0.5"]);
        let exclusions = ctx.config.exclusions().unwrap();
        let none = HashSet::new();

        let ids = phase2_ids(&ctx, &exclusions, &none);
        for id in ARP_FALLBACK_IDS {
            assert!(!ids.contains(&id), "{id} in {ids:?}");
        }
        assert!(ids.contains(&"dns"), "{ids:?}");
        assert!(ids.contains(&"router"), "{ids:?}");

        let ids = phase2_ids(&ctx, &ExclusionSet::default(), &none);
        assert!(ids.contains(&"credentials"), "{ids:?}");
        assert!(ids.contains(&"snmp"), "{ids:?}");

        ctx.discovered_devices.push(Device::new(ip("10.0.0.8")));
        let ids = phase2_ids(&ctx, &exclusions, &none);
        assert!(ids.contains(&"credentials"), "{ids:?}");
    }

    #[test]
    fn filter_phase2_skips_router_when_gateway_excluded() {
        let mut ctx = ctx_with(None, Perspective::Unauthenticated);
        ctx.gateway = Some(ip("10.0.0.1"));
        ctx.discovered_devices.push(Device::new(ip("10.0.0.8")));
        let none = HashSet::new();

        let by_ip = ExclusionSet::parse(&[], &owned(&["10.0.0.1"])).unwrap();
        assert!(!phase2_ids(&ctx, &by_ip, &none).contains(&"router"));

        let by_mac = HashSet::from([ip("10.0.0.1")]);
        assert!(!phase2_ids(&ctx, &ExclusionSet::default(), &by_mac).contains(&"router"));

        assert!(phase2_ids(&ctx, &ExclusionSet::default(), &none).contains(&"router"));
    }

    #[tokio::test]
    async fn bounded_times_out_with_clear_error() {
        let slow = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok(())
        };
        let err = bounded(Some(Duration::from_millis(20)), slow)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "scan exceeded scan.timeout_seconds (0s); raise it or set 0 to disable"
        );
        assert!(bounded(None, async { Ok(7) }).await.is_ok_and(|v| v == 7));
        assert!(
            bounded(Some(Duration::from_secs(5)), async { Ok(7) })
                .await
                .is_ok_and(|v| v == 7)
        );
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
        assert_eq!(
            classify_by_ports(&[80, 443, 9100, 631]),
            Some(DeviceType::Printer)
        );
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
        let mut devices = vec![Device::new(ip("192.168.1.220")).with_mac("00:11:32:aa:bb:cc")];
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
        let mut devices = vec![Device::new(ip("192.168.1.10"))];

        let findings = vec![
            Finding::new("services", "SSH on 10", "desc", Severity::Low)
                .with_ip(ip("192.168.1.10"))
                .with_device_hint(DeviceHint::new().with_os_guess("Linux (Debian)")),
        ];

        post_enrich_devices(&mut devices, &findings);
        assert_eq!(devices[0].os_guess.as_deref(), Some("Linux (Debian)"));
    }

    #[test]
    fn test_post_enrich_priority_ordering() {
        let mut devices = vec![Device::new(ip("192.168.1.30"))];

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
        let mut devices = vec![Device::new(ip("192.168.1.1"))];

        let findings = vec![
            Finding::new("ports", "Open port", "desc", Severity::Info).with_ip(ip("192.168.1.1")),
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
    #[test]
    fn fill_macs_from_arp_only_fills_missing_parseable() {
        use rikitikitavi_network::ArpEntry;
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut devices = vec![
            Device::new(ip("10.0.0.1")),
            Device::new(ip("10.0.0.2")).with_mac("aa:aa:aa:aa:aa:aa"),
            Device::new(ip("10.0.0.3")),
            Device::new(ip("10.0.0.4")),
        ];
        let arp = vec![
            ArpEntry {
                ip: ip("10.0.0.1"),
                mac: "bb:bb:bb:bb:bb:bb".to_owned(),
                interface: "eth0".to_owned(),
            },
            ArpEntry {
                ip: ip("10.0.0.2"),
                mac: "cc:cc:cc:cc:cc:cc".to_owned(),
                interface: "eth0".to_owned(),
            },
            ArpEntry {
                ip: ip("10.0.0.3"),
                mac: "(incomplete)".to_owned(),
                interface: "eth0".to_owned(),
            },
        ];
        assert_eq!(fill_macs_from_arp(&mut devices, &arp), 1);
        assert_eq!(
            devices[0].mac.map(|m| m.to_string()).as_deref(),
            Some("bb:bb:bb:bb:bb:bb")
        );
        assert_eq!(
            devices[1].mac.map(|m| m.to_string()).as_deref(),
            Some("aa:aa:aa:aa:aa:aa")
        );
        assert!(devices[2].mac.is_none() && devices[3].mac.is_none());
    }
}
