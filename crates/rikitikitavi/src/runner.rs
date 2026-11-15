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
use tracing::Instrument as _;

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
    // 128 hosts x 6 probe ports stays under a 1024 descriptor limit.
    let found =
        rikitikitavi_network::sweep::tcp_sweep_hosts(targets, Duration::from_millis(400), 128)
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
#[tracing::instrument(name = "discovery", skip_all, fields(devices, swept))]
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
    let span = tracing::Span::current();
    span.record("devices", ctx.discovered_devices.len());
    span.record("swept", added);
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
pub fn arp_ips_of_excluded_macs(exclusions: &ExclusionSet) -> HashSet<IpAddr> {
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
        "lan_client_exposure",
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
    let budget = Duration::from_secs(
        scanner
            .estimated_duration_secs()
            .saturating_mul(4)
            .clamp(60, 600),
    );
    run_scanner_within(scanner, ctx, budget).await
}

/// [`run_scanner_bounded`] with an explicit budget.
///
/// On overrun the scanner keeps whatever findings it streamed into `sink` before
/// the deadline (see [`Scanner::scan_collecting`]); a scanner that does not stream
/// yields nothing, as before, but the run continues either way. `sink` outlives the
/// scan future so a dropped (timed-out) future leaves its partial results behind.
async fn run_scanner_within(
    scanner: &dyn rikitikitavi_scanners::Scanner,
    ctx: &ScanContext,
    budget: Duration,
) -> Result<Vec<Finding>, rikitikitavi_core::ScanError> {
    let span = tracing::info_span!(
        "scanner",
        id = scanner.id(),
        budget_secs = budget.as_secs(),
        findings = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let mut collected: Vec<Finding> = Vec::new();
    let outcome = tokio::time::timeout(budget, scanner.scan_collecting(ctx, &mut collected))
        .instrument(span.clone())
        .await;
    span.record("findings", collected.len());
    span.record(
        "outcome",
        match &outcome {
            Ok(Ok(())) => "ok",
            Ok(Err(_)) if collected.is_empty() => "error",
            Ok(Err(_)) => "partial",
            Err(_) => "timeout",
        },
    );
    match outcome {
        Ok(Ok(())) => Ok(collected),
        Ok(Err(e)) => {
            if collected.is_empty() {
                Err(e)
            } else {
                tracing::warn!(
                    scanner = scanner.id(),
                    error = %e,
                    kept = collected.len(),
                    "scanner failed after streaming findings; keeping partial results"
                );
                Ok(collected)
            }
        }
        Err(_) => {
            tracing::warn!(
                scanner = scanner.id(),
                budget_secs = budget.as_secs(),
                kept = collected.len(),
                "scanner exceeded its time budget; keeping partial results"
            );
            Ok(collected)
        }
    }
}

/// One scanner run for `verify`.
#[derive(Debug)]
pub enum ReplayOutcome {
    Completed(Vec<Finding>),
    Failed(String),
    TimedOut,
}

/// Run `scanner` once under the [`run_scanner_bounded`] budget. Errors and timeouts are not
/// folded into partial results.
pub async fn replay_scanner(scanner: &dyn Scanner, ctx: &ScanContext) -> ReplayOutcome {
    let budget = Duration::from_secs(
        scanner
            .estimated_duration_secs()
            .saturating_mul(4)
            .clamp(60, 600),
    );
    replay_scanner_within(scanner, ctx, budget).await
}

async fn replay_scanner_within(
    scanner: &dyn Scanner,
    ctx: &ScanContext,
    budget: Duration,
) -> ReplayOutcome {
    let span = tracing::info_span!(
        "replay",
        id = scanner.id(),
        budget_secs = budget.as_secs(),
        outcome = tracing::field::Empty,
    );
    let mut collected = Vec::new();
    let outcome = tokio::time::timeout(budget, scanner.scan_collecting(ctx, &mut collected))
        .instrument(span.clone())
        .await;
    let replay = match outcome {
        Ok(Ok(())) => ReplayOutcome::Completed(collected),
        Ok(Err(e)) => ReplayOutcome::Failed(e.to_string()),
        Err(_) => ReplayOutcome::TimedOut,
    };
    span.record(
        "outcome",
        match replay {
            ReplayOutcome::Completed(_) => "ok",
            ReplayOutcome::Failed(_) => "error",
            ReplayOutcome::TimedOut => "timeout",
        },
    );
    replay
}

/// Root span for `verify`; the caller records `resolved`, `still_present`, `inconclusive`.
pub fn verify_span(findings: usize, hosts: usize) -> tracing::Span {
    tracing::info_span!(
        "verify",
        findings,
        hosts,
        resolved = tracing::field::Empty,
        still_present = tracing::field::Empty,
        inconclusive = tracing::field::Empty,
    )
}

/// Run all applicable scanners in two phases: `network`, `ports`, `device` run first
/// and populate `discovered_devices`; the remaining scanners then run concurrently.
/// Bounded by `scan.timeout_seconds` (0 = unbounded).
pub async fn run_scan(ctx: &mut ScanContext) -> Result<ScanResults> {
    let secs = ctx.config.timeout_seconds;
    let limit = (secs > 0).then(|| Duration::from_secs(secs));
    let span = tracing::info_span!(
        "scan",
        perspective = %ctx.perspective,
        intensity = ?ctx.config.intensity,
        devices = tracing::field::Empty,
        findings = tracing::field::Empty,
        risk_score = tracing::field::Empty,
    );
    let result = bounded(limit, run_scan_inner(ctx))
        .instrument(span.clone())
        .await;
    if let Ok(results) = &result {
        span.record("devices", results.devices.len());
        span.record("findings", results.findings.len());
        span.record("risk_score", results.risk_score);
    }
    result
}

#[allow(clippy::too_many_lines)]
async fn run_scan_inner(ctx: &mut ScanContext) -> Result<ScanResults> {
    let start = Instant::now();
    let registry = ScannerRegistry::new();
    // Recog pattern sets compile in ~1.7 s; overlap that with phase 1.
    let recog_warm = tokio::task::spawn_blocking(rikitikitavi_scanners::recog::warm_up);

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

    let _ = recog_warm.await;

    let rdns_task = spawn_rdns(ctx, &exclusions, &excluded_mac_ips);

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

    if let Some(task) = rdns_task
        && let Ok(outcome) = task.await
    {
        let ptr = rdns_findings(&outcome, &ctx.discovered_devices, &all_findings);
        all_findings.extend(ptr);
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
    rikitikitavi_scanners::hue::suppress_bridge_admin_no_auth(&mut all_findings);
    let correlated = rikitikitavi_scanners::http_audit::correlate_synology_rsync(
        &all_findings,
        &ctx.discovered_devices,
    );

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

    // Added after dedup so the Medium does not evict the rsync inventory finding.
    all_findings.extend(correlated);
    apply_product_remediation(&mut all_findings, &ctx.discovered_devices, ctx.gateway);
    #[cfg(feature = "unifi")]
    all_findings.extend(rikitikitavi_unifi::firmware::uncredentialed_advisory(
        &ctx.discovered_devices,
        ctx.gateway,
    ));

    // KEV before scoring.
    let kev_count = rikitikitavi_analysis::enrich_exploit_intelligence(&mut all_findings);
    if kev_count > 0 {
        tracing::info!(
            kev_count,
            "findings flagged as actively exploited (CISA KEV)"
        );
    }

    // OWASP IoT Top 10 (2018) taxonomy tags.
    rikitikitavi_analysis::enrich_standards(&mut all_findings);

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

    // Graded after dedup and the gateway fix-up, so each card sees the final class.
    let devices = std::mem::take(&mut ctx.discovered_devices);
    let report_cards = rikitikitavi_analysis::grade_devices(&devices, &all_findings);

    Ok(ScanResults {
        findings: all_findings,
        devices,
        report_cards,
        attack_paths,
        priority_actions,
        risk_score,
        scan_duration_secs: duration,
        scanned_at: Utc::now(),
        ..ScanResults::default()
    })
}

/// `(scanner, title prefix)` dropped when `(scanner, title prefix)` is on the same (ip, port).
const RESTATEMENTS: &[((&str, &str), (&str, &str))] = &[
    (
        ("http_audit", "Missing HSTS header"),
        ("ssl", "HTTPS without HSTS"),
    ),
    (
        ("http_audit", "Server version disclosure"),
        ("services", "HTTP server version disclosure"),
    ),
];

/// Drop restatements per `(affected_ip, affected_port)`; findings lacking either are kept.
///
/// The `ports` group goes when another scanner reports on the port at equal or
/// higher severity. [`RESTATEMENTS`] pairs lose their first member. Everything
/// else is kept, so distinct findings from different scanners coexist.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::BTreeMap;

    let mut by_port: BTreeMap<(IpAddr, u16), BTreeMap<String, Vec<Finding>>> = BTreeMap::new();
    let mut result: Vec<Finding> = Vec::new();

    for finding in findings {
        if let (Some(ip), Some(port)) = (finding.affected_ip, finding.affected_port) {
            by_port
                .entry((ip, port))
                .or_default()
                .entry(finding.scanner.clone())
                .or_default()
                .push(finding);
        } else {
            result.push(finding);
        }
    }

    for (_key, by_scanner) in by_port {
        let mut groups: Vec<(String, Vec<Finding>)> = by_scanner.into_iter().collect();
        apply_port_verdicts(&mut groups);

        let severity_of = |group: &[Finding]| group.iter().map(|f| f.severity).max();
        let deeper_max = groups
            .iter()
            .filter(|(scanner, _)| scanner != "ports")
            .filter_map(|(_, group)| severity_of(group))
            .max();
        let mut kept: Vec<Finding> = Vec::new();
        for (scanner, group) in groups {
            if scanner == "ports" && deeper_max.is_some_and(|d| Some(d) >= severity_of(&group)) {
                log_dropped(&group);
            } else {
                kept.extend(group);
            }
        }

        let restated: Vec<bool> = kept
            .iter()
            .map(|f| {
                RESTATEMENTS
                    .iter()
                    .any(|((scanner, title), (by, by_title))| {
                        f.scanner == *scanner
                            && f.title.starts_with(title)
                            && kept
                                .iter()
                                .any(|o| o.scanner == *by && o.title.starts_with(by_title))
                    })
            })
            .collect();
        for (finding, restated) in kept.into_iter().zip(restated) {
            if restated {
                log_dropped(std::slice::from_ref(&finding));
            } else {
                result.push(finding);
            }
        }
    }

    result.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.affected_ip.cmp(&b.affected_ip))
            .then_with(|| a.affected_port.cmp(&b.affected_port))
            .then_with(|| a.scanner.cmp(&b.scanner))
            .then_with(|| a.title.cmp(&b.title))
    });
    result
}

fn log_dropped(findings: &[Finding]) {
    for dropped in findings {
        tracing::debug!(
            scanner = %dropped.scanner,
            severity = ?dropped.severity,
            title = %dropped.title,
            "dropped by dedup"
        );
    }
}

/// Verdicts from deeper scanners on one (ip, port) that override the `ports` group:
/// a Confirmed MQTT auth-enforced result caps `ports` findings at Low and is folded into them;
/// an identified Denon/Marantz receiver's control-port finding drops the `ports` group.
fn apply_port_verdicts(groups: &mut Vec<(String, Vec<Finding>)>) {
    use rikitikitavi_core::{Confidence, Severity};
    use rikitikitavi_scanners::{credentials, mqtt};

    let deeper: Vec<&Finding> = groups
        .iter()
        .filter(|(scanner, _)| scanner != "ports")
        .flat_map(|(_, group)| group)
        .collect();
    let avr_control = deeper
        .iter()
        .any(|f| f.scanner == "credentials" && f.title.starts_with(credentials::AVR_CONTROL_TITLE));
    let mqtt_auth_evidence = deeper
        .iter()
        .find(|f| {
            f.scanner == "mqtt"
                && f.confidence == Confidence::Confirmed
                && f.title.starts_with(mqtt::AUTH_REQUIRED_TITLE)
        })
        .map(|f| f.evidence.clone());

    if avr_control {
        groups.retain(|(scanner, _)| scanner != "ports");
    } else if let Some(evidence) = mqtt_auth_evidence {
        for (_, group) in groups.iter_mut().filter(|(scanner, _)| scanner == "ports") {
            for f in group {
                f.severity = f.severity.min(Severity::Low);
                f.confidence = Confidence::Confirmed;
                f.description.push_str(
                    " The broker rejected an anonymous CONNECT, so authentication is \
                     enforced; credentials and messages still cross the network in cleartext.",
                );
                if f.evidence.is_none() {
                    f.evidence.clone_from(&evidence);
                }
            }
        }
        if groups.iter().any(|(scanner, _)| scanner == "ports") {
            for (_, group) in groups.iter_mut().filter(|(scanner, _)| scanner == "mqtt") {
                group.retain(|f| !f.title.starts_with(mqtt::AUTH_REQUIRED_TITLE));
            }
            groups.retain(|(_, group)| !group.is_empty());
        }
    }
}

/// Replace each finding's remediation with `remediation::resolve` against the
/// device at its IP. Per IP a device with a vendor is preferred; the gateway
/// resolves as a `Router`.
fn apply_product_remediation(
    findings: &mut [Finding],
    devices: &[Device],
    gateway: Option<IpAddr>,
) {
    use std::collections::HashMap;

    let mut by_ip: HashMap<IpAddr, Device> = HashMap::new();
    for device in devices {
        let keep = by_ip
            .get(&device.ip)
            .is_some_and(|d| d.vendor.is_some() || device.vendor.is_none());
        if !keep {
            by_ip.insert(device.ip, device.clone());
        }
    }
    if let Some(gw) = gateway.and_then(|ip| by_ip.get_mut(&ip)) {
        gw.device_type = DeviceType::Router;
    }
    for finding in findings {
        if let Some(device) = finding.affected_ip.and_then(|ip| by_ip.get(&ip)) {
            finding.remediation = rikitikitavi_scanners::remediation::resolve(finding, device);
        }
    }
}

/// Classify device type from open ports, with a free-text subtype naming the
/// signature that matched. Product-specific signatures are tested before generic
/// service ports.
fn classify_by_ports(open_ports: &[u16]) -> Option<(DeviceType, Option<&'static str>)> {
    let has = |port: u16| open_ports.contains(&port);

    if has(37777) || has(34567) {
        return Some((DeviceType::Nvr, Some("dahua_xmeye")));
    }
    if has(8123) {
        return Some((DeviceType::Hub, Some("home_assistant")));
    }
    if has(1400) {
        return Some((DeviceType::Speaker, Some("sonos")));
    }
    if has(7125) {
        return Some((DeviceType::Printer3d, Some("moonraker")));
    }
    if has(502) {
        // Modbus/TCP on a home LAN is solar, battery or EVSE gear.
        return Some((DeviceType::Inverter, Some("modbus_tcp")));
    }
    if has(32400) {
        return Some((DeviceType::MediaPlayer, Some("plex")));
    }
    if has(9100) || has(631) {
        return Some((DeviceType::Printer, None));
    }
    if has(554) || has(8554) {
        return Some((DeviceType::Camera, None));
    }
    if has(1883) || has(8883) {
        return Some((DeviceType::IoT, Some("mqtt_broker")));
    }
    if has(62078) {
        return Some((DeviceType::Phone, Some("ios_lockdownd")));
    }
    if has(55442) && has(55443) {
        return Some((DeviceType::Speaker, Some("amazon_echo")));
    }
    if has(5000) && has(5001) {
        return Some((DeviceType::Nas, None));
    }
    if has(8443) && has(8880) {
        return Some((DeviceType::Server, Some("unifi_controller")));
    }
    if has(3689) || has(5353) {
        return Some((DeviceType::MediaPlayer, None));
    }
    if has(3389) {
        return Some((DeviceType::Desktop, Some("windows_rdp")));
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
                        banner: finding.evidence.clone(),
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
            if let Some(subtype) = &hint.device_subtype
                && device.device_subtype.is_none()
            {
                device.device_subtype = Some(subtype.clone());
            }
        }
    }

    for device in &mut ctx.discovered_devices {
        if device.device_type == DeviceType::Unknown && !device.open_ports.is_empty() {
            let ports: Vec<u16> = device.open_ports.iter().map(|p| p.port).collect();
            if let Some((dt, subtype)) = classify_by_ports(&ports) {
                device.device_type = dt;
                if let Some(subtype) = subtype
                    && device.device_subtype.is_none()
                {
                    device.device_subtype = Some(subtype.to_owned());
                }
            }
        }
    }
}

/// Scanner id of reverse-DNS hint findings.
const RDNS_SCANNER: &str = "dns_ptr";

/// Nameservers and targets for the PTR pass: local nameservers from the gateway
/// and `resolv`, and IPv4 devices, both minus exclusions. `None` below Active
/// intensity or without a nameserver.
fn rdns_plan(
    ctx: &ScanContext,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
    resolv: &str,
) -> Option<(Vec<std::net::Ipv4Addr>, Vec<std::net::Ipv4Addr>)> {
    use rikitikitavi_models::config::ScanIntensity;
    use std::net::Ipv4Addr;

    if !ctx.config.intensity.at_least(ScanIntensity::Active) {
        return None;
    }
    let allowed = |ip: Ipv4Addr| {
        let ip = IpAddr::V4(ip);
        !exclusions.excludes_ip(ip) && !excluded_mac_ips.contains(&ip)
    };
    let gateway = match ctx.gateway {
        Some(IpAddr::V4(gw)) => Some(gw),
        _ => None,
    };
    let nameservers: Vec<Ipv4Addr> = rikitikitavi_network::rdns::local_nameservers(gateway, resolv)
        .into_iter()
        .filter(|ns| allowed(*ns))
        .collect();
    if nameservers.is_empty() {
        return None;
    }
    let targets: Vec<Ipv4Addr> = ctx
        .discovered_devices
        .iter()
        .filter_map(|d| match d.ip {
            IpAddr::V4(ip) if allowed(ip) => Some(ip),
            _ => None,
        })
        .collect();
    Some((nameservers, targets))
}

/// Start the PTR pass planned by [`rdns_plan`] under the `rdns` span.
fn spawn_rdns(
    ctx: &ScanContext,
    exclusions: &ExclusionSet,
    excluded_mac_ips: &HashSet<IpAddr>,
) -> Option<tokio::task::JoinHandle<rikitikitavi_network::rdns::RdnsOutcome>> {
    use rikitikitavi_network::rdns;

    let resolv = rdns::system_resolv_conf();
    let (nameservers, targets) = rdns_plan(ctx, exclusions, excluded_mac_ips, &resolv)?;
    let cfg = rdns::RdnsConfig {
        strip_suffixes: rdns::search_domains(&resolv),
        ..rdns::RdnsConfig::default()
    };
    let span = tracing::info_span!(
        "rdns",
        queried = tracing::field::Empty,
        resolved = tracing::field::Empty,
    );
    Some(tokio::spawn(
        async move {
            let outcome = rdns::reverse_lookup(&nameservers, &targets, &cfg).await;
            let span = tracing::Span::current();
            span.record("queried", outcome.queried);
            span.record("resolved", outcome.names.len());
            tracing::info!(
                via_rd0 = outcome.via_rd0,
                via_rd1 = outcome.via_rd1,
                "reverse DNS complete"
            );
            outcome
        }
        .instrument(span),
    ))
}

/// One `dns_ptr` hint finding per resolved device. The hostname is left off when
/// another hint already names the host; the type comes from the hostname table.
fn rdns_findings(
    outcome: &rikitikitavi_network::rdns::RdnsOutcome,
    devices: &[Device],
    findings: &[Finding],
) -> Vec<Finding> {
    use rikitikitavi_scanners::ha_discovery_db;
    use rikitikitavi_scanners::hostname_db::classify_hostname;

    let named: HashSet<IpAddr> = findings
        .iter()
        .filter(|f| f.device_hint.as_ref().is_some_and(|h| h.hostname.is_some()))
        .filter_map(|f| f.affected_ip)
        .collect();
    let mut out: Vec<Finding> = outcome
        .names
        .iter()
        .filter_map(|(ip, name)| {
            let ip = IpAddr::V4(*ip);
            let device = devices.iter().find(|d| d.ip == ip)?;
            let mut hint = DeviceHint::new();
            if device.hostname.is_none() && !named.contains(&ip) {
                hint = hint.with_hostname(name);
            }
            let mut description = format!("The local resolver's PTR record for {ip} is {name}.");
            if let Some(rule) = classify_hostname(name, device.vendor.as_deref()) {
                hint = hint
                    .with_device_type(rule.device_type)
                    .with_device_subtype(rule.subtype);
                let _ = std::fmt::Write::write_fmt(
                    &mut description,
                    format_args!(
                        " The name matches hostname pattern `{}` ({}).",
                        rule.pattern,
                        rule.device_type.label()
                    ),
                );
            } else {
                let mac = device.mac.as_ref().map(ToString::to_string);
                let typed = ha_discovery_db::dhcp_hostname_hits(name, mac.as_deref())
                    .into_iter()
                    .map(|hit| (hit.domain, ha_discovery_db::domain_device_type(hit.domain)))
                    .find(|(_, device_type)| *device_type != DeviceType::Unknown);
                if let Some((domain, device_type)) = typed {
                    hint = hint
                        .with_device_type(device_type)
                        .with_device_subtype(domain);
                    let _ = std::fmt::Write::write_fmt(
                        &mut description,
                        format_args!(
                            " The name matches the Home Assistant `{domain}` DHCP matcher ({}).",
                            device_type.label()
                        ),
                    );
                }
            }
            Some(
                Finding::new(
                    RDNS_SCANNER,
                    &format!("Reverse DNS name {name} for {ip}"),
                    &description,
                    rikitikitavi_core::Severity::Info,
                )
                .with_ip(ip)
                .with_confidence(rikitikitavi_core::Confidence::Probable)
                .with_device_hint(hint),
            )
        })
        .collect();
    out.sort_by_key(|f| f.affected_ip);
    out
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

/// Instance name used to ask HA's zeroconf table what a bare service-type match
/// yields. It must match no name glob in the table except `*`.
const BARE_MATCH_PROBE: &str = "rikitikitavi-probe";

/// mDNS service types behind the service labels the `mdns` scanner attaches to its
/// findings. The runner needs the type to ask which matcher tier produced a hint.
const MDNS_SERVICE_TYPES: &[(&str, &[&str])] = &[
    ("HTTP", &["_http._tcp.local"]),
    ("SSH", &["_ssh._tcp.local"]),
    ("SMB", &["_smb._tcp.local", "_afpovertcp._tcp.local"]),
    ("IPP", &["_ipp._tcp.local", "_printer._tcp.local"]),
    ("AirPlay", &["_airplay._tcp.local", "_raop._tcp.local"]),
    ("Google Cast", &["_googlecast._tcp.local"]),
    ("HomeKit", &["_hap._tcp.local"]),
    (
        "Matter",
        &[
            "_matter._tcp.local",
            "_matterc._udp.local",
            "_matterd._udp.local",
        ],
    ),
    ("Thread", &["_meshcop._udp.local", "_meshcop-e._udp.local"]),
];

/// True when a name glob or TXT predicate, rather than the service type alone,
/// produced this hint's integration domains.
fn mdns_hint_is_qualified(service: Option<&str>, hint: &DeviceHint) -> bool {
    use rikitikitavi_scanners::ha_discovery_db::zeroconf_domains;

    let (Some(service), Some(subtype)) = (service, hint.device_subtype.as_deref()) else {
        return false;
    };
    let Some((_, types)) = MDNS_SERVICE_TYPES.iter().find(|(l, _)| *l == service) else {
        return false;
    };

    let bare: Vec<&str> = types
        .iter()
        .flat_map(|st| zeroconf_domains(st, &format!("{BARE_MATCH_PROBE}.{st}."), &[]))
        .collect();
    subtype.split('/').any(|d| !bare.contains(&d))
}

/// Source rank of a hint: scanner tier, then matcher specificity within the tier.
fn hint_rank(finding: &Finding, hint: &DeviceHint) -> (u8, u8) {
    match finding.scanner.as_str() {
        "services" => (2, 0),
        "device" => (1, 0),
        RDNS_SCANNER => (1, 1),
        "mdns" => {
            // `mdns` hints carrying a vendor come from UPnP.
            if hint.vendor.is_some() {
                (4, 0)
            } else {
                let qualified = mdns_hint_is_qualified(finding.affected_service.as_deref(), hint);
                (3, u8::from(qualified))
            }
        }
        _ => (1, 2),
    }
}

/// Total order over hints so equal-ranked hints do not resolve by arrival order.
fn hint_order_key(rank: (u8, u8), hint: &DeviceHint) -> (u8, u8, &str, &str, &str, &str, &str) {
    (
        rank.0,
        rank.1,
        hint.device_type.map_or("", DeviceType::as_str),
        hint.device_subtype.as_deref().unwrap_or(""),
        hint.vendor.as_deref().unwrap_or(""),
        hint.hostname.as_deref().unwrap_or(""),
        hint.os_guess.as_deref().unwrap_or(""),
    )
}

/// Merge `DeviceHint`s from findings into devices; higher rank overwrites lower.
/// Tier: `device`/other = 1 (`device` < `dns_ptr` < other within it), `services` = 2,
/// `mdns` = 3, `mdns` with vendor (`UPnP`) = 4.
/// Within the `mdns` tier a name-glob or TXT-predicate match outranks a bare
/// service-type match; anything still equal is ordered by hint content, never by
/// the order the responses arrived in.
fn post_enrich_devices(devices: &mut [Device], findings: &[Finding]) {
    use std::collections::HashMap;

    let mut hints_by_ip: HashMap<IpAddr, Vec<((u8, u8), &DeviceHint)>> = HashMap::new();

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

        hints_by_ip
            .entry(ip)
            .or_default()
            .push((hint_rank(finding, hint), hint));
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
        sorted.sort_by(|(a_rank, a), (b_rank, b)| {
            hint_order_key(*a_rank, a).cmp(&hint_order_key(*b_rank, b))
        });

        let mut changed = false;
        let mut class_paired_with_subtype = false;
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
            // A subtype-only hint clears the class only when that class came in
            // on the same hint as the subtype it is replacing.
            if let Some(dt) = hint.device_type.filter(|dt| *dt != DeviceType::Unknown) {
                device.device_type = dt;
                class_paired_with_subtype = hint.device_subtype.is_some();
                if class_paired_with_subtype {
                    device.device_subtype.clone_from(&hint.device_subtype);
                }
                changed = true;
            } else if let Some(subtype) = &hint.device_subtype {
                if class_paired_with_subtype {
                    device.device_type = DeviceType::Unknown;
                    class_paired_with_subtype = false;
                }
                subtype.clone_into(device.device_subtype.get_or_insert_with(String::new));
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

/// Identity fields shared by devices behind one MAC.
#[derive(Default)]
struct MacSiblingInfo {
    device_type: DeviceType,
    device_subtype: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    os_guess: Option<String>,
}

/// Copy `device_type`, `device_subtype`, `vendor`, `hostname`, and `os_guess` between devices sharing a MAC
/// (same host seen at several IPs). Only fills fields that are unset/Unknown.
fn propagate_mac_siblings(devices: &mut [Device]) {
    use std::collections::HashMap;

    // Keyed by canonical `MacAddr` so textual MAC variants merge.
    let mut mac_info: HashMap<rikitikitavi_models::MacAddr, MacSiblingInfo> = HashMap::new();

    for device in devices.iter() {
        let Some(mac) = device.mac else {
            continue;
        };
        let entry = mac_info.entry(mac).or_default();
        if device.device_type != DeviceType::Unknown && entry.device_type == DeviceType::Unknown {
            entry.device_type = device.device_type;
        }
        if entry.device_subtype.is_none() {
            entry.device_subtype.clone_from(&device.device_subtype);
        }
        if entry.vendor.is_none() {
            entry.vendor.clone_from(&device.vendor);
        }
        if entry.hostname.is_none() {
            entry.hostname.clone_from(&device.hostname);
        }
        if entry.os_guess.is_none() {
            entry.os_guess.clone_from(&device.os_guess);
        }
    }

    for device in devices.iter_mut() {
        let Some(mac) = device.mac else {
            continue;
        };
        if let Some(info) = mac_info.get(&mac) {
            if device.device_type == DeviceType::Unknown && info.device_type != DeviceType::Unknown
            {
                device.device_type = info.device_type;
            }
            if device.device_subtype.is_none() {
                device.device_subtype.clone_from(&info.device_subtype);
            }
            if device.vendor.is_none() {
                device.vendor.clone_from(&info.vendor);
            }
            if device.hostname.is_none() {
                device.hostname.clone_from(&info.hostname);
            }
            if device.os_guess.is_none() {
                device.os_guess.clone_from(&info.os_guess);
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

    fn mqtt_ports_finding(ip_addr: IpAddr) -> Finding {
        Finding::new(
            "ports",
            &format!("MQTT (unencrypted) open on {ip_addr}:1883"),
            "MQTT without TLS (port 1883) transmits IoT messages in cleartext.",
            Severity::Medium,
        )
        .with_ip(ip_addr)
        .with_port(1883)
        .with_service("MQTT")
        .with_cwe("CWE-319")
    }

    fn mqtt_auth_finding(ip_addr: IpAddr, confidence: rikitikitavi_core::Confidence) -> Finding {
        Finding::new(
            "mqtt",
            &format!("MQTT broker requires authentication on {ip_addr}:1883"),
            "rejected",
            Severity::Info,
        )
        .with_confidence(confidence)
        .with_ip(ip_addr)
        .with_port(1883)
        .with_evidence("CONNACK return code 0x05 (not authorized)")
    }

    #[test]
    fn dedup_mqtt_auth_verdict_downgrades_ports_finding() {
        let addr = ip("192.168.2.133");
        let before = mqtt_ports_finding(addr);
        let fingerprint = before.fingerprint();
        let result = deduplicate_findings(vec![
            before,
            mqtt_auth_finding(addr, rikitikitavi_core::Confidence::Confirmed),
        ]);
        assert_eq!(result.len(), 1);
        let f = &result[0];
        assert_eq!(f.scanner, "ports");
        assert_eq!(f.fingerprint(), fingerprint);
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.confidence, rikitikitavi_core::Confidence::Confirmed);
        assert!(f.description.contains("authentication is enforced"));
        assert_eq!(
            f.evidence.as_deref(),
            Some("CONNACK return code 0x05 (not authorized)")
        );
    }

    #[test]
    fn dedup_unconfirmed_mqtt_verdict_leaves_ports_finding() {
        let addr = ip("192.168.2.133");
        let result = deduplicate_findings(vec![
            mqtt_ports_finding(addr),
            mqtt_auth_finding(addr, rikitikitavi_core::Confidence::Probable),
        ]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].scanner, "ports");
        assert_eq!(result[0].severity, Severity::Medium);
    }

    #[test]
    fn dedup_avr_control_finding_replaces_ports_telnet() {
        let addr = ip("192.168.1.34");
        let telnet = basic_finding("ports", Severity::High, addr, 23)
            .with_cwe("CWE-319")
            .with_evidence("banner");
        let avr = Finding::new(
            "credentials",
            &format!(
                "{} on {addr}:23",
                rikitikitavi_scanners::credentials::AVR_CONTROL_TITLE
            ),
            "control protocol",
            Severity::Medium,
        )
        .with_ip(addr)
        .with_port(23);
        let result = deduplicate_findings(vec![telnet, avr]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scanner, "credentials");
        assert_eq!(result[0].severity, Severity::Medium);
    }

    #[test]
    fn product_remediation_resolves_against_device_identity() {
        let dyson_ip = ip("192.168.2.133");
        let other_ip = ip("192.168.2.50");
        let base =
            rikitikitavi_scanners::remediation::get("rikitikitavi.ports.mqtt-unencrypted", &[]);
        let mut findings = vec![
            mqtt_ports_finding(dyson_ip).with_opt_remediation(base.clone()),
            mqtt_ports_finding(other_ip).with_opt_remediation(base.clone()),
        ];
        let mut devices = vec![
            Device::new(dyson_ip),
            Device::new(dyson_ip),
            Device::new(other_ip),
        ];
        devices[1].vendor = Some("Dyson".to_owned());
        apply_product_remediation(&mut findings, &devices, None);
        let dyson = findings[0].remediation.as_ref().unwrap();
        assert!(dyson.description.contains("Dyson"));
        assert!(dyson.steps.iter().any(|s| s.contains("192.168.2.133")));
        assert_eq!(findings[1].remediation, base);
    }

    #[test]
    fn product_remediation_treats_gateway_as_router() {
        let gw = ip("192.168.1.1");
        let mut findings = vec![basic_finding("ports", Severity::Low, gw, 22)];
        findings[0].title = format!("SSH open on {gw}:22");
        let mut device = Device::new(gw);
        device.vendor = Some("Ubiquiti".to_owned());
        apply_product_remediation(&mut findings, &[device.clone()], None);
        assert!(findings[0].remediation.is_none());
        apply_product_remediation(&mut findings, &[device], Some(gw));
        let rem = findings[0].remediation.as_ref().unwrap();
        assert!(
            rem.steps
                .iter()
                .any(|s| s.contains("Control Plane > Console > SSH"))
        );
    }

    #[test]
    fn dedup_keeps_distinct_findings_from_different_scanners() {
        let addr = ip("10.0.0.1");
        let mut cert = basic_finding("ssl", Severity::Medium, addr, 443);
        cert.title = "Excessive certificate validity on 10.0.0.1:443".to_owned();
        let mut header = basic_finding("http_audit", Severity::Low, addr, 443);
        header.title = "Missing X-Frame-Options on 10.0.0.1:443".to_owned();
        let open = basic_finding("ports", Severity::Info, addr, 443);
        let result = deduplicate_findings(vec![open, header, cert]);
        let scanners: Vec<&str> = result.iter().map(|f| f.scanner.as_str()).collect();
        assert_eq!(scanners, ["ssl", "http_audit"]);
    }

    #[test]
    fn dedup_keeps_ports_finding_that_outranks_deeper_scanners() {
        let addr = ip("10.0.0.1");
        let telnet = basic_finding("ports", Severity::High, addr, 23);
        let advert = basic_finding("mdns", Severity::Info, addr, 23);
        let result = deduplicate_findings(vec![advert, telnet]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].scanner, "ports");
    }

    #[test]
    fn dedup_drops_listed_restatements_only() {
        let addr = ip("10.0.0.1");
        let mut hsts = basic_finding("ssl", Severity::Low, addr, 443);
        hsts.title = "HTTPS without HSTS on 10.0.0.1:443".to_owned();
        let mut restated = basic_finding("http_audit", Severity::Info, addr, 443);
        restated.title = "Missing HSTS header on 10.0.0.1:443".to_owned();
        let result = deduplicate_findings(vec![restated.clone(), hsts]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].scanner, "ssl");
        assert_eq!(deduplicate_findings(vec![restated]).len(), 1);
    }

    #[test]
    fn dedup_output_order_is_independent_of_input_order() {
        let addr = ip("10.0.0.1");
        let a = basic_finding("ssl", Severity::Low, addr, 443);
        let b = basic_finding("http_audit", Severity::Low, addr, 443);
        let c = basic_finding("services", Severity::Low, ip("10.0.0.2"), 22);
        let forward = deduplicate_findings(vec![a.clone(), b.clone(), c.clone()]);
        let reverse = deduplicate_findings(vec![c, b, a]);
        let key = |v: &[Finding]| -> Vec<(String, Option<IpAddr>)> {
            v.iter()
                .map(|f| (f.scanner.clone(), f.affected_ip))
                .collect()
        };
        assert_eq!(key(&forward), key(&reverse));
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
    fn dedup_info_group_never_evicts_a_vulnerability() {
        let info = basic_finding("nuclei-detect", Severity::Info, ip("10.0.0.1"), 21)
            .with_evidence("220 ProFTPD")
            .with_service("ftp");
        let high = basic_finding("services", Severity::High, ip("10.0.0.1"), 21)
            .with_cwe("CWE-319")
            .with_service("ftp");
        let result = deduplicate_findings(vec![info, high]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].scanner, "services");
        assert_eq!(result[0].severity, Severity::High);
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

    /// Type only; the subtype is asserted separately where it carries information.
    fn port_type(ports: &[u16]) -> Option<DeviceType> {
        classify_by_ports(ports).map(|(dt, _)| dt)
    }

    #[test]
    fn test_classify_by_ports_printer() {
        assert_eq!(port_type(&[80, 443, 9100, 631]), Some(DeviceType::Printer));
    }

    #[test]
    fn test_classify_by_ports_camera() {
        assert_eq!(port_type(&[80, 554]), Some(DeviceType::Camera));
    }

    #[test]
    fn test_classify_by_ports_iot() {
        assert_eq!(port_type(&[1883]), Some(DeviceType::IoT));
    }

    #[test]
    fn test_classify_by_ports_nas() {
        assert_eq!(port_type(&[5000, 5001, 443]), Some(DeviceType::Nas));
    }

    #[test]
    fn test_classify_by_ports_phone() {
        assert_eq!(port_type(&[62078]), Some(DeviceType::Phone));
    }

    #[test]
    fn test_classify_by_ports_desktop() {
        assert_eq!(port_type(&[3389]), Some(DeviceType::Desktop));
    }

    #[test]
    fn classify_by_ports_echo() {
        assert_eq!(
            classify_by_ports(&[4070, 55442, 55443]),
            Some((DeviceType::Speaker, Some("amazon_echo")))
        );
        assert_eq!(classify_by_ports(&[55442]), None);
    }

    /// A port outside the default range never changes the verdict, alone or
    /// paired with a default port.
    #[test]
    fn classify_by_ports_uses_only_default_range_ports() {
        let common = rikitikitavi_scanners::ports::common_ports();
        for port in (1..=u16::MAX).filter(|p| !common.contains(p)) {
            assert_eq!(classify_by_ports(&[port]), None, "port {port}");
            for &known in &common {
                assert_eq!(
                    classify_by_ports(&[port, known]),
                    classify_by_ports(&[known]),
                    "ports {port}+{known}"
                );
            }
        }
    }

    #[test]
    fn test_classify_by_ports_none() {
        assert_eq!(classify_by_ports(&[80, 443]), None);
    }

    #[test]
    fn classify_by_ports_widened_classes() {
        assert_eq!(
            classify_by_ports(&[80, 37777]),
            Some((DeviceType::Nvr, Some("dahua_xmeye")))
        );
        assert_eq!(
            classify_by_ports(&[8123]),
            Some((DeviceType::Hub, Some("home_assistant")))
        );
        assert_eq!(
            classify_by_ports(&[1400, 5353]),
            Some((DeviceType::Speaker, Some("sonos")))
        );
        assert_eq!(
            classify_by_ports(&[7125]),
            Some((DeviceType::Printer3d, Some("moonraker")))
        );
        assert_eq!(
            classify_by_ports(&[502]),
            Some((DeviceType::Inverter, Some("modbus_tcp")))
        );
        assert_eq!(
            classify_by_ports(&[32400]),
            Some((DeviceType::MediaPlayer, Some("plex")))
        );
    }

    /// A camera port on an NVR must not downgrade it to `Camera`.
    #[test]
    fn classify_by_ports_prefers_specific_signature() {
        assert_eq!(port_type(&[554, 80, 37777]), Some(DeviceType::Nvr));
        assert_eq!(port_type(&[5353, 1400]), Some(DeviceType::Speaker));
    }

    #[test]
    fn propagate_mac_siblings_copies_subtype() {
        let mut devices = vec![
            Device::new(ip("10.0.0.1"))
                .with_mac("aa:bb:cc:dd:ee:ff")
                .with_device_type(DeviceType::Hub)
                .with_device_subtype("home_assistant"),
            Device::new(ip("10.0.0.2")).with_mac("AA-BB-CC-DD-EE-FF"),
        ];
        propagate_mac_siblings(&mut devices);
        assert_eq!(devices[1].device_type, DeviceType::Hub);
        assert_eq!(devices[1].device_subtype.as_deref(), Some("home_assistant"));
    }

    #[test]
    fn post_enrich_devices_applies_subtype_hint() {
        let mut devices = vec![Device::new(ip("10.0.0.5"))];
        let findings = vec![
            Finding::new("mdns", "hint", "desc", Severity::Info)
                .with_ip(ip("10.0.0.5"))
                .with_device_hint(
                    DeviceHint::new()
                        .with_device_type(DeviceType::Speaker)
                        .with_device_subtype("sonos"),
                ),
        ];
        post_enrich_devices(&mut devices, &findings);
        assert_eq!(devices[0].device_type, DeviceType::Speaker);
        assert_eq!(devices[0].device_subtype.as_deref(), Some("sonos"));
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

    fn rdns_outcome(entries: &[(&str, &str)]) -> rikitikitavi_network::rdns::RdnsOutcome {
        rikitikitavi_network::rdns::RdnsOutcome {
            names: entries
                .iter()
                .map(|(a, n)| (a.parse().unwrap(), (*n).to_owned()))
                .collect(),
            queried: entries.len(),
            via_rd0: entries.len(),
            via_rd1: 0,
        }
    }

    fn oui_finding(addr: &str, vendor: &str, dt: DeviceType) -> Finding {
        Finding::new("device", "oui", "desc", Severity::Info)
            .with_ip(ip(addr))
            .with_device_hint(DeviceHint::new().with_vendor(vendor).with_device_type(dt))
    }

    #[test]
    fn rdns_hint_types_unifi_ap_over_oui_switch() {
        let mut ap = Device::new(ip("192.168.1.20"));
        ap.vendor = Some("Ubiquiti".to_owned());
        let mut devices = vec![ap];
        let mut findings = vec![oui_finding("192.168.1.20", "Ubiquiti", DeviceType::Switch)];
        let ptr = rdns_findings(
            &rdns_outcome(&[("192.168.1.20", "U7Pro")]),
            &devices,
            &findings,
        );
        assert_eq!(ptr.len(), 1);
        assert_eq!(ptr[0].confidence, rikitikitavi_core::Confidence::Probable);
        findings.extend(ptr);
        post_enrich_devices(&mut devices, &findings);
        assert_eq!(devices[0].device_type, DeviceType::AccessPoint);
        assert_eq!(devices[0].device_subtype.as_deref(), Some("unifi_ap"));
        assert_eq!(devices[0].hostname.as_deref(), Some("U7Pro"));
    }

    #[test]
    fn rdns_hint_ranks_below_mdns_and_protocol_scanners() {
        let mut devices = vec![
            Device::new(ip("192.168.1.30")),
            Device::new(ip("192.168.1.31")),
        ];
        let mut findings = vec![
            Finding::new("mdns", "AirPlay", "desc", Severity::Info)
                .with_ip(ip("192.168.1.30"))
                .with_device_hint(
                    DeviceHint::new()
                        .with_hostname("denon.local")
                        .with_device_type(DeviceType::MediaPlayer),
                ),
            Finding::new("kasa", "kasa", "desc", Severity::Info)
                .with_ip(ip("192.168.1.31"))
                .with_device_hint(DeviceHint::new().with_device_type(DeviceType::IoT)),
        ];
        let ptr = rdns_findings(
            &rdns_outcome(&[("192.168.1.30", "MyQ-6C7"), ("192.168.1.31", "MyQ-0C9")]),
            &devices,
            &findings,
        );
        assert!(ptr[0].device_hint.as_ref().unwrap().hostname.is_none());
        findings.extend(ptr);
        post_enrich_devices(&mut devices, &findings);
        assert_eq!(devices[0].hostname.as_deref(), Some("denon"));
        assert_eq!(devices[0].device_type, DeviceType::MediaPlayer);
        assert_eq!(devices[1].device_type, DeviceType::IoT);
        assert_eq!(devices[1].hostname.as_deref(), Some("MyQ-0C9"));
    }

    #[test]
    fn rdns_plan_respects_intensity_and_exclusions() {
        let mut ctx = ctx_with(None, Perspective::Unauthenticated);
        ctx.gateway = Some(ip("192.168.1.1"));
        ctx.discovered_devices = vec![
            Device::new(ip("192.168.1.20")),
            Device::new(ip("192.168.1.21")),
            Device::new(ip("192.168.9.9")),
        ];
        let resolv = "nameserver 192.168.1.53\nnameserver 8.8.8.8\n";
        let exclusions = ExclusionSet::parse(
            &["192.168.9.0/24".to_owned(), "192.168.1.53".to_owned()],
            &[],
        )
        .unwrap();
        let by_mac = HashSet::from([ip("192.168.1.21")]);
        let (ns, targets) = rdns_plan(&ctx, &exclusions, &by_mac, resolv).unwrap();
        assert_eq!(ns, vec![std::net::Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(targets, vec![std::net::Ipv4Addr::new(192, 168, 1, 20)]);

        let gw_excluded = HashSet::from([ip("192.168.1.1")]);
        assert!(rdns_plan(&ctx, &ExclusionSet::default(), &gw_excluded, "").is_none());

        ctx.config.intensity = rikitikitavi_models::config::ScanIntensity::Passive;
        assert!(rdns_plan(&ctx, &ExclusionSet::default(), &HashSet::new(), resolv).is_none());
    }

    /// mDNS hints for a host advertising both `_http._tcp` (shelly, name glob) and
    /// `_googlecast._tcp` (cast, bare service type).
    fn shelly_and_cast_findings() -> [Finding; 2] {
        [
            Finding::new("mdns", "HTTP service advertised", "desc", Severity::Info)
                .with_ip(ip("192.168.1.40"))
                .with_service("HTTP")
                .with_device_hint(
                    DeviceHint::new()
                        .with_device_type(DeviceType::SmartPlug)
                        .with_device_subtype("shelly"),
                ),
            Finding::new("mdns", "Chromecast/Google Cast", "desc", Severity::Info)
                .with_ip(ip("192.168.1.40"))
                .with_service("Google Cast")
                .with_device_hint(
                    DeviceHint::new()
                        .with_device_type(DeviceType::MediaPlayer)
                        .with_device_subtype("cast"),
                ),
        ]
    }

    #[test]
    fn mdns_service_types_are_all_queried() {
        for (label, types) in MDNS_SERVICE_TYPES {
            for st in *types {
                assert!(
                    rikitikitavi_network::mdns::SERVICE_QUERIES.contains(st),
                    "{label}: {st} is not in SERVICE_QUERIES"
                );
            }
        }
    }

    #[test]
    fn test_mdns_qualified_matcher_is_recognised() {
        let [shelly, cast] = shelly_and_cast_findings();
        assert!(mdns_hint_is_qualified(
            shelly.affected_service.as_deref(),
            shelly.device_hint.as_ref().unwrap()
        ));
        assert!(!mdns_hint_is_qualified(
            cast.affected_service.as_deref(),
            cast.device_hint.as_ref().unwrap()
        ));
        // An unmapped service label cannot be checked, so it is never promoted.
        assert!(!mdns_hint_is_qualified(
            Some("SNMP"),
            shelly.device_hint.as_ref().unwrap()
        ));
    }

    #[test]
    fn test_post_enrich_prefers_qualified_mdns_matcher_either_order() {
        for reversed in [false, true] {
            let mut devices = vec![Device::new(ip("192.168.1.40"))];
            let mut findings = shelly_and_cast_findings().to_vec();
            if reversed {
                findings.reverse();
            }
            post_enrich_devices(&mut devices, &findings);
            assert_eq!(
                devices[0].device_type,
                DeviceType::SmartPlug,
                "reversed = {reversed}"
            );
            assert_eq!(devices[0].device_subtype.as_deref(), Some("shelly"));
        }
    }

    #[test]
    fn post_enrich_subtype_only_hint_does_not_keep_a_weaker_class() {
        let bare = Finding::new("mdns", "HomeKit accessory", "desc", Severity::Info)
            .with_ip(ip("192.168.1.42"))
            .with_service("HomeKit")
            .with_device_hint(
                DeviceHint::new()
                    .with_device_type(DeviceType::Hub)
                    .with_device_subtype("homekit_controller"),
            );
        let qualified = Finding::new("mdns", "HTTP service advertised", "desc", Severity::Info)
            .with_ip(ip("192.168.1.42"))
            .with_service("HTTP")
            .with_device_hint(DeviceHint::new().with_device_subtype("loqed"));
        assert!(mdns_hint_is_qualified(
            qualified.affected_service.as_deref(),
            qualified.device_hint.as_ref().unwrap()
        ));

        let mut devices = vec![Device::new(ip("192.168.1.42"))];
        post_enrich_devices(&mut devices, &[bare, qualified]);
        assert_eq!(devices[0].device_subtype.as_deref(), Some("loqed"));
        assert_eq!(
            devices[0].device_type,
            DeviceType::Unknown,
            "class borrowed from the weaker hint"
        );
    }

    #[test]
    fn post_enrich_subtype_only_hint_keeps_a_class_only_hints_type() {
        let cases = [
            ("services", DeviceType::IoT, "homewizard"),
            ("device", DeviceType::AccessPoint, "matter"),
        ];
        for (scanner, class, subtype) in cases {
            let classed = Finding::new(scanner, "Service", "desc", Severity::Info)
                .with_ip(ip("192.168.1.44"))
                .with_device_hint(DeviceHint::new().with_device_type(class));
            let subtyped = Finding::new("mdns", "mDNS service", "desc", Severity::Info)
                .with_ip(ip("192.168.1.44"))
                .with_service("Matter")
                .with_device_hint(DeviceHint::new().with_device_subtype(subtype));

            let mut devices = vec![Device::new(ip("192.168.1.44"))];
            post_enrich_devices(&mut devices, &[classed, subtyped]);
            assert_eq!(devices[0].device_type, class, "{scanner} class dropped");
            assert_eq!(devices[0].device_subtype.as_deref(), Some(subtype));
        }
    }

    #[test]
    fn post_enrich_class_only_hint_keeps_an_existing_subtype() {
        let mdns = Finding::new("mdns", "Hue bridge", "desc", Severity::Info)
            .with_ip(ip("192.168.1.43"))
            .with_service("mDNS")
            .with_device_hint(
                DeviceHint::new()
                    .with_device_type(DeviceType::IoT)
                    .with_device_subtype("hue"),
            );
        let upnp = Finding::new("mdns", "UPnP root device", "desc", Severity::Info)
            .with_ip(ip("192.168.1.43"))
            .with_service("UPnP")
            .with_device_hint(
                DeviceHint::new()
                    .with_vendor("Signify")
                    .with_device_type(DeviceType::IoT),
            );

        let mut devices = vec![Device::new(ip("192.168.1.43"))];
        post_enrich_devices(&mut devices, &[mdns, upnp]);
        assert_eq!(devices[0].device_type, DeviceType::IoT);
        assert_eq!(devices[0].device_subtype.as_deref(), Some("hue"));
        assert_eq!(devices[0].vendor.as_deref(), Some("Signify"));
    }

    #[test]
    fn test_post_enrich_same_rank_hints_are_order_independent() {
        let hints = [
            DeviceHint::new()
                .with_device_type(DeviceType::Speaker)
                .with_device_subtype("sonos"),
            DeviceHint::new()
                .with_device_type(DeviceType::SmartTv)
                .with_device_subtype("samsungtv"),
        ];
        let findings: Vec<Finding> = hints
            .iter()
            .map(|h| {
                Finding::new("mdns", "mDNS service", "desc", Severity::Info)
                    .with_ip(ip("192.168.1.41"))
                    .with_service("mDNS")
                    .with_device_hint(h.clone())
            })
            .collect();

        let mut forward = vec![Device::new(ip("192.168.1.41"))];
        post_enrich_devices(&mut forward, &findings);
        let mut backward = vec![Device::new(ip("192.168.1.41"))];
        let reversed: Vec<Finding> = findings.into_iter().rev().collect();
        post_enrich_devices(&mut backward, &reversed);

        assert_eq!(forward[0].device_type, backward[0].device_type);
        assert_eq!(forward[0].device_subtype, backward[0].device_subtype);
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

        #[test]
        fn prop_dedup_keeps_max_severity_per_key(
            findings in proptest::collection::vec(arb_finding_for_dedup(), 0..50)
        ) {
            let worst_per_key = |fs: &[Finding]| {
                let mut m: std::collections::HashMap<(IpAddr, u16), Severity> =
                    std::collections::HashMap::new();
                for f in fs {
                    if let (Some(ip), Some(port)) = (f.affected_ip, f.affected_port) {
                        let e = m.entry((ip, port)).or_insert(f.severity);
                        *e = (*e).max(f.severity);
                    }
                }
                m
            };
            let before = worst_per_key(&findings);
            let deduped = deduplicate_findings(findings);
            assert_eq!(before, worst_per_key(&deduped));
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

    /// Streams two findings, then blocks past the deadline before a third.
    struct PartialThenHang;

    #[async_trait::async_trait]
    impl Scanner for PartialThenHang {
        fn id(&self) -> &'static str {
            "partial-hang"
        }
        fn name(&self) -> &'static str {
            "partial then hang"
        }
        fn supported_perspectives(&self) -> &[Perspective] {
            &[Perspective::Unauthenticated]
        }
        async fn scan(
            &self,
            _ctx: &ScanContext,
        ) -> Result<Vec<Finding>, rikitikitavi_core::ScanError> {
            Ok(Vec::new())
        }
        async fn scan_collecting(
            &self,
            _ctx: &ScanContext,
            sink: &mut Vec<Finding>,
        ) -> Result<(), rikitikitavi_core::ScanError> {
            sink.push(Finding::new(
                "partial-hang",
                "before deadline",
                "d",
                Severity::Low,
            ));
            sink.push(Finding::new(
                "partial-hang",
                "also before",
                "d",
                Severity::Info,
            ));
            tokio::time::sleep(Duration::from_secs(3600)).await;
            sink.push(Finding::new(
                "partial-hang",
                "after deadline",
                "d",
                Severity::High,
            ));
            Ok(())
        }
    }

    /// Uses the default `scan_collecting`: nothing is observable until `scan` ends.
    struct DefaultSlow;

    #[async_trait::async_trait]
    impl Scanner for DefaultSlow {
        fn id(&self) -> &'static str {
            "default-slow"
        }
        fn name(&self) -> &'static str {
            "default slow"
        }
        fn supported_perspectives(&self) -> &[Perspective] {
            &[Perspective::Unauthenticated]
        }
        async fn scan(
            &self,
            _ctx: &ScanContext,
        ) -> Result<Vec<Finding>, rikitikitavi_core::ScanError> {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(vec![Finding::new(
                "default-slow",
                "done",
                "d",
                Severity::Info,
            )])
        }
    }

    struct FastOk;

    #[async_trait::async_trait]
    impl Scanner for FastOk {
        fn id(&self) -> &'static str {
            "fast-ok"
        }
        fn name(&self) -> &'static str {
            "fast ok"
        }
        fn supported_perspectives(&self) -> &[Perspective] {
            &[Perspective::Unauthenticated]
        }
        async fn scan(
            &self,
            _ctx: &ScanContext,
        ) -> Result<Vec<Finding>, rikitikitavi_core::ScanError> {
            Ok(vec![Finding::new("fast-ok", "quick", "d", Severity::Info)])
        }
    }

    // Real short budgets; the mock scanners sleep far longer, so the timeout
    // always fires first without needing tokio's `test-util` paused clock.
    #[tokio::test]
    async fn run_scanner_within_keeps_streamed_findings_on_timeout() {
        let ctx = ctx_with(None, Perspective::Unauthenticated);
        let found = run_scanner_within(&PartialThenHang, &ctx, Duration::from_millis(50))
            .await
            .expect("a timeout yields the partial results, not an error");
        assert_eq!(found.len(), 2, "kept what streamed before the deadline");
        assert!(found.iter().all(|f| f.title != "after deadline"));
    }

    #[tokio::test]
    async fn run_scanner_within_non_streaming_timeout_yields_nothing_but_continues() {
        let ctx = ctx_with(None, Perspective::Unauthenticated);
        let found = run_scanner_within(&DefaultSlow, &ctx, Duration::from_millis(50))
            .await
            .expect("a non-streaming timeout is Ok(empty), so the run continues");
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn run_scanner_within_returns_findings_within_budget() {
        let ctx = ctx_with(None, Perspective::Unauthenticated);
        let found = run_scanner_within(&FastOk, &ctx, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
    }
}
