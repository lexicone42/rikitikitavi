use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;
mod runner;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    // Load configuration
    let app_config = config::load_config(cli.config.as_deref())?;

    match cli.command {
        Command::Scan(args) => cmd_scan(args, &app_config).await,
        #[cfg(feature = "tui")]
        Command::Tui(args) => cmd_tui(args, &app_config).await,
        Command::Report(args) => {
            cmd_report(&args, &app_config);
            Ok(())
        }
        #[cfg(feature = "unifi")]
        Command::Unifi(args) => cmd_unifi(args, &app_config).await,
        Command::Aws(args) => cmd_aws(args, &app_config).await,
        Command::Modules(args) => {
            cmd_modules(args);
            Ok(())
        }
        Command::Init => {
            cmd_init();
            Ok(())
        }
        Command::Config(args) => cmd_config(&args, &app_config),
        #[cfg(feature = "monitor")]
        Command::Monitor(args) => cmd_monitor(args).await,
        Command::UpdateDb => cmd_update_db().await,
        Command::Version { verbose } => {
            cmd_version(verbose);
            Ok(())
        }
    }
}

/// List the `scan` flags that are accepted by the CLI but not yet wired into
/// the scan, so they can be reported instead of silently ignored.
fn unimplemented_scan_flags(args: &cli::ScanArgs) -> Vec<&'static str> {
    let mut ignored = Vec::new();
    if !matches!(args.network, cli::NetworkArg::Auto) {
        ignored.push("--network");
    }
    if args.ssid.is_some() {
        ignored.push("--ssid");
    }
    if args.password.is_some() {
        ignored.push("--password");
    }
    if args.interface.is_some() {
        ignored.push("--interface");
    }
    if args.upload {
        ignored.push("--upload");
    }
    if args.unifi_local {
        ignored.push("--unifi-local");
    }
    ignored
}

#[allow(clippy::too_many_lines)]
async fn cmd_scan(
    args: cli::ScanArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    use rikitikitavi_models::config::{PortRange, ScanIntensity, TOP_20_PORTS};

    // Honesty: several flags are accepted but not yet wired. Warn rather than
    // silently ignoring them, so a teammate never believes they targeted an
    // interface/SSID or uploaded results when nothing happened.
    if !args.quiet {
        let ignored = unimplemented_scan_flags(&args);
        if !ignored.is_empty() {
            eprintln!(
                "Warning: these flags are not yet implemented and will be ignored: {}",
                ignored.join(", ")
            );
        }
    }

    // Network discovery is implemented only for Linux and macOS; elsewhere the
    // ARP/route layer returns empty, which would otherwise look like a clean
    // network. Say so loudly rather than presenting an empty success.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if !args.quiet {
        eprintln!(
            "Warning: unsupported platform — network discovery requires Linux or macOS. \
             Results will be empty on this OS."
        );
    }

    let perspective: rikitikitavi_core::Perspective = args.perspective.into();

    // Map CLI flags to intensity (--quick and --aggressive are mutually exclusive)
    let intensity = if args.quick {
        ScanIntensity::Passive
    } else if args.aggressive {
        ScanIntensity::Aggressive
    } else {
        app_config.scan.intensity
    };

    // Override port range based on intensity
    let port_scan_range = match intensity {
        ScanIntensity::Passive => PortRange::Custom(TOP_20_PORTS.to_vec()),
        ScanIntensity::Aggressive => PortRange::Extended,
        ScanIntensity::Active => app_config.scan.port_scan_range.clone(),
    };

    let scan_config = rikitikitavi_models::config::ScanConfig {
        perspective,
        intensity,
        port_scan_range,
        modules: args.modules,
        attack_paths: args.attack_paths,
        ..app_config.scan.clone()
    };

    let mut ctx = rikitikitavi_models::ScanContext {
        target_network: None,
        gateway: None,
        perspective,
        network_mode: rikitikitavi_core::NetworkMode::Auto,
        config: scan_config,
        discovered_devices: Vec::new(),
    };

    // Perform network discovery to populate context
    if !args.quiet {
        // Active scanning without authorization can be illegal and disruptive.
        // Surface a one-line reminder at runtime (not just in SECURITY.md).
        eprintln!(
            "Note: only scan networks you own or are explicitly authorized to test. \
             Active/aggressive modes probe and (with --aggressive) attempt logins."
        );
        println!("{}", intensity.profile_name());
        println!("Discovering network...");
    }
    let devices = runner::discover_network(&mut ctx);
    ctx.discovered_devices = devices;

    // The ARP cache alone is often nearly empty (cold cache / fresh boot). Active
    // mode does a bounded TCP-connect sweep so a scan doesn't silently report ~0
    // devices. Passive mode stays read-only and skips this. A dry run is a preview
    // and must not touch the network, so it skips the sweep entirely.
    let swept = if args.dry_run {
        0
    } else {
        runner::active_host_discovery(&mut ctx).await
    };

    if !args.quiet {
        if let Some(gw) = ctx.gateway {
            println!("  Gateway:  {gw}");
        }
        if let Some(net) = &ctx.target_network {
            println!("  Network:  {net}");
        }
        println!(
            "  Devices:  {} ({swept} via active sweep)",
            ctx.discovered_devices.len()
        );
        println!();

        // Never present a near-empty result as a clean network — say why.
        if ctx.discovered_devices.len() <= 1 {
            eprintln!(
                "Warning: found {} host(s). If this looks too low, the ARP cache may be \
                 cold and the sweep found little — check you are on the right interface, \
                 run with --aggressive, or ensure the network allows TCP probing.",
                ctx.discovered_devices.len()
            );
        }
    }

    if args.dry_run {
        let registry = rikitikitavi_scanners::ScannerRegistry::new();
        let scanners = registry.for_perspective(perspective);
        println!("Would run {} scanners:", scanners.len());
        for s in &scanners {
            println!("  - {} ({})", s.name(), s.id());
        }
        return Ok(());
    }

    let results = runner::run_scan(&mut ctx).await?;

    // ── History: load previous before saving current ────────────────
    let history = rikitikitavi_analysis::ScanHistory::new();
    let previous = if args.compare_previous {
        history
            .as_ref()
            .and_then(|h| h.load_latest().ok().flatten())
    } else {
        None
    };

    // Auto-save unless --no-save
    if !args.no_save
        && let Some(ref h) = history
    {
        match h.save(&results) {
            Ok(path) => {
                if !args.quiet {
                    println!("Scan saved to {}", path.display());
                }
            }
            Err(e) => {
                tracing::warn!("failed to save scan history: {e}");
            }
        }
    }

    if let Some(output) = args.output {
        match args.format {
            cli::ReportFormatArg::Json => rikitikitavi_export::export_json(&results, &output)?,
            cli::ReportFormatArg::Html => rikitikitavi_export::export_html(&results, &output)?,
            cli::ReportFormatArg::Csv => rikitikitavi_export::export_csv(&results, &output)?,
            cli::ReportFormatArg::Ocsf => rikitikitavi_export::export_ocsf_json(&results, &output)?,
        }
        println!("Results written to {}", output.display());
    } else if !args.quiet {
        print_cli_report(&results);
    }

    // ── Print comparison if requested ───────────────────────────────
    if let Some(prev) = previous {
        let diff = rikitikitavi_analysis::diff_scan_results(&prev, &results);
        print_comparison_report(&diff);
    }

    // ── Severity-gated exit code for cron/CI self-audits ─────────────
    if let Some(threshold) = fail_on_threshold(args.fail_on) {
        let breach = results
            .findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .count();
        if breach > 0 {
            if !args.quiet {
                eprintln!("Failing: {breach} finding(s) at or above {threshold:?} (--fail-on).");
            }
            std::process::exit(2);
        }
    }

    Ok(())
}

/// Map the `--fail-on` argument to the minimum [`Severity`] that should trigger a
/// non-zero exit, or `None` when failing is disabled.
const fn fail_on_threshold(arg: cli::FailOnArg) -> Option<rikitikitavi_core::Severity> {
    use rikitikitavi_core::Severity;
    match arg {
        cli::FailOnArg::Never => None,
        cli::FailOnArg::Info => Some(Severity::Info),
        cli::FailOnArg::Low => Some(Severity::Low),
        cli::FailOnArg::Medium => Some(Severity::Medium),
        cli::FailOnArg::High => Some(Severity::High),
        cli::FailOnArg::Critical => Some(Severity::Critical),
    }
}

#[allow(clippy::too_many_lines)]
/// Compact identity label for a device in the grouped report, e.g. "HP (Printer)",
/// "myhost (Router)", "(Camera)", or "" when nothing is known.
fn device_identity_label(d: &rikitikitavi_models::Device) -> String {
    use rikitikitavi_models::DeviceType;
    let name = d.vendor.as_deref().or(d.hostname.as_deref());
    match (name, d.device_type) {
        (Some(n), DeviceType::Unknown) => format!("({n})"),
        (Some(n), k) => format!("{n} ({k:?})"),
        (None, DeviceType::Unknown) => String::new(),
        (None, k) => format!("({k:?})"),
    }
}

#[allow(clippy::too_many_lines)]
fn print_cli_report(results: &rikitikitavi_models::ScanResults) {
    use rikitikitavi_core::Severity;

    let total = results.findings.len();
    let critical = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let (grade, _) = rikitikitavi_analysis::risk_grade(critical, high, medium);

    // ── Header ──────────────────────────────────────────────────
    println!("Scan complete: {total} findings");
    println!("Risk score: {:.0}/100 ({grade})", results.risk_score);
    println!();

    // ── Severity breakdown ──────────────────────────────────────
    println!("  Severity breakdown:");
    if critical > 0 {
        println!("    CRITICAL  {critical}");
    }
    if high > 0 {
        println!("    HIGH      {high}");
    }
    if medium > 0 {
        println!("    MEDIUM    {medium}");
    }
    if low > 0 {
        println!("    LOW       {low}");
    }
    if info > 0 {
        println!("    INFO      {info}");
    }
    println!();

    // ── Actionable findings (Critical/High/Medium) with detail ─
    let actionable: Vec<_> = results
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        })
        .collect();

    // ── Devices needing attention (grouped by device) ───────────
    // A flat list of 200 findings is hard for a non-expert to act on; this
    // groups the actionable ones by device so the worst offenders stand out.
    // Network-wide findings without an IP (DNS, exposure) appear only in the
    // detailed list below.
    {
        use std::collections::BTreeMap;
        use std::fmt::Write as _;
        let mut by_device: BTreeMap<std::net::IpAddr, Vec<&rikitikitavi_models::Finding>> =
            BTreeMap::new();
        for f in &actionable {
            if let Some(ip) = f.affected_ip {
                by_device.entry(ip).or_default().push(f);
            }
        }
        if !by_device.is_empty() {
            let mut rows: Vec<_> = by_device.into_iter().collect();
            rows.sort_by_key(|(_, fs)| {
                let worst = fs
                    .iter()
                    .map(|f| f.severity)
                    .max()
                    .unwrap_or(Severity::Info);
                std::cmp::Reverse((worst, fs.len()))
            });
            println!("  Devices needing attention:");
            for (ip, fs) in &rows {
                let ident = results
                    .devices
                    .iter()
                    .find(|d| d.ip == *ip)
                    .map_or_else(String::new, device_identity_label);
                let mut badge = String::new();
                for (sev, name) in [
                    (Severity::Critical, "CRIT"),
                    (Severity::High, "HIGH"),
                    (Severity::Medium, "MED"),
                ] {
                    let n = fs.iter().filter(|f| f.severity == sev).count();
                    if n > 0 {
                        let _ = write!(badge, "{n} {name}  ");
                    }
                }
                let ip_str = ip.to_string();
                println!("    {ip_str:<15}  {ident:<26}  {}", badge.trim_end());
            }
            println!();
        }
    }

    if !actionable.is_empty() {
        println!("  Actionable findings:");
        println!();
        for f in &actionable {
            let exploited = if f.is_kev {
                "  ⚠ ACTIVELY EXPLOITED"
            } else {
                ""
            };
            let conf = match f.confidence {
                rikitikitavi_core::Confidence::Confirmed => "  ✓ confirmed",
                rikitikitavi_core::Confidence::Inferred => "  ~ inferred",
                rikitikitavi_core::Confidence::Probable => "",
            };
            // EPSS: probability of exploitation in the next 30 days (when known).
            let epss = f
                .epss
                .map_or_else(String::new, |e| format!("  EPSS {:.0}%", e * 100.0));
            println!("    [{:8}] {}{exploited}{conf}{epss}", f.severity, f.title);
            println!("              {}", f.description);
            if let Some(ref evidence) = f.evidence {
                println!("              Evidence: {evidence}");
            }
            if let Some(ref rem) = f.remediation
                && !rem.steps.is_empty()
            {
                let fix = rem.steps.join(" → ");
                let effort = rem
                    .effort
                    .as_ref()
                    .map_or(String::new(), |e| format!(" ({e})"));
                println!("              Fix: {fix}{effort}");
            }
            println!();
        }
    }

    // ── Informational (Low/Info) — compact list ─────────────────
    let informational: Vec<_> = results
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low | Severity::Info))
        .collect();

    if !informational.is_empty() {
        println!("  Informational ({}):", informational.len());
        for f in &informational {
            println!("    [{:8}] {}", f.severity, f.title);
        }
        println!();
    }

    // ── Priority actions ────────────────────────────────────────
    if !results.priority_actions.is_empty() {
        println!("  Top {} Priority Actions:", results.priority_actions.len());
        println!();
        for action in &results.priority_actions {
            let effort = action
                .effort
                .as_deref()
                .map_or(String::new(), |e| format!("  ({e})"));
            println!(
                "    #{} [{}] {}{}",
                action.rank, action.severity, action.title, effort,
            );
            println!(
                "       {} device(s), {} finding(s)",
                action.affected_device_count, action.finding_count,
            );
            for (i, step) in action.steps.iter().enumerate() {
                println!("       {}. {step}", i + 1);
            }
            println!();
        }
    }
}

fn print_comparison_report(diff: &rikitikitavi_analysis::ScanDiff) {
    if let Some(baseline) = diff.baseline_time {
        println!("Since last scan ({}):", baseline.format("%Y-%m-%d %H:%M"));
    } else {
        println!("Comparison with previous scan:");
    }

    if !diff.has_changes() {
        println!("  No changes detected.");
        println!();
        return;
    }

    println!(
        "  +{} new findings, -{} resolved, {} severity changes",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.severity_changes.len(),
    );
    println!(
        "  +{} new devices, -{} disappeared",
        diff.new_devices.len(),
        diff.disappeared_devices.len(),
    );
    println!();

    if !diff.new_findings.is_empty() {
        println!("  New:");
        for f in &diff.new_findings {
            println!("    [{:8}] {}", f.severity, f.title);
        }
        println!();
    }

    if !diff.resolved_findings.is_empty() {
        println!("  Resolved:");
        for f in &diff.resolved_findings {
            println!("    [{:8}] {}", f.severity, f.title);
        }
        println!();
    }

    if !diff.severity_changes.is_empty() {
        println!("  Changed:");
        for sc in &diff.severity_changes {
            println!(
                "    {} ({} -> {})",
                sc.finding.title, sc.old_severity, sc.new_severity,
            );
        }
        println!();
    }
}

#[cfg(feature = "tui")]
#[allow(clippy::too_many_lines)]
async fn cmd_tui(
    args: cli::TuiArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    use crossterm::{execute, terminal};
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;

    let theme = match args.theme {
        cli::ThemeArg::Dark => rikitikitavi_tui::app::Theme::Dark,
        cli::ThemeArg::Light => rikitikitavi_tui::app::Theme::Light,
        cli::ThemeArg::Hacker => rikitikitavi_tui::app::Theme::Hacker,
        cli::ThemeArg::Accessible => rikitikitavi_tui::app::Theme::Accessible,
    };

    let tui_config = rikitikitavi_tui::TuiConfig {
        theme,
        watch_mode: args.watch,
        watch_interval_secs: args.interval,
    };

    let mut app = rikitikitavi_tui::App::new(tui_config);

    // Load previous scan for comparison
    let history = rikitikitavi_analysis::ScanHistory::new();
    let previous_results = history
        .as_ref()
        .and_then(|h| h.load_latest().ok().flatten());

    // Perform initial scan before entering TUI
    let perspective = rikitikitavi_core::Perspective::Authenticated;
    let scan_config = rikitikitavi_models::config::ScanConfig {
        perspective,
        modules: None,
        attack_paths: true,
        ..app_config.scan.clone()
    };

    let mut ctx = rikitikitavi_models::ScanContext {
        target_network: None,
        gateway: None,
        perspective,
        network_mode: rikitikitavi_core::NetworkMode::Auto,
        config: scan_config.clone(),
        discovered_devices: Vec::new(),
    };

    app.scanning = true;
    "Initial network discovery...".clone_into(&mut app.scan_status);

    let devices = runner::discover_network(&mut ctx);
    ctx.discovered_devices = devices;
    "Running scanners...".clone_into(&mut app.scan_status);

    match runner::run_scan(&mut ctx).await {
        Ok(results) => {
            // Compute diff against previous scan
            if let Some(ref prev) = previous_results {
                let diff = rikitikitavi_analysis::diff_scan_results(prev, &results);
                app.set_scan_diff(diff);
            }
            // Save to history
            if let Some(ref h) = history
                && let Err(e) = h.save(&results)
            {
                tracing::warn!("failed to save scan history: {e}");
            }
            app.results = Some(results);
            app.status_message = Some("Initial scan complete".to_owned());
        }
        Err(e) => {
            app.status_message = Some(format!("Initial scan failed: {e}"));
        }
    }
    app.scanning = false;
    app.scan_progress = 1.0;

    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Channel for background re-scan results
    let (scan_tx, mut scan_rx) = tokio::sync::mpsc::channel::<rikitikitavi_models::ScanResults>(1);

    // Main loop
    loop {
        // Check for completed background scan
        if let Ok(results) = scan_rx.try_recv() {
            // Compute diff: compare new results against the previous scan
            if let Some(ref prev) = app.results {
                let diff = rikitikitavi_analysis::diff_scan_results(prev, &results);
                app.set_scan_diff(diff);
            }
            // Save to history
            if let Some(ref h) = history
                && let Err(e) = h.save(&results)
            {
                tracing::warn!("failed to save scan history: {e}");
            }
            app.results = Some(results);
            app.scanning = false;
            app.scan_progress = 1.0;
            app.scan_status = String::new();
            app.status_message = Some("Re-scan complete".to_owned());
        }

        app.tick = app.tick.wrapping_add(1);
        terminal.draw(|frame| rikitikitavi_tui::ui::draw(frame, &mut app))?;

        if let Some(event) =
            rikitikitavi_tui::events::poll_event(std::time::Duration::from_millis(100))?
        {
            let rescan_requested = if let Some(key) = rikitikitavi_tui::events::as_key_press(&event)
            {
                app.handle_key(key.code)
            } else if let Some(mouse) = rikitikitavi_tui::events::as_mouse_event(&event) {
                app.handle_mouse(*mouse)
            } else {
                false
            };
            if rescan_requested {
                // Spawn background re-scan
                let tx = scan_tx.clone();
                let rescan_config = scan_config.clone();
                tokio::spawn(async move {
                    let mut rescan_ctx = rikitikitavi_models::ScanContext {
                        target_network: None,
                        gateway: None,
                        perspective,
                        network_mode: rikitikitavi_core::NetworkMode::Auto,
                        config: rescan_config,
                        discovered_devices: Vec::new(),
                    };
                    let devices = runner::discover_network(&mut rescan_ctx);
                    rescan_ctx.discovered_devices = devices;
                    if let Ok(results) = runner::run_scan(&mut rescan_ctx).await {
                        let _ = tx.send(results).await;
                    }
                });
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn cmd_report(args: &cli::ReportArgs, _app_config: &rikitikitavi_models::config::AppConfig) {
    if args.latest {
        let Some(history) = rikitikitavi_analysis::ScanHistory::new() else {
            println!("Could not determine data directory.");
            return;
        };
        match history.load_latest() {
            Ok(Some(results)) => {
                println!(
                    "Last scan: {} ({} findings)",
                    results.scanned_at.format("%Y-%m-%d %H:%M:%S"),
                    results.findings.len(),
                );
                println!();
                print_cli_report(&results);
            }
            Ok(None) => {
                println!("No saved scans found.");
                println!("Run `rikitikitavi scan` first to generate scan history.");
            }
            Err(e) => {
                println!("Failed to load scan history: {e}");
            }
        }
    } else {
        println!("Report generation not yet implemented.");
        println!("Use `rikitikitavi report --latest` to view the most recent saved scan.");
        println!("Or run `rikitikitavi scan --output results.json` to export.");
    }
}

#[cfg(feature = "unifi")]
async fn cmd_unifi(
    args: cli::UniFiArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    match args.command {
        cli::UniFiCommand::Scan {
            local,
            controller,
            user,
            password,
            token,
            site,
            insecure,
            output,
        } => {
            // Opt into insecure TLS via either the CLI flag or the config file.
            let insecure = insecure
                || app_config
                    .unifi
                    .controller
                    .as_ref()
                    .is_some_and(|c| c.insecure);
            cmd_unifi_scan(
                local, controller, user, password, token, &site, insecure, output,
            )
            .await?;
        }
        cli::UniFiCommand::Devices => {
            println!("Device listing requires a controller connection.");
            println!("Use `rikitikitavi unifi scan --controller <url>` with credentials first.");
        }
        cli::UniFiCommand::FirmwareCheck => {
            println!("Firmware check requires a controller connection.");
            println!("Use `rikitikitavi unifi scan --controller <url>` with credentials.");
        }
        cli::UniFiCommand::AuditController => {
            println!("Controller audit requires a controller connection.");
            println!("Use `rikitikitavi unifi scan --controller <url>` with credentials.");
        }
        cli::UniFiCommand::Deploy {
            host, persistent, ..
        } => {
            println!("Deploying to {host} (persistent={persistent})...");
            println!("Deployment not yet implemented.");
        }
        cli::UniFiCommand::Tui { .. } => {
            println!("UniFi TUI not yet implemented.");
        }
        cli::UniFiCommand::Report { output, format } => {
            println!("Run `rikitikitavi unifi scan` first, then generate reports from the output.");
            if let Some(path) = output {
                println!("Would write {:?} report to {}", format, path.display());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "unifi")]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn cmd_unifi_scan(
    local: bool,
    controller: Option<String>,
    user: Option<String>,
    password: Option<String>,
    token: Option<String>,
    site: &str,
    insecure: bool,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    use rikitikitavi_unifi::UniFiClient;

    // Determine controller URL
    let url = if local {
        if let Some(env) = rikitikitavi_unifi::UniFiEnvironment::detect() {
            println!("Detected UniFi device: {:?}", env.device_type);
            if let Some(ver) = &env.unifi_os_version {
                println!("  UniFi OS: {ver}");
            }
            "https://localhost".to_owned()
        } else {
            anyhow::bail!("Not running on a UniFi device. Use --controller for remote mode.");
        }
    } else if let Some(ctrl) = controller {
        ctrl
    } else {
        anyhow::bail!("Specify --local (on-device) or --controller <url> for remote scanning.");
    };

    println!("Connecting to UniFi controller at {url}...");

    let mut client = UniFiClient::connect(&url, site, insecure)?;

    // Authenticate
    if let Some(tok) = token {
        client.login_token(&tok).await?;
        println!("Authenticated with API token.");
    } else if let (Some(u), Some(p)) = (user, password) {
        client.login(&u, &p).await?;
        println!("Authenticated with username/password.");
    } else {
        anyhow::bail!("Provide --token <api-token> or --user <username> --password <password>.");
    }

    println!("Running UniFi security audit...\n");

    let mut all_findings = Vec::new();

    // Audit WLANs
    match client.get_wlans().await {
        Ok(wlans) => {
            println!("WLANs: {} configured", wlans.len());
            for wlan in &wlans {
                let status = if wlan.enabled { "enabled" } else { "disabled" };
                println!("  {} ({}, {})", wlan.name, wlan.security, status);
            }
            for wlan in &wlans {
                all_findings.extend(rikitikitavi_unifi::scanner::audit_wlan(wlan));
            }
        }
        Err(e) => println!("  Failed to fetch WLANs: {e}"),
    }

    // Audit firewall rules
    match client.get_firewall_rules().await {
        Ok(rules) => {
            println!("\nFirewall rules: {} configured", rules.len());
            for rule in &rules {
                let name = rule.name.as_deref().unwrap_or("unnamed");
                let status = if rule.enabled { "on" } else { "off" };
                println!("  {} ({}, {})", name, rule.action, status);
            }
            all_findings.extend(rikitikitavi_unifi::scanner::audit_firewall_rules(&rules));
        }
        Err(e) => println!("  Failed to fetch firewall rules: {e}"),
    }

    // List devices and firmware
    match client.get_devices().await {
        Ok(devices) => {
            println!("\nAdopted devices: {}", devices.len());
            for dev in &devices {
                let name = dev.name.as_deref().unwrap_or(&dev.model);
                let ip = dev.ip.as_deref().unwrap_or("unknown");
                println!(
                    "  {} (model: {}, firmware: {}, ip: {})",
                    name, dev.model, dev.firmware_version, ip
                );
            }
        }
        Err(e) => println!("  Failed to fetch devices: {e}"),
    }

    // IDS/IPS events
    match client.get_ids_events(100).await {
        Ok(events) => {
            if events.is_empty() {
                println!("\nIDS/IPS: No events recorded (verify Threat Management is enabled)");
            } else {
                println!("\nIDS/IPS: {} events", events.len());
            }
        }
        Err(e) => println!("  Failed to fetch IDS events: {e}"),
    }

    // Summary
    println!("\n--- UniFi Security Audit ---");
    println!("Findings: {}", all_findings.len());
    for f in &all_findings {
        println!("  [{:8}] {}", f.severity, f.title);
    }

    // Export if requested
    if let Some(path) = output {
        let results = rikitikitavi_models::ScanResults {
            findings: all_findings,
            risk_score: 0.0,
            scanned_at: chrono::Utc::now(),
            ..Default::default()
        };
        rikitikitavi_export::export_json(&results, &path)?;
        println!("\nResults written to {}", path.display());
    }

    Ok(())
}

#[allow(clippy::unused_async)]
async fn cmd_aws(
    args: cli::AwsArgs,
    _app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    match args.command {
        cli::AwsCommand::RegisterSource => println!("Source registration not yet implemented."),
        cli::AwsCommand::Validate => println!("AWS validation not yet implemented."),
        cli::AwsCommand::GeneratePolicy => println!("IAM policy generation not yet implemented."),
        cli::AwsCommand::Upload { path } => {
            println!("Upload from {} not yet implemented.", path.display());
        }
    }
    Ok(())
}

fn cmd_modules(args: cli::ModulesArgs) {
    let registry = rikitikitavi_scanners::ScannerRegistry::new();

    match args.command {
        cli::ModulesCommand::List => {
            println!("Available scanner modules:");
            for scanner in registry.all() {
                println!(
                    "  {:14} {}  (est. {}s)",
                    scanner.id(),
                    scanner.name(),
                    scanner.estimated_duration_secs()
                );
            }
        }
        cli::ModulesCommand::Info { module } => {
            if let Some(scanner) = registry.get(&module) {
                println!("Module: {} ({})", scanner.name(), scanner.id());
                println!("Perspectives: {:?}", scanner.supported_perspectives());
                println!("Requires privileges: {}", scanner.requires_privileges());
                println!("Estimated duration: {}s", scanner.estimated_duration_secs());
            } else {
                println!("Unknown module: {module}");
                println!("Run `rikitikitavi modules list` to see available modules.");
            }
        }
    }
}

fn cmd_init() {
    println!("Interactive setup wizard not yet implemented.");
    println!("Create a config.yaml file manually — see config.example.yaml for reference.");
}

fn cmd_config(
    args: &cli::ConfigArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    match args.command {
        cli::ConfigCommand::Validate => {
            config::validate_config(app_config)?;
            println!("Configuration is valid.");
        }
        cli::ConfigCommand::Show => {
            // `config show` output is routinely pasted into tickets/chat, and the
            // help text promises redaction — scrub secrets before display.
            let yaml = serde_yaml_ng::to_string(&redacted_for_display(app_config))?;
            println!("{yaml}");
        }
    }
    Ok(())
}

/// Return a copy of the config with every secret replaced by a redaction marker,
/// for safe display via `config show`. `None` fields are left untouched so the
/// output still shows which credentials are unset.
fn redacted_for_display(
    cfg: &rikitikitavi_models::config::AppConfig,
) -> rikitikitavi_models::config::AppConfig {
    let mut shown = cfg.clone();
    if let Some(controller) = shown.unifi.controller.as_mut() {
        redact_secret(&mut controller.password);
        redact_secret(&mut controller.api_token);
    }
    if let Some(cloud) = shown.unifi.cloud.as_mut() {
        redact_secret(&mut cloud.api_key);
    }
    redact_secret(&mut shown.apis.shodan_api_key);
    redact_secret(&mut shown.apis.censys_api_id);
    redact_secret(&mut shown.apis.censys_api_secret);
    shown
}

/// Replace a present secret with a redaction marker, preserving `None`.
fn redact_secret(secret: &mut Option<String>) {
    if secret.is_some() {
        *secret = Some("***REDACTED***".to_owned());
    }
}

#[allow(clippy::unused_async)]
async fn cmd_update_db() -> Result<()> {
    println!("Database update not yet implemented.");
    Ok(())
}

#[cfg(feature = "monitor")]
#[allow(clippy::too_many_lines, clippy::unused_async)]
async fn cmd_monitor(args: cli::MonitorArgs) -> Result<()> {
    use std::collections::HashSet;
    use std::io::Write as _;

    use rikitikitavi_network::wifi_monitor;
    use rikitikitavi_scanners::passive_wifi;

    println!("Passive WiFi Monitor");
    println!("====================");
    println!();

    // ── Detect or use specified interface ────────────────────────
    let interface = if let Some(ref iface) = args.interface {
        iface.clone()
    } else {
        println!("Auto-detecting WiFi interface...");
        wifi_monitor::find_wifi_interface()?
    };
    println!("Interface: {interface}");

    // ── Check capability ────────────────────────────────────────
    match wifi_monitor::detect_capability() {
        wifi_monitor::MonitorCapability::Supported { ref phy, .. } => {
            println!("Monitor mode: supported (phy: {phy})");
        }
        wifi_monitor::MonitorCapability::NotSupported(reason) => {
            println!();
            println!("Monitor mode is not available: {reason}");
            println!();
            println!("Requirements:");
            println!("  - Linux: WiFi adapter with monitor mode support + iw installed");
            println!("  - macOS: Built-in WiFi adapter (will disconnect WiFi)");
            println!("  - Must be run as root (sudo)");
            return Ok(());
        }
    }

    // ── macOS warning ───────────────────────────────────────────
    if cfg!(target_os = "macos") && !args.yes {
        println!();
        println!("WARNING: On macOS, enabling monitor mode will disconnect your WiFi.");
        println!("Use --yes to skip this prompt.");
        println!();
        print!("Continue? [y/N] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // ── Set up monitor mode ─────────────────────────────────────
    println!();
    println!("Setting up monitor mode...");
    let session = wifi_monitor::setup_monitor(&interface)?;
    println!("Monitor interface: {}", session.monitor_interface);

    // ── Run capture ─────────────────────────────────────────────
    let duration = std::time::Duration::from_secs(args.duration);
    println!();
    println!(
        "Capturing management frames for {}s on {}...",
        args.duration, session.monitor_interface,
    );
    println!("(Press Ctrl+C to stop early)");
    println!();

    let results = passive_wifi::capture_frames(&session.monitor_interface, duration)?;

    println!(
        "Capture complete: {} frames in {}s",
        results.frame_count,
        results.capture_duration.as_secs(),
    );
    println!(
        "  APs: {}, Probes: {}, Deauths: {}, Disassocs: {}",
        results.beacons.len(),
        results.probe_requests.len(),
        results.deauth_events.len(),
        results.disassoc_events.len(),
    );
    println!();

    // ── Parse known BSSIDs ──────────────────────────────────────
    let known_bssids: HashSet<_> = args
        .known_bssids
        .iter()
        .filter_map(|s| rikitikitavi_network::wifi_frames::parse_mac(s))
        .collect();

    // ── Analyse ─────────────────────────────────────────────────
    let findings =
        passive_wifi::analyse_results(&results, &known_bssids, args.home_ssid.as_deref());

    // ── Print report ────────────────────────────────────────────
    if findings.is_empty() {
        println!("No findings.");
    } else {
        println!("{} finding(s):", findings.len());
        println!();
        for f in &findings {
            println!("  [{:8}] {}", f.severity, f.title);
            println!("             {}", f.description);
            if let Some(ref evidence) = f.evidence {
                println!("             Evidence: {evidence}");
            }
            println!();
        }
    }

    // ── Save to history if requested ────────────────────────────
    if args.save {
        let scan_results = rikitikitavi_models::ScanResults {
            findings,
            risk_score: 0.0,
            scanned_at: chrono::Utc::now(),
            ..Default::default()
        };

        if let Some(ref output) = args.output {
            match args.format {
                cli::ReportFormatArg::Json => {
                    rikitikitavi_export::export_json(&scan_results, output)?;
                }
                cli::ReportFormatArg::Html => {
                    rikitikitavi_export::export_html(&scan_results, output)?;
                }
                cli::ReportFormatArg::Csv => {
                    rikitikitavi_export::export_csv(&scan_results, output)?;
                }
                cli::ReportFormatArg::Ocsf => {
                    rikitikitavi_export::export_ocsf_json(&scan_results, output)?;
                }
            }
            println!("Results written to {}", output.display());
        }

        let history = rikitikitavi_analysis::ScanHistory::new();
        if let Some(h) = history {
            match h.save(&scan_results) {
                Ok(path) => println!("Saved to history: {}", path.display()),
                Err(e) => tracing::warn!("failed to save: {e}"),
            }
        }
    } else if let Some(ref output) = args.output {
        // Even without --save, write to output file if specified
        let scan_results = rikitikitavi_models::ScanResults {
            findings,
            risk_score: 0.0,
            scanned_at: chrono::Utc::now(),
            ..Default::default()
        };

        match args.format {
            cli::ReportFormatArg::Json => {
                rikitikitavi_export::export_json(&scan_results, output)?;
            }
            cli::ReportFormatArg::Html => {
                rikitikitavi_export::export_html(&scan_results, output)?;
            }
            cli::ReportFormatArg::Csv => {
                rikitikitavi_export::export_csv(&scan_results, output)?;
            }
            cli::ReportFormatArg::Ocsf => {
                rikitikitavi_export::export_ocsf_json(&scan_results, output)?;
            }
        }
        println!("Results written to {}", output.display());
    }

    // MonitorSession Drop will clean up the monitor interface
    drop(session);
    println!("Monitor mode cleaned up.");

    Ok(())
}

fn cmd_version(verbose: bool) {
    println!("rikitikitavi {}", env!("CARGO_PKG_VERSION"));
    if verbose {
        println!("rustc: {}", rustc_version());
        println!("target: {}", std::env::consts::ARCH);
        println!("os: {}", std::env::consts::OS);
        println!(
            "features: tui={}, unifi={}, monitor={}",
            cfg!(feature = "tui"),
            cfg!(feature = "unifi"),
            cfg!(feature = "monitor"),
        );
    }
}

fn rustc_version() -> &'static str {
    // This is set at compile time by the build script or default
    option_env!("RUSTC_VERSION").unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::{redact_secret, redacted_for_display};
    use rikitikitavi_models::config::{AppConfig, UniFiCloudConfig, UniFiControllerConfig};

    #[test]
    fn config_show_redacts_all_secrets() {
        let mut cfg = AppConfig::default();
        cfg.unifi.controller = Some(UniFiControllerConfig {
            username: Some("admin".to_owned()),
            password: Some("hunter2".to_owned()),
            api_token: Some("tok_live_abc".to_owned()),
            ..Default::default()
        });
        cfg.unifi.cloud = Some(UniFiCloudConfig {
            enabled: true,
            api_key: Some("cloud_key_xyz".to_owned()),
            ..Default::default()
        });
        cfg.apis.shodan_api_key = Some("shodan_zzz".to_owned());
        cfg.apis.censys_api_secret = Some("censys_sss".to_owned());

        let yaml = serde_yaml_ng::to_string(&redacted_for_display(&cfg)).unwrap();

        // No secret value survives to the displayed output.
        for leaked in [
            "hunter2",
            "tok_live_abc",
            "cloud_key_xyz",
            "shodan_zzz",
            "censys_sss",
        ] {
            assert!(
                !yaml.contains(leaked),
                "secret leaked in config show: {leaked}"
            );
        }
        assert!(yaml.contains("***REDACTED***"));
        // Non-secret fields are preserved.
        assert!(yaml.contains("admin"));
    }

    #[test]
    fn redact_secret_preserves_none() {
        let mut unset: Option<String> = None;
        redact_secret(&mut unset);
        assert_eq!(
            unset, None,
            "unset secrets must stay None, not become a marker"
        );
    }

    #[test]
    fn unimplemented_scan_flags_reports_set_no_ops() {
        use crate::{Cli, Command, unimplemented_scan_flags};
        use clap::Parser;

        let cli = Cli::parse_from(["rikitikitavi", "scan", "--upload", "--ssid", "HomeNet"]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        let ignored = unimplemented_scan_flags(&args);
        assert!(ignored.contains(&"--upload"));
        assert!(ignored.contains(&"--ssid"));
        // Flags that were not set must not be reported.
        assert!(!ignored.contains(&"--interface"));
        assert!(!ignored.contains(&"--network"));
    }

    #[test]
    fn unimplemented_scan_flags_empty_for_plain_scan() {
        use crate::{Cli, Command, unimplemented_scan_flags};
        use clap::Parser;

        let cli = Cli::parse_from(["rikitikitavi", "scan"]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        assert!(unimplemented_scan_flags(&args).is_empty());
    }

    #[test]
    fn fail_on_threshold_maps_severity() {
        use crate::{Cli, Command, cli::FailOnArg, fail_on_threshold};
        use clap::Parser;
        use rikitikitavi_core::Severity;

        assert_eq!(fail_on_threshold(FailOnArg::Never), None);
        assert_eq!(fail_on_threshold(FailOnArg::High), Some(Severity::High));
        assert_eq!(
            fail_on_threshold(FailOnArg::Critical),
            Some(Severity::Critical)
        );
        // Default parses to Never (no failure).
        let cli = Cli::parse_from(["rikitikitavi", "scan"]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(args.fail_on, FailOnArg::Never);
    }
}
