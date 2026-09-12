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

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    let loaded = config::load_config(cli.config.as_deref())?;
    let app_config = &loaded.config;

    match cli.command {
        Command::Scan(args) => cmd_scan(args, &loaded).await,
        #[cfg(feature = "tui")]
        Command::Tui(args) => cmd_tui(args, app_config).await,
        Command::Report(args) => {
            cmd_report(&args, app_config);
            Ok(())
        }
        #[cfg(feature = "unifi")]
        Command::Unifi(args) => cmd_unifi(args, app_config).await,
        Command::Aws(args) => cmd_aws(args, app_config).await,
        Command::Modules(args) => {
            cmd_modules(args);
            Ok(())
        }
        Command::Init => {
            cmd_init();
            Ok(())
        }
        Command::Config(args) => cmd_config(&args, &loaded),
        #[cfg(feature = "monitor")]
        Command::Monitor(args) => cmd_monitor(args).await,
        Command::UpdateDb => cmd_update_db().await,
        Command::Version { verbose } => {
            cmd_version(verbose);
            Ok(())
        }
    }
}

/// `scan` flags that were set but are not yet wired into the scan.
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
    #[cfg(feature = "unifi")]
    if args.unifi_local {
        ignored.push("--unifi-local");
    }
    ignored
}

/// `--quick` wins, then `--aggressive`; a config-file `aggressive` is capped at `Active`.
/// Second value: `true` when capped.
const fn effective_intensity(
    quick: bool,
    aggressive: bool,
    configured: rikitikitavi_models::config::ScanIntensity,
) -> (rikitikitavi_models::config::ScanIntensity, bool) {
    use rikitikitavi_models::config::ScanIntensity;
    if quick {
        (ScanIntensity::Passive, false)
    } else if aggressive {
        (ScanIntensity::Aggressive, false)
    } else if matches!(configured, ScanIntensity::Aggressive) {
        (ScanIntensity::Active, true)
    } else {
        (configured, false)
    }
}

#[allow(clippy::too_many_lines)]
async fn cmd_scan(args: cli::ScanArgs, loaded: &config::LoadedConfig) -> Result<()> {
    use rikitikitavi_models::config::{PortRange, ScanIntensity, TOP_20_PORTS};

    let app_config = &loaded.config;

    let ignored = unimplemented_scan_flags(&args);
    if !ignored.is_empty() {
        anyhow::bail!("not yet implemented: {}", ignored.join(", "));
    }

    // Network discovery is only implemented for Linux and macOS.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if !args.quiet {
        eprintln!(
            "Warning: unsupported platform — network discovery requires Linux or macOS. \
             Results will be empty on this OS."
        );
    }

    config::validate_scan_config(&app_config.scan)?;
    if !args.quiet
        && let Some(path) = loaded.path.as_ref()
    {
        println!("Config: {}", path.display());
    }

    // Control files are read before any network activity.
    let suppressions = args
        .suppress
        .as_deref()
        .map(|p| load_list(p, "suppression", parse_fingerprint))
        .transpose()?;
    let known_devices = args
        .known_devices
        .as_deref()
        .map(|p| load_list(p, "known-devices", parse_device_identifier))
        .transpose()?;

    let perspective: rikitikitavi_core::Perspective = args.perspective.into();

    let (intensity, capped) =
        effective_intensity(args.quick, args.aggressive, app_config.scan.intensity);
    if capped {
        eprintln!(
            "Note: config intensity 'aggressive' capped at 'active'; pass --aggressive to enable login attempts."
        );
    }

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
        parallelism: app_config.scan.effective_parallelism(),
        ..app_config.scan.clone()
    };
    let exclusions = scan_config.exclusions()?;

    let mut ctx = rikitikitavi_models::ScanContext {
        target_network: None,
        gateway: None,
        perspective,
        network_mode: rikitikitavi_core::NetworkMode::Auto,
        config: scan_config,
        discovered_devices: Vec::new(),
    };

    if !args.quiet {
        eprintln!(
            "Note: only scan networks you own or are explicitly authorized to test. \
             Active/aggressive modes probe and (with --aggressive) attempt logins."
        );
        println!("{}", intensity.profile_name());
        println!("Discovering network...");
    }
    // Dry run must not touch the network, so the sweep is skipped.
    let swept = if args.dry_run {
        ctx.discovered_devices = runner::discover_network(&mut ctx);
        runner::apply_exclusions(&mut ctx.discovered_devices, &exclusions);
        0
    } else {
        runner::discover_hosts(&mut ctx).await?
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

        if ctx.discovered_devices.len() <= 1 {
            eprintln!(
                "Warning: found {} host(s). If this looks too low, the ARP cache may be \
                 cold and the sweep found little — check you are on the right interface, \
                 run with --aggressive, or ensure the network allows TCP probing.",
                ctx.discovered_devices.len()
            );
        }
    }

    let registry = rikitikitavi_scanners::ScannerRegistry::new();
    let selection = runner::plan_scanners(&registry, &ctx)?;
    for note in selection_notices(&selection, perspective) {
        eprintln!("{note}");
    }
    if args.dry_run {
        println!("Would run {} scanners:", selection.scanners.len());
        for s in &selection.scanners {
            println!("  - {} ({})", s.name(), s.id());
        }
        return Ok(());
    }

    let mut results = runner::run_scan(&mut ctx).await?;

    // New-device detection
    if let (Some(known), Some(path)) = (known_devices.as_ref(), args.known_devices.as_ref()) {
        let new_devices: Vec<_> = results
            .devices
            .iter()
            .filter(|d| !known.contains(&device_identifier(d)))
            .map(new_device_finding)
            .collect();
        if !new_devices.is_empty() && !args.quiet {
            println!(
                "Detected {} new device(s) not in {}",
                new_devices.len(),
                path.display()
            );
        }
        results.findings.extend(new_devices);
    }
    if let Some(path) = args.write_known_devices.as_ref() {
        match write_known_devices_file(path, &results.devices) {
            Ok(n) if !args.quiet => println!("Wrote {n} known device(s) to {}", path.display()),
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Warning: could not write known-devices {}: {e}",
                    path.display()
                );
            }
        }
    }

    // Load the previous scan before saving the current one.
    let history = rikitikitavi_analysis::ScanHistory::new();
    let previous = if args.compare_previous {
        history
            .as_ref()
            .and_then(|h| h.load_latest().ok().flatten())
    } else {
        None
    };

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

    // Suppression is applied after the history save, so history keeps the full scan.
    if let Some(path) = args.write_baseline.as_ref() {
        match write_baseline_file(path, &results.findings) {
            Ok(n) if !args.quiet => {
                println!("Wrote {n} fingerprint(s) to baseline {}", path.display());
            }
            Ok(_) => {}
            Err(e) => eprintln!("Warning: could not write baseline {}: {e}", path.display()),
        }
    }
    if let (Some(set), Some(path)) = (suppressions.as_ref(), args.suppress.as_ref()) {
        let before = results.findings.len();
        results.findings.retain(|f| !set.contains(&f.fingerprint()));
        let suppressed = before - results.findings.len();
        if suppressed > 0 && !args.quiet {
            println!(
                "Suppressed {suppressed} finding(s) listed in {}",
                path.display()
            );
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

    if let Some(prev) = previous {
        let diff = rikitikitavi_analysis::diff_scan_results(&prev, &results);
        print_comparison_report(&diff);
    }

    if let Some(note) = exit_code_note(args.quiet, args.fail_on) {
        eprintln!("{note}");
    }
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

/// Stderr lines for ids dropped or added by `--modules` resolution.
fn selection_notices(
    selection: &runner::ModuleSelection<'_>,
    perspective: rikitikitavi_core::Perspective,
) -> Vec<String> {
    let mut notes = Vec::new();
    if !selection.skipped.is_empty() {
        notes.push(format!(
            "Warning: modules skipped (unsupported by {perspective} perspective): {}",
            selection.skipped.join(", ")
        ));
    }
    if !selection.added.is_empty() {
        notes.push(format!(
            "Note: phase-1 modules added: {}",
            selection.added.join(", ")
        ));
    }
    notes
}

/// Stderr note when `--quiet` hides the report and no `--fail-on` threshold is set.
const fn exit_code_note(quiet: bool, fail_on: cli::FailOnArg) -> Option<&'static str> {
    if quiet && matches!(fail_on, cli::FailOnArg::Never) {
        Some("Note: --fail-on not set; exit code does not reflect findings.")
    } else {
        None
    }
}

/// Create or truncate `path` for writing; mode `0o600` on Unix, existing files included.
fn create_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Write deduplicated fingerprints to `path`, one per line with the title as a `#`
/// comment. Returns the count written.
fn write_baseline_file(
    path: &std::path::Path,
    findings: &[rikitikitavi_models::Finding],
) -> std::io::Result<usize> {
    use std::collections::BTreeMap;
    use std::io::Write as _;
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for f in findings {
        seen.entry(f.fingerprint().to_string())
            .or_insert_with(|| f.title.clone());
    }
    let mut file = create_private(path)?;
    writeln!(
        file,
        "# rikitikitavi suppression baseline — listed findings are muted with --suppress"
    )?;
    for (fp, title) in &seen {
        writeln!(file, "{fp}  # {title}")?;
    }
    Ok(seen.len())
}

/// Entries parsed from a baseline / known-devices file.
struct ListFile<T> {
    entries: std::collections::HashSet<T>,
    invalid: usize,
}

/// One token per line, `#` starts a comment; tokens `parse` rejects count as `invalid`.
fn parse_list_file<T: Eq + std::hash::Hash>(
    contents: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> ListFile<T> {
    let mut entries = std::collections::HashSet::new();
    let mut invalid = 0;
    for line in contents.lines() {
        let token = line.split('#').next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        match parse(token) {
            Some(entry) => {
                entries.insert(entry);
            }
            None => invalid += 1,
        }
    }
    ListFile { entries, invalid }
}

/// Read a `--suppress` / `--known-devices` file. Unreadable, or invalid lines with no
/// valid entry, is an error; other invalid lines are counted on stderr.
fn load_list<T: Eq + std::hash::Hash>(
    path: &std::path::Path,
    what: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<std::collections::HashSet<T>> {
    use anyhow::Context as _;
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {what} file {}", path.display()))?;
    let parsed = parse_list_file(&contents, parse);
    if parsed.invalid > 0 {
        if parsed.entries.is_empty() {
            anyhow::bail!(
                "{what} file {} has no valid entries ({} unparseable line(s))",
                path.display(),
                parsed.invalid
            );
        }
        eprintln!(
            "Warning: {} unparseable line(s) in {what} file {}",
            parsed.invalid,
            path.display()
        );
    }
    Ok(parsed.entries)
}

fn parse_fingerprint(token: &str) -> Option<rikitikitavi_models::FindingFingerprint> {
    token.parse().ok()
}

/// Canonical known-devices token: MAC as `aa:bb:cc:dd:ee:ff`, else IP.
fn parse_device_identifier(token: &str) -> Option<String> {
    if let Ok(ip) = token.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    token
        .parse::<rikitikitavi_models::MacAddr>()
        .ok()
        .map(|m| m.to_string())
}

/// Known-devices identifier: MAC if known, otherwise IP.
fn device_identifier(d: &rikitikitavi_models::Device) -> String {
    d.mac.map_or_else(|| d.ip.to_string(), |m| m.to_string())
}

/// Build a "new device on network" finding for an unrecognized device.
fn new_device_finding(d: &rikitikitavi_models::Device) -> rikitikitavi_models::Finding {
    use rikitikitavi_core::{Confidence, Severity};
    let label = device_identity_label(d);
    let title = if label.is_empty() {
        format!("New device on network: {}", d.ip)
    } else {
        format!("New device on network: {} {label}", d.ip)
    };
    let mac_note = d.mac.map_or_else(String::new, |m| format!(" (MAC {m})"));
    let desc = format!(
        "A device not in your known-devices list appeared at {}{mac_note}. If you do \
         not recognize it, investigate — it may be an unauthorized device on your network.",
        d.ip
    );
    rikitikitavi_models::Finding::new("device", &title, &desc, Severity::Medium)
        .with_ip(d.ip)
        .with_confidence(Confidence::Confirmed)
        .with_cwe("CWE-284")
}

/// Write the known-devices set: one identifier per line with a label comment.
fn write_known_devices_file(
    path: &std::path::Path,
    devices: &[rikitikitavi_models::Device],
) -> std::io::Result<usize> {
    use std::collections::BTreeMap;
    use std::io::Write as _;
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for d in devices {
        seen.entry(device_identifier(d))
            .or_insert_with(|| device_identity_label(d));
    }
    let mut file = create_private(path)?;
    writeln!(
        file,
        "# rikitikitavi known devices — absent devices are flagged as new"
    )?;
    for (id, label) in &seen {
        writeln!(file, "{id}  # {label}")?;
    }
    Ok(seen.len())
}

/// Minimum `Severity` that triggers a non-zero exit for `--fail-on`; `None` disables.
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
/// Device label such as `"HP (Printer)"`, `"(Camera)"`, or empty when nothing is known.
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

    println!("Scan complete: {total} findings");
    println!("Risk score: {:.0}/100 ({grade})", results.risk_score);
    println!();

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

    // Actionable findings grouped by IP; findings without an IP appear only in the list below.
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
            // EPSS: probability of exploitation within 30 days.
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

/// Discovery plus the full scanner run; used by the initial TUI scan and re-scans.
#[cfg(feature = "tui")]
async fn tui_scan(
    scan_config: rikitikitavi_models::config::ScanConfig,
) -> Result<rikitikitavi_models::ScanResults> {
    let mut ctx = rikitikitavi_models::ScanContext {
        target_network: None,
        gateway: None,
        perspective: scan_config.perspective,
        network_mode: rikitikitavi_core::NetworkMode::Auto,
        config: scan_config,
        discovered_devices: Vec::new(),
    };
    runner::discover_hosts(&mut ctx).await?;
    runner::run_scan(&mut ctx).await
}

/// Apply a finished re-scan to `app`: store results or the error, and clear `scanning`.
#[cfg(feature = "tui")]
fn finish_rescan(
    app: &mut rikitikitavi_tui::App,
    history: Option<&rikitikitavi_analysis::ScanHistory>,
    outcome: Result<rikitikitavi_models::ScanResults>,
) {
    match outcome {
        Ok(results) => {
            if let Some(prev) = app.results.as_ref() {
                let diff = rikitikitavi_analysis::diff_scan_results(prev, &results);
                app.set_scan_diff(diff);
            }
            if let Some(h) = history
                && let Err(e) = h.save(&results)
            {
                tracing::warn!("failed to save scan history: {e}");
            }
            app.results = Some(results);
            app.scan_progress = 1.0;
            app.status_message = Some("Re-scan complete".to_owned());
        }
        Err(e) => {
            app.status_message = Some(format!("Re-scan failed: {e}"));
        }
    }
    app.scanning = false;
    app.scan_status = String::new();
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

    let history = rikitikitavi_analysis::ScanHistory::new();
    let previous_results = history
        .as_ref()
        .and_then(|h| h.load_latest().ok().flatten());

    let perspective = rikitikitavi_core::Perspective::Authenticated;
    let (intensity, capped) = effective_intensity(false, false, app_config.scan.intensity);
    if capped {
        eprintln!(
            "Note: config intensity 'aggressive' capped at 'active'; login attempts run only via `scan --aggressive`."
        );
    }
    let scan_config = rikitikitavi_models::config::ScanConfig {
        perspective,
        modules: None,
        attack_paths: true,
        intensity,
        parallelism: app_config.scan.effective_parallelism(),
        ..app_config.scan.clone()
    };

    app.scanning = true;
    match tui_scan(scan_config.clone()).await {
        Ok(results) => {
            if let Some(ref prev) = previous_results {
                let diff = rikitikitavi_analysis::diff_scan_results(prev, &results);
                app.set_scan_diff(diff);
            }
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

    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut rescan: Option<tokio::task::JoinHandle<Result<rikitikitavi_models::ScanResults>>> =
        None;

    loop {
        if rescan
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
            && let Some(handle) = rescan.take()
        {
            let outcome = handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("re-scan task aborted: {e}")));
            finish_rescan(&mut app, history.as_ref(), outcome);
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
                rescan = Some(tokio::spawn(tui_scan(scan_config.clone())));
            }
        }

        if app.should_quit {
            break;
        }
    }

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

    println!("\n--- UniFi Security Audit ---");
    println!("Findings: {}", all_findings.len());
    for f in &all_findings {
        println!("  [{:8}] {}", f.severity, f.title);
    }

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
    let what = match args.command {
        cli::AwsCommand::RegisterSource => "aws register-source".to_owned(),
        cli::AwsCommand::Validate => "aws validate".to_owned(),
        cli::AwsCommand::GeneratePolicy => "aws generate-policy".to_owned(),
        cli::AwsCommand::Upload { path } => format!("aws upload {}", path.display()),
    };
    anyhow::bail!("{what}: not yet implemented")
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

fn cmd_config(args: &cli::ConfigArgs, loaded: &config::LoadedConfig) -> Result<()> {
    match args.command {
        cli::ConfigCommand::Validate => {
            config::validate_config(&loaded.config)?;
            match loaded.path.as_ref() {
                Some(p) => println!("Configuration is valid: {}", p.display()),
                None => println!("Configuration is valid (no config file found; defaults)."),
            }
        }
        cli::ConfigCommand::Show => {
            let yaml = serde_yaml_ng::to_string(&redacted_for_display(&loaded.config))?;
            println!("{yaml}");
        }
    }
    Ok(())
}

/// Copy of the config with each present secret replaced by `***REDACTED***`; `None` stays `None`.
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

    let interface = if let Some(ref iface) = args.interface {
        iface.clone()
    } else {
        println!("Auto-detecting WiFi interface...");
        wifi_monitor::find_wifi_interface()?
    };
    println!("Interface: {interface}");

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

    println!();
    println!("Setting up monitor mode...");
    let session = wifi_monitor::setup_monitor(&interface)?;
    println!("Monitor interface: {}", session.monitor_interface);

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

    let known_bssids: HashSet<_> = args
        .known_bssids
        .iter()
        .filter_map(|s| rikitikitavi_network::wifi_frames::parse_mac(s))
        .collect();

    let findings =
        passive_wifi::analyse_results(&results, &known_bssids, args.home_ssid.as_deref());

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

    // `MonitorSession::drop` tears down the monitor interface.
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
    option_env!("RUSTC_VERSION").unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::{redact_secret, redacted_for_display};
    use rikitikitavi_models::config::{AppConfig, UniFiCloudConfig, UniFiControllerConfig};

    #[cfg(feature = "tui")]
    #[test]
    fn finish_rescan_error_clears_scanning_and_reports() {
        let mut app = rikitikitavi_tui::App::new(rikitikitavi_tui::TuiConfig::default());
        app.scanning = true;
        "Scanning...".clone_into(&mut app.scan_status);

        super::finish_rescan(&mut app, None, Err(anyhow::anyhow!("boom")));

        assert!(!app.scanning);
        assert!(app.scan_status.is_empty());
        assert!(app.results.is_none());
        assert_eq!(app.status_message.as_deref(), Some("Re-scan failed: boom"));
        // A new re-scan is accepted again.
        assert!(app.handle_key(crossterm::event::KeyCode::Char('s')));
    }

    #[cfg(feature = "tui")]
    #[test]
    fn finish_rescan_ok_stores_results_and_clears_scanning() {
        let mut app = rikitikitavi_tui::App::new(rikitikitavi_tui::TuiConfig::default());
        app.scanning = true;

        super::finish_rescan(
            &mut app,
            None,
            Ok(rikitikitavi_models::ScanResults::default()),
        );

        assert!(!app.scanning);
        assert!(app.results.is_some());
        assert_eq!(app.status_message.as_deref(), Some("Re-scan complete"));
    }

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
    fn effective_intensity_caps_config_aggressive() {
        use crate::effective_intensity;
        use rikitikitavi_models::config::ScanIntensity;

        assert_eq!(
            effective_intensity(false, false, ScanIntensity::Aggressive),
            (ScanIntensity::Active, true)
        );
        assert_eq!(
            effective_intensity(false, true, ScanIntensity::Aggressive),
            (ScanIntensity::Aggressive, false)
        );
        assert_eq!(
            effective_intensity(false, true, ScanIntensity::Passive),
            (ScanIntensity::Aggressive, false)
        );
        assert_eq!(
            effective_intensity(true, true, ScanIntensity::Aggressive),
            (ScanIntensity::Passive, false)
        );
        assert_eq!(
            effective_intensity(false, false, ScanIntensity::Passive),
            (ScanIntensity::Passive, false)
        );
        assert_eq!(
            effective_intensity(false, false, ScanIntensity::Active),
            (ScanIntensity::Active, false)
        );
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rikitikitavi-{}-{name}", std::process::id()))
    }

    #[test]
    fn parse_list_file_counts_invalid_tokens() {
        use crate::{parse_device_identifier, parse_fingerprint, parse_list_file};

        let parsed = parse_list_file(
            "# header\n01a2b3c4d5e6f708  # t\n\nzzz\n0x0000000000000001\n",
            parse_fingerprint,
        );
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.invalid, 1);

        let parsed = parse_list_file(
            "AA-BB-CC-DD-EE-FF\n192.168.1.5 # printer\nkitchen-tv\n",
            parse_device_identifier,
        );
        assert!(parsed.entries.contains("aa:bb:cc:dd:ee:ff"));
        assert!(parsed.entries.contains("192.168.1.5"));
        assert_eq!(parsed.invalid, 1);
    }

    #[test]
    fn load_list_fails_closed() {
        use crate::{load_list, parse_fingerprint};

        let missing = temp_path("missing-baseline");
        let msg = load_list(&missing, "suppression", parse_fingerprint)
            .unwrap_err()
            .to_string();
        assert!(msg.starts_with("cannot read suppression file "), "{msg}");

        let garbled = temp_path("garbled-baseline");
        std::fs::write(&garbled, "not-hex\nalso bad\n").unwrap();
        let msg = load_list(&garbled, "suppression", parse_fingerprint)
            .unwrap_err()
            .to_string();
        std::fs::remove_file(&garbled).ok();
        assert!(
            msg.ends_with("has no valid entries (2 unparseable line(s))"),
            "{msg}"
        );

        let header_only = temp_path("empty-baseline");
        std::fs::write(&header_only, "# rikitikitavi suppression baseline\n").unwrap();
        let set = load_list(&header_only, "suppression", parse_fingerprint).unwrap();
        std::fs::remove_file(&header_only).ok();
        assert!(set.is_empty());

        let mixed = temp_path("mixed-baseline");
        std::fs::write(&mixed, "01a2b3c4d5e6f708\nnot-hex\n").unwrap();
        let set = load_list(&mixed, "suppression", parse_fingerprint).unwrap();
        std::fs::remove_file(&mixed).ok();
        assert_eq!(set.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn written_control_files_are_private() {
        use crate::{write_baseline_file, write_known_devices_file};
        use std::os::unix::fs::PermissionsExt as _;

        let baseline = temp_path("baseline-mode");
        write_baseline_file(&baseline, &[]).unwrap();
        let mode = std::fs::metadata(&baseline).unwrap().permissions().mode();
        std::fs::remove_file(&baseline).ok();
        assert_eq!(mode & 0o777, 0o600);

        let known = temp_path("known-mode");
        write_known_devices_file(&known, &[]).unwrap();
        let mode = std::fs::metadata(&known).unwrap().permissions().mode();
        std::fs::remove_file(&known).ok();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn rewritten_control_file_becomes_private() {
        use crate::write_baseline_file;
        use std::os::unix::fs::PermissionsExt as _;

        let path = temp_path("baseline-rewrite-mode");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_baseline_file(&path, &[]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!contents.contains("old"));
    }

    #[test]
    fn selection_notices_name_skipped_and_added() {
        use crate::selection_notices;
        use rikitikitavi_core::Perspective;

        let registry = rikitikitavi_scanners::ScannerRegistry::new();
        let modules = ["neighbor".to_owned(), "dns".to_owned()];
        let sel = crate::runner::select_modules(&registry, &modules, Perspective::Unauthenticated)
            .unwrap();
        assert_eq!(
            selection_notices(&sel, Perspective::Unauthenticated),
            [
                "Warning: modules skipped (unsupported by unauthenticated perspective): neighbor",
                "Note: phase-1 modules added: network, ports, device",
            ]
        );

        let modules = ["ports".to_owned()];
        let sel = crate::runner::select_modules(&registry, &modules, Perspective::Unauthenticated)
            .unwrap();
        assert!(selection_notices(&sel, Perspective::Unauthenticated).is_empty());
    }

    #[test]
    fn exit_code_note_only_for_quiet_without_fail_on() {
        use crate::{cli::FailOnArg, exit_code_note};

        assert_eq!(
            exit_code_note(true, FailOnArg::Never),
            Some("Note: --fail-on not set; exit code does not reflect findings.")
        );
        assert_eq!(exit_code_note(true, FailOnArg::High), None);
        assert_eq!(exit_code_note(false, FailOnArg::Never), None);
    }

    #[tokio::test]
    async fn cmd_scan_rejects_unimplemented_flags() {
        use crate::{Cli, Command, cmd_scan, config::LoadedConfig};
        use clap::Parser;

        let cli = Cli::parse_from(["rikitikitavi", "scan", "--upload", "--interface", "eth0"]);
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        let loaded = LoadedConfig {
            config: AppConfig::default(),
            path: None,
        };
        let msg = cmd_scan(args, &loaded).await.unwrap_err().to_string();
        assert_eq!(msg, "not yet implemented: --interface, --upload");
    }

    #[tokio::test]
    async fn cmd_aws_is_unimplemented() {
        use crate::{Cli, Command, cmd_aws};
        use clap::Parser;

        let cli = Cli::parse_from(["rikitikitavi", "aws", "validate"]);
        let Command::Aws(args) = cli.command else {
            panic!("expected aws command");
        };
        let msg = cmd_aws(args, &AppConfig::default())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(msg, "aws validate: not yet implemented");
    }

    #[test]
    fn written_baseline_round_trips_through_loader() {
        use crate::{load_list, parse_fingerprint, write_baseline_file};
        use rikitikitavi_core::Severity;

        let f = rikitikitavi_models::Finding::new("ports", "Telnet open", "d", Severity::High);
        let path = temp_path("baseline-roundtrip");
        assert_eq!(
            write_baseline_file(&path, std::slice::from_ref(&f)).unwrap(),
            1
        );
        let set = load_list(&path, "suppression", parse_fingerprint).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(set.contains(&f.fingerprint()));
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
