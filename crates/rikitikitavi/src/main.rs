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
        Command::UpdateDb => cmd_update_db().await,
        Command::Version { verbose } => {
            cmd_version(verbose);
            Ok(())
        }
    }
}

async fn cmd_scan(
    args: cli::ScanArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    use rikitikitavi_models::config::{PortRange, ScanIntensity, TOP_20_PORTS};

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
        println!("{}", intensity.profile_name());
        println!("Discovering network...");
    }
    let devices = runner::discover_network(&mut ctx);
    ctx.discovered_devices = devices;

    if !args.quiet {
        if let Some(gw) = ctx.gateway {
            println!("  Gateway:  {gw}");
        }
        if let Some(net) = &ctx.target_network {
            println!("  Network:  {net}");
        }
        println!("  Devices:  {}", ctx.discovered_devices.len());
        println!();
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

    if let Some(output) = args.output {
        match args.format {
            cli::ReportFormatArg::Json => rikitikitavi_export::export_json(&results, &output)?,
            cli::ReportFormatArg::Html => rikitikitavi_export::export_html(&results, &output)?,
            cli::ReportFormatArg::Csv => rikitikitavi_export::export_csv(&results, &output)?,
        }
        println!("Results written to {}", output.display());
    } else if !args.quiet {
        println!("Scan complete: {} findings", results.findings.len());
        println!("Risk score: {:.0}/100", results.risk_score);
        println!();
        for f in &results.findings {
            println!("  [{:8}] {}", f.severity, f.title);
        }
    }

    Ok(())
}

#[cfg(feature = "tui")]
#[allow(clippy::too_many_lines)]
async fn cmd_tui(
    args: cli::TuiArgs,
    app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    use crossterm::{execute, terminal};
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

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
    let (scan_tx, mut scan_rx) =
        tokio::sync::mpsc::channel::<rikitikitavi_models::ScanResults>(1);

    // Main loop
    loop {
        // Check for completed background scan
        if let Ok(results) = scan_rx.try_recv() {
            app.results = Some(results);
            app.scanning = false;
            app.scan_progress = 1.0;
            app.scan_status = String::new();
            app.status_message = Some("Re-scan complete".to_owned());
        }

        terminal.draw(|frame| rikitikitavi_tui::ui::draw(frame, &mut app))?;

        if let Some(event) =
            rikitikitavi_tui::events::poll_event(std::time::Duration::from_millis(100))?
        {
            let rescan_requested =
                if let Some(key) = rikitikitavi_tui::events::as_key_press(&event) {
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

fn cmd_report(
    _args: &cli::ReportArgs,
    _app_config: &rikitikitavi_models::config::AppConfig,
) {
    println!("Report generation not yet implemented.");
    println!("Run a scan first with `rikitikitavi scan --output results.json`");
}

#[cfg(feature = "unifi")]
async fn cmd_unifi(
    args: cli::UniFiArgs,
    _app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    match args.command {
        cli::UniFiCommand::Scan {
            local,
            controller,
            user,
            password,
            token,
            site,
            output,
        } => {
            cmd_unifi_scan(local, controller, user, password, token, &site, output).await?;
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
            anyhow::bail!(
                "Not running on a UniFi device. Use --controller for remote mode."
            );
        }
    } else if let Some(ctrl) = controller {
        ctrl
    } else {
        anyhow::bail!(
            "Specify --local (on-device) or --controller <url> for remote scanning."
        );
    };

    println!("Connecting to UniFi controller at {url}...");

    let mut client = UniFiClient::new_insecure(&url, site)?;

    // Authenticate
    if let Some(tok) = token {
        client.login_token(&tok).await?;
        println!("Authenticated with API token.");
    } else if let (Some(u), Some(p)) = (user, password) {
        client.login(&u, &p).await?;
        println!("Authenticated with username/password.");
    } else {
        anyhow::bail!(
            "Provide --token <api-token> or --user <username> --password <password>."
        );
    }

    println!("Running UniFi security audit...\n");

    let mut all_findings = Vec::new();

    // Audit WLANs
    match client.get_wlans().await {
        Ok(wlans) => {
            println!("WLANs: {} configured", wlans.len());
            for wlan in &wlans {
                let status = if wlan.enabled { "enabled" } else { "disabled" };
                println!(
                    "  {} ({}, {})",
                    wlan.name, wlan.security, status
                );
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
            let yaml = serde_yaml_ng::to_string(app_config)?;
            println!("{yaml}");
        }
    }
    Ok(())
}

#[allow(clippy::unused_async)]
async fn cmd_update_db() -> Result<()> {
    println!("Database update not yet implemented.");
    Ok(())
}

fn cmd_version(verbose: bool) {
    println!("rikitikitavi {}", env!("CARGO_PKG_VERSION"));
    if verbose {
        println!("rustc: {}", rustc_version());
        println!("target: {}", std::env::consts::ARCH);
        println!("os: {}", std::env::consts::OS);
        println!(
            "features: tui={}, unifi={}",
            cfg!(feature = "tui"),
            cfg!(feature = "unifi"),
        );
    }
}

fn rustc_version() -> &'static str {
    // This is set at compile time by the build script or default
    option_env!("RUSTC_VERSION").unwrap_or("unknown")
}
