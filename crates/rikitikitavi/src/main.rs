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
    let perspective: rikitikitavi_core::Perspective = args.perspective.into();

    let scan_config = rikitikitavi_models::config::ScanConfig {
        perspective,
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
    };

    // Perform network discovery to populate context
    if !args.quiet {
        println!("Discovering network...");
    }
    let devices = runner::discover_network(&mut ctx);

    if !args.quiet {
        if let Some(gw) = ctx.gateway {
            println!("  Gateway:  {gw}");
        }
        if let Some(net) = &ctx.target_network {
            println!("  Network:  {net}");
        }
        println!("  Devices:  {}", devices.len());
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

    let mut results = runner::run_scan(&ctx).await?;
    results.devices = devices;

    if let Some(output) = args.output {
        rikitikitavi_export::export_json(&results, &output)?;
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
    };

    app.scanning = true;
    "Initial network discovery...".clone_into(&mut app.scan_status);

    let devices = runner::discover_network(&mut ctx);
    "Running scanners...".clone_into(&mut app.scan_status);

    match runner::run_scan(&ctx).await {
        Ok(mut results) => {
            results.devices = devices;
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
    execute!(stdout, terminal::EnterAlternateScreen)?;
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

        terminal.draw(|frame| rikitikitavi_tui::ui::draw(frame, &app))?;

        if let Some(event) =
            rikitikitavi_tui::events::poll_event(std::time::Duration::from_millis(100))?
        {
            if let Some(key) = rikitikitavi_tui::events::as_key_press(&event) {
                let rescan_requested = app.handle_key(key.code);
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
                        };
                        let devices = runner::discover_network(&mut rescan_ctx);
                        if let Ok(mut results) = runner::run_scan(&rescan_ctx).await {
                            results.devices = devices;
                            let _ = tx.send(results).await;
                        }
                    });
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), terminal::LeaveAlternateScreen)?;
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
#[allow(clippy::unused_async)]
async fn cmd_unifi(
    args: cli::UniFiArgs,
    _app_config: &rikitikitavi_models::config::AppConfig,
) -> Result<()> {
    match args.command {
        cli::UniFiCommand::Scan { local, .. } => {
            if local {
                if let Some(env) = rikitikitavi_unifi::UniFiEnvironment::detect() {
                    println!("Detected UniFi device: {:?}", env.device_type);
                } else {
                    println!("Not running on a UniFi device. Use --controller for remote mode.");
                }
            }
            println!("UniFi scan not yet implemented.");
        }
        cli::UniFiCommand::Devices => {
            println!("Device listing not yet implemented.");
        }
        cli::UniFiCommand::FirmwareCheck => {
            println!("Firmware check not yet implemented.");
        }
        cli::UniFiCommand::AuditController => {
            println!("Controller audit not yet implemented.");
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
        cli::UniFiCommand::Report { .. } => {
            println!("UniFi report not yet implemented.");
        }
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
            let yaml = serde_yaml::to_string(app_config)?;
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
