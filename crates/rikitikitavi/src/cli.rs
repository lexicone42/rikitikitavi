use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rikitikitavi",
    about = "Home network security auditor",
    version,
    long_about = "Rikitikitavi scans your home network for security vulnerabilities \
                  and reports findings to AWS Security Lake."
)]
pub struct Cli {
    /// Path to configuration file.
    #[arg(short, long, global = true, env = "RIKITIKITAVI_CONFIG")]
    pub config: Option<PathBuf>,

    /// Logging verbosity.
    #[arg(short, long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a network security scan.
    Scan(ScanArgs),

    /// Launch the interactive TUI dashboard.
    #[cfg(feature = "tui")]
    Tui(TuiArgs),

    /// Generate a report from the last scan.
    Report(ReportArgs),

    /// UniFi-specific commands.
    #[cfg(feature = "unifi")]
    Unifi(UniFiArgs),

    /// AWS Security Lake commands.
    Aws(AwsArgs),

    /// List available scanner modules.
    Modules(ModulesArgs),

    /// Interactive setup wizard.
    Init,

    /// Validate configuration.
    Config(ConfigArgs),

    /// Update vulnerability databases.
    UpdateDb,

    /// Show version and system information.
    Version {
        /// Show detailed system info.
        #[arg(long)]
        verbose: bool,
    },
}

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct ScanArgs {
    /// Attacker perspective to simulate.
    #[arg(long, default_value = "unauthenticated")]
    pub perspective: PerspectiveArg,

    /// Network access mode.
    #[arg(long, default_value = "auto")]
    pub network: NetworkArg,

    /// `WiFi` SSID (when --network wifi).
    #[arg(long)]
    pub ssid: Option<String>,

    /// `WiFi` password.
    #[arg(long)]
    pub password: Option<String>,

    /// Ethernet interface name.
    #[arg(long)]
    pub interface: Option<String>,

    /// Comma-separated list of scanner modules to run.
    #[arg(long, value_delimiter = ',')]
    pub modules: Option<Vec<String>>,

    /// Output file path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format (json or html).
    #[arg(long, default_value = "json")]
    pub format: ReportFormatArg,

    /// Generate attack path analysis.
    #[arg(long)]
    pub attack_paths: bool,

    /// Quick scan (fewer checks, faster).
    #[arg(long)]
    pub quick: bool,

    /// Aggressive scan (thorough, may trigger alerts).
    #[arg(long)]
    pub aggressive: bool,

    /// Upload results after scanning.
    #[arg(long)]
    pub upload: bool,

    /// Dry run — show what would be scanned without scanning.
    #[arg(long)]
    pub dry_run: bool,

    /// Suppress non-essential output.
    #[arg(long)]
    pub quiet: bool,

    /// Compare results against the most recent saved scan.
    #[arg(long)]
    pub compare_previous: bool,

    /// Do not auto-save scan results to history.
    #[arg(long)]
    pub no_save: bool,

    /// Scan with `UniFi` local API access (when running on `UniFi` device).
    #[cfg(feature = "unifi")]
    #[arg(long)]
    pub unifi_local: bool,
}

#[derive(Args)]
pub struct TuiArgs {
    /// Continuous monitoring mode.
    #[arg(long)]
    pub watch: bool,

    /// Scan interval in seconds (watch mode).
    #[arg(long, default_value = "300")]
    pub interval: u64,

    /// TUI color theme.
    #[arg(long, default_value = "dark")]
    pub theme: ThemeArg,

    /// Attacker perspective.
    #[arg(long, default_value = "unauthenticated")]
    pub perspective: PerspectiveArg,

    /// Network mode.
    #[arg(long, default_value = "auto")]
    pub network: NetworkArg,

    /// `WiFi` SSID.
    #[arg(long)]
    pub ssid: Option<String>,
}

#[derive(Args)]
pub struct ReportArgs {
    /// Report output format.
    #[arg(long, default_value = "html")]
    pub format: ReportFormatArg,

    /// Output file path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Include attack path analysis.
    #[arg(long)]
    pub attack_paths: bool,

    /// Load and print the most recent saved scan from history.
    #[arg(long)]
    pub latest: bool,
}

#[derive(Args)]
pub struct UniFiArgs {
    #[command(subcommand)]
    pub command: UniFiCommand,
}

#[derive(Subcommand)]
pub enum UniFiCommand {
    /// Scan `UniFi` network.
    Scan {
        /// Use local API (on-device).
        #[arg(long)]
        local: bool,
        /// Controller URL (remote mode).
        #[arg(long)]
        controller: Option<String>,
        /// Controller username.
        #[arg(long)]
        user: Option<String>,
        /// Controller password.
        #[arg(long)]
        password: Option<String>,
        /// API token (`UniFi` OS 2.x+), alternative to username/password.
        #[arg(long)]
        token: Option<String>,
        /// Site name.
        #[arg(long, default_value = "default")]
        site: String,
        /// Output file path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// List adopted devices.
    Devices,
    /// Check firmware across all devices.
    FirmwareCheck,
    /// Audit controller security.
    AuditController,
    /// Deploy to a `UniFi` device.
    Deploy {
        /// Device hostname or IP.
        #[arg(long)]
        host: String,
        /// SSH user.
        #[arg(long, default_value = "root")]
        user: String,
        /// Install with persistence.
        #[arg(long)]
        persistent: bool,
    },
    /// Launch `UniFi` TUI dashboard.
    Tui {
        /// Watch mode.
        #[arg(long)]
        watch: bool,
    },
    /// Generate `UniFi` security report.
    Report {
        /// Output file.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Report format.
        #[arg(long, default_value = "html")]
        format: ReportFormatArg,
    },
}

#[derive(Args)]
pub struct AwsArgs {
    #[command(subcommand)]
    pub command: AwsCommand,
}

#[derive(Subcommand)]
pub enum AwsCommand {
    /// Register custom Security Lake source.
    RegisterSource,
    /// Validate AWS connectivity.
    Validate,
    /// Generate required IAM policy.
    GeneratePolicy,
    /// Manually upload findings.
    Upload {
        /// Path to findings file.
        path: PathBuf,
    },
}

#[derive(Args)]
pub struct ModulesArgs {
    #[command(subcommand)]
    pub command: ModulesCommand,
}

#[derive(Subcommand)]
pub enum ModulesCommand {
    /// List all scanner modules.
    List,
    /// Show info about a specific module.
    Info {
        /// Module ID.
        module: String,
    },
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration file.
    Validate,
    /// Show current configuration (secrets redacted).
    Show,
}

// ── Value enums for clap ────────────────────────────────────────────────

#[derive(Clone, ValueEnum)]
pub enum PerspectiveArg {
    Neighbor,
    Unauthenticated,
    Authenticated,
    Privileged,
}

impl From<PerspectiveArg> for rikitikitavi_core::Perspective {
    fn from(arg: PerspectiveArg) -> Self {
        match arg {
            PerspectiveArg::Neighbor => Self::Neighbor,
            PerspectiveArg::Unauthenticated => Self::Unauthenticated,
            PerspectiveArg::Authenticated => Self::Authenticated,
            PerspectiveArg::Privileged => Self::Privileged,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum NetworkArg {
    Auto,
    Wifi,
    Ethernet,
    External,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ReportFormatArg {
    Json,
    Html,
    Csv,
}

#[derive(Clone, ValueEnum)]
pub enum ThemeArg {
    Dark,
    Light,
    Hacker,
    Accessible,
}
