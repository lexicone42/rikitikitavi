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

    /// Logging verbosity (error, warn, info, debug, trace).
    #[arg(short, long, global = true, default_value = "warn")]
    pub log_level: String,

    /// Log output format. Spans report their duration when they close.
    #[arg(long, global = true, default_value = "text")]
    pub log_format: LogFormat,

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

    /// Re-check findings from the last full scan against only the affected hosts.
    #[command(after_help = "Exit codes:\n  \
        0  every verified finding is resolved (or none were selected)\n  \
        1  error\n  \
        3  at least one finding is still present\n  \
        4  none still present, but some are inconclusive (host offline, scanner \
        error or timeout, or the finding cannot be replayed by a unicast probe)")]
    Verify(VerifyArgs),

    /// Markdown fix checklist from the last full scan (Do now / This weekend / Replace / Accepted).
    FixPlan(FixPlanArgs),

    /// Markdown network-segmentation proposal from the last full scan (zones, allow rules,
    /// mDNS proxy list). Text only; configures nothing.
    SegmentPlan(SegmentPlanArgs),

    /// Generate a report from the last scan.
    Report(ReportArgs),

    /// UniFi-specific commands.
    #[cfg(feature = "unifi")]
    Unifi(UniFiArgs),

    /// AWS Security Lake commands. Not yet implemented; every subcommand exits non-zero.
    Aws(AwsArgs),

    /// List available scanner modules.
    Modules(ModulesArgs),

    /// Interactive setup wizard.
    Init,

    /// Validate configuration.
    Config(ConfigArgs),

    /// Passive `WiFi` monitoring — listen for 802.11 management frames.
    #[cfg(feature = "monitor")]
    Monitor(MonitorArgs),

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
    /// Attacker perspective to simulate [default: config `scan.perspective`, else unauthenticated].
    #[arg(long)]
    pub perspective: Option<PerspectiveArg>,

    /// Network access mode. Not yet implemented: only `auto` is accepted.
    #[arg(long, default_value = "auto")]
    pub network: NetworkArg,

    /// `WiFi` SSID. Not yet implemented; passing it is an error.
    #[arg(long)]
    pub ssid: Option<String>,

    /// `WiFi` password. Not yet implemented; passing it is an error.
    #[arg(long)]
    pub password: Option<String>,

    /// Ethernet interface name. Not yet implemented; passing it is an error.
    #[arg(long)]
    pub interface: Option<String>,

    /// Comma-separated list of scanner modules to run.
    #[arg(long, value_delimiter = ',')]
    pub modules: Option<Vec<String>>,

    /// Output file path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format (json, html, csv, ocsf or prometheus).
    #[arg(long, default_value = "json")]
    pub format: ReportFormatArg,

    /// Exit with code 2 if any finding is at or above this severity.
    #[arg(long, default_value = "never")]
    pub fail_on: FailOnArg,

    /// Suppress findings whose fingerprint is listed in this baseline file.
    /// The file must exist and be readable.
    #[arg(long)]
    pub suppress: Option<PathBuf>,

    /// Accepted-risk ledger (YAML). Listed findings stay in the report, marked accepted,
    /// and are left out of the risk score, grades, priority actions and `--fail-on`.
    /// Entries past `expires` are ignored. Invalid or oversize files are an error.
    #[arg(long)]
    pub accept_file: Option<PathBuf>,

    /// Write all current findings' fingerprints to this file for use with `--suppress`.
    #[arg(long)]
    pub write_baseline: Option<PathBuf>,

    /// Flag discovered devices not listed in this known-devices file as new-device findings.
    /// The file must exist and be readable.
    #[arg(long)]
    pub known_devices: Option<PathBuf>,

    /// Write all discovered device identifiers to this file for use with `--known-devices`.
    #[arg(long)]
    pub write_known_devices: Option<PathBuf>,

    /// Evaluate a YAML declarative-rules file against the scan facts and add its
    /// findings. The file must exist and be readable. See examples/rules/.
    #[arg(long)]
    pub rules: Option<PathBuf>,

    /// Generate attack path analysis.
    #[arg(long)]
    pub attack_paths: bool,

    /// Quick scan (fewer checks, faster).
    #[arg(long, conflicts_with = "aggressive")]
    pub quick: bool,

    /// Aggressive scan (thorough, may trigger alerts).
    #[arg(long)]
    pub aggressive: bool,

    /// Upload results after scanning. Not yet implemented; passing it is an error.
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

    /// Scan with `UniFi` local API access. Not yet implemented; passing it is an error.
    #[cfg(feature = "unifi")]
    #[arg(long)]
    pub unifi_local: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Only findings at or above this severity [default: low, or none with --finding].
    #[arg(long)]
    pub severity: Option<SeverityArg>,

    /// Only findings on these hosts (repeatable or comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub ip: Vec<std::net::IpAddr>,

    /// Only these findings, by fingerprint or finding id (repeatable or comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub finding: Vec<String>,

    /// Allow replaying login checks (`credentials` findings).
    #[arg(long)]
    pub aggressive: bool,

    /// Accepted-risk ledger (YAML, as for `scan --accept-file`); listed findings are not re-checked.
    #[arg(long)]
    pub accept_file: Option<PathBuf>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: VerifyFormatArg,

    /// Write the report to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct FixPlanArgs {
    /// Accepted-risk ledger (YAML, as for `scan --accept-file`); fills the Accepted section.
    #[arg(long)]
    pub accept_file: Option<PathBuf>,

    /// Write the plan to this file (mode 0600) instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct SegmentPlanArgs {
    /// Write the plan to this file (mode 0600) instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum VerifyFormatArg {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for rikitikitavi_core::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

#[derive(Args)]
pub struct TuiArgs {
    /// Re-scan automatically every `--interval` seconds.
    #[arg(long)]
    pub watch: bool,

    /// Scan interval in seconds (watch mode), minimum 5.
    #[arg(long, default_value = "300", value_parser = clap::value_parser!(u64).range(5..))]
    pub interval: u64,

    /// TUI color theme.
    #[arg(long, default_value = "dark")]
    pub theme: ThemeArg,

    /// Attacker perspective [default: config `scan.perspective`, else unauthenticated].
    #[arg(long)]
    pub perspective: Option<PerspectiveArg>,

    /// Network access mode. Not yet implemented: only `auto` is accepted.
    #[arg(long, default_value = "auto")]
    pub network: NetworkArg,

    /// `WiFi` SSID. Not yet implemented; passing it is an error.
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
        /// Disable TLS certificate validation (self-signed controllers).
        /// WARNING: exposes admin credentials to on-path attackers.
        #[arg(long)]
        insecure: bool,
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

#[cfg(feature = "monitor")]
#[derive(Args)]
pub struct MonitorArgs {
    /// `WiFi` interface to monitor (auto-detected if omitted).
    #[arg(long)]
    pub interface: Option<String>,

    /// Monitoring duration in seconds, minimum 1.
    #[arg(long, default_value = "60", value_parser = clap::value_parser!(u64).range(1..))]
    pub duration: u64,

    /// Known BSSID(s) to exclude from rogue AP detection (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub known_bssids: Vec<String>,

    /// Home network SSID for rogue AP detection.
    #[arg(long)]
    pub home_ssid: Option<String>,

    /// Output file path.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format.
    #[arg(long, default_value = "json")]
    pub format: ReportFormatArg,

    /// Save results to scan history.
    #[arg(long)]
    pub save: bool,

    /// Skip confirmation prompts (e.g. macOS connection-drop warning).
    #[arg(long)]
    pub yes: bool,
}

// Value enums for clap.

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

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ReportFormatArg {
    Json,
    Html,
    Csv,
    Ocsf,
    /// Prometheus text exposition 0.0.4, for `node_exporter`'s textfile collector.
    Prometheus,
}

/// Minimum severity that makes `scan` exit non-zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FailOnArg {
    /// Never fail on findings.
    Never,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, ValueEnum)]
pub enum ThemeArg {
    Dark,
    Light,
    Hacker,
    Accessible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tui")]
    #[test]
    fn tui_interval_rejects_below_five() {
        assert!(Cli::try_parse_from(["rikitikitavi", "tui", "--interval", "0"]).is_err());
        assert!(Cli::try_parse_from(["rikitikitavi", "tui", "--interval", "4"]).is_err());
        let cli = Cli::try_parse_from(["rikitikitavi", "tui", "--interval", "5"]).unwrap();
        let Command::Tui(args) = cli.command else {
            panic!("expected tui command");
        };
        assert_eq!(args.interval, 5);
    }

    #[cfg(feature = "monitor")]
    #[test]
    fn monitor_duration_rejects_zero() {
        assert!(Cli::try_parse_from(["rikitikitavi", "monitor", "--duration", "0"]).is_err());
        let cli = Cli::try_parse_from(["rikitikitavi", "monitor", "--duration", "1"]).unwrap();
        let Command::Monitor(args) = cli.command else {
            panic!("expected monitor command");
        };
        assert_eq!(args.duration, 1);
    }

    #[test]
    fn scan_quick_conflicts_with_aggressive() {
        assert!(Cli::try_parse_from(["rikitikitavi", "scan", "--quick", "--aggressive"]).is_err());
        assert!(Cli::try_parse_from(["rikitikitavi", "scan", "--quick"]).is_ok());
        assert!(Cli::try_parse_from(["rikitikitavi", "scan", "--aggressive"]).is_ok());
    }

    #[test]
    fn scan_defaults_parse() {
        let cli = Cli::try_parse_from(["rikitikitavi", "scan"]).unwrap();
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(args.fail_on, FailOnArg::Never);
        assert!(matches!(args.network, NetworkArg::Auto));
        assert!(args.accept_file.is_none());
    }

    #[test]
    fn fix_plan_parses() {
        let cli = Cli::try_parse_from(["rikitikitavi", "fix-plan"]).unwrap();
        let Command::FixPlan(args) = cli.command else {
            panic!("expected fix-plan command");
        };
        assert!(args.accept_file.is_none() && args.output.is_none());
        let cli = Cli::try_parse_from([
            "rikitikitavi",
            "fix-plan",
            "--accept-file",
            "a.yaml",
            "-o",
            "plan.md",
        ])
        .unwrap();
        let Command::FixPlan(args) = cli.command else {
            panic!("expected fix-plan command");
        };
        assert_eq!(args.output.unwrap(), PathBuf::from("plan.md"));
    }

    #[test]
    fn segment_plan_parses() {
        let cli = Cli::try_parse_from(["rikitikitavi", "segment-plan"]).unwrap();
        let Command::SegmentPlan(args) = cli.command else {
            panic!("expected segment-plan command");
        };
        assert!(args.output.is_none());
        let cli = Cli::try_parse_from(["rikitikitavi", "segment-plan", "-o", "zones.md"]).unwrap();
        let Command::SegmentPlan(args) = cli.command else {
            panic!("expected segment-plan command");
        };
        assert_eq!(args.output.unwrap(), PathBuf::from("zones.md"));
        assert!(
            Cli::try_parse_from(["rikitikitavi", "segment-plan", "--accept-file", "a"]).is_err()
        );
    }

    #[test]
    fn accept_file_parses_on_scan_and_verify() {
        let cli = Cli::try_parse_from(["rikitikitavi", "scan", "--accept-file", "a.yaml"]).unwrap();
        let Command::Scan(args) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(args.accept_file.unwrap(), PathBuf::from("a.yaml"));
        let cli =
            Cli::try_parse_from(["rikitikitavi", "verify", "--accept-file", "a.yaml"]).unwrap();
        let Command::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.accept_file.unwrap(), PathBuf::from("a.yaml"));
    }
    #[test]
    fn verify_parses_filters() {
        let cli = Cli::try_parse_from([
            "rikitikitavi",
            "verify",
            "--severity",
            "high",
            "--ip",
            "10.0.0.1,10.0.0.2",
            "--finding",
            "00000000000000ab",
            "--format",
            "json",
        ])
        .unwrap();
        let Command::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert_eq!(args.severity, Some(SeverityArg::High));
        assert_eq!(args.ip.len(), 2);
        assert_eq!(args.finding, ["00000000000000ab"]);
        assert_eq!(args.format, VerifyFormatArg::Json);
        assert!(!args.aggressive);
        assert!(args.accept_file.is_none());
        assert!(Cli::try_parse_from(["rikitikitavi", "verify", "--ip", "nope"]).is_err());
    }

    #[test]
    fn verify_defaults() {
        let cli = Cli::try_parse_from(["rikitikitavi", "verify"]).unwrap();
        let Command::Verify(args) = cli.command else {
            panic!("expected verify command");
        };
        assert!(args.severity.is_none() && args.ip.is_empty() && args.finding.is_empty());
        assert_eq!(args.format, VerifyFormatArg::Text);
    }

    #[test]
    fn log_format_defaults_to_text_and_accepts_json() {
        let cli = Cli::try_parse_from(["rikitikitavi", "version"]).unwrap();
        assert_eq!(cli.log_format, LogFormat::Text);
        let cli = Cli::try_parse_from(["rikitikitavi", "scan", "--log-format", "json"]).unwrap();
        assert_eq!(cli.log_format, LogFormat::Json);
        assert!(Cli::try_parse_from(["rikitikitavi", "--log-format", "xml", "version"]).is_err());
    }
}
