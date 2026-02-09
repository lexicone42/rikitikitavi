// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #7: Building CLIs with clap
// ============================================================================
//
// `clap` is Rust's most popular CLI argument parsing library. We use the
// "derive" API which generates the parser from struct/enum definitions.
//
// Our CLI structure in crates/rikitikitavi/src/cli.rs:
//   rikitikitavi scan --perspective unauthenticated --modules dns,ports
//   rikitikitavi tui --watch --theme hacker
//   rikitikitavi unifi scan --local
//   rikitikitavi modules list

use clap::{Parser, Subcommand, Args, ValueEnum};
use std::path::PathBuf;

// ── TOP-LEVEL CLI ─────────────────────────────────────────────────────────

/// The top-level struct represents the entire CLI.
/// `#[derive(Parser)]` generates the argument parser.
#[derive(Parser)]
#[command(
    name = "rikitikitavi",
    about = "Home network security auditor",  // shown in --help
    version,                                    // auto from Cargo.toml
)]
pub struct Cli {
    // Global arguments (available to all subcommands)

    /// Path to configuration file.
    #[arg(
        short,          // -c
        long,           // --config
        global = true,  // Available on all subcommands
        env = "RIKITIKITAVI_CONFIG",  // Can also be set via env var
    )]
    pub config: Option<PathBuf>,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

// ── SUBCOMMANDS ───────────────────────────────────────────────────────────

/// Each variant becomes a subcommand (rikitikitavi scan, rikitikitavi tui, etc.)
#[derive(Subcommand)]
pub enum Command {
    /// Run a network security scan.
    Scan(ScanArgs),

    /// Launch the interactive TUI.
    Tui,

    /// List scanner modules.
    Modules(ModulesArgs),

    /// Show version info.
    Version {
        /// Show detailed info.
        #[arg(long)]
        verbose: bool,
    },
}

// ── COMMAND ARGUMENTS ─────────────────────────────────────────────────────

/// Arguments for the `scan` subcommand.
#[derive(Args)]
pub struct ScanArgs {
    /// Attacker perspective to simulate.
    #[arg(long, default_value = "unauthenticated")]
    //          ↑ Default value if not provided
    pub perspective: PerspectiveArg,

    /// Comma-separated list of scanner modules.
    #[arg(long, value_delimiter = ',')]
    //          ↑ --modules dns,ports,wifi → vec!["dns", "ports", "wifi"]
    pub modules: Option<Vec<String>>,

    /// Output file path.
    #[arg(short, long)]  // -o or --output
    pub output: Option<PathBuf>,

    /// Quick scan (fewer checks).
    #[arg(long)]
    pub quick: bool,

    /// Dry run — show what would happen.
    #[arg(long)]
    pub dry_run: bool,
}

// ── NESTED SUBCOMMANDS ────────────────────────────────────────────────────

/// Arguments for `rikitikitavi modules`
#[derive(Args)]
pub struct ModulesArgs {
    #[command(subcommand)]
    pub command: ModulesCommand,
}

/// `rikitikitavi modules list` or `rikitikitavi modules info <module>`
#[derive(Subcommand)]
pub enum ModulesCommand {
    /// List all modules.
    List,
    /// Show info about a module.
    Info {
        /// Module ID (e.g., "dns", "ports").
        module: String,  // Positional argument (no -- prefix)
    },
}

// ── VALUE ENUMS ───────────────────────────────────────────────────────────

/// clap can parse enum values from strings automatically!
#[derive(Clone, ValueEnum)]
pub enum PerspectiveArg {
    Neighbor,
    Unauthenticated,
    Authenticated,
    Privileged,
}
// With this, clap accepts: --perspective neighbor, --perspective authenticated, etc.
// Invalid values show a nice error message listing valid options.

// ── HOW IT ALL FITS TOGETHER ──────────────────────────────────────────────

fn main() {
    // In one line, clap parses args, validates them, and gives you a struct!
    let cli = Cli::parse();

    // Now use pattern matching to handle each command:
    match cli.command {
        Command::Scan(args) => {
            if args.dry_run {
                println!("Dry run — would scan with perspective: {:?}", args.perspective as u8);
                if let Some(modules) = &args.modules {
                    println!("Modules: {}", modules.join(", "));
                }
            } else {
                println!("Scanning...");
            }
        }
        Command::Tui => println!("Launching TUI..."),
        Command::Modules(args) => {
            match args.command {
                ModulesCommand::List => println!("All modules: dns, ports, wifi, ..."),
                ModulesCommand::Info { module } => println!("Info about: {module}"),
            }
        }
        Command::Version { verbose } => {
            println!("rikitikitavi 0.1.0");
            if verbose {
                println!("Built with Rust on Linux");
            }
        }
    }
}

// ── TRY IT ────────────────────────────────────────────────────────────────
//
// Run these commands from the project root:
//
//   cargo run -- --help
//   cargo run -- scan --help
//   cargo run -- scan --dry-run
//   cargo run -- scan --perspective neighbor --modules dns,ports
//   cargo run -- modules list
//   cargo run -- modules info dns
//   cargo run -- version --verbose
