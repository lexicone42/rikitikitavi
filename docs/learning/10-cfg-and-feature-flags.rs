// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #10: Feature Flags and Conditional Compilation
// ============================================================================
//
// This file explains how rikitikitavi uses Cargo feature flags and #[cfg]
// attributes to make parts of the codebase optional. Key concepts:
// conditional compilation, optional dependencies, and platform-specific code.
//
// ── CARGO FEATURE FLAGS ─────────────────────────────────────────────────────
//
// In the binary crate's Cargo.toml:
//
//   [features]
//   default = ["tui", "unifi"]
//   tui = ["dep:rikitikitavi-tui", "dep:ratatui", "dep:crossterm"]
//   unifi = ["dep:rikitikitavi-unifi"]
//   monitor = ["rikitikitavi-scanners/monitor", "rikitikitavi-network/monitor"]
//   minimal = []
//
// What this means:
//
// - `default = ["tui", "unifi"]` — building with `cargo build` includes TUI
//   and UniFi support. WiFi monitoring is NOT default (needs libpcap).
//
// - `tui = ["dep:rikitikitavi-tui", ...]` — the "tui" feature enables three
//   optional dependencies. `dep:` prefix means "this dependency is only
//   compiled when this feature is active."
//
// - `monitor = ["rikitikitavi-scanners/monitor"]` — features propagate to
//   dependencies! Enabling "monitor" on the binary also enables "monitor"
//   on the scanners and network crates.
//
// - `minimal = []` — an empty feature for minimal builds (no TUI, no UniFi,
//   no WiFi monitoring).
//
// ── USING FEATURES IN CODE ──────────────────────────────────────────────────
//
// Features control what code is compiled:
//
//   #[cfg(feature = "tui")]
//   mod tui_commands;
//
//   #[cfg(feature = "tui")]
//   use rikitikitavi_tui::App;
//
//   fn main() {
//       match cli.command {
//           #[cfg(feature = "tui")]
//           Command::Tui(args) => cmd_tui(args),
//
//           #[cfg(feature = "monitor")]
//           Command::Monitor(args) => cmd_monitor(args),
//
//           Command::Scan(args) => cmd_scan(args),  // always available
//       }
//   }
//
// If you build without `--features tui`, the TUI command literally doesn't
// exist in the binary. It's not hidden — it's not compiled at all.
//
// ── OPTIONAL DEPENDENCIES ───────────────────────────────────────────────────
//
// In Cargo.toml:
//
//   [dependencies]
//   rikitikitavi-tui = { path = "../rikitikitavi-tui", optional = true }
//   ratatui = { workspace = true, optional = true }
//   crossterm = { workspace = true, optional = true }
//
// `optional = true` means this dependency is only pulled in when its feature
// is enabled. This is how `cargo install` without `--features monitor`
// avoids needing libpcap — the `pcap` crate is never compiled.
//
// ── PLATFORM-SPECIFIC CODE ──────────────────────────────────────────────────
//
// Beyond features, #[cfg] also handles platform differences:
//
//   #[cfg(target_os = "linux")]
//   pub fn detect_gateway() -> Option<IpAddr> {
//       let contents = std::fs::read_to_string("/proc/net/route").ok()?;
//       parse_proc_route(&contents)
//           .into_iter()
//           .find(|r| r.is_default)
//           .map(|r| r.gateway)
//   }
//
//   #[cfg(target_os = "macos")]
//   pub fn detect_gateway() -> Option<IpAddr> {
//       let output = Command::new("route")
//           .args(["-n", "get", "default"])
//           .output().ok()?;
//       parse_route_output(&String::from_utf8_lossy(&output.stdout))
//   }
//
// The compiler picks ONE of these based on the target platform. The other
// doesn't exist in the binary — not even as dead code.
//
// ── THE TEST TRICK: cfg(any(..., test)) ─────────────────────────────────────
//
// Problem: the macOS parser is only compiled on macOS. But our CI runs on
// Linux. How do we test the macOS parser?
//
//   #[cfg(any(target_os = "macos", test))]
//   fn parse_arp_command_output(contents: &str) -> Vec<ArpEntry> {
//       contents.lines().filter_map(|line| {
//           // Parse "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
//       }).collect()
//   }
//
// `#[cfg(any(target_os = "macos", test))]` means:
//   - On macOS: always compiled (used at runtime)
//   - On Linux: only compiled during `cargo test` (for testing only)
//
// Since the parser is a pure function taking `&str`, it doesn't need a
// real macOS system to test — just the string format that macOS produces.
//
// ── FEATURE FLAGS IN THE SCANNER CRATE ──────────────────────────────────────
//
// The scanners crate has its own feature propagation:
//
//   # In rikitikitavi-scanners/Cargo.toml
//   [features]
//   monitor = ["rikitikitavi-network/monitor", "dep:pcap"]
//
// When the binary enables "monitor", it propagates:
//
//   binary (monitor) → scanners (monitor) → network (monitor)
//                                         → pcap crate
//
// This means the passive WiFi scanner and pcap dependency are ONLY compiled
// when you explicitly ask for them.
//
// ── CONDITIONAL MODULE INCLUSION ────────────────────────────────────────────
//
// Entire modules can be feature-gated:
//
//   // In rikitikitavi-scanners/src/lib.rs
//   #[cfg(feature = "monitor")]
//   pub mod passive_wifi;
//
//   #[cfg(feature = "monitor")]
//   pub use passive_wifi::PassiveWifiScanner;
//
// And in the scanner registry:
//
//   pub fn new() -> Self {
//       let mut scanners: Vec<Box<dyn Scanner>> = vec![
//           Box::new(NetworkScanner),
//           Box::new(PortScanner),
//           // ... always-available scanners ...
//       ];
//
//       #[cfg(feature = "monitor")]
//       scanners.push(Box::new(PassiveWifiScanner));
//
//       Self { scanners }
//   }
//
// ── BUILD-TIME VS RUNTIME CHECKS ───────────────────────────────────────────
//
// Important distinction:
//
//   #[cfg(feature = "tui")]     ← COMPILE TIME: code doesn't exist without feature
//   if cfg!(feature = "tui")    ← RUNTIME: code exists but branch is optimized away
//
// The `#[cfg(...)]` attribute removes code entirely — it's as if you deleted
// those lines. The `cfg!(...)` macro evaluates to `true` or `false` at compile
// time, so the optimizer removes the dead branch, but the code must still
// type-check.
//
// We use `#[cfg]` (attributes) almost everywhere because we want the code
// to truly not exist — no binary size cost, no compilation cost.
//
// ── INSTALLING WITH FEATURES ────────────────────────────────────────────────
//
// Users choose what they want:
//
//   # Default: TUI + UniFi, no WiFi monitoring
//   cargo install --git https://github.com/lexicone42/rikitikitavi
//
//   # Everything including WiFi monitoring (needs libpcap)
//   cargo install --git https://github.com/lexicone42/rikitikitavi --features monitor
//
//   # Minimal: just the scanner, no TUI, no UniFi
//   cargo install --git https://github.com/lexicone42/rikitikitavi --no-default-features
//
// ── KEY TAKEAWAYS ───────────────────────────────────────────────────────────
//
// 1. Feature flags make dependencies and code OPTIONAL — not compiled if unused
// 2. `dep:crate_name` in features means the dependency is only pulled in when
//    the feature is active
// 3. Features propagate through the dependency tree (binary → scanners → network)
// 4. #[cfg(target_os = "...")] handles platform differences at zero cost
// 5. #[cfg(any(target_os = "macos", test))] lets you test platform code in CI
// 6. Making expensive dependencies (libpcap) non-default keeps `cargo install` simple

fn main() {
    println!("Read the comments above to learn about feature flags and conditional compilation.");
}
