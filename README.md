# rikitikitavi

A home network security auditor written in Rust. Scans your local network for
common misconfigurations, weak services, exposed ports, and provides actionable
remediation guidance.

Named after [Rikki-Tikki-Tavi](https://en.wikipedia.org/wiki/Rikki-Tikki-Tavi),
the vigilant mongoose that protects the household.

## Features

**10 Security Scanners**

| Scanner | What it checks |
|---------|---------------|
| Network Discovery | Interface enumeration, ARP cache, device count |
| Port Scanner | TCP connect scan of 42 common ports across all LAN hosts |
| DNS Security | Resolver configuration, DNSSEC validation, DNS-over-HTTPS |
| Router Security | Admin panel exposure, HTTPS enforcement, UPnP |
| Service Banners | SSH version, Redis auth, Telnet detection, HTTP headers |
| Device Fingerprinting | MAC OUI vendor lookup, port-based device classification |
| Credential Hygiene | Anonymous FTP, SMB exposure, HTTP admin without auth |
| External Exposure | Public IP detection, port forwarding (NAT traversal) checks |
| WiFi Security | Nearby network encryption grading (Open/WEP/WPA/WPA2/WPA3) |
| Network Isolation | Flat network detection, inter-VLAN routing, subnet analysis |

**UniFi Integration**

Deep security auditing for Ubiquiti UniFi networks:
- WLAN encryption and PMF (802.11w) configuration audit
- Firewall rule analysis (overly permissive rules, disabled rules)
- Device firmware version reporting
- IDS/IPS event summary
- On-device detection (Dream Machine, Cloud Gateway, etc.)

**Cross-Platform**

- **Linux**: reads `/proc/net/route`, `/proc/net/arp`, `/sys/class/net/`
- **macOS**: uses `ifconfig`, `route`, `arp`, `system_profiler` (WiFi)

**Terminal UI**

Interactive TUI built with [ratatui](https://ratatui.rs/) for browsing scan
results, with background re-scan support.

## Installation

```bash
# Clone and build
git clone https://github.com/lexicone42/rikitikitavi.git
cd rikitikitavi
cargo build --release

# The binary is at target/release/rikitikitavi
```

Requires Rust 1.75+. No system dependencies beyond standard OS tools.

## Usage

### Quick Scan

```bash
# Run all scanners against the local network
rikitikitavi scan

# Scan with JSON output
rikitikitavi scan --format json --output results.json

# Scan with CSV output
rikitikitavi scan --format csv --output results.csv
```

### Interactive TUI

```bash
rikitikitavi tui
```

Keys: `d` Dashboard, `n` Network Map, `f` Findings, `s` Re-scan, `e` Export, `q` Quit

### UniFi Scanning

```bash
# Scan a remote UniFi controller
rikitikitavi unifi scan --controller https://192.168.1.1 --username admin --password secret

# Use API token (UniFi OS 2.x+)
rikitikitavi unifi scan --controller https://192.168.1.1 --token YOUR_API_TOKEN
```

### Populating the ARP Cache (Linux)

By default the scanner reads the OS ARP cache, which only contains recently
contacted hosts. For a more complete scan, pre-populate the cache:

```bash
# Ping sweep + ARP cache population (requires sudo)
sudo /tmp/rikitikitavi-nethelper.sh
rikitikitavi scan
```

## Architecture

```
rikitikitavi (9-crate workspace)
├── rikitikitavi          CLI binary, scan orchestration
├── rikitikitavi-core     Severity, Perspective, ScanError enums
├── rikitikitavi-models   Finding, Device, ScanContext types
├── rikitikitavi-network  Cross-platform network discovery
├── rikitikitavi-scanners Scanner trait + 10 scanner implementations
├── rikitikitavi-analysis Risk scoring engine
├── rikitikitavi-export   JSON, CSV, HTML, Security Lake output
├── rikitikitavi-tui      Terminal UI (ratatui + crossterm)
└── rikitikitavi-unifi    UniFi controller API client + scanner
```

Key design decisions:
- **`unsafe_code = "forbid"`** across the entire workspace
- **Clippy pedantic + nursery** with `-D warnings` (zero tolerance)
- **`async_trait`** for the Scanner interface, **tokio** runtime
- **Platform parsing functions take `&str`** for unit testability; public
  functions handle file/command I/O

## Findings Format

Each finding includes:
- **Severity**: Critical, High, Medium, Low, Info
- **Scanner ID**: which scanner produced it
- **Title and Description**: human-readable explanation
- **Affected host/port/service** (when applicable)
- **CWE reference** (e.g., CWE-319 for cleartext transmission)
- **Remediation steps** with estimated effort

## Development

```bash
# Run all tests (92 tests across workspace)
cargo test --workspace

# Clippy (pedantic + nursery, must be clean)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build optimized release binary
cargo build --release

# Build size-optimized for embedded (UniFi devices)
cargo build --profile release-embedded
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
