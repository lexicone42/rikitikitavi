# rikitikitavi

A home network security auditor written in Rust. Scans your local network for
common misconfigurations, weak services, exposed ports, and provides actionable
remediation guidance.

Named after [Rikki-Tikki-Tavi](https://en.wikipedia.org/wiki/Rikki-Tikki-Tavi),
the vigilant mongoose that protects the household.

## Features

**18 Security Scanners** with two-phase adaptive scanning

Phase 1 discovers your network, then Phase 2 uses those discoveries to run
deep, targeted checks — only probing services that actually exist.

| Scanner | What it checks |
|---------|---------------|
| **Network Discovery** | Interface enumeration, ARP cache, device count |
| **Port Scanner** | TCP connect scan of 42+ common ports across all LAN hosts |
| **Device Fingerprinting** | MAC OUI vendor lookup, port-based device classification |
| **DNS Security** | Resolver config, DNSSEC validation, DNS rebinding, cross-resolver validation |
| **Router Security** | Admin panel exposure, HTTPS enforcement, UPnP |
| **WiFi Security** | Nearby network encryption grading (Open/WEP/WPA/WPA2/WPA3) |
| **External Exposure** | Public IP detection, port forwarding (NAT traversal) checks |
| **Credential Hygiene** | Anonymous FTP, SMB exposure, Telnet, RDP, HTTP admin no-auth |
| **Network Isolation** | Flat network detection, inter-VLAN routing, subnet analysis |
| **Service Banners** | SSH version, HTTP headers, banner grabbing |
| **SSL/TLS Certificates** | Self-signed, expired, weak keys, TLS 1.0/1.1 |
| **mDNS/SSDP Discovery** | Service advertisement enumeration, UPnP device discovery |
| **HTTP Security Audit** | Missing security headers, default pages, admin path enumeration |
| **Database Security** | Auth-less Redis/MongoDB/MySQL/Elasticsearch/Memcached, version fingerprinting |
| **SMB Security** | SMBv1 (EternalBlue-vulnerable) detection, NetBIOS exposure |
| **ARP Security** | ARP spoofing detection (duplicate MACs/IPs, broadcast MACs) |
| **DHCP Security** | Rogue DHCP server detection, APIPA address detection |
| **Neighbor Discovery** | IPv6 neighbor table analysis |

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

Interactive TUI built with [ratatui](https://ratatui.rs/) with full mouse
support:
- Click footer tabs to navigate screens
- Click table rows to select findings/devices
- Right-click to open detail views
- Scroll wheel to move selection
- Keyboard: `D` Dashboard, `N` Network, `F` Findings, `A` Attacks, `S` Scan, `E` Export, `Q` Quit

**Two-Phase Adaptive Scanning**

```
Phase 1 (Discovery)          Phase 2 (Deep Analysis)
┌─────────┐                  ┌──────────────┐
│ Network  │─┐               │ DNS Security │
│ Ports    │─┤── enrich ──>  │ SSL/TLS      │
│ Device   │─┘   devices     │ Database     │
└─────────┘                  │ SMB          │
                             │ ARP/DHCP     │
    Discovers IPs,           │ Credentials  │
    open ports,              │ HTTP Audit   │
    device types             │ ... (14 more)│
                             └──────────────┘
                             Uses discovered ports
                             to target checks
```

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

# Scan with HTML report
rikitikitavi scan --format html --output report.html
```

### Interactive TUI

```bash
rikitikitavi tui
```

Supports keyboard navigation and full mouse interaction (click, right-click,
scroll wheel).

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
├── rikitikitavi          CLI binary, two-phase scan orchestration
├── rikitikitavi-core     Severity, Perspective, ScanError enums
├── rikitikitavi-models   Finding, Device, ScanContext, config types
├── rikitikitavi-network  Cross-platform network discovery (ARP, routes, interfaces, WiFi)
├── rikitikitavi-scanners Scanner trait + 18 scanner implementations
├── rikitikitavi-analysis Risk scoring + attack path generation
├── rikitikitavi-export   JSON, CSV, HTML, OCSF/Security Lake output
├── rikitikitavi-tui      Terminal UI (ratatui + crossterm, mouse support)
└── rikitikitavi-unifi    UniFi controller API client + scanner
```

Key design decisions:
- **`unsafe_code = "forbid"`** across the entire workspace
- **Clippy pedantic + nursery** with `-D warnings` (zero tolerance)
- **`async_trait`** for the Scanner interface, **tokio** runtime
- **Two-phase adaptive scanning** — discovery first, then targeted deep analysis
- **Platform parsing functions take `&str`** for unit testability; public
  functions handle file/command I/O
- **314 tests** including 50+ property-based tests (proptest)

## Findings Format

Each finding includes:
- **Severity**: Critical, High, Medium, Low, Info
- **Scanner ID**: which scanner produced it
- **Title and Description**: human-readable explanation
- **Affected host/port/service** (when applicable)
- **CWE reference** (e.g., CWE-319 for cleartext transmission)
- **Remediation steps** with estimated effort

Example:
```
 CRIT  Redis accessible without authentication on 192.168.1.50:6379
       CWE-306 | Remediation: Enable Redis AUTH, bind to 127.0.0.1

 HIGH  SMBv1 enabled on 192.168.1.30:445
       CWE-327 | Remediation: Disable SMBv1 (EternalBlue/WannaCry vulnerable)

 MED   DNSSEC validation not enforced
       CWE-350 | Remediation: Switch to Quad9 (9.9.9.9) or Cloudflare (1.1.1.1)
```

## Development

```bash
# Run all tests (314 tests including 50+ property-based)
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
