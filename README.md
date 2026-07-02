# rikitikitavi

```
                                .------.__
   /\      ____________________/ o    o   >--~~<§
  /  `----'                      `--ww--'
 (              .----.   .----.     /        "When I was a young man I was led to believe
  \   .--------|      |-|      |--'           there were organisations to kill my snakes for me
   `--'        |      | |      |              I.E. the church, I.E. the government, I.E. school
               `------' `------'              But when I got a little older
                                              I learned I had to kill them myself"

                                                                             ─ Donovan
```

A home network security auditor written in Rust. Scans your local network for
misconfigurations, weak services, exposed ports, and provides actionable
remediation guidance.

Named after [Rikki-Tikki-Tavi](https://en.wikipedia.org/wiki/Rikki-Tikki-Tavi),
the vigilant mongoose from Kipling's *Jungle Book* — and the
[Donovan song](https://www.youtube.com/watch?v=HsjYQ4sbR1c) about
learning to kill your own snakes. This one hunts security vulnerabilities.

## Quick Start

```bash
# Install from GitHub (Rust 1.88+ required)
cargo install --git https://github.com/lexicone42/rikitikitavi

# Run a scan
rikitikitavi scan

# Interactive terminal UI
rikitikitavi tui

# JSON output
rikitikitavi scan --format json --output results.json

# OCSF output for AWS Security Lake
rikitikitavi scan --format ocsf --output findings.ndjson
```

### WiFi Monitoring (optional)

Passive WiFi monitoring requires `libpcap-dev` and is not included by default:

```bash
# Install with WiFi monitoring support
cargo install --git https://github.com/lexicone42/rikitikitavi --features monitor

# On Debian/Ubuntu, install libpcap first:
sudo apt-get install libpcap-dev

# Then monitor WiFi traffic
sudo rikitikitavi monitor --interface wlan0
```

## Features

### 25 Security Scanners

Two-phase adaptive scanning: Phase 1 discovers your network, then Phase 2 runs
deep, targeted checks — only probing services that actually exist on your
network.

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
                             Runs concurrently,
                             skips irrelevant checks
```

| Scanner | What it checks |
|---------|---------------|
| **Network Discovery** | Interface enumeration, ARP cache, device count |
| **Port Scanner** | TCP connect scan of 42+ common ports across all LAN hosts |
| **Device Fingerprinting** | MAC OUI vendor lookup, port-based device classification |
| **DNS Security** | Resolver config, DNSSEC validation, DNS rebinding, cross-resolver checks |
| **Router Security** | Admin panel exposure, HTTPS enforcement, UPnP |
| **WiFi Security** | Nearby network encryption grading (Open/WEP/WPA/WPA2/WPA3) |
| **External Exposure** | Public IP detection, port forwarding (NAT traversal) checks |
| **Credential Hygiene** | Anonymous FTP, SMB exposure, Telnet, RDP, HTTP admin no-auth |
| **Network Isolation** | Flat network detection, inter-VLAN routing, subnet analysis |
| **Service Banners** | SSH version, HTTP headers, banner grabbing |
| **SSL/TLS Certificates** | Self-signed, expired, weak keys, TLS 1.0/1.1 |
| **mDNS/SSDP Discovery** | Service advertisement enumeration, UPnP device discovery |
| **HTTP Security Audit** | Missing security headers, default pages, admin path enumeration |
| **Database Security** | Auth-less Redis/MongoDB/MySQL/Elasticsearch/Memcached |
| **SMB Security** | SMBv1 (EternalBlue-vulnerable) detection, NetBIOS exposure |
| **ARP Security** | ARP spoofing detection (duplicate MACs/IPs, broadcast MACs) |
| **DHCP Security** | Rogue DHCP server detection, APIPA address detection |
| **SNMP** | Default community strings (`public`/`private`) over UDP; sysDescr leak |
| **MQTT** | Broker anonymous-access probe (CONNECT/CONNACK, non-destructive) |
| **Management Plane** | Unauthenticated Docker API, kubelet, and Kubernetes API exposure |
| **Printers** | CUPS/IPP (CVE-2024-4717x) + raw JetDirect (9100) exposure |
| **TR-069 / CWMP** | ISP remote-management (7547) reachable on the LAN |
| **RTSP / ONVIF** | IP-camera streams reachable without authentication |
| **UPnP-IGD** | Router WAN→LAN port forwards ("what's exposed to the internet?") |
| **Passive WiFi** | 802.11 frame analysis, rogue AP detection, deauth attacks *(feature: `monitor`)* |

### Exploit Intelligence & Confidence

Not every finding deserves equal panic. rikitikitavi layers three signals on top
of raw CVE/CVSS so a non-expert knows what to fix first:

- **Actively exploited (CISA KEV):** findings whose CVE is in the CISA Known
  Exploited Vulnerabilities catalog (an embedded snapshot, refreshed via
  `scripts/gen_kev_db.py`) are badged **⚠ ACTIVELY EXPLOITED**, escalated to at
  least High, and weighted more heavily in the risk score.
- **EPSS scores:** findings are enriched with the EPSS probability that each CVE
  will be exploited in the next 30 days (rendered as `EPSS 94%`). Fetched
  best-effort from FIRST.org at scan time — offline scans simply skip it.
- **Confidence tiers:** every finding declares how it was established —
  **✓ confirmed** (demonstrated, e.g. a login actually succeeded), *probable*
  (banner/version match), or **~ inferred** (heuristic). A version banner is
  only *probable* because a backported patch can leave an old version string,
  so confirmed findings stand out from ones worth double-checking.

### Scan Comparison

Track how your network security changes over time:

```bash
# Save a baseline scan
rikitikitavi scan

# Later, compare against previous
rikitikitavi scan --compare-previous

# Don't save to history
rikitikitavi scan --no-save
```

Comparison uses fingerprint-based diffing — findings are tracked by
`(scanner, title, ip, port)`, so they survive DHCP address changes when
devices keep their MAC. Severity changes are tracked separately from
new/resolved findings.

### UniFi Integration

Deep security auditing for Ubiquiti UniFi networks:

```bash
# Scan a remote UniFi controller
rikitikitavi unifi scan --controller https://192.168.1.1 \
    --user admin --password secret

# API token auth (UniFi OS 2.x+)
rikitikitavi unifi scan --controller https://192.168.1.1 \
    --token YOUR_API_TOKEN

# Self-signed controller cert? Opt out of TLS validation explicitly.
# By default the client validates the certificate before sending credentials.
rikitikitavi unifi scan --controller https://192.168.1.1 --user admin --password secret --insecure
```

- WLAN encryption and PMF (802.11w) configuration audit
- Firewall rule analysis (overly permissive rules, disabled rules)
- Device firmware version reporting
- IDS/IPS event summary
- On-device detection (Dream Machine, Cloud Gateway, etc.)

### OCSF Export for AWS Security Lake

Export findings in [OCSF 1.1](https://schema.ocsf.io/) format (class 2002:
Vulnerability Finding) as NDJSON — one JSON object per line, ready for AWS
Glue crawler to convert to Parquet and ingest into Security Lake.

```bash
rikitikitavi scan --format ocsf --output findings.ndjson

# Upload to S3 (partition path for Glue)
aws s3 cp findings.ndjson \
  s3://your-bucket/ext/rikitikitavi/region=us-east-1/accountId=123456789/eventDay=20260212/
```

### Terminal UI

Interactive TUI built with [ratatui](https://ratatui.rs/):

```
┌──────────────────────────────────────────────────────────────┐
│  RIKITIKITAVI ─ Home Network Security Auditor                │
├──────────────────────────────────────────────────────────────┤
│  Risk Score: 72/100 (C)      Scan: 2m 14s                   │
│  ████████████████░░░░░░░░    25 scanners, 47 findings        │
│                                                              │
│  CRIT ██  3    NEW   5       ┌─────────────────┐            │
│  HIGH ████  7  CHG   2       │   ,:::::::,     │            │
│  MED  ████████  18           │  ,::/^\:::::,   │            │
│  LOW  ██████  12             │ ,::( ^  ^)::,   │            │
│  INFO ███████  7             │ `:::\ w  /::;   │            │
│                              │   ';:`. .':;'   │            │
│                              │      ~§>        │            │
├───────────┬──────────────────┴─────────────────┤            │
│ D Dashboard │ N Network │ F Findings │ A Attacks │          │
└──────────────────────────────────────────────────────────────┘
```

- Full mouse support: click tabs, rows, right-click for detail
- Keyboard: `D`ashboard, `N`etwork, `F`indings, `A`ttacks, `S`can, `E`xport, `Q`uit
- Scan diff badges: **NEW** and **CHG** markers on changed findings
- ASCII mongoose with animated snake (because why not)

### Cross-Platform

- **Linux**: reads `/proc/net/route`, `/proc/net/arp`, `/sys/class/net/`
- **macOS**: uses `ifconfig`, `route`, `arp`, `system_profiler`

## CLI Reference

```
rikitikitavi <COMMAND>

Commands:
  scan        Run network security scan
  tui         Launch interactive terminal UI
  report      Generate report from saved scan
  unifi       UniFi controller commands
  aws         AWS Security Lake commands
  modules     List available scanner modules
  monitor     Passive WiFi monitoring (requires --features monitor)
  config      Show/validate configuration (secrets redacted)
  init        Interactive setup wizard
  update-db   Update vulnerability databases
  version     Show version info
```

### Scan Options

```
rikitikitavi scan [OPTIONS]

Options:
  --perspective <P>      Attacker model: neighbor, unauthenticated,
                         authenticated, privileged [default: unauthenticated]
  --quick                Passive scan (top 20 ports only)
  --aggressive           Deep scan (extended port range)
  --modules <M>          Comma-separated scanner list
  --output <PATH>        Output file path
  --format <F>           Output format: json, csv, html, ocsf
  --attack-paths         Generate attack path analysis
  --compare-previous     Diff against last saved scan
  --fail-on <SEVERITY>   Exit code 2 if any finding is at/above this severity
                         (never, info, low, medium, high, critical) — for
                         cron/CI self-audits, e.g. --fail-on high
  --suppress <FILE>      Mute findings whose fingerprint is in this baseline
  --write-baseline <F>   Write current findings' fingerprints to a baseline file
  --known-devices <F>    Flag any device not in this file as a "new device"
  --write-known-devices <F>  Write current devices to a known-devices file
  --quiet                Suppress progress output and the consent notice
  --no-save              Don't save to scan history
  --dry-run              Show what would be scanned (no active probing)
```

> **Log level:** defaults to `warn` so the report stays readable; use
> `--log-level info` for scan progress detail.

**Baselines & recurring audits.** Establish a baseline once, then surface only
what's new on later scans — ideal for cron/CI (`--fail-on` sets the exit code):

```bash
rikitikitavi scan --write-baseline .rikitikitavi-baseline \
                  --write-known-devices .rikitikitavi-devices
# ...later runs only report new findings / new devices:
rikitikitavi scan --suppress .rikitikitavi-baseline \
                  --known-devices .rikitikitavi-devices --fail-on high
```

> **Consent:** rikitikitavi prints a one-line reminder that you should only scan
> networks you own or are authorized to test. Active default-credential *login
> attempts* are gated behind `--aggressive`; the default scan detects and flags
> exposures without attempting logins.

### Host Discovery

In the default (Active) mode, rikitikitavi runs a bounded, unprivileged
TCP-connect sweep across the detected subnet, so a cold ARP cache on a freshly
booted machine no longer yields an empty "looks clean" report. `--quick`
(Passive) mode stays read-only and only reads the ARP cache; to enrich it first:

```bash
nmap -sn 192.168.1.0/24   # or: fping -a -g 192.168.1.0/24
rikitikitavi scan --quick
```

## Findings Format

Each finding includes severity, scanner ID, title, description, affected
host/port/service, CWE reference, and remediation steps with estimated effort:

```
 CRIT  Redis accessible without authentication on 192.168.1.50:6379
       CWE-306 | Remediation: Enable Redis AUTH, bind to 127.0.0.1

 HIGH  SMBv1 enabled on 192.168.1.30:445
       CWE-327 | Remediation: Disable SMBv1 (EternalBlue/WannaCry vulnerable)

 MED   DNSSEC validation not enforced
       CWE-350 | Remediation: Switch to Quad9 (9.9.9.9) or Cloudflare (1.1.1.1)

 LOW   SSH server banner reveals version (OpenSSH 8.9p1) on 192.168.1.10:22
       CWE-200 | Remediation: Suppress version in sshd_config
```

---

## Architecture

```
                    ┌─────────────────────┐
                    │   rikitikitavi (bin) │
                    │  CLI + orchestration │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                     │
   ┌──────┴──────┐   ┌────────┴────────┐   ┌───────┴───────┐
   │   scanners  │   │    analysis     │   │    export     │
   │ 25 scanners │   │ risk, diff,     │   │ JSON, CSV,    │
   │ + registry  │   │ attack paths    │   │ HTML, OCSF    │
   └──────┬──────┘   └────────┬────────┘   └───────────────┘
          │                    │
   ┌──────┴──────┐   ┌────────┴────────┐   ┌───────────────┐
   │   network   │   │     models      │   │      tui      │
   │ ARP, routes,│   │ Finding, Device,│   │   ratatui +   │
   │ WiFi, iface │   │ ScanContext     │   │   crossterm   │
   └──────┬──────┘   └────────┬────────┘   └───────────────┘
          │                    │
          │            ┌───────┴───────┐    ┌───────────────┐
          └────────────│     core      │    │     unifi     │
                       │ Severity,     │    │ API client +  │
                       │ Perspective   │    │ scanner       │
                       └───────────────┘    └───────────────┘
```

This is a 9-crate Rust workspace. The dependency graph flows downward — `core`
is the foundation with zero dependencies, `models` builds on it, and everything
else builds on those two.

### Design Deep Dive

This section explains the key design patterns and Rust concepts used throughout
the codebase, organized as a learning guide.

#### Workspace Organization

The workspace is split into crates by concern, not by layer. Each crate has a
focused responsibility and a clear public API. The `Cargo.toml` at the root
defines shared dependencies, lint configuration, and build profiles:

```toml
[workspace.lints.rust]
unsafe_code = "forbid"          # No unsafe anywhere

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }  # Strict linting
nursery = { level = "warn", priority = -1 }   # Even stricter
```

This means every crate inherits `unsafe_code = "forbid"` and clippy
pedantic+nursery. The `-D warnings` in CI turns all warnings into errors.

#### The Scanner Trait (`async_trait`)

Every scanner implements this trait:

```rust
#[async_trait]
pub trait Scanner: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn supported_perspectives(&self) -> &[Perspective];
    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError>;
    fn estimated_duration_secs(&self) -> u64;
    fn requires_privileges(&self) -> bool { false }
    fn relevant_ports(&self) -> &[u16] { &[] }  // empty = always run
}
```

`relevant_ports()` enables Phase 2 filtering — if a scanner returns `&[3306,
5432]` and no hosts have those ports open, it's skipped entirely.

The `ScannerRegistry` holds `Vec<Box<dyn Scanner>>` and provides filtering by
perspective or ID. Adding a new scanner is: implement the trait, add one line to
`ScannerRegistry::new()`.

#### Builder Pattern for Domain Models

`Finding` and `Device` use chainable builders:

```rust
Finding::new("ssl", "Expired Certificate", "Certificate expired 30 days ago", Severity::High)
    .with_ip("192.168.1.10".parse().unwrap())
    .with_port(443)
    .with_cwe("CWE-295")
    .with_remediation(Remediation { /* ... */ })
    .with_evidence("CN=expired.local, Not After: 2025-01-01")
```

Each `.with_*()` method takes `self` and returns `Self`, so they chain.
Optional fields default to `None`/empty. This avoids constructors with 15
parameters.

#### Fingerprint-Based Identity

Findings need stable identity across scans for comparison. A fingerprint is
derived from `(scanner, title, affected_ip, affected_port)`:

```rust
impl Finding {
    pub fn fingerprint(&self) -> FindingFingerprint {
        let mut hasher = DefaultHasher::new();
        self.scanner.hash(&mut hasher);
        self.title.hash(&mut hasher);
        self.affected_ip.hash(&mut hasher);
        self.affected_port.hash(&mut hasher);
        FindingFingerprint(hasher.finish())
    }
}
```

If a finding's description or severity changes but the scanner, title, IP, and
port are the same, it's the *same* finding with updated details — not a new
one. This lets scan comparison correctly report "severity changed from Medium to
High" rather than "old one resolved, new one appeared."

Devices use MAC address (preferred) or IP as their fingerprint, so they survive
DHCP address changes.

#### Cross-Platform Network Layer

Network functions are split into pure parsing and I/O:

```rust
// Pure — takes &str, easy to unit test with literal strings
fn parse_proc_route(contents: &str) -> Vec<RouteEntry> { /* ... */ }

// Public — reads from /proc, calls the pure function
pub fn detect_gateway() -> Option<IpAddr> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_proc_route(&contents)
        .into_iter()
        .find(|r| r.is_default)
        .map(|r| r.gateway)
}
```

Linux reads `/proc` directly (no shelling out). macOS calls `ifconfig`,
`route`, `arp` and parses their output. Platform selection uses `#[cfg]`:

```rust
#[cfg(target_os = "linux")]
fn read_arp_table() -> Vec<ArpEntry> { /* parse /proc/net/arp */ }

#[cfg(target_os = "macos")]
fn read_arp_table() -> Vec<ArpEntry> { /* parse `arp -an` output */ }
```

Tests import the macOS parsers on Linux with
`#[cfg(any(target_os = "macos", test))]` so they run in CI.

#### Two-Phase Scan Orchestration

The runner (`runner.rs`) coordinates scanning:

1. **Phase 1** — `network`, `ports`, `device` run sequentially (each needs
   the previous results)
2. **Enrichment** — discovered ports are grouped by IP to build device
   profiles, then injected into `ScanContext`
3. **Phase 2** — remaining 22 scanners run concurrently via
   `futures::future::join_all`, filtered by `relevant_ports()`
4. **Deduplication** — when Phase 1 and Phase 2 produce findings for the same
   `(ip, port)`, the one with more detail wins (scored by evidence, CWE,
   remediation, description length)

#### OCSF Export Pipeline

The `From<&Finding>` trait converts findings to OCSF schema structs:

```rust
impl From<&Finding> for OcsfFinding {
    fn from(f: &Finding) -> Self {
        Self {
            class_uid: 2002,  // Vulnerability Finding
            severity_id: f.severity.ocsf_id(),
            time: f.discovered_at.timestamp_millis(),  // epoch ms
            // ... CWE → analytic, CVEs → vulnerabilities, IP/port → resources
        }
    }
}
```

Timestamps are epoch milliseconds (OCSF `timestamp_t`), not RFC 3339 strings.
NDJSON output (one JSON object per line) is what Glue/Athena prefer for
parallel processing.

#### Property-Based Testing

Beyond standard unit tests, the codebase uses `proptest` for invariant testing:

```rust
proptest! {
    #[test]
    fn finding_json_roundtrip(f in arb_finding()) {
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(f.title, back.title);
        prop_assert_eq!(f.severity, back.severity);
    }

    #[test]
    fn diff_covers_all_findings(old in vec(arb_finding(), 0..20),
                                 new in vec(arb_finding(), 0..20)) {
        let diff = diff_scan_results(&old, &new);
        // Every unique fingerprint lands in exactly one category
    }
}
```

This catches edge cases that example-based tests miss — serialization
roundtrips, diff category coverage, fingerprint stability.

#### Error Handling

The crate uses a two-level error strategy:

- **`ScanError`** (in `core`) — scanner-specific errors with context (scanner
  ID, description). Scanners return `Result<Vec<Finding>, ScanError>`.
- **`anyhow::Result`** — used at the CLI/orchestration level where errors are
  displayed to the user, not programmatically matched.

Scanners that encounter non-fatal errors (e.g., a single host timeout) log them
and continue rather than failing the entire scan.

#### Build Profiles

```toml
[profile.release]
lto = true               # Link-time optimization
codegen-units = 1         # Single codegen unit (slower build, faster binary)
panic = "abort"           # No unwinding (smaller binary)
strip = true              # Strip debug symbols
opt-level = "z"           # Optimize for size

[profile.release-fast]    # When you want speed over size
opt-level = 3

[profile.release-embedded]  # For UniFi device deployment
opt-level = "z"
lto = "fat"
```

The default release profile optimizes for size (`opt-level = "z"`) because this
tool runs on home network devices where disk space matters more than nanosecond
performance.

### Adding a New Scanner

1. Create `crates/rikitikitavi-scanners/src/my_scanner.rs`
2. Implement the `Scanner` trait
3. Register in `ScannerRegistry::new()` (`traits.rs`)
4. Add `mod my_scanner;` to `lib.rs`
5. Write tests

### Adding a New Export Format

1. Create `crates/rikitikitavi-export/src/my_format.rs`
2. Implement `export_my_format(results: &ScanResults, path: &Path) -> Result<()>`
3. Re-export in `lib.rs`
4. Add variant to `ReportFormatArg` in `cli.rs`
5. Wire dispatch in `main.rs`

## Development

```bash
# Run all tests (~1050 tests including property-based)
cargo test --workspace

# Clippy (pedantic + nursery, must be clean)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --check

# Supply chain audit
cargo deny check

# Build optimized release
cargo build --release

# Build for UniFi device deployment
cargo build --profile release-embedded
```

CI runs all of the above on every push to `main` and every PR.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

---

```
              ~§>
    The mongoose is watching your network.
```
