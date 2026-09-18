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

### 32 Security Scanners

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
| **Google Cast** | Cast device identification via `eureka_info`, exposed setup endpoint (8008/8443) |
| **PaperCut** | NG/MF build and edition from 9191 asset paths, CVE-2026-81578/82078 correlation |
| **TP-Link Kasa** | Unauthenticated local control on 9999 (read-only `get_sysinfo`), geolocation disclosure |
| **Tuya local** | Passive broadcast leak on UDP 6666/6667, control port 6668 |
| **Hikvision SADP** | UDP 37020 discovery, firmware build date floor, CVE correlation |
| **Modbus/SunSpec** | Inverters, batteries and EV chargers on 502, SunSpec identification (read-only) |
| **Matter / Thread** | Commissionable Matter devices and Thread border routers via mDNS (`_matter`, `_matterc`, `_meshcop`) |
| **nuclei detection** | Read-only banner/handshake product identification from projectdiscovery nuclei detection templates |
| **Neighbor/Proximity** | Stub: registered for the `neighbor` perspective, returns no findings yet |
| **Network Isolation** | Flat network detection, inter-VLAN routing, subnet analysis |
| **Service Banners** | SSH version, HTTP headers, banner grabbing |
| **SSL/TLS Certificates** | Self-signed, expired, weak keys, TLS 1.0/1.1 |
| **mDNS/SSDP Discovery** | Service advertisement enumeration, UPnP device discovery |
| **HTTP Security Audit** | Missing security headers, default pages, admin path enumeration |
| **Database Security** | Auth-less Redis/MongoDB/MySQL/Elasticsearch/Memcached |
| **SMB Security** | SMBv1 (EternalBlue-vulnerable) detection, NetBIOS exposure |
| **ARP Security** | ARP spoofing detection (duplicate MACs/IPs, broadcast MACs) |
| **DHCP Security** | APIPA (self-assigned) address and missing-gateway detection |
| **SNMP** | Default community strings (`public`/`private`) over UDP; sysDescr leak |
| **MQTT** | Broker anonymous-access probe (CONNECT/CONNACK, non-destructive) |
| **Management Plane** | Unauthenticated Docker API, kubelet, and Kubernetes API exposure |
| **Printers** | CUPS/IPP (CVE-2024-4717x) + raw JetDirect (9100) exposure |
| **TR-069 / CWMP** | ISP remote-management (7547) reachable on the LAN |
| **RTSP / ONVIF** | IP-camera streams reachable without authentication |
| **UPnP-IGD** | Router WAN→LAN port forwards ("what's exposed to the internet?") |
| **Passive WiFi** | 802.11 frame analysis, rogue AP detection, deauth attacks *(`rikitikitavi monitor`, feature `monitor`)* |

The 32 registered scanners are every row except Passive WiFi, which is not in
`ScannerRegistry` and runs only through the `monitor` command.

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

Comparison uses fingerprint-based diffing. Findings are keyed on
`(scanner, title, ip, port)`, so a finding on a host whose DHCP address changed
shows up as one resolved plus one new. Devices are keyed on MAC (IP only when
the MAC is unknown), so they survive address changes. Severity changes are
tracked separately from new/resolved findings.

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
# `unifi.controller.insecure: true` in config.yaml does the same and prints the same warning.
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
│  ████████████████░░░░░░░░    32 scanners, 47 findings        │
│                                                              │
│  CRIT ██  3    NEW   5       ┌─────────────────┐            │
│  HIGH ████  7  CHG   2       │   ,:::::::,     │            │
│  MED  ████████  18           │  ,::/^\:::::,   │            │
│  LOW  ██████  12             │ ,::( ^  ^)::,   │            │
│  INFO ███████  7             │ `:::\ w  /::;   │            │
│                              │   ';:`. .':;'   │            │
│                              │      ~§>        │            │
├─────────────┬───────────┬───┴────────┬────────┴──┬───────────┤
│ D Dashboard │ N Network │ F Findings │ A Attacks │ T Actions │
└──────────────────────────────────────────────────────────────┘
```

- Full mouse support: click tabs and rows, right-click for detail, scroll wheel
  moves the selection
- Keyboard: `D`ashboard, `N`etwork, `F`indings, `A`ttacks, `T`op actions,
  `S`can (re-scan), `L` toggle severity filter, `E`xport, `Enter` device
  detail / `Esc` back, `Tab`/`Shift+Tab` or `←`/`→` cycle screens,
  `↑`/`↓`/`j`/`k`, `PageUp`/`PageDown`, `Home`/`End` move the selection, `Q`uit
- Watch mode: `tui --watch --interval 300` re-scans every N seconds (see
  [TUI Options](#tui-options))
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
  report      Print the last saved scan (--latest); other modes not yet implemented
  unifi       UniFi controller commands
  aws         AWS Security Lake commands (not yet implemented; every subcommand exits non-zero)
  modules     List available scanner modules
  monitor     Passive WiFi monitoring (requires --features monitor)
  config      Show/validate configuration (secrets redacted)
  init        Interactive setup wizard (not yet implemented; points at config.example.yaml)
  update-db   Update vulnerability databases (not yet implemented)
  version     Show version info
```

### Global Options

```
  -c, --config <PATH>    Config file [env: RIKITIKITAVI_CONFIG]; skips the default search
  -l, --log-level <L>    error, warn, info, debug, trace [default: warn]
```

Both apply to every subcommand.

### Scan Options

```
rikitikitavi scan [OPTIONS]

Options:
  --perspective <P>      Attacker model: neighbor, unauthenticated,
                         authenticated, privileged [default: config
                         scan.perspective, else unauthenticated]. Only `wifi`
                         and the `neighbor` stub accept neighbor, so that
                         perspective is effectively a WiFi-only scan
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
  --quiet                Suppress progress output and the consent notice; with
                         no --output the findings report is suppressed too
                         (stderr then notes if --fail-on is unset)
  --no-save              Don't save to scan history
  --dry-run              Show what would be scanned (no active probing)
  --network <M>, --ssid, --password, --interface, --upload, --unifi-local
                         Parsed but not implemented: any of these (--network
                         other than auto) exits with "not yet implemented"
```

### TUI Options

```
rikitikitavi tui [OPTIONS]

Options:
  --watch                Re-scan automatically every --interval seconds
  --interval <SECS>      Watch interval [default: 300]; values below 5 are rejected
  --theme <T>            dark, light, hacker, accessible [default: dark]
  --perspective <P>      As for scan [default: config scan.perspective, else unauthenticated]
  --network, --ssid      Not yet implemented; passing them is an error
```

The TUI runs at the config intensity (capped at active), always with attack
paths, and saves every scan to history. `S` re-scans on demand.

### Report

`rikitikitavi report --latest` prints the most recent saved scan. Without
`--latest`, `report` only prints "not yet implemented"; `--format`, `--output`
and `--attack-paths` are parsed but unused.

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

Order after a scan: new-device findings are appended and `--write-known-devices`
written; history is saved; `--write-baseline` is written; `--suppress`
filtering is applied; the report, then the `--compare-previous` diff, are
printed; `--fail-on` is evaluated last, on the filtered set. History and a
baseline written in the same run as `--suppress` therefore contain the full,
unfiltered set.

> **Consent:** rikitikitavi prints a one-line reminder that you should only scan
> networks you own or are authorized to test. *Password-guessing* telnet logins
> are gated behind `--aggressive`. The default (Active) scan still performs
> unauthenticated protocol logins that need no secret: anonymous FTP
> (`USER anonymous`, plus a PASV `LIST` when accepted), SNMP `public`/`private`
> community probes, and an anonymous MQTT `CONNECT`. `--quick` (Passive) limits
> the credential scanner to the gateway and skips the SNMP and MQTT probes.

### Configuration File

`rikitikitavi` loads the file given by `--config`/`-c` (or `RIKITIKITAVI_CONFIG`); otherwise the first of `./config.yaml`, `./config.yml`, `/etc/rikitikitavi/config.yaml`; otherwise built-in defaults. An explicit path that does not exist is an error. `scan` prints `Config: <path>` unless `--quiet`.

[`config.example.yaml`](config.example.yaml) documents every key with its default. Keys that parse but are not read yet (`logging.*`, `output.*`, `scan.network_mode`, `security_lake.*`, and others) are marked "reserved" there. `scan.perspective` is the default for `--perspective` on `scan` and `tui`; `scan.modules` and `scan.attack_paths` are overridden by `--modules`/`--attack-paths` or their absence. Safety-relevant keys under `scan`:

```yaml
scan:
  intensity: active            # passive | active | aggressive; a file value of aggressive is capped
                               # at active, login attempts require `scan --aggressive`
  parallelism: 100             # default 100; 1..=4096, outside that range is a startup error
  timeout_seconds: 0           # 0 = unbounded; otherwise the whole scan aborts after N seconds
  excluded_networks: ["192.168.50.0/24"]                    # CIDRs never probed
  excluded_devices: ["192.168.1.40", "aa:bb:cc:dd:ee:ff"]  # IPs never probed; MACs once the ARP cache knows them
```

Exclusion semantics: MAC entries are resolved to IPs through the ARP cache before the host sweep and re-applied after the sweep fills in MACs. Findings on excluded hosts are dropped after the scan, except `arp` findings, so spoofing that involves an excluded host is still reported. If every discovered host is excluded, the six ARP-fallback scanners (`credentials`, `services`, `smb`, `snmp`, `database`, `mgmt-plane`) are skipped; if the gateway is excluded, `router` is skipped.

Independently of `scan.timeout_seconds`, each scanner runs under its own budget of 4× its estimated duration, clamped to 60–600 s; a scanner that exceeds it is skipped with a warning and contributes no findings.

Reports, baseline and known-device files are written with mode `0600`; the scan-history directory with `0700`.

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
   │ 32 scanners │   │ risk, diff,     │   │ JSON, CSV,    │
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
has no intra-workspace dependencies (its runtime deps are thiserror, anyhow,
tracing, serde, chrono, uuid, ipnetwork), `models` builds on it, and everything
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
derived from `(scanner, title, affected_ip, affected_port)` with a hand-rolled
FNV-1a 64 hasher, because `DefaultHasher` (SipHash) is not guaranteed stable
across Rust releases and fingerprints are persisted in baseline files:

```rust
impl Finding {
    pub fn fingerprint(&self) -> FindingFingerprint {
        // Byte layout: scanner 0xff title 0xff ip-tag [octets] port-tag [port BE].
        let mut hasher = Fnv1a64::new();
        hasher.write(self.scanner.as_bytes());
        hasher.write_u8(0xff);
        hasher.write(self.title.as_bytes());
        hasher.write_u8(0xff);
        match self.affected_ip {
            None => hasher.write_u8(0),
            Some(IpAddr::V4(v4)) => { hasher.write_u8(4); hasher.write(&v4.octets()); }
            Some(IpAddr::V6(v6)) => { hasher.write_u8(6); hasher.write(&v6.octets()); }
        }
        match self.affected_port {
            None => hasher.write_u8(0),
            Some(port) => { hasher.write_u8(1); hasher.write(&port.to_be_bytes()); }
        }
        FindingFingerprint(hasher.finish())
    }
}
```

If a finding's description or severity changes but the scanner, title, IP, and
port are the same, it's the *same* finding with updated details — not a new
one. This lets scan comparison correctly report "severity changed from Medium to
High" rather than "old one resolved, new one appeared."

Baseline files written by `--write-baseline` carry a `# format: fnv1a-1`
header. `--suppress` warns when the header is missing or different and asks
for a regenerate with `--write-baseline`; baselines from before the FNV-1a
hasher must be regenerated.

Devices use MAC address (preferred) or IP as their fingerprint
(`DeviceFingerprint::{Mac, Ip}`), so they survive DHCP address changes.

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
3. **Phase 2** — remaining 29 scanners run concurrently via
   `futures::future::join_all`, filtered by `relevant_ports()`
4. **Deduplication** — when Phase 1 and Phase 2 produce findings for the same
   `(ip, port)`, the one with more detail wins (scored by evidence, CWE,
   remediation, description length)

#### OCSF Export Pipeline

The `From<&Finding>` trait converts findings to OCSF schema structs:

```rust
#[derive(Serialize, Deserialize)]
pub struct OcsfFinding {
    pub class_uid: u32,
    // ...
    #[serde(serialize_with = "serialize_epoch_ms", deserialize_with = "deserialize_epoch_ms")]
    pub time: DateTime<Utc>,  // stays a DateTime in Rust, epoch ms on the wire
}

impl From<&Finding> for OcsfFinding {
    fn from(f: &Finding) -> Self {
        Self {
            class_uid: 2002,  // Vulnerability Finding
            severity_id: f.severity.ocsf_id(),
            time: f.discovered_at,
            // ... CWE → analytic, CVEs → vulnerabilities, IP/port → resources
        }
    }
}
```

Timestamps are epoch milliseconds (OCSF `timestamp_t`), not RFC 3339 strings;
the conversion lives in the serde attribute, not in `From`.
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

The parsers that consume network-sourced bytes (DNS packets, 802.11 frames,
SSH KEX, service banners, HTTP headers, SSDP/UPnP, X.509 DER, identifiers)
also have libFuzzer harnesses under `fuzz/fuzz_targets/`; see `fuzz/README.md`.

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
inherits = "release"
opt-level = 3

[profile.release-embedded]  # For UniFi device deployment
inherits = "release"
opt-level = "z"
lto = "fat"

[profile.release-unifi]   # Size/speed middle ground for UniFi gateways
inherits = "release"
opt-level = "s"
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
# Run all tests (1710 tests across 17 binaries, incl. ~200 proptest invariants)
cargo test --workspace

# Clippy (pedantic + nursery, must be clean)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --check

# Supply chain audit
cargo deny check

# Fuzz the network-facing parsers (nightly + cargo-fuzz; see fuzz/README.md)
cargo +nightly fuzz list
cargo +nightly fuzz run dns_packet -- -max_total_time=60

# Build optimized release
cargo build --release

# Build for UniFi device deployment
cargo build --profile release-embedded
```

CI (`.github/workflows/ci.yml`) runs six jobs on every push to `main` and
every PR: `check` (fmt + clippy), `test` (Linux), `test-macos`, `msrv`
(`cargo check` on Rust 1.88), `deny`, and `fuzz-build` (nightly `cargo fuzz
build`; the fuzzers are built, not run). Release-profile builds are not part
of CI.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

---

```
              ~§>
    The mongoose is watching your network.
```
