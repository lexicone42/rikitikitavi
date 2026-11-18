# rikitikitavi

```
         n,---.n
         ( o o )
          \ Y /              __       "When I was a young man I was led to believe
         /`---'\          -<'o )       there were organisations to kill my snakes for me
        / /| |\ \            ) )       I.E. the church, I.E. the government, I.E. school
       ( ( | | ) )          / /        But when I got a little older
        \_\| |/_/          ( (         I learned I had to kill them myself"
          |   |             \ \
          | | |        ~-.__/ /                                          ─ Donovan
 ~-..__.-(_/ \_)        `----'
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
# Install from GitHub (Rust 1.89+ required)
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
# On Debian/Ubuntu, install libpcap first
sudo apt-get install libpcap-dev

# Install with WiFi monitoring support
cargo install --git https://github.com/lexicone42/rikitikitavi --features monitor

# Monitor for 60 s (the default; --duration sets it)
sudo rikitikitavi monitor --interface wlan0
```

`monitor` also takes `--home-ssid`, `--known-bssids`, `--output` and `--format`.
Without the feature the subcommand does not exist.

## Features

### 39 Security Scanners

Two-phase adaptive scanning: Phase 1 discovers your network, then Phase 2 runs
deep, targeted checks — only probing services that actually exist on your
network.

Devices are identified by a layered stack: IEEE OUI vendor lookup (MA-L, MA-M and MA-S registries, longest prefix first), Home Assistant's discovery tables (DHCP/mDNS/SSDP matchers), Rapid7 Recog banner fingerprints, mDNS service types including Matter and Thread border routers, and names from reverse DNS, NetBIOS and, if configured, the UniFi controller (see [Host Discovery](#host-discovery)). Each scan also produces a per-device letter-grade report card.

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
    device types             │ ... and more │
                             └──────────────┘
                             Runs concurrently,
                             skips irrelevant checks
```

| Scanner | What it checks |
|---------|---------------|
| **Network Discovery** | Interface enumeration, ARP cache, device count |
| **Port Scanner** | TCP connect scan of a default list of common ports across all LAN hosts (top 20 with `--quick`, an extended list with `--aggressive`) |
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
| **Network Isolation** | Flat network detection, devices outside the home subnet, inter-VLAN routing probes |
| **Service Banners** | SSH version, HTTP headers, banner grabbing |
| **SSL/TLS Certificates** | Self-signed, expired, weak keys, TLS 1.0/1.1 |
| **mDNS/SSDP Discovery** | Service advertisement enumeration, UPnP device discovery; Apple TV tvOS version (from AirPlay) against KEV fix versions and end-of-life, AirPlay receivers with no access control |
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
| **KNXnet/IP** | Building-automation gateways on UDP 3671 (`SEARCH_REQUEST` only), unsecured service families |
| **Media Servers** | Plex `/identity` version correlation (Plex2Shell KEV chain below 1.43.3.10861, CVE-2020-5741, CVE-2025-34158), Jellyfin `/System/Info/Public` and UDP 7359 discovery, open first-run wizard |
| **3D Printers** | Moonraker/Klipper authorization posture (7125/7130) and `OctoPrint` (5000), identification paths only |
| **Hue Bridge** | Unauthenticated `/api/config` firmware read; BSB002 below 1975170000 (CVE-2026-3557, CVE-2026-3562) |
| **Spotify Connect** | ZeroConf `getInfo` device identification (type, brand, model); identification only |
| **DD-WRT UPnP** | Unauthenticated `MiniUPnPd`/DD-WRT control endpoints reachable on the LAN |
| **Client-Side LAN Exposure** | Devices attacked as *clients* of a hostile LAN service (no listening port to scan) |
| **Passive WiFi** | 802.11 frame analysis, rogue AP detection, deauth attacks *(`rikitikitavi monitor`, feature `monitor`)* |

The 39 registered scanners are every row above except two: Passive WiFi, which is
not in `ScannerRegistry` and runs only through the `monitor` command, and
Matter / Thread, which is a capability of the mDNS/SSDP scanner rather than a
scanner of its own.

### Exploit Intelligence & Confidence

rikitikitavi adds these signals on top of raw CVE/CVSS so a non-expert knows
what to fix first:

- **Actively exploited (CISA KEV):** findings whose CVE is in the CISA Known
  Exploited Vulnerabilities catalog (an embedded snapshot, refreshed via
  `scripts/gen_kev_db.py`) are badged **⚠ ACTIVELY EXPLOITED**, escalated to at
  least High unless their confidence is only *inferred*, and weighted more
  heavily in the risk score.
- **EPSS scores:** findings are enriched with the EPSS probability that each CVE
  will be exploited in the next 30 days (rendered as `EPSS 94%`). Fetched
  best-effort from FIRST.org at scan time — offline scans simply skip it.
- **Confidence tiers:** every finding declares how it was established —
  **✓ confirmed** (demonstrated, e.g. a login actually succeeded), *probable*
  (banner/version match), or **~ inferred** (heuristic). A version banner is
  only *probable* because a backported patch can leave an old version string,
  so confirmed findings stand out from ones worth double-checking.
- **Exploitation tier (CISA Vulnrichment):** an embedded SSVC snapshot (CC0) adds a `poc` tier — public exploit code exists but exploitation is not yet observed — between KEV and the rest, and backfills CWEs.
- **End-of-life components:** server and OS versions are checked against endoflife.date cycles; a distribution-backported build is flagged Low rather than Medium since it may still carry fixes.
- **OWASP IoT Top 10:** each finding is tagged with its OWASP IoT Top 10 (2018) category (`I1`–`I10`) in the JSON, CSV, HTML and OCSF output.
- **AyySSHush backdoor:** SSH on TCP 53282 is flagged (CVE-2023-39780, CISA KEV), with the ASUS-specific CVE asserted only when the host is identifiably ASUS.

### Per-Device Report Cards

Every discovered device gets a letter grade from its own findings and its device
class, alongside the network-wide score:

```
  Devices needing attention (grade | device | findings):
    D  192.168.1.64     Hikvision (Camera)          1 HIGH  [new]
    C  192.168.1.80     Denon (Media Player)        1 HIGH

  Device grades (own scoring, not a certification):
    A 57,  C 1,  not assessed 2
    Tracking: 2 new, 59 known
```

The ladder is the scan-wide one (F: any critical; D: >2 high; C: any high;
B: >3 medium; A: otherwise), with two device-scoped adjustments:

- a finding CISA lists as exploited in the wild caps the grade at **F**;
- a class whose compromise reaches past the device itself is graded one letter
  harder — hubs, routers, access points and NAS boxes hold other devices'
  credentials, locks, EV chargers, inverters and thermostats actuate the
  physical world, cameras, NVRs and doorbells record it.

A host with no findings and no open ports is **not assessed** rather than A:
nothing was observed, which is not the same as nothing being wrong. These grades
are this tool's own scoring of what is visible from the LAN — not a conformance
verdict. Schemes like ETSI EN 303 645 and the FCC Cyber Trust Mark rest on
manufacturer evidence no network scan can see.

Grades appear in the terminal report, the HTML device inventory, the TUI
overview, device table and device detail, the JSON `report_cards` array, and the
Prometheus export. With `--known-devices`, each card also carries whether the
host is `known`, `new`, or `untracked` (no list supplied, so nothing is claimed).

### Metrics Export

For cron-driven scans, `--format prometheus` writes
[Prometheus text exposition 0.0.4](https://prometheus.io/docs/instrumenting/exposition_formats/)
for node_exporter's textfile collector:

```bash
rikitikitavi scan --quiet --format prometheus \
  --output /var/lib/node_exporter/textfile_collector/rikitikitavi.prom
```

The file is written under a temporary name and renamed into place, so a scrape
never sees a half-written file. Metrics: `rikitikitavi_devices`, `devices_new`,
`findings{severity,confidence}`, `kev_findings`, `poc_findings`, `eol_findings`,
`risk_score`, `scan_duration_seconds`, `last_scan_timestamp_seconds`,
`devices_by_grade{grade}`, `device_grade{ip}` (A=4 … F=0) and the
`device_info{ip,mac,vendor,device_type,hostname,status}` identity metric to join
on. Deliberately not OpenMetrics: the textfile collector parses with
`expfmt.NewTextParser`, which rejects `# EOF` and `_created` series and would
drop the whole file.

Unlike every other export, this file is written **0644**, not 0600: node_exporter
reads it as its own user. `device_info` carries the IP, MAC, vendor, type and
hostname of every host, so write it where the collector reads it, not into a
directory other local accounts can browse.

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

### Fixing and Verifying

Every finding at Low or above carries a remediation; a test fails the build if
one is added without. Fixes are product-aware where a vendor source exists
(Kasa fixed-firmware builds per model and hardware version, Denon/Marantz
network control, Dyson's built-in broker, Hue and UniFi update paths).

```bash
# Markdown checklist from the last scan: Do now / This weekend / Replace / Accepted
rikitikitavi fix-plan -o fix-plan.md

# After fixing, re-check only the affected hosts
rikitikitavi verify                       # Low and above
rikitikitavi verify --finding 8a49cb832045970f
rikitikitavi verify --ip 192.168.1.64 --format json

# Record a risk you have decided to live with
rikitikitavi scan --accept-file accepted.yaml
```

`fix-plan` groups items per device; each item has its fix, references and a
`verify` command to re-check it.

`verify` replays the scanners behind each prior finding against that host
alone and reports `resolved`, `still present` or `inconclusive`. An offline
host, a scanner error or timeout, or a finding that cannot be replayed by a
unicast probe (mDNS, UPnP, ARP) is inconclusive, never resolved. Login checks
(`credentials` findings) are replayed only with `--aggressive`. Exit codes:
0 all resolved (or nothing selected), 1 error, 3 some still present, 4 none
still present but some inconclusive.

`rikitikitavi segment-plan -o segment-plan.md` proposes Trusted / IoT /
Infrastructure zones from the last scan, with per-device reasons, an
allow-rule table built from the ports seen open, and the mDNS services that
must cross zones. It is text only: it never configures a device.

The accept file is YAML:

```yaml
accepted:
  - fingerprint: "01a2b3c4d5e6f708"
    reason: Printer is on the isolated IoT VLAN
    accepted_on: 2026-11-01
    expires: 2027-02-01
    compensating: Inbound blocked at the gateway   # optional
```

Accepted findings stay in the report with their reason but leave the risk
score, grades, priority actions and `--fail-on`. Past `expires` the entry is
ignored with a warning and the finding is active again. Unknown keys, invalid
dates and files over 256 KiB are errors. `scan`, `tui`, `verify` (accepted
findings are not re-checked) and `fix-plan` (fills its Accepted section) all
take `--accept-file`. Fingerprints are printed by `verify`, `fix-plan`, the
TUI finding view and JSON output.

### UniFi Integration

Two paths use a UniFi controller.

**Client import during `scan` and `tui`.** When `unifi.controller` in the
config has a `url` and an `api_token` (or `username` and `password`), each scan
reads the controller's client list (read-only). Owner-set aliases and
hostnames name devices, in the order alias > scanner names > controller
hostname > NetBIOS > PTR. Connected clients the scan did not see are
summarised in one finding. Devices carry `seen_by`. `unifi.mode: disabled`
turns the import off. Without credentials, an identified UniFi gateway gets one
Info advisory naming the SAB-069 fixed firmware versions.

**`unifi scan`** audits the controller configuration. It reads the URL, site
and credentials from `unifi.controller` in the config file; flags override
them. Secrets can also come from `RIKITIKITAVI_UNIFI_TOKEN` or
`RIKITIKITAVI_UNIFI_PASSWORD`. Avoid `--password` and `--token` on a shared
machine: command-line values are visible in the process list.

```bash
# Controller and credentials from config.yaml
rikitikitavi unifi scan

# API token (UniFi OS 2.x+) from the environment
RIKITIKITAVI_UNIFI_TOKEN=... rikitikitavi unifi scan --controller https://192.168.1.1

# Username and password
RIKITIKITAVI_UNIFI_PASSWORD=... rikitikitavi unifi scan \
    --controller https://192.168.1.1 --user admin

# Self-signed controller cert? Opt out of TLS validation explicitly.
# By default the client validates the certificate before sending credentials.
# `unifi.controller.insecure: true` in config.yaml does the same and prints the same warning.
rikitikitavi unifi scan --insecure
```

- WLAN encryption, PMF (802.11w), guest and default-SSID audit
- Firewall rule analysis (overly permissive rules, disabled rules, no custom rules)
- Adopted-device firmware checked against UniFi Security Advisory Bulletin 069
  fixed versions
- IDS/IPS event count
- `--local` runs on the device itself (Dream Machine, Cloud Gateway, etc.) and
  adds its own firmware check; `--site` selects the site (default `default`);
  `-o` writes the findings as JSON

The other `unifi` subcommands (`devices`, `firmware-check`,
`audit-controller`, `deploy`, `tui`, `report`) are placeholders: they print a
pointer to `unifi scan` or "not yet implemented".

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
  1 Overview  2 Devices  3 Findings  4 Actions  5 Paths         ⠹ scanning 12s
╭ Hunting ────────────────────────╮╭ Risk ─────────────────────────────────────╮
│          n,---.n                ││ Network grade  D  Needs Attention         │
│          ( o o )                ││ 24 devices · 131 findings · +2 new, -1 re…│
│           \ Y /              __ ││                                           │
│          /`---'\          -<'o )││ Critical                         0        │
│         / /| |\ \            ) )││ High     █▊                      3        │
│        ( ( | | ) )          / / ││ Medium   ███████▎                12       │
│         \_\| |/_/          ( (  ││ Low      ██████████████████▍     31       │
│           |   |             \ \ ││ Info     ███████████████████████ 85       │
│           | | |        ~-.__/ / ││                                           │
│  ~-..__.-(_/ \_)        `----'  ││ Device grades  A 19  B 2  C 2  D 1        │
╰─────────────────────────────────╯╰───────────────────────────────────────────╯
╭ Devices needing attention ───────────────────────────────────────────────────╮
│  D  nas                           1 high, 2 medium, 10 low; nas class graded…│
│  C  office-plug                   1 high, 1 low                              │
╰──────────────────────────────────────────────────────────────────────────────╯
╭ What to fix first ───────────────────────────────────────────────────────────╮
│  HIGH  Update the firmware, then re-scan                           2 devices │
│  MED   Enable authentication on the web admin interface            1 device  │
╰──────────────────────────────────────────────────────────────────────────────╯
 1-5 tabs  s scan  e export  ? help  q quit
```

- Opens at once on the last saved scan; the first scan runs in the background
  and replaces it, with new and changed findings marked **NEW** / **CHG**
- **Devices**: every device in a scrolling table with grade, name, type,
  proposed segmentation zone and finding counts; `Enter` opens a device with its
  ports and findings, `f` there lists its findings
- **Findings**: table plus a wrapped detail pane; `Enter` opens the full
  finding (description, evidence, fix steps, CVEs, fingerprint for the accept
  file); `/` searches, `l` shows Low and Info
- **Top actions** and **Attack paths** scroll
- `e` writes three files to the working directory, named after the scan time:
  the results JSON, the fix plan and the segmentation plan
- Keys: `1`-`5`, `Tab` or `←`/`→` switch tabs (also `d` `n` `f` `t` `a`);
  `↑`/`↓`/`j`/`k`, `PageUp`/`PageDown`, `g`/`G` move or scroll; `Esc` goes back
  or clears the search; `o` sorts devices; `s` scans again; `?` lists every
  key; `q` or `Ctrl-C` quits
- Mouse: click a tab or a row, click the row again (or right-click) to open it,
  wheel scrolls
- Watch mode: `tui --watch --interval 300` re-scans every N seconds (see
  [TUI Options](#tui-options))

### Cross-Platform

- **Linux**: reads `/proc/net/route`, `/proc/net/arp`, `/sys/class/net/`;
  WiFi scanning uses `iwconfig`/`iwlist`
- **macOS**: uses `ifconfig`, `route`, `arp`, `system_profiler` (falls back to
  `airport` on older releases)
- Other platforms build, but network discovery returns nothing

## CLI Reference

```
rikitikitavi [OPTIONS] <COMMAND>

Commands:
  scan          Run a network security scan
  tui           Launch the interactive terminal UI
  verify        Re-check findings from the last full scan on the affected hosts only
  fix-plan      Markdown fix checklist from the last full scan
  segment-plan  Markdown zone and allow-rule proposal from the last full scan
  report        Print the last saved scan (--latest); other modes not yet implemented
  unifi         UniFi controller commands (only `unifi scan` is implemented)
  aws           AWS Security Lake commands (not yet implemented; every subcommand exits non-zero)
  modules       `modules list`, `modules info <id>`
  monitor       Passive WiFi monitoring (only in a `--features monitor` build)
  config        `config validate`, `config show` (secrets redacted)
  init          Setup wizard (not yet implemented; points at config.example.yaml)
  update-db     Update vulnerability databases (not yet implemented)
  version       Show version info (`--verbose` for system details)
```

### Global Options

```
  -c, --config <PATH>    Config file [env: RIKITIKITAVI_CONFIG]; skips the default search
  -l, --log-level <L>    error, warn, info, debug, trace [default: warn]
      --log-format <F>   text, json [default: text]
```

All three apply to every subcommand. `RUST_LOG`, when set, overrides
`--log-level`.

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
  --aggressive           Deep scan (extended port range, longer timeouts,
                         password-guessing logins)
  --modules <M>          Comma-separated scanner list (ids from `modules list`)
  -o, --output <PATH>    Write the report to this file instead of printing
                         the terminal report
  --format <F>           json, csv, html, ocsf, prometheus [default: json];
                         used only with --output
  --attack-paths         Generate attack path analysis
  --compare-previous     Diff against last saved scan
  --fail-on <SEVERITY>   Exit code 2 if any finding is at/above this severity
                         (never, info, low, medium, high, critical) — for
                         cron/CI self-audits, e.g. --fail-on high
  --suppress <FILE>      Mute findings whose fingerprint is in this baseline
  --accept-file <FILE>   Accepted-risk ledger (see "Fixing and Verifying")
  --write-baseline <F>   Write current findings' fingerprints to a baseline file
  --known-devices <F>    Flag any device not in this file as a "new device"
  --write-known-devices <F>  Write current devices to a known-devices file
  --rules <FILE>         Evaluate a YAML declarative-rules file against the scan
                         facts and add its findings (see "Custom rules")
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
  --accept-file <FILE>   Accepted-risk ledger, as for scan
  --network, --ssid      Not yet implemented; --ssid, or --network other than
                         auto, is an error
```

The TUI runs at the config intensity (capped at active), always with attack
paths, and saves every scan to history. `s` re-scans on demand. With
`unifi.controller` credentials in the config it imports the controller's client
list, as `scan` does. Logging to the terminal is off while the TUI runs; set
`RUST_LOG` and redirect stderr to a file to capture it.

### Verify, Fix-Plan and Segment-Plan Options

All three read the most recent full scan in history; they fail if there is
none, so run `scan` (without `--no-save`) first.

```
rikitikitavi verify [OPTIONS]
  --severity <S>         Only findings at or above this severity
                         [default: low, or none with --finding]
  --ip <IP>              Only findings on these hosts (repeatable or comma-separated)
  --finding <ID>         Only these findings, by fingerprint or finding id
  --aggressive           Allow replaying login checks (`credentials` findings)
  --accept-file <FILE>   Listed findings are not re-checked
  --format <F>           text, json [default: text]
  -o, --output <PATH>    Write the report to this file instead of stdout

rikitikitavi fix-plan [-o <PATH>] [--accept-file <FILE>]
rikitikitavi segment-plan [-o <PATH>]
```

`fix-plan` and `segment-plan` write Markdown to stdout, or to `-o` with mode
0600.

### Report

`rikitikitavi report --latest` prints the most recent saved scan. Without
`--latest`, `report` only prints "not yet implemented"; `--format`, `--output`
and `--attack-paths` are parsed but unused.

> **Log level:** defaults to `warn` so the report stays readable; use
> `--log-level info` for scan progress detail.

### Baselines and Recurring Audits

Establish a baseline once, then surface only what's new on later scans, for
cron or CI (`--fail-on` sets the exit code):

```bash
rikitikitavi scan --write-baseline .rikitikitavi-baseline \
                  --write-known-devices .rikitikitavi-devices
# ...later runs only report new findings / new devices:
rikitikitavi scan --suppress .rikitikitavi-baseline \
                  --known-devices .rikitikitavi-devices --fail-on high
```

Order after a scan: `--rules` findings are added; new-device findings are
appended and `--write-known-devices` written; history is saved;
`--write-baseline` is written; `--accept-file` entries are applied; `--suppress`
filtering is applied; the report is printed (or written to `--output`), then the
`--compare-previous` diff; `--fail-on` is evaluated last, on the filtered set.
History and a baseline written in the same run as `--accept-file` or
`--suppress` therefore contain the full, unfiltered set.

> **Consent:** rikitikitavi prints a one-line reminder that you should only scan
> networks you own or are authorized to test. *Password-guessing* telnet logins
> are gated behind `--aggressive`. The default (Active) scan still performs
> unauthenticated protocol logins that need no secret: anonymous FTP
> (`USER anonymous`, plus a PASV `LIST` when accepted), SNMP `public`/`private`
> community probes, and an anonymous MQTT `CONNECT`. `--quick` (Passive) limits
> the credential scanner to the gateway and skips the SNMP and MQTT probes.

### Configuration File

`rikitikitavi` loads the file given by `--config`/`-c` (or `RIKITIKITAVI_CONFIG`); otherwise the first of `./config.yaml`, `./config.yml`, `/etc/rikitikitavi/config.yaml`; otherwise built-in defaults. An explicit path that does not exist is an error. `scan` prints `Config: <path>` unless `--quiet`.

[`config.example.yaml`](config.example.yaml) documents every key with its default. Keys that parse but are not read yet (`logging.*`, `output.*`, `scan.network_mode`, `security_lake.*`, and others) are marked "reserved" there. `scan.perspective` is the default for `--perspective` on `scan` and `tui`; `scan.modules` is the default for `--modules`, and `scan.attack_paths: true` is the same as passing `--attack-paths`. `unifi.controller` turns on the controller client import (see [UniFi Integration](#unifi-integration)); `config show` prints the loaded config with secrets redacted. Safety-relevant keys under `scan`:

```yaml
scan:
  intensity: active            # passive | active | aggressive; a file value of aggressive is capped
                               # at active, login attempts require `scan --aggressive`
  parallelism: 256             # default 256; 1..=4096, outside that range is a startup error
  timeout_seconds: 0           # 0 = unbounded; otherwise the whole scan aborts after N seconds
  excluded_networks: ["192.168.50.0/24"]                    # CIDRs never probed
  excluded_devices: ["192.168.1.40", "aa:bb:cc:dd:ee:ff"]  # IPs never probed; MACs once the ARP cache knows them
```

Exclusion semantics: MAC entries are resolved to IPs through the ARP cache before the host sweep and re-applied after the sweep fills in MACs. Findings on excluded hosts are dropped after the scan, except `arp` findings, so spoofing that involves an excluded host is still reported. If every discovered host is excluded, the six ARP-fallback scanners (`credentials`, `services`, `smb`, `snmp`, `database`, `mgmt-plane`) are skipped; if the gateway is excluded, `router` is skipped.

Independently of `scan.timeout_seconds`, each scanner runs under its own budget of 4× its estimated duration, clamped to 60–600 s. A scanner that exceeds it is stopped with a warning; it keeps only the findings it had already reported incrementally (span outcome `partial`), which for most scanners is none.

Reports, baseline and known-device files are written with mode `0600` (the Prometheus textfile export is `0644`); the scan-history directory with `0700`.

### Custom rules

`--rules <file>` loads a YAML file of declarative checks and evaluates them
against the facts a scan already collected — per device: open ports (with
service, version and banner), device type, and the findings already raised.
No packets are sent; rules only reason over what the scanners found, and run
after scanning, before the report. Each matched device produces one finding.

```yaml
rules:
  - id: telnet-on-camera
    title: Telnet reachable on a camera or recorder   # keep it version-free
    severity: high                # info | low | medium | high | critical
    confidence: probable          # inferred (default) | probable
    description: Unencrypted admin shell on a camera or NVR.
    cwe: CWE-319
    references: [https://example.test/advisory]
    remediation:
      description: Disable Telnet; use HTTPS or SSH.
      steps: [Log in, Turn off Telnet, Re-scan]
      effort: 10 minutes
    match:                        # a bare list is an implicit "all"
      all:
        - port_open: 23
      any:
        - device_type_is: camera
        - device_type_is: nvr
```

Predicates (each is a one-key map, and the whole set is total — no code
execution, no regex):

| Predicate | Holds when |
|-----------|------------|
| `port_open: <port>` | the device has that port open |
| `device_type_is: <name>` | device type equals that wire name (`camera`, `nvr`, `nas`, `router`, `iot`, …) |
| `has_finding: <text>` | a finding on the device has that scanner id, or a title containing that text (case-insensitive) |
| `banner_contains: <text>` | a service, version or banner on any open port contains that text; scope with `{ port: <p>, text: <t> }` |
| `service_version_lt: { service: <s>, version: <v> }` | a service (optionally `port: <p>`) has a version below `v`, compared dotted-numerically (`1.9.0 < 1.10.0`) |

`match` is a bare list (all must hold), or `{ all: [...], any: [...] }` — a rule
matches when every `all` predicate holds and, if `any` is present, at least one
`any` predicate holds. Substring patterns are bounded to 200 bytes and matched
case-insensitively as plain text. A rule may not claim `confirmed` confidence:
it reasons over collected facts rather than performing a fresh protocol
exchange, so confidence is capped at `probable`. Loading fails with a clear
error on malformed YAML, an unknown field or device type, an empty match, or an
over-long pattern. See [`examples/rules/`](examples/rules/).

### Logging and Tracing

A scan is traced as spans: `scan` (root), `discovery`, one `scanner` span per
scanner carrying `id`, `findings`, `outcome` (`ok`, `partial`, `error`, `timeout`)
and `budget_secs`, and `rdns`, `nbns` and `unifi_clients` for the naming passes
(`verify` has its own root span). Each span logs its busy and idle time when it
closes:

```bash
rikitikitavi -l info scan                 # per-scanner timings on stderr
rikitikitavi -l info --log-format json scan 2> scan.log.jsonl
```

To export traces to an OpenTelemetry collector, build with the `otel` feature
(off by default, so the default binary has no export path) and set the standard
endpoint variable. Export is independent of `--log-level` and covers only this
project's spans:

```bash
cargo install --git <repo> --features otel
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 rikitikitavi scan
```

Traces go over OTLP/HTTP to `<endpoint>/v1/traces` with `service.name=rikitikitavi`.
Without the variable set, nothing is exported even in an `otel` build.

### Host Discovery

In Active and Aggressive mode, devices are named by two passes that run
alongside Phase 2:

- a reverse-DNS (PTR) pass against the gateway and any RFC 1918 resolvers from
  `resolv.conf`, never a public one; names are typed by a small hostname table
  and the Home Assistant DHCP matchers;
- a NetBIOS node-status (NBSTAT) pass, unicast UDP 137 to private addresses
  with SMB open or no name yet. A self-reported NetBIOS name ranks above a PTR
  name, except macOS's generated `MAC-xxxxxx` form.

With UniFi controller credentials in the config, controller aliases and
hostnames also name devices (see [UniFi Integration](#unifi-integration)).

In the default (Active) mode, rikitikitavi runs a bounded, unprivileged
TCP-connect sweep across the detected subnet, so a cold ARP cache on a freshly
booted machine does not yield an empty "looks clean" report. `--quick`
(Passive) mode stays read-only and only reads the ARP cache; to enrich it first:

```bash
nmap -sn 192.168.1.0/24   # or: fping -a -g 192.168.1.0/24
rikitikitavi scan --quick
```

## Findings Format

Each finding carries a severity, confidence, scanner ID, title, description,
affected host/port/service, CWE and CVE references, evidence, and remediation
steps with estimated effort. The JSON, CSV, HTML and OCSF exports carry all of
it. The terminal report prints a summary, the device table shown under
[Per-Device Report Cards](#per-device-report-cards), then
Critical/High/Medium findings in full and Low/Info as one line each,
accepted findings, and the top priority actions:

```
Scan complete: 131 findings
Risk score: 41/100 (F  CRITICAL ISSUES)

  Severity breakdown:
    CRITICAL  1
    HIGH      3
    MEDIUM    12
    ...

  Actionable findings:

    [CRITICAL] Redis accessible without authentication on 192.168.1.50:6379
              Redis at 192.168.1.50:6379 responds to commands without requiring ...
              Fix: Edit redis.conf and set 'requirepass <strong-password>'. → ...

  Informational (115):
    [LOW     ] ...
```

---

## Architecture

This is a 9-crate Rust workspace under `crates/`:

| Crate | Contents | Workspace dependencies |
|-------|----------|------------------------|
| `rikitikitavi` | Binary: CLI, scan runner, `verify`, accept file | all others (`tui`, `unifi` optional) |
| `rikitikitavi-core` | `Severity`, `Confidence`, `Perspective`, `ScanError` | none |
| `rikitikitavi-models` | `Finding`, `Device`, `ScanContext`, `ScanResults`, config types, OCSF structs | core |
| `rikitikitavi-network` | ARP, routes, interfaces, WiFi, host sweep, PTR and NBSTAT lookups, public IP, EPSS fetch | none |
| `rikitikitavi-scanners` | `Scanner` trait, `ScannerRegistry`, the 39 scanners, remediation templates, embedded fingerprint tables | core, models, network |
| `rikitikitavi-analysis` | Risk score, device grades, scan diff and history, attack paths, priority actions, KEV/Vulnrichment, OWASP tags, declarative rules | core, models |
| `rikitikitavi-export` | JSON, CSV, HTML, OCSF, Prometheus, fix plan, segment plan | core, models, analysis |
| `rikitikitavi-tui` | ratatui + crossterm terminal UI | core, models, export, analysis |
| `rikitikitavi-unifi` | UniFi controller client, local detection, WLAN/firewall/firmware audit | core, models, scanners |

Cargo features of the binary: `tui` and `unifi` (default), `monitor`
(passive WiFi, needs libpcap), `otel` (OTLP trace export), and `minimal`
(an empty marker; build with `--no-default-features` for a binary without the
TUI and UniFi crates).

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
    // Default calls scan(); override to keep partial findings on timeout.
    async fn scan_collecting(&self, ctx: &ScanContext, sink: &mut Vec<Finding>)
        -> Result<(), ScanError> { /* ... */ }
    fn estimated_duration_secs(&self) -> u64 { 30 }   // also sets the time budget
    fn requires_privileges(&self) -> bool { false }
    fn relevant_ports(&self) -> &[u16] { &[] }  // empty = always run
}
```

`relevant_ports()` enables Phase 2 filtering — if a scanner returns `&[3306,
5432]` and no hosts have those ports open, it's skipped entirely.

The `ScannerRegistry` holds `Vec<Box<dyn Scanner>>` and provides filtering by
perspective or ID (see [Adding a New Scanner](#adding-a-new-scanner)).

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
// Pure: takes &str, unit-tested with literal strings
fn parse_proc_route(contents: &str) -> Vec<RouteEntry> { /* ... */ }
fn detect_gateway_from_proc(contents: &str) -> Option<IpAddr> { /* ... */ }

// Public: reads the platform source, calls the pure function
pub fn detect_gateway() -> Result<Option<IpAddr>> { /* ... */ }
```

Linux reads `/proc` and `/sys` for routes, ARP and interfaces; only the WiFi
scan shells out (`iwconfig`, `iwlist`). macOS calls `ifconfig`,
`route`, `arp` and `system_profiler` and parses their output. Platform
selection uses `#[cfg]`:

```rust
#[cfg(target_os = "linux")]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> { /* parse /proc/net/arp */ }

#[cfg(target_os = "macos")]
fn read_arp_cache_platform() -> Result<Vec<ArpEntry>> { /* parse `arp -a` output */ }
```

Tests import the macOS parsers on Linux with
`#[cfg(any(target_os = "macos", test))]` so they run in CI.

#### Two-Phase Scan Orchestration

The runner (`runner.rs`) coordinates scanning:

1. **Phase 1** — `network`, `ports`, `device` run sequentially (each needs
   the previous results)
2. **Enrichment** — discovered ports are grouped by IP to build device
   profiles, then injected into `ScanContext`
3. **Phase 2** — the remaining selected scanners run concurrently via
   `futures::future::join_all`, filtered by `relevant_ports()`; the PTR,
   NBSTAT and UniFi client passes run alongside them
4. **Deduplication** — only restatements are dropped: the generic `ports`
   finding when a deeper scanner reports on the same `(ip, port)` at equal or
   higher severity, and two listed cross-scanner pairs (HSTS, server version).
   Distinct findings from different scanners on one port are kept, and
   findings with the same fingerprint collapse to the most severe
5. **Post-processing** — product-aware remediation, then KEV/Vulnrichment, OWASP
   tags and EPSS, then attack paths, risk score, priority actions and device
   grades

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

Beyond unit tests, `proptest` checks invariants such as JSON round-trips,
valid NDJSON for OCSF export, scan-diff symmetry, and risk-score bounds and
monotonicity (search for `fn prop_`).

The parsers that consume network-sourced bytes (DNS packets, 802.11 frames,
SSH KEX, service banners, HTTP headers, SSDP/UPnP, X.509 DER, OT and
smart-home protocols, web-app responses, Recog matching, among others) also
have libFuzzer harnesses under `fuzz/fuzz_targets/`; see
[`fuzz/README.md`](fuzz/README.md).

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
4. Add `pub mod my_scanner;` to `lib.rs`
5. Attach a remediation to every finding above Info (templates live in
   `crates/rikitikitavi-scanners/templates/`); `tests/remediation_coverage.rs`
   fails otherwise
6. If its probes go only to known hosts, consider adding its id to
   `REPLAYABLE` in `crates/rikitikitavi/src/verify.rs` so `verify` can re-check it
7. Write tests

### Adding a New Export Format

1. Create `crates/rikitikitavi-export/src/my_format.rs`
2. Implement `export_my_format(results: &ScanResults, path: &Path) -> Result<()>`
3. Re-export in `lib.rs`
4. Add variant to `ReportFormatArg` in `cli.rs`
5. Wire dispatch in `write_report` in `main.rs`

## Development

```bash
# Run all tests (unit, integration and proptest)
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
every PR: `check` (fmt, clippy, and clippy with `--features otel`), `test`
(Linux), `test-macos`, `msrv`
(`cargo check` on Rust 1.89), `deny`, and `fuzz-build` (nightly `cargo fuzz
build`; the fuzzers are built, not run). Release-profile builds are not part
of CI.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

---

```
     n,---.n
     ( o o )     The mongoose is watching your network.
```
