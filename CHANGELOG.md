# Changelog

## 0.5.1 — 2026-11-17

- `verify` gave wrong verdicts in three cases:
  - A powered-off host with a stale ARP entry counted as alive, so its
    findings could be reported resolved. A host now counts as alive only if it
    answers TCP (accepts or refuses a connection).
  - `services` findings were re-checked against the banner saved in the last
    scan, so a closed port or an upgraded daemon stayed "still present".
    Banners are now read again from the host.
  - The Synology rsync correlation finding, which no scanner run reproduces,
    was reported resolved. It is now inconclusive with "run a full scan".
  Replaying a `services` finding no longer probes the gateway as well.
- TUI: the insecure-TLS warning for the UniFi controller no longer prints over
  the screen, and a panic inside a scan no longer restores the terminal while
  the UI is still running.
- Accept file: `fingerprint` must be a quoted string. Unquoted, YAML turned
  `0x…`, leading-zero and all-digit values into numbers and the entry matched
  nothing or the wrong fingerprint.
- `scan.modules` in the config is honoured (the CLI flag still wins).
  `scan.attack_paths` is honoured too, and its default is now `false` to match
  what `scan` has always done without `--attack-paths`.
- The services and ssl scanners respect `scan.parallelism` below their own
  caps of 64 and 32 hosts.
- Piping output to `head` no longer panics.
- `monitor --save` stored its result as a full scan, so `verify`, `fix-plan`,
  `segment-plan`, `--compare-previous` and the TUI start screen could pick up
  a device-less result. Monitor results are now saved as `monitor-*.json` and
  never read as the last scan.
- `unifi scan` reads the URL, site and credentials from `unifi.controller` in
  the config, and secrets from `RIKITIKITAVI_UNIFI_TOKEN` /
  `RIKITIKITAVI_UNIFI_PASSWORD`. Flags still override.
- The TUI's `e` export replaces a symlink at the output path instead of
  writing through it.
- Help text says which subcommands are not implemented, and that `--format`
  applies to `--output` only.
- CI lints the `monitor` feature.

## 0.5.0 — 2026-11-17

- http_audit: fewer duplicate admin-page findings. An admin path that returns
  the device's front page, or the page it serves for a path that does not
  exist (single-page apps, redirects to the front page), is no longer reported
  as "Possibly exposed admin page". One page returned by several admin paths
  is reported once, under the first path. A UniFi camera went from 12 such
  findings to none. The dropped findings show as resolved in the next scan
  diff.
- Docs checked against the code: README (CLI reference, sample output,
  architecture), SECURITY.md (every outbound call, UniFi import, `verify`,
  file handling), both roadmaps (status per item), RUST_PATTERNS, the learning
  files and THIRD-PARTY-NOTICES. New `CLAUDE.md` for AI-assisted work. The
  0.4.0 entry named the wrong credential corpus; it is RouterSploit's.
- cargo-deny ignores RUSTSEC-2026-0543 (chrono unmaintained, no vulnerability)
  until chrono is replaced.
- Hardening: `Debug` output redacts the UniFi cloud, Shodan and Censys API
  keys (the controller password already was). The public-IP and EPSS responses
  are read with a size cap, like every LAN response.
- TUI rebuilt. It opens on the last saved scan and runs the first scan in the
  background (it used to show a blank terminal until the scan finished). The
  network map, which listed 15 devices at most, is now a scrolling device table
  with grade, proposed zone and finding counts; a device opens to its ports and
  findings. Finding, action and attack-path text wraps and scrolls instead of
  being cut at the pane edge. New: `/` search, `?` help, Ctrl-C to quit, a
  finding's CVEs, KEV flag, confidence and fingerprint, `--accept-file`, the
  UniFi client import, and `e` writing the results JSON, fix plan and segment
  plan under timestamped names (it used to overwrite
  `rikitikitavi-results.json`). Themes paint their background. The terminal is
  restored on errors and panics, and log output no longer draws over the
  screen. Device-type emoji are gone (their width differs between terminals).
  New mascot, here and in the README.
- reqwest 0.13.5 (was held at 0.13.1 by a removed `webpki-roots` feature):
  sensitive headers are stripped on cross-scheme redirects. Outbound TLS now
  validates against the OS root store. The authenticated UniFi client follows
  no redirects.
- Scan speed, found with the span timings: a full scan of a 71-device /22 drops
  from about 126 s to 27 s. The services scanner probes hosts concurrently and
  reuses the banners phase 1 already read; ssl and nuclei-detect run hosts in
  parallel; the port scan interleaves hosts with at most 16 probes in flight
  per host; the discovery sweep probes its liveness ports at once. Default
  `parallelism` is 256 (was 100).
- `verify` subcommand: replays the scanners behind prior findings on the
  affected hosts only and reports resolved / still present / inconclusive
  (exit 0 / 3 / 4). An offline host is never "resolved".
- `fix-plan` subcommand: Markdown checklist from the last scan, grouped per
  device, each item with its fix, references and a `verify` command.
- `--accept-file`: accepted-risk ledger with reason and expiry. Accepted
  findings stay visible but leave the score, grades and `--fail-on`.
- Every finding at Low or above carries a remediation, enforced by a test.
  Remediation templates match on vendor, product, device type and port:
  Dyson MQTT, Denon/Marantz network control, Hue and UniFi get vendor-specific
  steps. 61 templates added.
- Reverse-DNS device naming through the gateway resolver (RFC 1918 resolvers
  only), with a hostname table and the Home Assistant DHCP hostname matchers
  for typing. On the test LAN, named devices rose from 18 to 59 of 71.
- NetBIOS NBSTAT naming pass (unicast UDP 137, private addresses only). A
  self-reported name ranks above a PTR name, except macOS's generated
  `MAC-xxxxxx` form.
- Vendor lookup uses the IEEE MA-M (6,688) and MA-S (7,280) registries, longest
  prefix first. MA-L drops its 442 "IEEE Registration Authority" parent rows
  (40,055 entries).
- UniFi SAB-069 fixed-version floors (CVE-2026-77555 and five siblings): checked
  against firmware on the credentialed and on-device paths; without
  credentials an identified gateway gets one Info advisory naming the floors.
- Apple TV: `osvers` from AirPlay checked against six KEV fix versions
  (tvOS 15.2 to 26.3) and the tvOS end-of-life table; models that cannot run
  tvOS 27 are told to replace. AirPlay receivers that advertise no password,
  PIN or pairing requirement get a Low finding.
- `segment-plan` subcommand: proposes Trusted / IoT / Infrastructure zones from
  the last scan, with per-device reasons, an allow-rule table built from the
  ports seen open, and the mDNS services that must cross zones. Text only.
- UniFi client import: when `unifi.controller` credentials are in the config,
  `scan` reads the controller's client list and uses owner-set aliases and
  hostnames to name devices (alias > scanner names > controller hostname >
  NetBIOS > PTR). Connected clients the scan did not see are summarised in one
  finding. `mode: disabled` turns it off. Devices carry `seen_by`.
- Authenticated UniFi API responses are capped at 16 MiB; controller
  credentials are redacted from `Debug` output.
- Findings with the same fingerprint collapse to the most severe.
- Plex: one verdict for the Plex2Shell chain below 1.43.3.10861 (four KEV CVEs).
- Kasa: fixed-firmware table per model and hardware version from TP-Link FAQ
  5342 and 5267 (CVE-2026-108473, CVE-2026-76784); the fix names the build.
- New scanners: Hue Bridge firmware (CVE-2026-3557, CVE-2026-3562) and Spotify
  Connect identification. 37 scanners become 39.
- Synology: SA-26:13 / SA-26:19 minimum builds on the DSM finding; rsync on a
  Synology host is flagged for CVE-2026-85101. PHP2Shell floors on
  `X-Powered-By` (CVE-2026-109618, CVE-2026-109619).
- Default ports grew from 58 to 66 (3689, 4070, 5001, 7000, 8880, 55442, 55443,
  62078) so the iOS, NAS, UniFi-controller and new Echo classifier rules fire.
- Deduplication drops only restatements: the generic `ports` finding when a
  deeper scanner reports on the port at equal or higher severity, and two
  listed cross-scanner pairs. Distinct findings from different scanners on one
  port are all kept; before, one scanner's group won and the rest were dropped
  (30 Low/Medium findings on the test LAN, e.g. certificate and header
  findings). Expect them as "new" in the first `--compare-previous` diff.
  Finding order is now deterministic.
- An MQTT broker that enforces authentication is reported Low, not Medium.
  An identified Denon/Marantz receiver gets no telnet credential probe; its
  finding is retitled, so its fingerprint changes.
- `--suppress` now also removes suppressed findings from priority actions and
  attack paths. Byte caps on suppress, known-devices, accept and rule files.
- Home Assistant discovery tables regenerated at fa47075 (adds `hp_printer`,
  drops six Dahua OUIs from `imou`).
- Tracing: `scan`, `discovery` and per-scanner spans (findings, outcome, time
  budget); spans log busy/idle time on close. `--log-format text|json`.
- Optional OTLP/HTTP trace export behind the `otel` cargo feature, active only
  when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; independent of the log level.
- Dependencies refreshed; six `quinn-proto`/`quinn-udp` advisories cleared.
- YAML parsing moved from `serde_yaml_ng` (on the archived `unsafe-libyaml`) to
  the pure-Rust `serde-saphyr`, for config, rule files and remediation templates.
- MSRV raised to 1.89 (required by `uuid`). Unused workspace dependencies removed.
- KEV catalog 2026.11.13 (1,781 entries), the IEEE OUI table and the
  endoflife.date table regenerated.

## 0.4.0 — 2026-09-20

The whole detection roadmap, plus custom rules, per-device report cards, and a
robustness sweep (two adversarial re-reviews, fuzzing, and mutation testing).
25 scanners grew to 37 and the test suite from 1325 to 2196.

### Breaking

- Product-identification and Tuya finding titles changed, so their fingerprints
  changed. Regenerate `--write-baseline` / `--known-devices` files after
  upgrading, or stale entries stop matching for one scan.
- The default common port list grew from 43 to 58 so the new scanners are
  reachable at the default range; a plain `scan` now probes those extra ports.

### New scanners (25 → 37)

- **Smart-home and media:** Google Cast, TP-Link Kasa (unauthenticated local
  control on 9999), Tuya local protocol, Plex/Jellyfin media servers,
  Moonraker/OctoPrint 3D printers, KNXnet/IP building automation.
- **Cameras and OT:** Hikvision SADP discovery, Modbus/SunSpec on solar,
  battery and EV equipment.
- **Web and infrastructure:** PaperCut NG/MF (CVE-2026-81578/82078), DD-WRT
  `upnpd` (CVE-2021-27137), nuclei detection templates, client-side LAN
  exposure (Sonos SMB client issue).
- ASUS "AyySSHush" backdoor check: SSH on TCP 53282 (CVE-2023-39780, KEV),
  asserted with the CVE only where the host is identifiably ASUS.
- Every probe is read-only, exclusion-aware, and intensity-gated.

### Device identification

- `DeviceType` gains 13 variants (hub, smart lock, thermostat, EV charger,
  inverter, NVR, doorbell, vacuum, smart plug, speaker, appliance, 3D printer,
  sensor) and a free-text `device_subtype`, with one canonical snake_case
  spelling across JSON, HTML, TUI and terminal output.
- mDNS asks for 113 consumer service types and interprets TXT records; Home
  Assistant's discovery tables (Apache-2.0) identify devices above the OUI tier;
  Matter devices and Thread border routers are reported with commissioning state.
- Rapid7 Recog fingerprints (BSD-2-Clause, 2,430 patterns) identify products,
  firmware and device class from banners already collected. Identification is
  Info/Probable and the title carries no version, so patch upgrades don't churn
  `--compare-previous`.

### Intelligence and scoring

- CISA Vulnrichment SSVC (CC0): the `poc` exploitation tier and CWE backfill
  feed risk scoring.
- endoflife.date (MIT) product cycles replace hand-coded "current stable"
  version claims; distribution-backported builds are scored Low, not Medium.
- OWASP IoT Top 10 (2018) tags: each finding is mapped to a category (I1–I10)
  by CWE or scanner, in JSON, HTML and OCSF. Identifiers only, cited.

### Reporting and interface

- Per-device report cards: a letter grade from a device's own findings and its
  class, in the terminal report, HTML inventory, TUI, and the JSON
  `report_cards` array. This is the tool's own scoring, not a conformance verdict.
- `--format prometheus`: text exposition 0.0.4 for node_exporter's textfile
  collector (device, finding, KEV, EOL and grade metrics; written 0644 with a
  world-readable-file warning).
- Device tracking status (`known` / `new` / `untracked`) appears per device.

### Custom rules and credentials

- `scan --rules <file>`: a declarative engine matches YAML rules over the
  scan's own facts (ports, versions, banners, findings, device type) with a
  small total predicate set — no code execution, bounded patterns, and a rule
  can never mint a Confirmed finding. Example rules under `examples/rules/`.
- A default-credential corpus (RouterSploit wordlists, BSD-3-Clause). Login attempts run only at
  `--aggressive`, capped and rate-limited, stopping at first success and
  honouring exclusions; below `--aggressive`, a device whose class ships
  defaults gets a Low/Inferred "verify" advisory with no login.

### Quality

- Two full adversarial re-reviews of the new surface; every confirmed finding
  fixed, including a dedup bug that could drop a High finding for a richer Info
  one on the same port.
- Fuzzing grew to 13 libFuzzer targets over the network-facing parsers; an
  extended soak found no crashes.
- cargo-mutants is set up (`.cargo/mutants.toml`). Mutation testing hardened
  the analysis logic to only proven-equivalent survivors and raised the scanner
  classification score from 68% to 86.5% catchable, killing real test gaps.
- A macOS CI job; the Linux-only parsers are gated so the workspace builds and
  tests clean on macOS.

## 0.3.0 — 2026-09-16

Hardening pass before the first shared release. Every change below is covered by
tests; the workspace runs 1322 tests, clippy pedantic+nursery on stable 1.98,
an MSRV 1.88 check, cargo-deny, and a nightly fuzz build in CI.

### Breaking

- **Baseline and known-device files must be regenerated.** `Finding::fingerprint`
  now uses FNV-1a over an explicit byte layout (stable across Rust releases,
  pointer width and endianness). Baseline files carry `# format: fnv1a-1`;
  `--suppress` warns when the header is missing or different.
- `Finding.affected_mac` is a `MacAddr` (serialised unchanged as the canonical
  lowercase string; unparseable legacy strings deserialise as `null`).
- Unimplemented flags (`--ssid`, `--password`, `--interface`, `--upload`,
  `--unifi-local`, `aws upload`) are hard errors instead of warnings.
- `--quick` and `--aggressive` conflict; `tui --interval` requires >= 5,
  `monitor --duration` >= 1; `scan.parallelism` must be 1..=4096.
- The DHCP scanner's TCP-based "rogue server" check was removed (it could
  never fire on UDP-only ports).

### Safety controls

- `scan.excluded_devices` / `scan.excluded_networks` are enforced before every
  probe: discovery, the TCP sweep, the port scanner, UPnP/IGD fetches, the
  alternate-gateway probe, and every scanner's findings. MAC exclusions apply
  once the ARP cache knows the host.
- A config-file `intensity: aggressive` is capped at `active`; default-credential
  login attempts require the explicit `--aggressive` flag. The loaded config
  path is printed.
- `--suppress` and `--known-devices` fail closed on unreadable or garbled files.
- Reports, baseline, known-device and history files are written with mode
  0600 (history directory 0700).
- Finding evidence strips C0/C1 controls, ANSI escapes and Unicode bidi/format
  controls; CSV export neutralises formula-leading cells.
- One `unauthenticated_probe_client()` owns TLS-validation bypass for the
  unauthenticated HTTP probes; a source test keeps it that way.

### Fixes

- UTF-8 boundary panics in evidence truncation, SMTP EHLO, SSH version, HTML
  title, FTP PASV and TUI truncation; SSH KEXINIT and SNMP BER length arithmetic
  is checked; Webmin version comparison no longer overflows.
- UniFi client matches the controller wire format (`_id`, `version`, integer
  `state`, `ip_subnet`, `dhcpd_enabled`, firewall address/group scoping,
  `inner_alert_*`), detects UniFi OS (`/proxy/network`, `/api/auth/login`), and
  its probe requires a UniFi body marker.
- Telnet default-credential classification is tri-state and only confirms on a
  positive shell indicator; MongoDB no-auth check sends a real `listDatabases`;
  Apache CVE-2021-41773/42013 match exact 2.4.49/2.4.50 only.
- mDNS/SSDP collection has deadlines and record caps; SRV responder attribution
  fixed; radiotap extended present words parsed at the right offsets; iwlist
  `hidden` computed per cell; airport rows split on tokens; macOS `arp -a`
  octets zero-padded.
- Hosts found by the TCP sweep get their MAC from the ARP cache, so
  `--known-devices` matches across runs; known-device matching accepts MAC or IP.
- `--modules`: unknown ids error before any network activity, unsupported
  perspectives are skipped with a warning, phase-1 modules are added
  automatically, `--dry-run` lists the real set.
- TUI: dashboard clicks select findings, network-map row offset follows the
  renderer, re-scan errors clear the scanning state, `--watch` re-scans every
  `--interval` seconds, the TUI uses the same host discovery as `scan`.
- `report --latest | head` no longer aborts (panic=abort + closed stdout).
- Attack paths chain only same-host findings; isolation uses the target
  network prefix instead of /24; HTTP audit runs endpoints concurrently.

### Testing

- 75 property tests (round-trip, invariance, monotonicity, table integrity).
- `fuzz/`: eight libFuzzer targets over the network-facing parsers
  (`cargo +nightly fuzz`); an initial soak of ~166M executions found nothing.
- CI: macOS test job and nightly fuzz-build job added.

## 0.2.0 — 2026-07-02

Modernisation: edition 2024, MSRV 1.88, dependency security updates,
`MacAddr` newtype, macOS fixes, new-device detection and suppression baselines.
