# Changelog

## Unreleased

Roadmap waves 1 and 2 (see docs/ROADMAP.md).

- OWASP IoT Top 10 (2018) taxonomy tags: a post-scan enrichment pass maps each
  finding to zero or one category (`I1`–`I10`), primarily by CWE id and, for
  findings with no CWE, by scanner id. Findings carry a new `standards` field
  (additive; old scan history loads unchanged). Tags appear in the JSON report,
  in the HTML report per finding, and in OCSF export under `unmapped.standards`.
  Only the bare category identifiers are used; the labels are this project's own
  factual restatements, not OWASP's descriptive prose. (CP-13)
- mDNS discovery asks for the consumer service set (113 types, batched) and
  interprets TXT records; Home Assistant's generated discovery tables
  (Apache-2.0: 164 zeroconf, 89 SSDP, 103 MAC-only DHCP matchers, 71 HomeKit
  models) feed device identification above the OUI tier; Matter devices and
  Thread border routers are reported with their commissioning state.
- endoflife.date (MIT) product cycles replace the hand-coded "current stable"
  version claims in the services and HTTP audits. An end-of-life join made from
  the table alone is Low, not Medium, when the header names a distribution build
  (`(Debian)`, `1ubuntu2`, `+deb12u1`), which may still carry backported fixes —
  unless that distribution generation is itself end-of-life (`+deb10`, `.el7`,
  `(CentOS)`), where it stays Medium.
- nuclei detection templates (MIT, inert send payloads only) identify products
  from banners and handshakes as a new read-only scanner.

- Rapid7 Recog banner fingerprints (BSD-2-Clause, 2,430 patterns over 13 match
  keys) identify products, firmware and device class from strings the scanners
  already collect: SSH, Telnet, FTP, SMTP, IMAP and POP greetings, the HTTP
  `Server` header, `WWW-Authenticate` realm and page title, SNMP `sysDescr`,
  X.509 subject and issuer, and the `@PJL INFO ID` reply. Identification is
  Info/Probable — a banner is a claim, not a demonstration — and a device type is
  set only from Recog's own device vocabulary through a curated map, never from a
  product name. The finding title carries no version ("nginx identified at
  10.0.0.5:80"), so a patch upgrade does not read as one finding resolved and
  another raised; the version stays in the description and the service field.
  This changes the fingerprint of every existing identification finding once:
  rewrite saved baseline and suppression files (`--write-baseline`) after
  upgrading, or those entries stop matching and the noise returns for one scan.

- Six new scanners: Google Cast, PaperCut NG/MF (CVE-2026-81578/82078), TP-Link
  Kasa (unauthenticated local control on 9999), Tuya local protocol, Hikvision
  SADP discovery, Modbus/SunSpec on solar, battery and EV equipment. All probes
  are read-only and honour exclusions.
- ASUS "AyySSHush" backdoor check: SSH on TCP 53282 (CVE-2023-39780, KEV) and
  SSH banners on non-standard gateway ports. The CVE and its factory-reset
  remediation are asserted only where the vendor or the SSH banner names ASUS as
  a token; any other host with 53282 open gets a vendor-neutral High/Probable
  finding with no CVE.
- `DeviceType` gains 13 variants (hub, smart lock, thermostat, EV charger,
  inverter, NVR, doorbell, vacuum, smart plug, speaker, appliance, 3D printer,
  sensor) plus a free-text `device_subtype`; one canonical snake_case spelling
  in JSON, HTML, TUI and terminal output; unknown names read as `unknown`.
- CISA Vulnrichment SSVC (CC0) embedded for the CVEs the scanners emit: the
  `poc` exploitation tier and CWE backfill feed risk scoring.
- 15 ports added to the common scan list (43 -> 58), so the scanners that
  declare them stay reachable at the default range; THIRD-PARTY-NOTICES.md
  added.

- Per-device report cards: a letter grade per device from its own findings and
  its device class (KEV findings cap at F; classes that hold other devices'
  credentials or act on the physical world are graded one letter harder; a host
  with nothing observed is "not assessed", not A). Rendered in the terminal
  report, HTML inventory, TUI dashboard/map/detail and the JSON `report_cards`
  array. It is this tool's own scoring, not a conformance verdict against any
  scheme.
- Device tracking status (`known` / `new` / `untracked`) from `--known-devices`
  now appears per device in reports, not only as a finding.
- `--format prometheus`: Prometheus text exposition 0.0.4 for node_exporter's
  textfile collector, written atomically (device, finding, KEV, EOL, grade and
  per-device identity metrics).
- mDNS device hints are ranked by matcher specificity: a name-glob or
  TXT-predicate match from Home Assistant's zeroconf table now outranks a bare
  service-type match, and equal-ranked hints are ordered by content instead of
  by the order the responses arrived in.
- Five more scanners from the roadmap's threat and hardware sections, all
  read-only: KNXnet/IP building automation (UDP 3671 SEARCH_REQUEST; reports
  reachable attack surface and programming mode, and deliberately attaches no
  CVE, since the CVE-2023-4346 precondition is a bus-level property no
  KNXnet/IP datagram carries), Plex and Jellyfin media servers (CVE-2020-5741
  and CVE-2025-34158 version ranges, Jellyfin first-run setup left open),
  Moonraker/Klipper and OctoPrint 3D printers (authentication posture read from
  Moonraker's own `/access/info`, OctoPrint identified by its `X-Clacks-Overhead`
  header), the DD-WRT `upnpd` banner check for CVE-2021-27137 (KEV; MiniUPnPd
  banners are a negative indicator and the crashing proof of concept is never
  sent), and a client-side LAN exposure category for devices attacked as clients
  of services other hosts offer, seeded with the Sonos SMB client issue.

Review fixes on those five scanners:

Review fixes on the Cast/PaperCut/Kasa/Tuya/SADP/Modbus scanners:

- PaperCut: a host listening on both admin ports (9191 and 9192) is probed once,
  TLS first, so a default install no longer produces two findings for one
  service. The unverified-build finding no longer carries `cve_ids` — KEV
  enrichment raised it to High regardless of confidence, which made its Medium
  unreachable and could flag any page merely mentioning PaperCut as a KEV RCE;
  the CVE ids stay in the description and references.
- Cast: empty-string `eureka_info` fields (`local_authorization_token_hash`,
  `cloud_device_id` on an unlinked speaker) no longer count as disclosed, so an
  all-empty response no longer yields a Medium exposure finding.
- Modbus: the 3-character `sma` vendor needle is matched as a whole manufacturer
  token instead of as a substring of the model, so Victron SmartSolar and
  Smappee gear is no longer labelled a solar inverter; Smappee added as a meter.
- Modbus, PaperCut and Cast probe hosts with bounded concurrency behind their
  own phase deadline, so an overrun keeps the findings collected so far instead
  of the runner discarding the scanner's whole result.
- SADP: multicast replies from outside `--target` are dropped on receipt, and an
  unparseable first datagram no longer claims a host's dedup slot. The
  CVE-2017-7921 text no longer states an unsupported KEV catalog date.
- Tuya: the uncorroborated TCP/6668 finding is titled "TCP/6668 open on
  {ip}, Tuya protocol unconfirmed" and no longer asserts a vendor the probe
  never established (6668 is also an IRC alternate port). **Baseline entries for
  the old title stop matching.**
- THIRD-PARTY-NOTICES.md: entries for the softScheck/tplink-smartplug Kasa
  protocol description and test vector (Apache-2.0), and for the tinytuya-published
  Tuya broadcast key.
- The nuclei detection pass follows a redirect only back to the same origin. A
  device that 302s elsewhere had that response matched and reported against the
  original `ip:port`, including the device hint that rewrites its type. A
  same-origin `/` -> `/login` redirect is still followed, so the common device
  landing page is not lost; a redirect to another host or port is not, so an
  HTTPS management port is identified only when it is itself scanned.
- Client-side LAN exposure: a device whose published name carries a model token
  the advisory does not name (a Sonos Beam, One, Arc, Port, ...) now reports at
  `Info` instead of `Low`, naming the token in the description, evidence and a
  debug log. It is not dropped: those tokens are also ordinary room names, and
  the advisory names where the bug was demonstrated, not necessarily every model
  the firmware ships to. Absence of any name still reports at Low.
- A Plex or Jellyfin server, and a generic `server` row of the nuclei hint table
  (Nextcloud, Pi-hole, iLO), no longer relabel an already-identified device as a
  generic `server`; a NAS running Plex or Nextcloud stays a NAS (and stays in
  the class-weighted grading set). The subtype is still recorded.
- `nuclei_db`'s `TcpTemplate.vendor` / `HttpTemplate.vendor` column is gone. It
  was never read, and several rows carried a product name in it; `nuclei_detect`
  derives vendor from its own curated `HINTS` table. Regenerating the table with
  `scripts/gen_nuclei_db.py` now emits no vendor column.
- The Prometheus export is written 0644, not 0600: node_exporter's textfile
  collector runs as its own user and could not read the file, so no series ever
  appeared. The three snapshot gauges lost the counter-only `_total` suffix and
  are now `rikitikitavi_devices`, `rikitikitavi_kev_findings` and
  `rikitikitavi_eol_findings`.
- The SSVC note appended to a finding's description is a single line; the blank
  line it used to embed broke the terminal, TUI and HTML layouts, all of which
  render a description as one line.
- A report card only claims the device class cost a letter when the grade
  actually stepped down; an already-F device no longer says so.
- The Vulnrichment table selects rows from production source plus an explicit
  allowlist (`scripts/vulnrichment_extra_cves.txt`), so CVE ids that exist only
  as test fixtures no longer get embedded (26 records, was 29).
- A KEV finding forces grade F before the device-class step-down runs, so a
  weighted-class card whose grade KEV decided no longer reports (or counts) the
  class rule as the reason.
- New `rikitikitavi_poc_findings` gauge: findings with public exploit code and
  no observed exploitation, the tier KEV cannot express.
- `gen_vulnrichment_db.py` strips comments and `#[cfg(test)]` items with a lexer
  that knows string, raw-string and char literals, and `--check <table>` re-runs
  the row selection offline against a committed table.
- `DeviceType::label` gives a human spelling (`IoT`, `Smart TV`, `Access Point`)
  and the terminal report and new-device findings use it; the JSON, Prometheus
  and history wire names are unchanged, and the HTML and TUI device inventories
  still print the wire name. **"New device on network" finding titles change for
  multi-word device types, so a `--suppress` baseline written by an earlier build
  no longer matches those findings — rewrite it with `--write-baseline`.**
- Finding dedup per (IP, port) now prefers the group with the highest severity
  before the most detailed one, and breaks ties on scanner id: an Info service
  identification can no longer evict a High vulnerability, and two runs of the
  same scan report the same findings.
- The risk score and the device report cards are recomputed after new-device
  findings are added and suppressed findings removed, so the printed and exported
  score and grades match the findings shown beside them.
- mDNS TXT model and vendor keys are read per service type: `md`/`vn` in
  `_raop._tcp` are metadata types and protocol version, not model and vendor, and
  no longer surface as a device model.

- Default-credential corpus (RouterSploit wordlists, BSD-3-Clause): 79 home/SOHO
  `user:pass` pairs curated from `defaults.txt` (generic or vendor-tagged) and all
  119 SNMP community strings from `snmp.txt`, embedded as a sorted generated table
  (`crates/rikitikitavi-scanners/src/default_creds_db.rs`, regenerate with
  `uv run python scripts/gen_default_creds_db.py`). No exploit code imported.
  - SNMP scanner: the community wordlist now extends past `public`/`private` with a
    capped, prevalence-ordered, corpus-attributed slice (≤ 12 communities per host,
    with a per-host time budget so silent hosts stay cheap). A GET is a read, not a
    login, so this still runs at Active; it honours `--exclude` and stops at the
    first community that answers.
  - Credentials scanner now honours `scan.excluded_networks` / `excluded_devices`
    (it did not before).
  - At Active and below, a device whose class is known to ship default credentials
    (router, AP, camera, NVR, doorbell, printer, NAS) gets a Low/Inferred advisory
    keyed on the class — no login is attempted.
  - Only at `--aggressive`: capped default-login testing for telnet, FTP and HTTP
    Basic-auth admin panels. Vendor-matching pairs are tried first, attempts are
    rate-limited and capped at 8 per service per host, and testing stops at the
    first success — chosen to never risk account lockout on the owner's own LAN.
    Confirmed only on a real login; the `--aggressive` gate is unchanged (a config
    file still cannot raise intensity to Aggressive).
- User-extensible declarative checks (`--rules <file>`): a YAML file of rules
  matches total predicates over the facts a scan already collected — per device,
  open ports (service/version/banner), device type, and the findings already
  raised — and emits a finding. Predicates are `port_open`, `device_type_is`,
  `has_finding`, `banner_contains` and `service_version_lt`; `match` is a bare
  list (AND) or `{ all, any }`. No code execution and no regex — substring
  patterns are plain, case-insensitive and bounded to 200 bytes; versions compare
  dotted-numerically. Rules send no packets and run after scanning, before the
  report; each participates in risk scoring and grading. A rule may not claim
  `confirmed` confidence (it reasons over collected facts), so confidence is
  capped at `probable`. Loading fails with a clear error on malformed YAML, an
  unknown field or device type, an empty match, or an over-long pattern. Example
  rule files ship under `examples/rules/`.
- A scanner that overruns its per-scanner time budget now keeps the findings it
  produced before the deadline instead of losing the whole result. The `Scanner`
  trait gains an optional `scan_collecting` that streams findings into a sink as
  they are produced; scanners that do not override it behave as before (a timeout
  yields nothing), but the run always continues.
- The ASUS "AyySSHush" (CVE-2023-39780) attribution now gates on the OUI of the
  MAC — the hardware vendor — not `device.vendor`, which a UPnP/SSDP-advertised
  `manufacturer` string can overwrite. A non-ASUS host advertising "ASUS" over
  UPnP no longer reaches the Confirmed/Critical CVE tier; it gets the
  vendor-neutral High/Probable finding.

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
