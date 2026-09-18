# Changelog

## Unreleased

Roadmap waves 1 and 2 (see docs/ROADMAP.md).

- mDNS discovery asks for the consumer service set (113 types, batched) and
  interprets TXT records; Home Assistant's generated discovery tables
  (Apache-2.0: 164 zeroconf, 89 SSDP, 103 MAC-only DHCP matchers, 71 HomeKit
  models) feed device identification above the OUI tier; Matter devices and
  Thread border routers are reported with their commissioning state.
- endoflife.date (MIT) product cycles replace the hand-coded "current stable"
  version claims in the services and HTTP audits.
- nuclei detection templates (MIT, inert send payloads only) identify products
  from banners and handshakes as a new read-only scanner.

- Six new scanners: Google Cast, PaperCut NG/MF (CVE-2026-81578/82078), TP-Link
  Kasa (unauthenticated local control on 9999), Tuya local protocol, Hikvision
  SADP discovery, Modbus/SunSpec on solar, battery and EV equipment. All probes
  are read-only and honour exclusions.
- ASUS "AyySSHush" backdoor check: SSH on TCP 53282 (CVE-2023-39780, KEV) and
  SSH banners on non-standard gateway ports.
- `DeviceType` gains 13 variants (hub, smart lock, thermostat, EV charger,
  inverter, NVR, doorbell, vacuum, smart plug, speaker, appliance, 3D printer,
  sensor) plus a free-text `device_subtype`; one canonical snake_case spelling
  in JSON, HTML, TUI and terminal output; unknown names read as `unknown`.
- CISA Vulnrichment SSVC (CC0) embedded for the CVEs the scanners emit: the
  `poc` exploitation tier and CWE backfill feed risk scoring.
- 14 ports added to the common scan list; THIRD-PARTY-NOTICES.md added.

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
