# Security Policy

## Scope

Rikitikitavi is a **home network security auditor** — it scans networks you own
or have authorization to test. It is not an offensive security tool.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a Vulnerability

If you find a security vulnerability in rikitikitavi itself (not a finding it
reports about your network), please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Report it privately through a
   [GitHub Security Advisory](https://github.com/lexicone42/rikitikitavi/security/advisories/new).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

This is a small project maintained on a best-effort basis. We aim to
acknowledge reports within a few days and to prioritise fixes for critical
issues.

## Security Design Principles

### Safe Rust Only

Every workspace crate enforces `unsafe_code = "forbid"`, so there is no
`unsafe` block in this repository's own code. Dependencies are not covered:
tokio, rustls with the `aws-lc-rs` crypto provider (C and assembly), and
libpcap for the opt-in `monitor` feature all contain unsafe or foreign code.

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

### Strict Linting

Clippy `pedantic` and `nursery` are enabled workspace-wide, and CI runs
`cargo clippy --workspace --all-targets -- -D warnings`, so any lint is a build
failure. Among others this catches unchecked numeric casts
(`cast_sign_loss`, `cast_possible_truncation`, `cast_possible_wrap`).

### Dependency Auditing

[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) runs in CI to
check:

- **Advisories**: Known vulnerabilities in dependencies (RustSec advisory database)
- **Licenses**: Allowlist of permissive licenses (MIT, Apache-2.0,
  Apache-2.0 WITH LLVM-exception, BSD-2/3-Clause, ISC, MPL-2.0, OpenSSL,
  Unicode-3.0, Unicode-DFS-2016, Zlib, CDLA-Permissive-2.0)
- **Sources**: crates.io is the only allowed registry; unknown registries and
  git sources are set to `warn`, not `deny` (`deny.toml`)

### Fuzzing and Property Tests

Thirteen libFuzzer harnesses under `fuzz/fuzz_targets/` cover the parsers that
consume network-sourced bytes: `dns_packet`, `wifi_frame`, `ssh_kex`,
`service_banners`, `http_headers`, `ssdp_upnp`, `x509_der`, `identifiers`,
`smart_home`, `ot_protocols`, `web_apps`, `recog`, `tables`. CI builds every
target on nightly (`fuzz-build` job) but does not run them; run them locally per
`fuzz/README.md`. The workspace also carries about 270 `proptest` properties (no
panic on arbitrary input, counting invariants, serialization and fingerprint
round-trips). A cargo-mutants configuration (`.cargo/mutants.toml`) is provided
for measuring whether the tests catch injected bugs; mutation testing is not run
in CI.

### Network Scanning Safety

- **Authorization notice**: `scan` prints a one-line reminder that you must
  only scan networks you own or are explicitly authorized to test (suppressed by
  `--quiet`).
- **Observe, don't change**: Scanners send crafted but non-destructive probes;
  none is meant to modify device or network state. At the default (Active)
  intensity this includes a bounded TCP-connect host sweep, multicast and
  broadcast discovery (mDNS, SSDP, Hikvision SADP, KNXnet/IP search), and
  application-layer probes (an SNMP `GET` of `sysDescr`, an MQTT `CONNECT`, an
  RTSP `DESCRIBE`, a UPnP-IGD `GetGenericPortMappingEntry`, an HTTP `GET`, etc.).
- **Host sweep**: before scanning, Active and Aggressive scans TCP-connect to
  ports 80, 443, 22, 445, 8080 and 53 on up to 4,096 IPv4 addresses of the
  local network (excluded hosts skipped) to find hosts missing from the ARP
  cache. `--quick` skips the sweep.
- **TCP connect scan**: The port scanner uses standard TCP connections (not
  SYN/half-open scans), which don't require raw sockets or root privileges.
  `--quick` scans 20 ports; `--aggressive` scans the extended range.
- **No exploitation**: Rikitikitavi detects vulnerabilities but never exploits
  them. It reports "Redis has no auth" but doesn't read or write Redis data.
- **Credential testing**: default-credential logins against telnet, FTP and
  HTTP Basic-auth panels run **only with `--aggressive`** (see the next
  section) — bounded, not brute force, never on by default. The default
  (Active) scan still performs unauthenticated protocol logins that need no
  secret: anonymous FTP (`USER anonymous`, then a PASV `LIST` if accepted), SNMP
  community probes, and an anonymous MQTT `CONNECT`. It flags cleartext Telnet
  and no-auth Redis without logging in. `--quick` (Passive) limits the
  credential scanner to the gateway and skips the SNMP and MQTT probes.
- **`verify`** replays the scanners behind earlier findings against only the
  affected hosts, honours the current exclusions, and replays `credentials`
  findings (login checks) only with `verify --aggressive`.
- **Rate limiting**: Scanners use connection timeouts and semaphore-based
  concurrency to avoid flooding the network.

### Default-credential corpus and login testing

The credential scanner draws on an embedded default-credential corpus curated
from the RouterSploit wordlists (BSD-3-Clause; see THIRD-PARTY-NOTICES.md):
79 home/SOHO `user:pass` pairs from `defaults.txt` (generic or vendor-tagged) and
all 119 SNMP community strings from `snmp.txt`. It is a static table
(`crates/rikitikitavi-scanners/src/default_creds_db.rs`) containing no exploit
code. How it is used depends strictly on scan intensity:

- **SNMP communities (Active-ok)**: an SNMP `GET` is a read, not a login, so the
  community wordlist runs at Active. It is capped at 8 communities per host,
  ordered by prevalence, time-budgeted so a silent host is not probed for long,
  and it stops at the first community that answers. No SET is ever sent.
- **Active and below — no login**: for a device whose class is known to ship
  default credentials (router, access point, camera, NVR, doorbell, printer,
  NAS), the scanner emits a Low/Inferred advisory keyed on the class ("this
  device class ships default credentials — verify"). No authentication is
  attempted; the corpus only informs the wording.
- **Aggressive only — capped login testing**: default-credential logins against
  telnet, FTP and HTTP Basic-auth admin panels run **only** with `--aggressive`.
  A configuration file cannot raise intensity to Aggressive — a config value of
  `aggressive` is capped at Active by `scan`, `verify` and `tui` — so an
  untrusted config never enables login attempts. Safeguards:
  - **Capped**: at most 8 attempts per service per host (`MAX_LOGIN_ATTEMPTS`),
    never the whole corpus. Vendor-matching pairs are tried first so few attempts
    are needed.
  - **Rate-limited**: a 250 ms delay between successive attempts against one host.
  - **Stops at first success**: testing halts on the first accepted login per
    service, so a compromised default is confirmed with the fewest attempts.
  - **Lockout awareness**: the small cap is meant to stay under typical account
    lockout and IDS thresholds; a login is still a login, so it is gated and
    bounded rather than exhaustive.
  - **Cleartext**: these are known default pairs sent over plain telnet, FTP and
    HTTP (no TLS), as the services under test require.
  - **Honest confidence**: a finding is `Confirmed` only on a real protocol
    answer (a shell/login indicator for telnet, FTP `230`, a non-`401`/`403`
    response to HTTP Basic); otherwise it stays Inferred/inconclusive.
- **Exclusions honoured**: hosts and networks listed in `scan.excluded_devices` /
  `scan.excluded_networks` are never probed by the credential or SNMP scanner, at
  any intensity.

### Passive WiFi Monitoring

The `monitor` feature (opt-in, not default) captures WiFi management frames
only:

- Beacons, probe requests, deauthentication frames
- Does **not** capture data frames or payload content
- Requires root/sudo for monitor mode. On Linux it adds a virtual monitor
  interface with `iw`; on macOS it enables rfmon on the WiFi interface, which
  disconnects it for the duration
- Uses a pcap BPF filter (`type mgt`) so only management frames are captured

### Data Handling

- **Scan history** is stored locally as JSON under the platform data
  directory (`~/.local/share/rikitikitavi/scans/` on Linux,
  `~/Library/Application Support/rikitikitavi/scans/` on macOS). Full scans and
  `verify` results are each pruned to the 10 most recent. A saved scan holds
  the full device inventory and findings, including any client names, aliases
  and notes imported from a UniFi controller. `--no-save` skips it.
- **File permissions**: every file rikitikitavi writes — scan history,
  JSON/CSV/HTML/OCSF exports, fix and segmentation plans, baselines,
  known-devices files — goes through `core::fs::write_private`, which creates
  with mode `0600` and re-chmods an existing file; the history directory is
  created with `create_private_dir` (`0700`). The one exception is
  `--format prometheus`, written `0644` so node_exporter's textfile collector can
  read it.
- **TUI export**: pressing `e` in the TUI writes
  `rikitikitavi-<timestamp>.json`, `-fix-plan.md` and `-segment-plan.md` to the
  current working directory (mode `0600`).
- **Input files**: the accept file (`--accept-file`, capped at 256 KiB),
  baseline and known-devices files (4 MiB) and rules files (1 MiB) are read with
  size caps and rejected when invalid. The config file is YAML and is trusted.
- **No telemetry by default**: Rikitikitavi does not phone home or upload scan
  results. The default build contains no trace exporter. A build with the
  opt-in `otel` cargo feature exports execution traces over OTLP/HTTP only when
  `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is
  set, and only to that endpoint. Those traces carry scanner names, timings,
  finding counts and this tool's own log events, which can include device IP
  addresses; point it at a collector you control.
- **Outbound calls**: beyond your local network, a scan contacts:
  - *Public IP detection* (`exposure` module): tries `api.ipify.org`,
    `ifconfig.me`, then `icanhazip.com` in order. The module then TCP-connects
    to a list of common service ports on your own public IP to look for port
    forwards. Disable by excluding the `exposure` module.
  - *DNS checks* (`dns` module): resolves `www.google.com`,
    `www.cloudflare.com`, `www.example.com` and `dnssec-failed.org` through your
    configured resolvers, queries `1.1.1.1` directly for `www.example.com` to
    compare answers, and looks up SPF/DMARC records for the system's DNS search
    domain if one is set.
  - *EPSS enrichment*: when a scan turns up CVEs, their exploitation-probability
    scores are fetched best-effort from `api.first.org` (FIRST.org). The request
    carries the CVE ids found on your network, which reveals something about the
    software you run. Lookup failures are ignored.
  - *UniFi controller*: only when configured (see below).
  - *`update-db`*: not yet implemented; makes no network calls.

  The CISA KEV catalog, CISA Vulnrichment SSVC data, end-of-life dates, OUI
  registry and fingerprint databases are **embedded** as static snapshots
  regenerated by the scripts in `scripts/` (see THIRD-PARTY-NOTICES.md) — no
  runtime fetch.
- **OCSF export**: Findings are written to local files. The `aws` subcommands
  and `scan --upload` are not implemented; S3 upload is manual (you run
  `aws s3 cp` yourself).

### UniFi Integration

- **Client import during `scan` and `tui`**: when `unifi.controller` in the
  config has a `url` plus an `api_token` or a `username` and `password` (and
  `unifi.mode` is not `disabled`), the scan logs in to the controller and reads
  its client list (`stat/sta` and `rest/user`). Nothing is written to the
  controller. `scan` prints a line when it does this. Imported names and notes
  are stripped of control and format characters and length-capped. The URL must
  not embed credentials, and the whole import is bounded by a 60 s timeout.
- **`unifi scan`** reads credentials from `unifi.controller` in the config
  file, from `RIKITIKITAVI_UNIFI_TOKEN` / `RIKITIKITAVI_UNIFI_PASSWORD`, or
  from `--token` / `--password`. Command-line values are visible to other
  local users in the process list and may land in shell history; prefer the
  config file or the environment.
- **Secrets at rest**: controller `password`/`api_token`, `unifi.cloud.api_key`
  and the `apis.*` keys are stored in plaintext YAML if you put them in the
  config. Protect the file (`chmod 600`). `config show` redacts them, and the
  `Debug` output of the controller config prints `<redacted>` for the password
  and token.
- The UniFi client supports both cookie-based session auth and API token auth.
  It does not follow redirects, so credentials and the CSRF header never go to
  another origin, and API responses are capped at 16 MiB.
- **TLS certificate validation is on by default** — the client validates the
  controller cert before sending credentials. Validation is disabled by the
  `--insecure` flag or by `unifi.controller.insecure: true` in the config file;
  both go through `UniFiClient::connect`, which prints a stderr warning whenever
  validation is off. The unauthenticated controller-detection probe in the
  `unifi` scanner skips validation and sends no credentials.

### TLS Configuration

HTTPS uses `rustls` (pure Rust TLS), TLS 1.2+ only, trusting the operating
system's certificate store through `rustls-platform-verifier`. Whether the peer
certificate is *validated* depends on the caller:

- **Validated**: outbound internet calls (public-IP providers, EPSS) and the
  UniFi controller client (unless `--insecure` /
  `unifi.controller.insecure`).
- **Not validated, by design**: unauthenticated LAN probes. Scanners that must
  tolerate self-signed device certificates build their client through
  `http_util::unauthenticated_probe_client`, which sets
  `danger_accept_invalid_certs(true)` and must never carry credentials; a test
  asserts that flag appears in no other scanner file. The TLS scanner installs
  a no-op certificate verifier so it can inspect self-signed and expired
  certificates instead of failing the handshake.

## Threat Model

Rikitikitavi trusts:

- **The local machine**: It reads `/proc`, executes network commands, and binds
  sockets. A compromised host can feed it false data.
- **Its config file**: it can name a UniFi controller to log in to and carry
  secrets, but it cannot enable login attempts (see above).
- **The local network** (partially): Scan results reflect what the network
  reports. ARP spoofing could cause incorrect results; rikitikitavi flags
  duplicate-IP/MAC and broadcast-MAC anomalies in the ARP cache, but it sends
  no DHCP traffic and does not detect rogue DHCP servers (the `dhcp` scanner
  only reports APIPA addresses and gateway-less interfaces).
- **crates.io**: Rust dependencies are pulled from the public registry.
  `cargo-deny` mitigates known supply chain risks.

Rikitikitavi does **not** trust:

- **Network services**: All service responses (banners, certificates, HTTP
  headers) are treated as untrusted input and parsed defensively; the
  network-facing parsers are fuzzed (see above). LAN HTTP bodies are read
  through `http_util::read_body_capped` (2 MiB default); individual scanners use
  smaller caps (for example 8 KiB for RTSP, 16 KiB for Hue, 256 KiB for Kasa,
  media servers and 3D printers), and UDP discovery caps the number of replies
  it keeps.
- **Evidence text**: `Finding::with_evidence` strips control characters,
  Unicode format controls (zero-width, bidi) and ANSI escapes, then truncates
  to 256 bytes on a char boundary, so device-supplied bytes cannot inject
  terminal escapes or hide text in reports. A property test enforces both
  bounds. The HTML report HTML-escapes, and the Markdown fix plan escapes
  Markdown, before writing device-supplied text.
- **UniFi controller responses**: client names, hostnames and notes are
  sanitised and capped (64 characters, 128 for notes) before use.
- **WiFi frames**: The 802.11 frame parser validates all lengths before
  accessing offsets. Malformed frames are silently dropped, never cause panics.

## Known Limitations

- **Host discovery**: hosts come from the OS ARP cache plus the TCP-connect
  sweep. A host that is not in the ARP cache and neither accepts nor refuses a
  connection on any sweep port is missed. IPv6 networks are not swept, and
  networks larger than 4,096 addresses are swept only in part.
- **No raw socket scanning**: Scans use the OS socket API without raw
  sockets, so there are no SYN scans, no ICMP scans and no OS fingerprinting
  via TCP/IP stack analysis.
- **Single-subnet**: The scanner targets one local network at a time. It does
  not route through multiple subnets.
