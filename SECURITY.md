# Security Policy

## Scope

Rikitikitavi is a **home network security auditor** — it scans networks you own
or have authorization to test. It is not an offensive security tool.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting a Vulnerability

If you find a security vulnerability in rikitikitavi itself (not a finding it
reports about your network), please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email: Open a [GitHub Security Advisory](https://github.com/lexicone42/rikitikitavi/security/advisories/new)
   (preferred) or email the maintainer directly.
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days
for critical issues.

## Security Design Principles

### Safe Rust Only

The entire workspace enforces `unsafe_code = "forbid"`. There is no `unsafe`
block anywhere in the codebase. This eliminates entire classes of memory safety
bugs (buffer overflows, use-after-free, data races) by construction.

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
```

### Strict Linting

Clippy pedantic and nursery lints are enabled with `-D warnings` (errors, not
warnings). This catches common security-relevant issues:

- Unchecked casts (`cast_sign_loss`, `cast_possible_truncation`)
- Missing error handling
- Unnecessary `unwrap()` calls
- Redundant or dead code

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

Eight libFuzzer harnesses under `fuzz/fuzz_targets/` cover the parsers that
consume network-sourced bytes: `dns_packet`, `wifi_frame`, `ssh_kex`,
`service_banners`, `http_headers`, `ssdp_upnp`, `x509_der`, `identifiers`. CI
builds every target on nightly (`fuzz-build` job) but does not run them; run
them locally per `fuzz/README.md`. The workspace also carries ~200 `proptest`
invariants (no panic on arbitrary input, counting invariants, serialization and
fingerprint round-trips).

### Network Scanning Safety

- **Authorization notice**: Every scan prints a one-line reminder that you must
  only scan networks you own or are explicitly authorized to test.
- **Reads, never writes**: Scanners observe and send crafted-but-non-destructive
  probes; they never modify device or network state. In Active mode this
  includes a bounded TCP-connect host sweep and application-layer probes (an SNMP
  `GET` of `sysDescr`, an MQTT `CONNECT`, an RTSP `DESCRIBE`, a UPnP-IGD
  `GetGenericPortMappingEntry`, an HTTP `GET`, etc.) — all read-only.
- **TCP connect scan**: The port scanner uses standard TCP connections (not
  SYN/half-open scans), which don't require raw sockets or root privileges.
- **No exploitation**: Rikitikitavi detects vulnerabilities but never exploits
  them. It reports "Redis has no auth" but doesn't read or write Redis data.
- **Credential testing**: Password-guessing Telnet logins run **only with
  `--aggressive`**, against a small dictionary of canonical pairs
  (`admin/admin`, etc.), and log in on success to *confirm* the exposure —
  bounded, not brute force, never on by default. The default (Active) scan
  still performs unauthenticated protocol logins that need no secret:
  anonymous FTP (`USER anonymous`, then a PASV `LIST` if accepted), SNMP
  `public`/`private` community probes, and an anonymous MQTT `CONNECT`. It
  flags cleartext Telnet and no-auth Redis without logging in. `--quick`
  (Passive) limits the credential scanner to the gateway and skips the SNMP and
  MQTT probes.
- **Rate limiting**: Scanners use connection timeouts and semaphore-based
  concurrency to avoid flooding the network.

### Passive WiFi Monitoring

The `monitor` feature (opt-in, not default) captures WiFi management frames
only:

- Beacons, probe requests, deauthentication frames
- Does **not** capture data frames or payload content
- Requires root/sudo for monitor mode
- Uses pcap with BPF filters to minimize captured traffic

### Data Handling

- **Scan history** is stored locally as JSON under the platform data
  directory (`~/.local/share/rikitikitavi/scans/` on Linux,
  `~/Library/Application Support/rikitikitavi/scans/` on macOS), pruned to the
  10 most recent scans.
- **File permissions**: every file rikitikitavi writes — scan history,
  JSON/CSV/HTML/OCSF exports, baselines, known-devices files — goes through
  `core::fs::write_private`, which creates with mode `0600` and re-chmods an
  existing file; the history directory is created with `create_private_dir`
  (`0700`). The one exception is `--format prometheus`, written `0644` so
  node_exporter's textfile collector can read it.
- **No telemetry**: Rikitikitavi does not phone home or transmit scan results
  anywhere.
- **Outbound calls**: rikitikitavi makes a small number of external calls beyond
  scanning your local network:
  - *Public IP detection* (exposure module): tries `api.ipify.org`,
    `ifconfig.me`, then `icanhazip.com` in order. Disable by excluding the
    `exposure` module.
  - *EPSS enrichment*: when a scan turns up CVEs, their exploitation-probability
    scores are fetched best-effort from `api.first.org` (FIRST.org). Skipped
    automatically when offline.
  - *`update-db`*: not yet implemented; makes no network calls.
  The CISA KEV catalog is **embedded** (a versioned static snapshot in
  `kev_db.rs`, regenerated with `scripts/gen_kev_db.py`) — no runtime fetch.
- **No telemetry**: none of these transmit your scan results anywhere.
- **OCSF export**: Findings are written to local files. S3 upload is manual
  (you run `aws s3 cp` yourself).

### UniFi Integration

- Credentials can be passed via CLI arguments/environment variables, or stored
  in the config file (`unifi.controller.password`/`api_token`, and the
  `apis.shodan_api_key`/`censys_*` keys). If you put secrets in the config,
  protect the file (`chmod 600`); `config show` redacts them, but they are stored
  in plaintext YAML.
- The UniFi client supports both cookie-based session auth and API token auth.
- **TLS certificate validation is on by default** — the client validates the
  controller cert before sending credentials. Validation is disabled by the
  `--insecure` flag or by `unifi.controller.insecure: true` in the config file;
  both go through `UniFiClient::connect`, which prints the same loud stderr
  warning whenever validation is off, whichever source set it.

### TLS Configuration

HTTPS uses `rustls` (pure Rust TLS), TLS 1.2+ only, with Mozilla's roots via
`webpki-roots` and no system certificate store. Whether the peer certificate
is *validated* depends on the caller:

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
  network-facing parsers are fuzzed (see above). HTTP bodies are read through
  a 2 MiB cap.
- **Evidence text**: `Finding::with_evidence` strips control characters,
  Unicode format controls (zero-width, bidi) and ANSI escapes, then truncates
  to 256 bytes on a char boundary, so device-supplied bytes cannot inject
  terminal escapes or hide text in reports. A property test enforces both
  bounds.
- **WiFi frames**: The 802.11 frame parser validates all lengths before
  accessing offsets. Malformed frames are silently dropped, never cause panics.

## Known Limitations

- **ARP cache completeness**: The scanner reads the OS ARP cache, which only
  contains recently-contacted hosts. A full subnet ping sweep before scanning
  is recommended.
- **No raw socket scanning**: Without `unsafe`, we can't craft raw packets.
  This means no SYN scans, no ICMP scans, no OS fingerprinting via TCP/IP
  stack analysis.
- **Single-subnet**: The scanner targets one local network at a time. It does
  not route through multiple subnets.
