# Security Policy

## Scope

Rikitikitavi is a **home network security auditor** — it scans networks you own
or have authorization to test. It is not an offensive security tool.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

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
- **Licenses**: Only permissive licenses allowed (MIT, Apache-2.0, BSD, ISC, MPL-2.0, Zlib)
- **Sources**: Dependencies must come from crates.io (no unknown registries or git sources)

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
- **Credential testing**: By default the credential scanner only *detects*
  anonymous/default access (anonymous FTP, no-auth Redis) and flags cleartext
  Telnet. **Only with `--aggressive`** does it attempt default-credential Telnet
  logins against a small dictionary of canonical pairs (`admin/admin`, etc.) to
  *confirm* the exposure. That is bounded default-credential testing — it does
  send passwords and log in on success — not full brute force, and it is never
  on by default.
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

- **Scan history** is stored locally in the XDG data directory
  (`~/.local/share/rikitikitavi/scans/`) as JSON files.
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
  - *`update-db`*: fetches vulnerability databases when you run it.
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
  controller cert before sending credentials. The `--insecure` flag (for
  self-signed certs) must be explicitly passed to opt out, and it prints a loud
  warning when it does.

### TLS Configuration

All HTTPS connections use `rustls` (pure Rust TLS) with:
- TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1)
- Mozilla's trusted root certificates via `webpki-roots`
- No system certificate store dependencies

## Threat Model

Rikitikitavi trusts:

- **The local machine**: It reads `/proc`, executes network commands, and binds
  sockets. A compromised host can feed it false data.
- **The local network** (partially): Scan results reflect what the network
  reports. ARP spoofing or rogue DHCP could cause incorrect results (though
  rikitikitavi also detects these attacks).
- **crates.io**: Rust dependencies are pulled from the public registry.
  `cargo-deny` mitigates known supply chain risks.

Rikitikitavi does **not** trust:

- **Network services**: All service responses (banners, certificates, HTTP
  headers) are treated as untrusted input and parsed defensively.
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
