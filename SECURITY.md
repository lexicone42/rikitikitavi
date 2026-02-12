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

- **Read-only by default**: Most scanners only observe (ARP cache, DNS config,
  WiFi networks, service banners). They don't modify network state.
- **TCP connect scan**: The port scanner uses standard TCP connections (not
  SYN/half-open scans), which don't require raw sockets or root privileges.
- **No exploitation**: Rikitikitavi detects vulnerabilities but never exploits
  them. It reports "Redis has no auth" but doesn't read or write Redis data.
- **Credential testing**: The credential scanner checks for anonymous/default
  access (anonymous FTP, no-auth Redis). It does not brute-force passwords.
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
- **Public IP detection**: The exposure scanner queries `https://api.ipify.org`
  to detect your public IP. This is the only external network call (besides
  scanning your local network). It can be disabled by excluding the `exposure`
  module.
- **OCSF export**: Findings are written to local files. S3 upload is manual
  (you run `aws s3 cp` yourself).

### UniFi Integration

- Credentials are passed via CLI arguments or environment variables, never
  stored on disk by rikitikitavi.
- The UniFi client supports both cookie-based session auth and API token auth.
- HTTPS certificate validation is enabled by default. The `--insecure` flag
  (for self-signed certs) must be explicitly passed.

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
