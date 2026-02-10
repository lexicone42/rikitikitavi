use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::IpAddr;

use crate::Scanner;

/// DNS security scanner — checks DNS configuration, DNSSEC validation,
/// and common misconfigurations.
pub struct DnsScanner;

/// Parse `/etc/resolv.conf` to extract configured nameservers.
fn parse_resolv_conf(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("nameserver") {
                line.split_whitespace().nth(1)?.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

/// Read nameservers from `/etc/resolv.conf`.
fn read_nameservers() -> Vec<IpAddr> {
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(contents) => parse_resolv_conf(&contents),
        Err(e) => {
            tracing::warn!("cannot read /etc/resolv.conf: {e}");
            Vec::new()
        }
    }
}

/// Check DNSSEC validation by resolving `dnssec-failed.org`.
///
/// This domain has an intentionally broken DNSSEC signature.
/// If the resolver returns a result, DNSSEC validation is NOT enforced.
async fn check_dnssec_validation(nameservers: &[IpAddr]) -> Option<bool> {
    if nameservers.is_empty() {
        return None;
    }

    // Build a resolver using the system's nameservers
    let ns_group = NameServerConfigGroup::from_ips_clear(nameservers, 53, true);
    let config = ResolverConfig::from_parts(None, Vec::new(), ns_group);
    let mut opts = ResolverOpts::default();
    opts.validate = false; // Don't validate locally — we want to see what the upstream does
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 1;

    let resolver = TokioAsyncResolver::tokio(config, opts);
    resolver.lookup_ip("dnssec-failed.org.").await.map_or(
        // Lookup failed (SERVFAIL) = DNSSEC validation IS enforced
        Some(true),
        |response| {
            if response.iter().next().is_none() {
                Some(true) // Empty response = validation worked
            } else {
                Some(false) // Got IPs = DNSSEC NOT enforced
            }
        },
    )
}

#[async_trait]
impl Scanner for DnsScanner {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn name(&self) -> &'static str {
        "DNS Security"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running DNS security scan");
        let mut findings = Vec::new();

        let nameservers = read_nameservers();

        if nameservers.is_empty() {
            findings.push(Finding::new(
                "dns",
                "No DNS servers configured",
                "No nameservers found in /etc/resolv.conf. DNS resolution may \
                 not be working, or the system uses an alternative resolver \
                 (e.g. systemd-resolved).",
                Severity::High,
            ));
            return Ok(findings);
        }

        // Report configured nameservers
        let ns_list: Vec<String> = nameservers.iter().map(ToString::to_string).collect();
        findings.push(Finding::new(
            "dns",
            &format!("DNS servers: {}", ns_list.join(", ")),
            &format!(
                "The system is configured to use the following DNS servers: {}",
                ns_list.join(", ")
            ),
            Severity::Info,
        ));

        // Check if DNS is the gateway (common router DNS)
        if let Some(gateway) = ctx.gateway {
            if nameservers.contains(&gateway) {
                findings.push(
                    Finding::new(
                        "dns",
                        "DNS resolves through the router",
                        &format!(
                            "DNS server {gateway} is the default gateway. This is common \
                             but means DNS security depends entirely on the router's \
                             configuration. Consider using a hardened DNS resolver like \
                             Quad9 (9.9.9.9) or Cloudflare (1.1.1.1)."
                        ),
                        Severity::Info,
                    )
                    .with_ip(gateway),
                );
            }
        }

        // Check for well-known privacy/security DNS
        let has_secure_dns = nameservers.iter().any(|ns| {
            let s = ns.to_string();
            matches!(
                s.as_str(),
                "9.9.9.9" | "149.112.112.112" |  // Quad9
                "1.1.1.1" | "1.0.0.1" |           // Cloudflare
                "8.8.8.8" | "8.8.4.4" |           // Google
                "208.67.222.222" | "208.67.220.220" // OpenDNS
            )
        });

        if !has_secure_dns {
            findings.push(Finding::new(
                "dns",
                "No well-known secure DNS provider in use",
                "The configured DNS servers are not well-known security-focused \
                 resolvers. Consider Quad9 (9.9.9.9) for malware blocking, or \
                 Cloudflare (1.1.1.1) for privacy. This is informational — your \
                 current DNS may be adequate.",
                Severity::Info,
            ));
        }

        // DNSSEC validation check
        match check_dnssec_validation(&nameservers).await {
            Some(true) => {
                findings.push(Finding::new(
                    "dns",
                    "DNSSEC validation is enforced",
                    "The configured DNS resolver correctly rejects domains with \
                     broken DNSSEC signatures (dnssec-failed.org).",
                    Severity::Info,
                ));
            }
            Some(false) => {
                findings.push(
                    Finding::new(
                        "dns",
                        "DNSSEC validation not enforced",
                        "The configured DNS resolver successfully resolved \
                         dnssec-failed.org, which has an intentionally broken \
                         DNSSEC signature. This means DNSSEC validation is not \
                         enforced, leaving DNS responses vulnerable to spoofing.",
                        Severity::Medium,
                    )
                    .with_cwe("CWE-350")
                    .with_references(vec![
                        "https://dnssec-failed.org/".to_owned(),
                    ]),
                );
            }
            None => {
                tracing::debug!("skipping DNSSEC check — no nameservers available");
            }
        }

        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_resolv_conf() {
        let contents = "\
# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 8.8.8.8
search home.lan
";
        let ns = parse_resolv_conf(contents);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ns[1], IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_parse_resolv_conf_empty() {
        let ns = parse_resolv_conf("# empty config\n");
        assert!(ns.is_empty());
    }

    #[test]
    fn test_parse_resolv_conf_with_options() {
        let contents = "\
options ndots:5
nameserver 1.1.1.1
search example.com
nameserver 9.9.9.9
";
        let ns = parse_resolv_conf(contents);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(ns[1], IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    }
}
