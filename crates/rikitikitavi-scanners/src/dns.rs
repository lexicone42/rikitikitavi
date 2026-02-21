use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
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

/// Parse macOS `scutil --dns` output to extract nameservers from the default resolver.
///
/// The output contains numbered resolver blocks. The default resolver is `resolver #1`.
/// Each block may contain `nameserver[N] : <ip>` lines.
#[cfg(any(target_os = "macos", test))]
fn parse_scutil_dns_nameservers(contents: &str) -> Vec<IpAddr> {
    let mut nameservers = Vec::new();
    let mut in_default_resolver = false;

    for line in contents.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("resolver #1") {
            in_default_resolver = true;
            continue;
        }
        // Any subsequent "resolver #N" (N > 1) ends the default block.
        if in_default_resolver && trimmed.starts_with("resolver #") {
            break;
        }

        if in_default_resolver {
            if let Some(rest) = trimmed.strip_prefix("nameserver[") {
                // Format: "nameserver[0] : 192.168.1.1" or "nameserver[1] : fd00::1"
                // Split on " : " (the scutil delimiter), not bare ":" which breaks IPv6.
                if let Some(ip_str) = rest.split_once(" : ").map(|(_, v)| v) {
                    if let Ok(ip) = ip_str.trim().parse() {
                        nameservers.push(ip);
                    }
                }
            }
        }
    }

    nameservers
}

/// Parse macOS `scutil --dns` output to extract the search domain from the default resolver.
#[cfg(any(target_os = "macos", test))]
fn parse_scutil_dns_search_domain(contents: &str) -> Option<String> {
    let mut in_default_resolver = false;

    for line in contents.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("resolver #1") {
            in_default_resolver = true;
            continue;
        }
        if in_default_resolver && trimmed.starts_with("resolver #") {
            break;
        }

        if in_default_resolver {
            if let Some(rest) = trimmed.strip_prefix("search domain[") {
                // Format: "search domain[0] : home.arpa"
                if let Some(domain) = rest.split_once(" : ").map(|(_, v)| v.trim()) {
                    if !domain.is_empty() && domain.contains('.') {
                        return Some(domain.to_owned());
                    }
                }
            }
        }
    }

    None
}

/// Read the system's configured DNS nameservers.
///
/// On Linux, reads `/etc/resolv.conf`. On macOS, uses `scutil --dns` to query
/// the system resolver (`mDNSResponder`), falling back to `/etc/resolv.conf`.
fn read_nameservers() -> Vec<IpAddr> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil")
            .arg("--dns")
            .output()
        {
            if output.status.success() {
                let contents = String::from_utf8_lossy(&output.stdout);
                let ns = parse_scutil_dns_nameservers(&contents);
                if !ns.is_empty() {
                    return ns;
                }
                tracing::debug!("scutil --dns returned no nameservers, falling back to resolv.conf");
            }
        }
    }

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

/// Check whether the resolver returns private IP addresses for public domains,
/// which could indicate DNS rebinding attacks or DNS hijacking.
///
/// We resolve several well-known domains and check if any return private IPs.
async fn check_dns_rebinding(nameservers: &[IpAddr], findings: &mut Vec<Finding>) {
    if nameservers.is_empty() {
        return;
    }

    let ns_group = NameServerConfigGroup::from_ips_clear(nameservers, 53, true);
    let config = ResolverConfig::from_parts(None, Vec::new(), ns_group);
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 1;

    let resolver = TokioAsyncResolver::tokio(config, opts);

    // Resolve well-known public domains that should NEVER return private IPs
    let test_domains = ["www.google.com.", "www.cloudflare.com.", "www.example.com."];

    for domain in &test_domains {
        if let Ok(response) = resolver.lookup_ip(*domain).await {
            for ip in response.iter() {
                if is_private_ip(ip) {
                    findings.push(
                        Finding::new(
                            "dns",
                            &format!("DNS returns private IP for {domain}: {ip}"),
                            &format!(
                                "Resolving {domain} returned private IP address {ip}. \
                                 This strongly suggests DNS hijacking or a captive portal. \
                                 An attacker controlling DNS can redirect traffic to \
                                 malicious servers for credential theft or malware delivery."
                            ),
                            Severity::Critical,
                        )
                        .with_ip(ip)
                        .with_cwe("CWE-350")
                        .with_opt_remediation(crate::remediation::get(
                            "rikitikitavi.dns.hijacking-detected",
                            &[],
                        )),
                    );
                }
            }
        }
    }
}

/// Check if an IP address is in a private/reserved range.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8
            || octets[0] == 127
            // 169.254.0.0/16 (APIPA)
            || (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(v6) => {
            // ::1 loopback or fc00::/7 unique local
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Cross-validate DNS by comparing configured resolver results against a
/// well-known public resolver (Cloudflare 1.1.1.1). Discrepancies may
/// indicate DNS tampering.
async fn check_dns_cross_validation(nameservers: &[IpAddr], findings: &mut Vec<Finding>) {
    if nameservers.is_empty() {
        return;
    }

    // Don't cross-validate if the configured resolver IS a well-known public one
    let cloudflare: IpAddr = "1.1.1.1".parse().unwrap();
    let google: IpAddr = "8.8.8.8".parse().unwrap();
    if nameservers.contains(&cloudflare) || nameservers.contains(&google) {
        return;
    }

    // Resolve using configured DNS
    let ns_group = NameServerConfigGroup::from_ips_clear(nameservers, 53, true);
    let local_config = ResolverConfig::from_parts(None, Vec::new(), ns_group);
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 1;
    let local_resolver = TokioAsyncResolver::tokio(local_config, opts);

    // Resolve using Cloudflare 1.1.1.1
    let cf_group = NameServerConfigGroup::from_ips_clear(&[cloudflare], 53, true);
    let cf_config = ResolverConfig::from_parts(None, Vec::new(), cf_group);
    let cf_opts = {
        let mut o = ResolverOpts::default();
        o.timeout = std::time::Duration::from_secs(5);
        o.attempts = 1;
        o
    };
    let cf_resolver = TokioAsyncResolver::tokio(cf_config, cf_opts);

    let test_domain = "www.example.com.";

    let local_result = local_resolver.lookup_ip(test_domain).await;
    let cf_result = cf_resolver.lookup_ip(test_domain).await;

    if let (Ok(local_ips), Ok(cf_ips)) = (local_result, cf_result) {
        let local_set: std::collections::HashSet<IpAddr> = local_ips.iter().collect();
        let cf_set: std::collections::HashSet<IpAddr> = cf_ips.iter().collect();

        if !local_set.is_empty() && !cf_set.is_empty() && local_set.is_disjoint(&cf_set) {
            let local_str: Vec<String> = local_set.iter().map(ToString::to_string).collect();
            let cf_str: Vec<String> = cf_set.iter().map(ToString::to_string).collect();
            findings.push(
                Finding::new(
                    "dns",
                    "DNS responses differ from public resolver",
                    &format!(
                        "Resolving {test_domain} returned different IPs from your \
                         configured DNS ({}) vs Cloudflare 1.1.1.1 ({}). \
                         This could indicate DNS hijacking, ISP manipulation, \
                         or a captive portal.",
                        local_str.join(", "),
                        cf_str.join(", ")
                    ),
                    Severity::Medium,
                )
                .with_cwe("CWE-350")
                .with_opt_remediation(crate::remediation::get(
                    "rikitikitavi.dns.cross-validation-mismatch",
                    &[],
                )),
            );
        }
    }
}

// ── Email security (SPF / DKIM / DMARC) via TXT records ──────────

/// Classify an SPF TXT record.
pub fn classify_spf(record: &str) -> Option<Finding> {
    let lower = record.to_lowercase();
    if !lower.starts_with("v=spf1") {
        return None;
    }

    // SPF with "+all" allows anyone to send mail — very bad
    if lower.contains("+all") {
        return Some(
            Finding::new(
                "dns",
                "SPF allows all senders (+all)",
                &format!(
                    "SPF record uses +all, which permits any IP to send mail for \
                     this domain. This defeats the purpose of SPF entirely. \
                     Record: {record}"
                ),
                Severity::High,
            )
            .with_cwe("CWE-284"),
        );
    }

    // "~all" (softfail) is weak but common
    if lower.contains("~all") {
        return Some(Finding::new(
            "dns",
            "SPF uses softfail (~all)",
            &format!(
                "SPF record uses ~all (softfail) instead of -all (hardfail). \
                 Unauthorized senders may still deliver mail. Record: {record}"
            ),
            Severity::Low,
        ));
    }

    // "-all" is good
    Some(Finding::new(
        "dns",
        "SPF record configured",
        &format!("SPF: {record}"),
        Severity::Info,
    ))
}

/// Classify a DMARC TXT record.
pub fn classify_dmarc(record: &str) -> Option<Finding> {
    let lower = record.to_lowercase();
    if !lower.starts_with("v=dmarc1") {
        return None;
    }

    // p=none means monitoring-only — no enforcement
    if lower.contains("p=none") {
        return Some(Finding::new(
            "dns",
            "DMARC policy is none (monitoring only)",
            &format!(
                "DMARC record uses p=none, which monitors but does not reject \
                 spoofed mail. Consider upgrading to p=quarantine or p=reject. \
                 Record: {record}"
            ),
            Severity::Low,
        ));
    }

    Some(Finding::new(
        "dns",
        "DMARC policy configured",
        &format!("DMARC: {record}"),
        Severity::Info,
    ))
}

/// Query TXT records for a domain using the given resolver.
async fn query_txt_records(resolver: &TokioAsyncResolver, domain: &str) -> Vec<String> {
    resolver.lookup(domain, RecordType::TXT).await.map_or_else(
        |_| Vec::new(),
        |response| {
            response
                .record_iter()
                .filter_map(|r| {
                    r.data().map(|data| {
                        let s = data.to_string();
                        s.trim_matches('"').to_owned()
                    })
                })
                .collect()
        },
    )
}

/// Check email security records (SPF, DKIM, DMARC) for a domain.
async fn check_email_security(nameservers: &[IpAddr], domain: &str, findings: &mut Vec<Finding>) {
    if nameservers.is_empty() || domain.is_empty() {
        return;
    }

    let ns_group = NameServerConfigGroup::from_ips_clear(nameservers, 53, true);
    let config = ResolverConfig::from_parts(None, Vec::new(), ns_group);
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 1;
    let resolver = TokioAsyncResolver::tokio(config, opts);

    // SPF — TXT record on the domain itself
    let txt_records = query_txt_records(&resolver, &format!("{domain}.")).await;
    let has_spf = txt_records
        .iter()
        .any(|r| r.to_lowercase().starts_with("v=spf1"));

    for record in &txt_records {
        if let Some(finding) = classify_spf(record) {
            findings.push(finding);
        }
    }

    if !has_spf {
        findings.push(Finding::new(
            "dns",
            &format!("No SPF record for {domain}"),
            &format!(
                "No SPF TXT record found for {domain}. Without SPF, anyone can \
                 send email appearing to come from this domain."
            ),
            Severity::Medium,
        ));
    }

    // DMARC — TXT record at _dmarc.domain
    let dmarc_records = query_txt_records(&resolver, &format!("_dmarc.{domain}.")).await;
    let has_dmarc = dmarc_records
        .iter()
        .any(|r| r.to_lowercase().starts_with("v=dmarc1"));

    for record in &dmarc_records {
        if let Some(finding) = classify_dmarc(record) {
            findings.push(finding);
        }
    }

    if !has_dmarc {
        findings.push(Finding::new(
            "dns",
            &format!("No DMARC record for {domain}"),
            &format!(
                "No DMARC TXT record found at _dmarc.{domain}. Without DMARC, \
                 there is no policy to handle SPF/DKIM failures, making email \
                 spoofing easier."
            ),
            Severity::Medium,
        ));
    }

    // DKIM — check common selector "default" at default._domainkey.domain
    let dkim_records = query_txt_records(&resolver, &format!("default._domainkey.{domain}.")).await;
    let has_dkim = dkim_records
        .iter()
        .any(|r| r.to_lowercase().contains("v=dkim1"));

    if has_dkim {
        findings.push(Finding::new(
            "dns",
            &format!("DKIM record found for {domain}"),
            &format!(
                "DKIM record at default._domainkey.{domain}: {}",
                dkim_records.first().map_or("", String::as_str)
            ),
            Severity::Info,
        ));
    }
    // Note: DKIM not found is not necessarily a finding since the selector
    // could be different (google, selector1, etc.) and we can't enumerate all.
}

/// Extract the search domain from `/etc/resolv.conf`.
fn parse_search_domain(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("search") {
            let domain = rest.split_whitespace().next()?;
            // Skip obviously internal-only domains
            if !domain.is_empty() && domain.contains('.') {
                return Some(domain.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("domain") {
            let domain = rest.split_whitespace().next()?;
            if !domain.is_empty() && domain.contains('.') {
                return Some(domain.to_owned());
            }
        }
    }
    None
}

/// Read the search domain from the system DNS configuration.
///
/// On macOS, queries `scutil --dns` first (authoritative source), falling back
/// to `/etc/resolv.conf`. On Linux, reads `/etc/resolv.conf` directly.
fn read_search_domain() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil")
            .arg("--dns")
            .output()
        {
            if output.status.success() {
                let contents = String::from_utf8_lossy(&output.stdout);
                let domain = parse_scutil_dns_search_domain(&contents);
                if domain.is_some() {
                    return domain;
                }
            }
        }
    }

    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|contents| parse_search_domain(&contents))
}

#[async_trait]
#[allow(clippy::too_many_lines)]
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
            let description = if cfg!(target_os = "macos") {
                "No nameservers found via scutil --dns or /etc/resolv.conf. \
                 DNS resolution may not be working. This is unusual on macOS — \
                 mDNSResponder normally configures DNS automatically via DHCP."
            } else {
                "No nameservers found in /etc/resolv.conf. DNS resolution may \
                 not be working, or the system uses an alternative resolver \
                 (e.g. systemd-resolved)."
            };
            findings.push(Finding::new(
                "dns",
                "No DNS servers configured",
                description,
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

        // DNS rebinding check — resolve a known test domain and check
        // if private IPs appear in public DNS responses
        check_dns_rebinding(&nameservers, &mut findings).await;

        // Cross-validate DNS between configured resolver and a public one
        check_dns_cross_validation(&nameservers, &mut findings).await;

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
                    .with_references(refs!["https://dnssec-failed.org/"])
                    .with_opt_remediation(crate::remediation::get(
                        "rikitikitavi.dns.dnssec-not-enforced",
                        &[],
                    )),
                );
            }
            None => {
                tracing::debug!("skipping DNSSEC check — no nameservers available");
            }
        }

        // Email security records (SPF/DKIM/DMARC) for the local domain
        if let Some(domain) = read_search_domain() {
            tracing::info!(domain = %domain, "checking email security records");
            check_email_security(&nameservers, &domain, &mut findings).await;
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
    use proptest::prelude::*;
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

    // ── is_private_ip tests ─────────────────────────────────────────

    #[test]
    fn test_private_ip_10() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_private_ip_172_16() {
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(!is_private_ip("172.15.0.1".parse().unwrap()));
        assert!(!is_private_ip("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_private_ip_192_168() {
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn test_private_ip_loopback() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_private_ip_apipa() {
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn test_public_ip() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn test_private_ipv6_loopback() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn test_private_ipv6_ula() {
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn test_public_ipv6() {
        assert!(!is_private_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_private_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    // ── SPF / DMARC classification tests ──────────────────────────

    #[test]
    fn test_classify_spf_hardfail() {
        let finding = classify_spf("v=spf1 include:_spf.google.com -all").unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_spf_softfail() {
        let finding = classify_spf("v=spf1 include:example.com ~all").unwrap();
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_spf_plus_all() {
        let finding = classify_spf("v=spf1 +all").unwrap();
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_classify_spf_not_spf() {
        assert!(classify_spf("some random TXT record").is_none());
    }

    #[test]
    fn test_classify_dmarc_reject() {
        let finding = classify_dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_classify_dmarc_none() {
        let finding = classify_dmarc("v=DMARC1; p=none; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn test_classify_dmarc_not_dmarc() {
        assert!(classify_dmarc("random record").is_none());
    }

    // ── Search domain parsing tests ─────────────────────────────────

    #[test]
    fn test_parse_search_domain() {
        let contents = "nameserver 192.168.1.1\nsearch example.com\n";
        assert_eq!(
            parse_search_domain(contents),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn test_parse_search_domain_with_domain_keyword() {
        let contents = "nameserver 8.8.8.8\ndomain mycompany.org\n";
        assert_eq!(
            parse_search_domain(contents),
            Some("mycompany.org".to_owned())
        );
    }

    #[test]
    fn test_parse_search_domain_no_dot() {
        // Single-label domains like "lan" are skipped
        let contents = "nameserver 192.168.1.1\nsearch lan\n";
        assert!(parse_search_domain(contents).is_none());
    }

    #[test]
    fn test_parse_search_domain_none() {
        let contents = "nameserver 192.168.1.1\n";
        assert!(parse_search_domain(contents).is_none());
    }

    // ── macOS scutil --dns parser tests ────────────────────────────

    const SAMPLE_SCUTIL_DNS: &str = "\
DNS configuration

resolver #1
  search domain[0] : home.arpa
  nameserver[0] : 192.168.1.1
  nameserver[1] : fd00::1
  if_index : 13 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #3
  domain   : 254.169.in-addr.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300200

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : home.arpa
  nameserver[0] : 192.168.1.1
  nameserver[1] : fd00::1
  if_index : 13 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
";

    #[test]
    fn test_parse_scutil_dns_nameservers() {
        let ns = parse_scutil_dns_nameservers(SAMPLE_SCUTIL_DNS);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ns[1], "fd00::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_scutil_dns_nameservers_empty() {
        let ns = parse_scutil_dns_nameservers("DNS configuration\n\nresolver #1\n  domain : local\n");
        assert!(ns.is_empty());
    }

    #[test]
    fn test_parse_scutil_dns_ignores_scoped_resolvers() {
        // Only resolver #1 from the main section, not the scoped one
        let ns = parse_scutil_dns_nameservers(SAMPLE_SCUTIL_DNS);
        // Should NOT have 4 entries (2 main + 2 scoped), just the first 2
        assert_eq!(ns.len(), 2);
    }

    #[test]
    fn test_parse_scutil_dns_search_domain() {
        let domain = parse_scutil_dns_search_domain(SAMPLE_SCUTIL_DNS);
        assert_eq!(domain, Some("home.arpa".to_owned()));
    }

    #[test]
    fn test_parse_scutil_dns_search_domain_none() {
        let domain = parse_scutil_dns_search_domain(
            "DNS configuration\n\nresolver #1\n  nameserver[0] : 8.8.8.8\n",
        );
        assert!(domain.is_none());
    }

    #[test]
    fn test_parse_scutil_dns_no_resolver() {
        let ns = parse_scutil_dns_nameservers("DNS configuration\n\n");
        assert!(ns.is_empty());
    }

    // ── Proptests ───────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_is_private_ip_no_panic(
            a in 0_u8..=255_u8,
            b in 0_u8..=255_u8,
            c in 0_u8..=255_u8,
            d in 0_u8..=255_u8,
        ) {
            let ip: IpAddr = format!("{a}.{b}.{c}.{d}").parse().unwrap();
            let result = is_private_ip(ip);
            // Verify invariant: 10.x.x.x is always private
            if a == 10 {
                assert!(result, "10.x.x.x should be private");
            }
            // 192.168.x.x is always private
            if a == 192 && b == 168 {
                assert!(result, "192.168.x.x should be private");
            }
        }

        #[test]
        fn prop_parse_resolv_conf_no_panic(contents in ".*") {
            let _ = parse_resolv_conf(&contents);
        }

        #[test]
        fn prop_classify_spf_no_panic(record in ".*") {
            let _ = classify_spf(&record);
        }

        #[test]
        fn prop_classify_dmarc_no_panic(record in ".*") {
            let _ = classify_dmarc(&record);
        }

        #[test]
        fn prop_parse_search_domain_no_panic(contents in ".*") {
            let _ = parse_search_domain(&contents);
        }

        #[test]
        fn prop_parse_scutil_dns_no_panic(contents in ".*") {
            let _ = parse_scutil_dns_nameservers(&contents);
            let _ = parse_scutil_dns_search_domain(&contents);
        }
    }
}
