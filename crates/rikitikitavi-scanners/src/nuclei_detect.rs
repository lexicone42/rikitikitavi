use async_trait::async_trait;
use futures::stream::StreamExt;
use reqwest::redirect::Policy;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::{ExclusionSet, ScanIntensity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Scanner;
use crate::http_util::{read_body_capped, unauthenticated_probe_client};
use crate::media_server::server_hint_type;
use crate::nuclei_db::{
    ByteMatcher, Condition, HTTP_TEMPLATES, HttpMatcher, HttpPart, HttpTemplate, Probe,
    TCP_TEMPLATES, TcpTemplate, is_http_port, tcp_templates_for_port,
};

/// Second identification pass driven by the generated nuclei detection table.
///
/// For each port Phase 1 found open, the templates declaring that port are
/// grouped by the bytes they send, so one connection serves every template with
/// the same probe. Every payload is inert (the generator refuses anything that
/// authenticates, mutates or changes the peer's state, and `nuclei_db/tests.rs`
/// re-checks the committed table), and the HTTP pass is an unauthenticated GET
/// of documented paths.
///
/// Templates that only name the protocol are skipped ([`DUPLICATES_SERVICES_PASS`]):
/// this pass reports what the services pass cannot name. Table ports 81 and 8728
/// sit outside `ports.rs`'s Common and Extended ranges, so nothing selects them
/// until those lists carry them.
pub struct NucleiDetectScanner;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_millis(1500);
/// Wait for a continuation segment, once the peer has said something.
const READ_IDLE_TIMEOUT: Duration = Duration::from_millis(300);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Detection strings live in the first few KiB; bound what a hostile peer can feed us.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 128 * 1024;
const MAX_CONCURRENCY: usize = 8;
/// Distinct paths fetched per HTTP target. Covers every path the table asks
/// for today (13); the cap only bounds a future regeneration.
const MAX_HTTP_PATHS: usize = 16;
/// Paths fetched in parallel per HTTP target.
const MAX_HTTP_PATH_CONCURRENCY: usize = 4;
/// Same-origin redirect hops followed per request.
const MAX_HTTP_REDIRECTS: usize = 2;
/// Probe groups run per TCP target.
const MAX_PROBE_GROUPS: usize = 6;
/// A match this long is product-specific rather than a generic protocol word.
const CONFIRMED_PATTERN_BYTES: usize = 12;
const PROBABLE_PATTERN_BYTES: usize = 5;

// ── Response parts ──────────────────────────────────────────────────────

/// Bytes read from one probe sequence, plus the lowercased copies that
/// case-insensitive matchers search.
#[derive(Debug, Default)]
struct TcpParts {
    body: Vec<u8>,
    body_lower: Vec<u8>,
    named: Vec<(&'static str, Vec<u8>, Vec<u8>)>,
}

impl TcpParts {
    fn push(&mut self, name: Option<&'static str>, data: &[u8]) {
        let room = MAX_RESPONSE_BYTES.saturating_sub(self.body.len());
        let data = &data[..data.len().min(room)];
        self.body.extend_from_slice(data);
        self.body_lower
            .extend_from_slice(&data.to_ascii_lowercase());
        if let Some(name) = name {
            self.named
                .push((name, data.to_vec(), data.to_ascii_lowercase()));
        }
    }

    /// Part named by a matcher; an unknown name has no bytes.
    fn part(&self, name: &str, lowered: bool) -> &[u8] {
        if name == "body" {
            return if lowered {
                &self.body_lower
            } else {
                &self.body
            };
        }
        self.named
            .iter()
            .find(|(n, _, _)| *n == name)
            .map_or(&[][..], |(_, raw, low)| if lowered { low } else { raw })
    }

    const fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

// ── Matching ────────────────────────────────────────────────────────────

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Longest pattern of `matcher` present in `haystack`.
fn longest_present(matcher: &ByteMatcher, haystack: &[u8]) -> Option<usize> {
    matcher
        .patterns
        .iter()
        .filter(|p| contains(haystack, p))
        .map(|p| p.len())
        .max()
}

/// Whether a matcher fires, and the longest pattern that made it fire.
fn matcher_hit(matcher: &ByteMatcher, parts: &TcpParts) -> (bool, usize) {
    let haystack = parts.part(matcher.part, matcher.case_insensitive);
    let hits = matcher
        .patterns
        .iter()
        .filter(|p| contains(haystack, p))
        .count();
    let present = match matcher.condition {
        Condition::And => hits == matcher.patterns.len(),
        Condition::Or => hits > 0,
    };
    let longest = if present {
        longest_present(matcher, haystack).unwrap_or(0)
    } else {
        0
    };
    (present != matcher.negative, longest)
}

/// One template that identified something.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    id: &'static str,
    product: &'static str,
    /// Longest pattern that matched: how specific the evidence is.
    longest: usize,
    labels: Vec<&'static str>,
    evidence: String,
}

fn escape_pattern(pattern: &[u8]) -> String {
    let shown = &pattern[..pattern.len().min(48)];
    let mut out = String::with_capacity(shown.len());
    for &byte in shown {
        if (0x20..0x7f).contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    if pattern.len() > shown.len() {
        out.push('…');
    }
    out
}

/// Evaluate one TCP template against what came back.
fn template_hit(template: &'static TcpTemplate, parts: &TcpParts) -> Option<Hit> {
    if parts.is_empty() {
        return None;
    }
    let mut fired = 0usize;
    let mut longest = 0usize;
    let mut labels = Vec::new();
    let mut matched = Vec::new();

    for matcher in template.matchers {
        let (hit, pattern_len) = matcher_hit(matcher, parts);
        if !hit {
            continue;
        }
        fired += 1;
        longest = longest.max(pattern_len);
        if let Some(label) = matcher.label {
            labels.push(label);
        }
        if !matcher.negative
            && let Some(pattern) = matcher
                .patterns
                .iter()
                .filter(|p| contains(parts.part(matcher.part, matcher.case_insensitive), p))
                .max_by_key(|p| p.len())
        {
            matched.push(format!("{}~\"{}\"", matcher.part, escape_pattern(pattern)));
        }
    }

    let all = match template.condition {
        Condition::And => fired == template.matchers.len(),
        Condition::Or => fired > 0,
    };
    if !all || matched.is_empty() {
        return None;
    }

    Some(Hit {
        id: template.id,
        product: template.product,
        longest,
        labels,
        evidence: matched.join(", "),
    })
}

// ── HTTP matching ───────────────────────────────────────────────────────

/// One fetched HTTP response, with lowercased copies for case-insensitive matchers.
#[derive(Debug, Clone)]
struct HttpParts {
    path: String,
    status: u16,
    headers: String,
    headers_lower: String,
    body: String,
    body_lower: String,
}

impl HttpParts {
    /// `HttpPart::All` is searched as headers-then-body: a pattern straddling
    /// the boundary is not matched, which only makes detection stricter.
    const fn haystacks(&self, part: HttpPart, lowered: bool) -> [&str; 2] {
        let (headers, body) = if lowered {
            (self.headers_lower.as_str(), self.body_lower.as_str())
        } else {
            (self.headers.as_str(), self.body.as_str())
        };
        match part {
            HttpPart::Body => [body, ""],
            HttpPart::Header => [headers, ""],
            HttpPart::All => [headers, body],
        }
    }
}

fn http_matcher_hit(matcher: &HttpMatcher, parts: &HttpParts) -> (bool, usize) {
    match matcher {
        HttpMatcher::Status { codes, negative } => {
            let present = codes.contains(&parts.status);
            (present != *negative, 0)
        }
        HttpMatcher::Words {
            part,
            patterns,
            condition,
            case_insensitive,
            negative,
            ..
        } => {
            let haystacks = parts.haystacks(*part, *case_insensitive);
            let present_patterns: Vec<&&str> = patterns
                .iter()
                .filter(|p| haystacks.iter().any(|h| h.contains(**p)))
                .collect();
            let present = match condition {
                Condition::And => present_patterns.len() == patterns.len(),
                Condition::Or => !present_patterns.is_empty(),
            };
            let longest = present_patterns.iter().map(|p| p.len()).max().unwrap_or(0);
            (present != *negative, if present { longest } else { 0 })
        }
    }
}

fn http_template_hit(template: &'static HttpTemplate, parts: &HttpParts) -> Option<Hit> {
    if !template.paths.contains(&parts.path.as_str()) {
        return None;
    }
    let mut fired = 0usize;
    let mut longest = 0usize;
    let mut labels = Vec::new();
    let mut matched = Vec::new();

    for matcher in template.matchers {
        let (hit, pattern_len) = http_matcher_hit(matcher, parts);
        if !hit {
            continue;
        }
        fired += 1;
        longest = longest.max(pattern_len);
        if let HttpMatcher::Words {
            part,
            patterns,
            case_insensitive,
            negative,
            label,
            ..
        } = matcher
        {
            if let Some(label) = label {
                labels.push(*label);
            }
            let haystacks = parts.haystacks(*part, *case_insensitive);
            if !*negative
                && let Some(pattern) = patterns
                    .iter()
                    .filter(|p| haystacks.iter().any(|h| h.contains(**p)))
                    .max_by_key(|p| p.len())
            {
                let part_name = match part {
                    HttpPart::Body => "body",
                    HttpPart::Header => "header",
                    HttpPart::All => "response",
                };
                matched.push(format!(
                    "{part_name}~\"{}\"",
                    escape_pattern(pattern.as_bytes())
                ));
            }
        }
    }

    let all = match template.condition {
        Condition::And => fired == template.matchers.len(),
        Condition::Or => fired > 0,
    };
    if !all || matched.is_empty() {
        return None;
    }

    Some(Hit {
        id: template.id,
        product: template.product,
        longest,
        labels,
        evidence: format!("GET {} {} {}", parts.path, parts.status, matched.join(", ")),
    })
}

// ── Probe planning ──────────────────────────────────────────────────────

/// A probe sequence plus every template that shares it.
#[derive(Debug)]
struct ProbeGroup {
    probes: &'static [Probe],
    read_size: usize,
    templates: Vec<&'static TcpTemplate>,
}

fn same_probes(a: &[Probe], b: &[Probe]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.data == y.data && x.name == y.name && x.read == y.read)
}

/// Group templates so each distinct probe sequence costs one connection.
fn group_by_probe(templates: &[&'static TcpTemplate]) -> Vec<ProbeGroup> {
    let mut groups: Vec<ProbeGroup> = Vec::new();
    for template in templates {
        if let Some(group) = groups
            .iter_mut()
            .find(|g| same_probes(g.probes, template.probes))
        {
            group.read_size = group.read_size.max(template.read_size);
            group.templates.push(template);
        } else {
            groups.push(ProbeGroup {
                probes: template.probes,
                read_size: template.read_size,
                templates: vec![template],
            });
        }
    }
    if groups.len() > MAX_PROBE_GROUPS {
        let dropped: Vec<&str> = groups[MAX_PROBE_GROUPS..]
            .iter()
            .flat_map(|g| g.templates.iter().map(|t| t.id))
            .collect();
        tracing::warn!(
            dropped = dropped.len(),
            templates = ?dropped,
            "probe groups over the per-port cap; these templates will not fire"
        );
        groups.truncate(MAX_PROBE_GROUPS);
    }
    groups
}

// ── Probe execution ─────────────────────────────────────────────────────

/// Read up to `limit` bytes: a banner split across TCP segments must not
/// truncate. Stops at the limit, at EOF, or when the peer goes quiet.
async fn read_chunk(stream: &mut TcpStream, limit: usize) -> Vec<u8> {
    let limit = limit.min(MAX_RESPONSE_BYTES);
    let mut out = Vec::new();
    let mut buf = vec![0u8; limit];
    while out.len() < limit {
        let timeout = if out.is_empty() {
            READ_TIMEOUT
        } else {
            READ_IDLE_TIMEOUT
        };
        let room = limit - out.len();
        match tokio::time::timeout(timeout, stream.read(&mut buf[..room])).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// Run one probe group against `ip:port`, read-only.
async fn run_probe_group(ip: IpAddr, port: u16, group: &ProbeGroup) -> Option<TcpParts> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut parts = TcpParts::default();
    if group.probes.is_empty() {
        let data = read_chunk(&mut stream, group.read_size).await;
        parts.push(None, &data);
        return Some(parts);
    }

    for probe in group.probes {
        if tokio::time::timeout(READ_TIMEOUT, stream.write_all(probe.data))
            .await
            .is_err()
        {
            break;
        }
        let limit = probe.read.unwrap_or(group.read_size);
        let data = read_chunk(&mut stream, limit).await;
        parts.push(probe.name, &data);
        if parts.body.len() >= MAX_RESPONSE_BYTES {
            break;
        }
    }
    Some(parts)
}

/// Templates whose product names only the protocol. `ports.rs` already labels
/// the port and `services.rs` banner-parses and CVE-correlates it, so reporting
/// these would restate the services pass; this pass exists for what that pass
/// cannot name. Every id is checked against the table by a test.
const DUPLICATES_SERVICES_PASS: &[&str] = &[
    "esmtp-detect",
    "ftp-detect",
    "imap-detect",
    "openssh-detect",
    "pop3-detect",
    "smtp-detect",
    "telnet-detect",
    "vnc-service-detect",
];

/// Hits of `templates` on one response, less the ones that only restate the protocol.
fn hits_for(templates: &[&'static TcpTemplate], parts: &TcpParts) -> Vec<Hit> {
    templates
        .iter()
        .filter(|t| !DUPLICATES_SERVICES_PASS.contains(&t.id))
        .filter_map(|t| template_hit(t, parts))
        .collect()
}

/// Every TCP hit on one open port.
async fn probe_tcp_port(ip: IpAddr, port: u16) -> Vec<Hit> {
    let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(port).collect();
    if templates.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for group in group_by_probe(&templates) {
        let Some(parts) = run_probe_group(ip, port, &group).await else {
            continue;
        };
        hits.extend(hits_for(&group.templates, &parts));
    }
    hits
}

/// Distinct paths to fetch, root first, capped.
fn http_paths() -> Vec<&'static str> {
    let mut paths: Vec<&'static str> = Vec::new();
    for template in HTTP_TEMPLATES {
        for path in template.paths {
            if !paths.contains(path) {
                paths.push(path);
            }
        }
    }
    // Stable, so the fetch order is the table order with the root first.
    paths.sort_by_key(|p| usize::from(*p != "/"));
    paths.truncate(MAX_HTTP_PATHS);
    paths
}

const fn scheme_for(port: u16) -> &'static str {
    match port {
        443 | 8443 => "https",
        _ => "http",
    }
}

/// Follow a redirect only back to the same origin, so a hit is always attributed
/// to the `ip:port` that was requested (see `a_redirect_off_the_target_origin_is_not_followed`).
fn same_origin_redirects() -> Policy {
    Policy::custom(|attempt| {
        let Some(origin) = attempt.previous().first() else {
            return attempt.stop();
        };
        let next = attempt.url();
        let same_origin = next.scheme() == origin.scheme()
            && next.host_str() == origin.host_str()
            && next.port_or_known_default() == origin.port_or_known_default();
        if same_origin && attempt.previous().len() <= MAX_HTTP_REDIRECTS {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

fn http_probe_client() -> reqwest::Result<reqwest::Client> {
    unauthenticated_probe_client(HTTP_TIMEOUT, same_origin_redirects())
}

/// Headers rendered one `name: value` line each, as nuclei's `header` part is,
/// except that `http` has already lowercased every name. The generator
/// lowercases the name part of header patterns to match; values keep their case.
fn render_headers(headers: &reqwest::header::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        let _ = writeln!(
            out,
            "{}: {}",
            name.as_str().to_ascii_lowercase(),
            value.to_str().unwrap_or("<binary>")
        );
    }
    out
}

/// Fetch one path and match every template that asks for it.
async fn fetch_and_match(client: &reqwest::Client, url: String, path: &'static str) -> Vec<Hit> {
    let Ok(response) = client.get(url).send().await else {
        return Vec::new();
    };
    let status = response.status().as_u16();
    let headers = render_headers(response.headers());
    let body = read_body_capped(response, MAX_BODY_BYTES).await;
    let parts = HttpParts {
        path: path.to_owned(),
        status,
        headers_lower: headers.to_lowercase(),
        headers,
        body_lower: body.to_lowercase(),
        body,
    };
    HTTP_TEMPLATES
        .iter()
        .filter_map(|template| http_template_hit(template, &parts))
        .collect()
}

/// Every HTTP hit on one open port.
///
/// The root GET gates the rest: a port that does not answer it is not serving
/// HTTP, and paying a timeout for each remaining path would be wasted.
async fn probe_http_port(client: &reqwest::Client, ip: IpAddr, port: u16) -> Vec<Hit> {
    let scheme = scheme_for(port);
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let mut paths = http_paths();
    if paths.first() != Some(&"/") {
        return Vec::new();
    }
    let rest = paths.split_off(1);

    let Ok(root) = client
        .get(format!("{scheme}://{host}:{port}/"))
        .send()
        .await
    else {
        return Vec::new();
    };
    let status = root.status().as_u16();
    let headers = render_headers(root.headers());
    let body = read_body_capped(root, MAX_BODY_BYTES).await;
    let root_parts = HttpParts {
        path: "/".to_owned(),
        status,
        headers_lower: headers.to_lowercase(),
        headers,
        body_lower: body.to_lowercase(),
        body,
    };
    let mut hits: Vec<Hit> = HTTP_TEMPLATES
        .iter()
        .filter_map(|template| http_template_hit(template, &root_parts))
        .collect();

    let pending: Vec<_> = rest
        .into_iter()
        .map(|path| fetch_and_match(client, format!("{scheme}://{host}:{port}{path}"), path))
        .collect();
    let fetched = futures::stream::iter(pending)
        .buffer_unordered(MAX_HTTP_PATH_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    hits.extend(fetched.into_iter().flatten());
    hits
}

// ── Findings ────────────────────────────────────────────────────────────

/// Product keyword to (vendor, device type). Keyed on the lowercased product
/// name; first match wins, so the specific entries come first.
const HINTS: &[(&str, Option<&str>, DeviceType)] = &[
    ("diskstation", Some("Synology"), DeviceType::Nas),
    ("synology", Some("Synology"), DeviceType::Nas),
    ("hp media vault", Some("HP"), DeviceType::Nas),
    ("net disk", None, DeviceType::Nas),
    ("nextcloud", None, DeviceType::Server),
    ("hikvision", Some("Hikvision"), DeviceType::Camera),
    ("vivotek", Some("VIVOTEK"), DeviceType::Camera),
    ("network camera", None, DeviceType::Camera),
    ("ispy", None, DeviceType::Camera),
    ("mikrotik", Some("MikroTik"), DeviceType::Router),
    ("routeros", Some("MikroTik"), DeviceType::Router),
    ("zywall", Some("Zyxel"), DeviceType::Router),
    ("freebox", Some("Free"), DeviceType::Router),
    ("fiberhome", Some("FiberHome"), DeviceType::Router),
    ("miniupnpd", None, DeviceType::Router),
    ("opendreambox", None, DeviceType::MediaPlayer),
    ("dreambox", None, DeviceType::MediaPlayer),
    ("jellyfin", None, DeviceType::MediaPlayer),
    ("airtame", Some("Airtame"), DeviceType::MediaPlayer),
    ("samsung", Some("Samsung"), DeviceType::SmartTv),
    ("hue personal", Some("Signify"), DeviceType::Hub),
    ("openhap", None, DeviceType::Hub),
    ("node-red", None, DeviceType::Hub),
    ("meteobridge", None, DeviceType::IoT),
    ("xerox", Some("Xerox"), DeviceType::Printer),
    ("lexmark", Some("Lexmark"), DeviceType::Printer),
    ("lanier", Some("Lanier"), DeviceType::Printer),
    ("tp print", Some("TP-Link"), DeviceType::Printer),
    ("pi-hole", None, DeviceType::Server),
    ("ilo", Some("HPE"), DeviceType::Server),
];

/// A hint overwrites the device's vendor and type in `post_enrich_devices`, so
/// only evidence specific enough to be at least [`Confidence::Probable`] may.
/// `current` is the device's type today: a generic `Server` row never replaces a
/// type already resolved (see `a_generic_server_row_never_replaces_a_specific_type`).
fn device_hint(matched: &Hit, current: DeviceType) -> Option<DeviceHint> {
    if confidence_for(matched.longest) < Confidence::Probable {
        return None;
    }
    let product = matched.product.to_lowercase();
    let (_, vendor, device_type) = HINTS.iter().find(|(key, _, _)| product.contains(key))?;

    let mut hint = DeviceHint::new().with_device_subtype(matched.id);
    if let Some(vendor) = vendor {
        hint = hint.with_vendor(*vendor);
    }
    let applied = if matches!(*device_type, DeviceType::Server) {
        server_hint_type(current)
    } else {
        Some(*device_type)
    };
    if let Some(device_type) = applied {
        hint = hint.with_device_type(device_type);
    }
    Some(hint)
}

/// Longest matched pattern first: the most specific evidence names the product.
///
/// Panics on an empty slice; callers build a finding only from a non-empty one.
fn primary(hits: &[Hit]) -> &Hit {
    hits.iter()
        .max_by_key(|h| (h.longest, h.product.len()))
        .expect("a finding is built only from at least one hit")
}

const fn confidence_for(longest: usize) -> Confidence {
    if longest >= CONFIRMED_PATTERN_BYTES {
        Confidence::Confirmed
    } else if longest >= PROBABLE_PATTERN_BYTES {
        Confidence::Probable
    } else {
        Confidence::Inferred
    }
}

/// Lowercase slug of a product name, for the `service` field.
fn service_slug(product: &str) -> String {
    let mut slug = String::with_capacity(product.len());
    let mut dash = false;
    for ch in product.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.extend(ch.to_lowercase());
            dash = false;
        } else if !dash && !slug.is_empty() {
            slug.push('-');
            dash = true;
        }
    }
    slug.trim_end_matches('-').to_owned()
}

fn identification_finding(ip: IpAddr, port: u16, hits: &[Hit], current: DeviceType) -> Finding {
    let hit = primary(hits);
    let also: Vec<&str> = hits
        .iter()
        .filter(|h| h.id != hit.id)
        .map(|h| h.product)
        .collect();
    let also_text = if also.is_empty() {
        String::new()
    } else {
        format!(" The same response also matched: {}.", also.join(", "))
    };

    // Matcher names are upstream labels for *how* a template matched; they belong
    // in the evidence, not in the title, which must stay stable per detection.
    let evidence = hits
        .iter()
        .map(|h| {
            let labels = if h.labels.is_empty() {
                String::new()
            } else {
                format!(" [{}]", h.labels.join(", "))
            };
            format!("{}{labels}: {}", h.id, h.evidence)
        })
        .collect::<Vec<_>>()
        .join(" | ");

    let finding = Finding::new(
        "nuclei-detect",
        &format!("{} identified on {ip}:{port}", hit.product),
        &format!(
            "An unauthenticated, read-only probe of {ip}:{port} matched the nuclei \
             detection template `{}`, which identifies {}. The probe sends only the \
             inert bytes the template declares — no credentials and no command that \
             changes state — and classifies whatever comes back. This is an \
             inventory result, not a vulnerability: it tells you what is listening \
             so you can decide whether it should be.{also_text}",
            hit.id, hit.product
        ),
        Severity::Info,
    )
    .with_confidence(confidence_for(hit.longest))
    .with_ip(ip)
    .with_port(port)
    .with_service(service_slug(hit.product))
    .with_evidence(evidence)
    .with_remediation(Remediation {
        description: "Confirm this service is meant to be reachable from the LAN.".to_owned(),
        steps: vec![
            format!(
                "Identify the device at {ip} and confirm {} is a service you run \
                 deliberately.",
                hit.product
            ),
            "Disable the service, or bind it to localhost, if nothing on this \
             network needs it."
                .to_owned(),
            format!(
                "Otherwise restrict TCP/{port} to the hosts that use it, and keep \
                 the product patched."
            ),
        ],
        effort: Some("15 minutes".to_owned()),
    })
    .with_references(refs![
        "https://github.com/projectdiscovery/nuclei-templates",
    ]);

    match device_hint(hit, current) {
        Some(device) => finding.with_device_hint(device),
        None => finding,
    }
}

// ── Scanner ─────────────────────────────────────────────────────────────

/// One (device, port) target.
#[derive(Debug, Clone, Copy)]
struct Target {
    ip: IpAddr,
    port: u16,
    /// The device's type before this pass; gates the generic `Server` hint.
    device_type: DeviceType,
}

/// Ports worth probing on one device: those some template declares.
fn targets_for(ctx: &ScanContext, exclusions: &ExclusionSet) -> Vec<Target> {
    let mut targets = Vec::new();
    for device in &ctx.discovered_devices {
        if exclusions.excludes_device(device) {
            continue;
        }
        let ports: BTreeSet<u16> = device.open_ports.iter().map(|p| p.port).collect();
        for port in ports {
            if is_http_port(port) || tcp_templates_for_port(port).next().is_some() {
                targets.push(Target {
                    ip: device.ip,
                    port,
                    device_type: device.device_type,
                });
            }
        }
    }
    targets
}

#[async_trait]
impl Scanner for NucleiDetectScanner {
    fn id(&self) -> &'static str {
        "nuclei-detect"
    }

    fn name(&self) -> &'static str {
        "Nuclei Detection Templates"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running nuclei detection pass");

        if !ctx.config.intensity.at_least(ScanIntensity::Active) {
            tracing::info!("skipping nuclei detection pass in quick scan mode");
            return Ok(Vec::new());
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "nuclei-detect".to_owned(),
                message: e.to_string(),
            })?;

        let targets = targets_for(ctx, &exclusions);
        if targets.is_empty() {
            tracing::info!("no ports matched the nuclei detection table");
            return Ok(Vec::new());
        }
        tracing::info!(
            target_count = targets.len(),
            tcp_templates = TCP_TEMPLATES.len(),
            http_templates = HTTP_TEMPLATES.len(),
            "probing"
        );

        let client = http_probe_client().map_err(|e| ScanError::ScannerFailed {
            scanner: "nuclei-detect".to_owned(),
            message: e.to_string(),
        })?;

        let concurrency = ctx.config.parallelism.clamp(1, MAX_CONCURRENCY);
        let findings: Vec<Finding> = futures::stream::iter(targets.into_iter().map(|target| {
            let client = client.clone();
            async move {
                let mut hits = probe_tcp_port(target.ip, target.port).await;
                if is_http_port(target.port) {
                    hits.extend(probe_http_port(&client, target.ip, target.port).await);
                }
                (target, hits)
            }
        }))
        .buffer_unordered(concurrency)
        .filter_map(|(target, hits)| async move {
            (!hits.is_empty())
                .then(|| identification_finding(target.ip, target.port, &hits, target.device_type))
        })
        .collect()
        .await;

        tracing::info!(findings_count = findings.len(), "nuclei detection complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }

    fn relevant_ports(&self) -> &[u16] {
        crate::nuclei_db::NUCLEI_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nuclei_db::{http_template, tcp_template};
    use proptest::prelude::*;

    /// Parts holding one banner, as a probe with no `name` produces.
    fn body(data: &[u8]) -> TcpParts {
        let mut parts = TcpParts::default();
        parts.push(None, data);
        parts
    }

    fn hits_on(id: &str, parts: &TcpParts) -> bool {
        template_hit(tcp_template(id).expect(id), parts).is_some()
    }

    /// Smallest `Hit::longest` the template could ever report: an `And` needs
    /// every pattern, so its floor is the longest one; an `Or` needs only the
    /// shortest. Same rule again over the template's own matchers.
    fn worst_case(condition: Condition, per_matcher: &[usize]) -> usize {
        match condition {
            Condition::And => per_matcher.iter().copied().max().unwrap_or(0),
            Condition::Or => per_matcher.iter().copied().min().unwrap_or(0),
        }
    }

    fn worst_case_tcp(template: &TcpTemplate) -> usize {
        let per: Vec<usize> = template
            .matchers
            .iter()
            .filter(|m| !m.negative)
            .map(|m| {
                worst_case(
                    m.condition,
                    &m.patterns.iter().map(|p| p.len()).collect::<Vec<_>>(),
                )
            })
            .collect();
        worst_case(template.condition, &per)
    }

    fn worst_case_http(template: &HttpTemplate) -> usize {
        let per: Vec<usize> = template
            .matchers
            .iter()
            .filter_map(|m| match m {
                HttpMatcher::Words {
                    patterns,
                    condition,
                    negative: false,
                    ..
                } => Some(worst_case(
                    *condition,
                    &patterns.iter().map(|p| p.len()).collect::<Vec<_>>(),
                )),
                _ => None,
            })
            .collect();
        worst_case(template.condition, &per)
    }

    // ── Real banners ────────────────────────────────────────────────

    /// vsftpd 3.0.5 greeting, as Debian ships it.
    const VSFTPD_BANNER: &[u8] = b"220 (vsFTPd 3.0.5)\r\n";
    /// Synology DSM FTP greeting.
    const DISKSTATION_BANNER: &[u8] = b"220 DiskStation FTP server ready.\r\n";
    /// OpenSSH identification string (RFC 4253 section 4.2).
    const OPENSSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
    /// Dropbear identification string.
    const DROPBEAR_BANNER: &[u8] = b"SSH-2.0-dropbear_2022.83\r\n";

    #[test]
    fn vsftpd_banner_identifies_vsftpd_only() {
        let parts = body(VSFTPD_BANNER);
        assert!(hits_on("vsftpd-detect", &parts));
        assert!(!hits_on("diskstation-ftp-detect", &parts));
        assert!(!hits_on("pure-ftpd-detect", &parts));
    }

    #[test]
    fn diskstation_banner_identifies_the_nas() {
        let parts = body(DISKSTATION_BANNER);
        let hit = template_hit(tcp_template("diskstation-ftp-detect").unwrap(), &parts).unwrap();
        assert_eq!(hit.product, "DiskStation FTP Service");
        assert_eq!(hit.longest, "DiskStation FTP server ready".len());
        assert_eq!(confidence_for(hit.longest), Confidence::Confirmed);
    }

    #[test]
    fn openssh_matches_case_insensitively_and_dropbear_does_not() {
        assert!(hits_on("openssh-detect", &body(OPENSSH_BANNER)));
        assert!(!hits_on("openssh-detect", &body(DROPBEAR_BANNER)));
        assert!(hits_on("sshd-dropbear-detect", &body(DROPBEAR_BANNER)));
    }

    #[test]
    fn an_empty_response_identifies_nothing() {
        let parts = TcpParts::default();
        for template in TCP_TEMPLATES {
            assert!(template_hit(template, &parts).is_none(), "{}", template.id);
        }
    }

    #[test]
    fn and_condition_needs_every_pattern() {
        // telnet-detect wants both "Telnet" and "Login authentication".
        let partial = body(b"\xff\xfd\x18\r\nTelnet service\r\n");
        assert!(!hits_on("telnet-detect", &partial));
        let full = body(b"\xff\xfd\x18\r\nTelnet service\r\nLogin authentication\r\n");
        assert!(hits_on("telnet-detect", &full));
    }

    #[test]
    fn redis_protected_mode_reply_identifies_redis() {
        let reply = b"-DENIED Redis is running in protected mode because protected \
                      mode is enabled and no bind address was specified\r\n";
        assert!(hits_on("redis-detect", &body(reply)));
    }

    #[test]
    fn named_parts_are_matched_separately() {
        let template = tcp_template("siemens-s7-detect").unwrap();
        let szl = b"\x03\x00\x00\x7f\x02\xf0\x802\x07\x00\x00\x00\x00 6ES7 315-2EH14-0AB0 ";
        let mut parts = TcpParts::default();
        parts.push(Some("cotp"), b"\x03\x00\x00\x16\x11\xd0");
        parts.push(Some("setup"), b"\x03\x00\x00\x1b\x02\xf0\x80");
        parts.push(Some("szl"), szl);
        assert!(template_hit(template, &parts).is_some());

        // The same bytes under a part the template does not read must not match.
        let mut wrong = TcpParts::default();
        wrong.push(Some("cotp"), szl);
        assert!(template_hit(template, &wrong).is_none());
    }

    #[test]
    fn unknown_part_has_no_bytes() {
        let parts = body(b"anything");
        assert!(parts.part("nosuchpart", false).is_empty());
        assert_eq!(parts.part("body", false), b"anything");
    }

    #[test]
    fn negative_matchers_suppress_a_hit() {
        let template = tcp_template("nfs-v3-exposed").unwrap();
        let reply = b"VER3\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(template_hit(template, &body(reply)).is_some());

        let mut http_reply = reply.to_vec();
        http_reply.extend_from_slice(b"HTTP/1.1 400 Bad Request");
        assert!(template_hit(template, &body(&http_reply)).is_none());
    }

    // ── Probe planning ──────────────────────────────────────────────

    #[test]
    fn port_21_templates_collapse_into_few_connections() {
        let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(21).collect();
        assert!(templates.len() > 60, "{} templates", templates.len());
        let groups = group_by_probe(&templates);
        assert!(groups.len() <= MAX_PROBE_GROUPS, "{} groups", groups.len());
        let grouped: usize = groups.iter().map(|g| g.templates.len()).sum();
        assert_eq!(grouped, templates.len());
    }

    #[test]
    fn no_port_loses_templates_to_the_probe_group_cap() {
        for &port in crate::nuclei_db::NUCLEI_PORTS {
            let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(port).collect();
            if templates.is_empty() {
                continue;
            }
            let groups = group_by_probe(&templates);
            let grouped: usize = groups.iter().map(|g| g.templates.len()).sum();
            assert_eq!(
                grouped,
                templates.len(),
                "port {port} plans more than {MAX_PROBE_GROUPS} probe groups; \
                 {} templates are dropped",
                templates.len() - grouped
            );
        }
    }

    #[test]
    fn grouping_keeps_the_largest_read_size() {
        let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(21).collect();
        for group in group_by_probe(&templates) {
            let expected = group.templates.iter().map(|t| t.read_size).max().unwrap();
            assert_eq!(group.read_size, expected);
        }
    }

    #[test]
    fn every_port_in_the_table_plans_at_least_one_group() {
        for &port in crate::nuclei_db::NUCLEI_PORTS {
            let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(port).collect();
            if templates.is_empty() {
                assert!(is_http_port(port), "port {port} selects nothing");
                continue;
            }
            assert!(!group_by_probe(&templates).is_empty());
        }
    }

    #[test]
    fn response_bytes_are_capped() {
        let mut parts = TcpParts::default();
        parts.push(None, &vec![b'a'; MAX_RESPONSE_BYTES * 2]);
        assert_eq!(parts.body.len(), MAX_RESPONSE_BYTES);
        assert_eq!(parts.body_lower.len(), MAX_RESPONSE_BYTES);
    }

    #[test]
    fn tcp_parts_is_empty_tracks_the_body() {
        assert!(TcpParts::default().is_empty());
        assert!(!body(b"x").is_empty());
    }

    fn probe(data: &'static [u8], name: Option<&'static str>, read: Option<usize>) -> Probe {
        Probe { data, name, read }
    }

    #[test]
    fn same_probes_compares_every_field() {
        let base = [probe(b"a", Some("n"), Some(10))];
        assert!(same_probes(&base, &base));
        assert!(same_probes(&[], &[]));
        // A single field differing is enough to differ.
        assert!(!same_probes(&base, &[probe(b"b", Some("n"), Some(10))]));
        assert!(!same_probes(&base, &[probe(b"a", Some("m"), Some(10))]));
        assert!(!same_probes(&base, &[probe(b"a", Some("n"), Some(20))]));
        // Length differences differ even when the shared prefix matches.
        assert!(!same_probes(
            &base,
            &[base[0], probe(b"a", Some("n"), Some(10))]
        ));
        assert!(!same_probes(&base, &[]));
    }

    fn leak_template(id: &'static str, data: &'static [u8]) -> &'static TcpTemplate {
        let probes: &'static [Probe] = Box::leak(vec![probe(data, None, None)].into_boxed_slice());
        Box::leak(Box::new(TcpTemplate {
            id,
            product: "test",
            ports: &[1],
            probes,
            read_size: 1024,
            condition: Condition::Or,
            matchers: &[],
        }))
    }

    #[test]
    fn probe_groups_over_the_cap_are_truncated() {
        // One distinct probe sequence per template -> one group each.
        let ids = ["t0", "t1", "t2", "t3", "t4", "t5", "t6"];
        let datas: [&[u8]; 7] = [b"a", b"b", b"c", b"d", b"e", b"f", b"g"];
        assert_eq!(ids.len(), MAX_PROBE_GROUPS + 1);
        let templates: Vec<&'static TcpTemplate> = ids
            .iter()
            .zip(datas)
            .map(|(id, data)| leak_template(id, data))
            .collect();
        assert_eq!(group_by_probe(&templates).len(), MAX_PROBE_GROUPS);

        // Templates sharing a probe collapse into one group, none dropped.
        let shared = vec![leak_template("s0", b"same"), leak_template("s1", b"same")];
        let groups = group_by_probe(&shared);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].templates.len(), 2);
    }

    /// A banner split across segments must arrive whole, or detection would
    /// depend on how the peer chunked its write.
    #[tokio::test]
    async fn a_split_banner_is_read_whole() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-Open").await.unwrap();
            tokio::time::sleep(Duration::from_millis(60)).await;
            sock.write_all(b"SSH_9.6p1\r\n").await.unwrap();
            // Held open: the idle timeout, not EOF, has to end the read.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let data = read_chunk(&mut stream, 1024).await;
        assert_eq!(String::from_utf8_lossy(&data), "SSH-2.0-OpenSSH_9.6p1\r\n");
    }

    #[tokio::test]
    async fn a_read_stops_at_the_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = sock.write_all(&vec![b'x'; 8192]).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        assert_eq!(read_chunk(&mut stream, 16).await.len(), 16);
    }

    // ── HTTP ────────────────────────────────────────────────────────

    /// Serve one canned response per connection until the test drops the task.
    async fn serve_http(listener: tokio::net::TcpListener, response: String) {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let response = response.clone();
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let _ = sock.read(&mut scratch).await;
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    }

    /// Answer `/` with a 302 to `/login`, and every other path with `page`.
    async fn serve_login_redirect(listener: tokio::net::TcpListener, page: String) {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let page = page.clone();
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let read = sock.read(&mut scratch).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&scratch[..read]).into_owned();
                let response = if request.starts_with("GET / ") {
                    "HTTP/1.1 302 Found\r\nLocation: /login\r\nContent-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                        .to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                        page.len()
                    )
                };
                let _ = sock.write_all(response.as_bytes()).await;
            });
        }
    }

    #[tokio::test]
    async fn a_redirect_off_the_target_origin_is_not_followed() {
        let page = "<html><head><title>Hello! Welcome to Synology Web Station!</title>\
                    </head><body></body></html>";
        let elsewhere = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let elsewhere_port = elsewhere.local_addr().unwrap().port();
        tokio::spawn(serve_http(
            elsewhere,
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            ),
        ));

        let redirector = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirector_port = redirector.local_addr().unwrap().port();
        tokio::spawn(serve_http(
            redirector,
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere_port}/\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        ));

        let client = http_probe_client().unwrap();
        // The redirect target on its own does identify Synology.
        let direct = probe_http_port(&client, "127.0.0.1".parse().unwrap(), elsewhere_port).await;
        assert!(
            direct.iter().any(|h| h.id == "synology-web-station"),
            "the fixture no longer identifies anything: {direct:?}"
        );
        // Through the redirector it must not.
        let hits = probe_http_port(&client, "127.0.0.1".parse().unwrap(), redirector_port).await;
        assert!(
            !hits.iter().any(|h| h.id == "synology-web-station"),
            "a redirect credited another origin's response to this target: {hits:?}"
        );
    }

    #[tokio::test]
    async fn a_same_origin_redirect_is_followed() {
        let page = "<html><head><title>Hello! Welcome to Synology Web Station!</title>\
                    </head><body></body></html>";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve_login_redirect(listener, page.to_owned()));

        let client = http_probe_client().unwrap();
        let hits = probe_http_port(&client, "127.0.0.1".parse().unwrap(), port).await;
        assert!(
            hits.iter().any(|h| h.id == "synology-web-station"),
            "a same-origin redirect lost the identification: {hits:?}"
        );
    }

    fn http(path: &str, status: u16, headers: &str, page: &str) -> HttpParts {
        HttpParts {
            path: path.to_owned(),
            status,
            headers: headers.to_owned(),
            headers_lower: headers.to_lowercase(),
            body: page.to_owned(),
            body_lower: page.to_lowercase(),
        }
    }

    #[test]
    fn synology_web_station_needs_body_and_status() {
        let page = "<html><head><title>Hello! Welcome to Synology Web Station!</title>\
                    </head><body></body></html>";
        let template = http_template("synology-web-station").unwrap();
        assert!(http_template_hit(template, &http("/", 200, "", page)).is_some());
        // The same page behind a 403 does not satisfy the status matcher.
        assert!(http_template_hit(template, &http("/", 403, "", page)).is_none());
    }

    /// Header names reach us lowercased, so the rendered block — not a
    /// hand-written wire form — is what a header matcher has to fire on.
    #[test]
    fn header_matcher_reads_the_rendered_header_block() {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(b"Server").unwrap(),
            HeaderValue::from_static("Boa/0.94.14rc21"),
        );
        let rendered = render_headers(&headers);
        assert_eq!(rendered, "server: Boa/0.94.14rc21\n");

        let template = http_template("boa-web-server").unwrap();
        assert!(http_template_hit(template, &http("/", 200, &rendered, "")).is_some());
        // The same text in the body is not a header match.
        assert!(http_template_hit(template, &http("/", 200, "", &rendered)).is_none());
    }

    #[test]
    fn every_header_pattern_can_match_a_lowercased_name() {
        for template in HTTP_TEMPLATES {
            for matcher in template.matchers {
                let HttpMatcher::Words {
                    part: HttpPart::Header,
                    patterns,
                    ..
                } = matcher
                else {
                    continue;
                };
                for pattern in *patterns {
                    // Only a leading header-name token is normalised; values keep their case.
                    let Some((name, _)) = pattern.split_once(':') else {
                        continue;
                    };
                    if name.is_empty()
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        continue;
                    }
                    assert!(
                        !name.bytes().any(|b| b.is_ascii_uppercase()),
                        "{} matches header name {name}, which is never uppercase on the wire",
                        template.id
                    );
                }
            }
        }
    }

    /// End to end through the real client: a `Server:` matcher has to survive
    /// `reqwest`'s own header handling, not just our rendering of it.
    #[tokio::test]
    async fn a_boa_header_is_identified_through_the_http_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\n\
                              Content-Type: text/html\r\nContent-Length: 6\r\n\
                              Connection: close\r\n\r\nrouter",
                        )
                        .await;
                });
            }
        });

        let client = http_probe_client().unwrap();
        let hits = probe_http_port(&client, addr.ip(), addr.port()).await;
        assert!(
            hits.iter().any(|h| h.id == "boa-web-server"),
            "boa not identified: {hits:?}"
        );
    }

    #[test]
    fn a_template_only_matches_its_own_paths() {
        let template = http_template("hikvision-detect").unwrap();
        let page = "Hikvision Digital Technology Co., Ltd. All Rights Reserved.";
        assert!(http_template_hit(template, &http("/doc/page/login.asp", 200, "", page)).is_some());
        assert!(http_template_hit(template, &http("/", 200, "", page)).is_none());
    }

    #[test]
    fn http_paths_are_bounded_and_root_first() {
        let paths = http_paths();
        assert_eq!(paths.first(), Some(&"/"));
        assert!(paths.len() <= MAX_HTTP_PATHS);
        assert_eq!(paths, http_paths(), "path order must be deterministic");
    }

    /// A template whose paths are never fetched could never fire.
    #[test]
    fn every_http_template_has_a_path_that_is_fetched() {
        let paths = http_paths();
        for template in HTTP_TEMPLATES {
            assert!(
                template.paths.iter().any(|p| paths.contains(p)),
                "{} asks for {:?}, none of which is fetched",
                template.id,
                template.paths
            );
        }
    }

    #[test]
    fn scheme_follows_the_port() {
        assert_eq!(scheme_for(443), "https");
        assert_eq!(scheme_for(8443), "https");
        assert_eq!(scheme_for(80), "http");
        assert_eq!(scheme_for(8123), "http");
    }

    // ── Finding shape ───────────────────────────────────────────────

    fn sample_hits() -> Vec<Hit> {
        let parts = body(DISKSTATION_BANNER);
        vec![
            template_hit(tcp_template("diskstation-ftp-detect").unwrap(), &parts).unwrap(),
            Hit {
                id: "ftp-detect",
                product: "FTP Service",
                longest: 3,
                labels: Vec::new(),
                evidence: "body~\"ftp\"".to_owned(),
            },
        ]
    }

    #[test]
    fn the_most_specific_match_names_the_finding() {
        let hits = sample_hits();
        assert_eq!(primary(&hits).id, "diskstation-ftp-detect");

        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let finding = identification_finding(ip, 21, &hits, DeviceType::Unknown);
        assert_eq!(
            finding.title,
            "DiskStation FTP Service identified on 192.168.1.10:21"
        );
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_port, Some(21));
        assert_eq!(
            finding.affected_service.as_deref(),
            Some("diskstation-ftp-service")
        );
        assert!(finding.description.contains("FTP Service"));
        // The "also matched" list names the *other* hits, not the primary.
        assert!(
            finding.description.contains("also matched: FTP Service."),
            "{}",
            finding.description
        );
        let evidence = finding.evidence.unwrap();
        assert!(evidence.contains("diskstation-ftp-detect"));
        assert!(evidence.contains("ftp-detect"));
    }

    // ── Not restating the services pass ─────────────────────────────

    #[test]
    fn a_generic_protocol_banner_yields_nothing() {
        let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(22).collect();
        assert!(hits_for(&templates, &body(OPENSSH_BANNER)).is_empty());
        // The matcher still works; it is the reporting that is left to services.rs.
        assert!(hits_on("openssh-detect", &body(OPENSSH_BANNER)));
    }

    #[test]
    fn a_product_specific_banner_still_identifies() {
        let templates: Vec<&'static TcpTemplate> = tcp_templates_for_port(21).collect();
        let ids: Vec<&str> = hits_for(&templates, &body(DISKSTATION_BANNER))
            .iter()
            .map(|h| h.id)
            .collect();
        assert!(ids.contains(&"diskstation-ftp-detect"), "{ids:?}");
        assert!(!ids.contains(&"ftp-detect"), "{ids:?}");
    }

    #[test]
    fn every_suppressed_id_is_in_the_table() {
        for id in DUPLICATES_SERVICES_PASS {
            assert!(tcp_template(id).is_some(), "{id} is no longer in the table");
        }
        assert!(DUPLICATES_SERVICES_PASS.windows(2).all(|w| w[0] < w[1]));
    }

    // ── Device hints ────────────────────────────────────────────────

    /// A hint overwrites a device's identity, so weak evidence must not carry one.
    #[test]
    fn a_weak_match_carries_no_device_hint() {
        let weak = Hit {
            id: "x",
            product: "Synology DiskStation",
            longest: PROBABLE_PATTERN_BYTES - 1,
            labels: Vec::new(),
            evidence: String::new(),
        };
        assert_eq!(confidence_for(weak.longest), Confidence::Inferred);
        assert!(device_hint(&weak, DeviceType::Unknown).is_none());

        let strong = Hit {
            longest: PROBABLE_PATTERN_BYTES,
            ..weak
        };
        assert!(device_hint(&strong, DeviceType::Unknown).is_some());
    }

    /// Every hint-emitting template must clear the Probable bar even on its
    /// weakest possible match, or a regeneration could rewrite a device's
    /// identity off an Inferred one.
    #[test]
    fn hint_emitting_templates_match_specifically_enough() {
        let rows = TCP_TEMPLATES
            .iter()
            .map(|t| (t.id, t.product, worst_case_tcp(t)))
            .chain(
                HTTP_TEMPLATES
                    .iter()
                    .map(|t| (t.id, t.product, worst_case_http(t))),
            );
        for (id, product, worst) in rows {
            let lowered = product.to_lowercase();
            let emits = HINTS.iter().any(|(key, _, _)| lowered.contains(key));
            if !emits {
                continue;
            }
            let hit = Hit {
                id,
                product,
                longest: worst,
                labels: Vec::new(),
                evidence: String::new(),
            };
            assert!(
                device_hint(&hit, DeviceType::Unknown).is_some(),
                "{id} can write a device hint off a {worst}-byte match"
            );
        }
    }

    #[test]
    fn every_hint_key_names_a_product_in_the_table() {
        let products: Vec<String> = TCP_TEMPLATES
            .iter()
            .map(|t| t.product)
            .chain(HTTP_TEMPLATES.iter().map(|t| t.product))
            .map(str::to_lowercase)
            .collect();
        for (key, _, _) in HINTS {
            assert!(
                products.iter().any(|p| p.contains(key)),
                "no product contains the hint key {key}"
            );
        }
    }

    /// CUPS runs on desktops and Raspberry Pis, not only on printers.
    #[test]
    fn cups_does_not_force_a_printer() {
        let template = http_template("cups-detect").unwrap();
        let hit = Hit {
            id: template.id,
            product: template.product,
            longest: 20,
            labels: Vec::new(),
            evidence: String::new(),
        };
        assert!(device_hint(&hit, DeviceType::Unknown).is_none());
        // The finding still says what is listening.
        let finding = identification_finding(
            "10.0.0.3".parse().unwrap(),
            631,
            &[hit],
            DeviceType::Unknown,
        );
        assert_eq!(finding.affected_service.as_deref(), Some("cups"));
    }

    #[test]
    fn a_recognised_product_carries_a_device_hint() {
        let hint = device_hint(&sample_hits()[0], DeviceType::Unknown).unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("Synology"));
        assert_eq!(hint.device_type, Some(DeviceType::Nas));
        assert_eq!(
            hint.device_subtype.as_deref(),
            Some("diskstation-ftp-detect")
        );
    }

    #[test]
    fn a_generic_server_row_never_replaces_a_specific_type() {
        let page = "<html><body>var nc_lastLogin = 0; var nc_pageLoad = 1;</body></html>";
        let parts = http("/", 200, "", page);
        let nextcloud = http_template_hit(http_template("nextcloud-detect").unwrap(), &parts)
            .expect("nextcloud-detect matches");
        assert_eq!(confidence_for(nextcloud.longest), Confidence::Confirmed);

        for current in [DeviceType::Nas, DeviceType::Router, DeviceType::Camera] {
            let hint = device_hint(&nextcloud, current).expect("hint");
            assert_eq!(hint.device_type, None, "{current}");
            assert_eq!(hint.device_subtype.as_deref(), Some("nextcloud-detect"));

            let finding = identification_finding(
                "10.0.0.9".parse().unwrap(),
                443,
                std::slice::from_ref(&nextcloud),
                current,
            );
            assert_eq!(
                finding.device_hint.expect("hint").device_type,
                None,
                "{current}"
            );
        }
        for current in [DeviceType::Unknown, DeviceType::Server] {
            let hint = device_hint(&nextcloud, current).expect("hint");
            assert_eq!(hint.device_type, Some(DeviceType::Server), "{current}");
        }

        // A specific row still applies over any current type.
        assert_eq!(
            device_hint(&sample_hits()[0], DeviceType::Server)
                .unwrap()
                .device_type,
            Some(DeviceType::Nas)
        );
    }

    #[test]
    fn every_generic_server_row_is_gated_on_the_current_type() {
        let generic = HINTS
            .iter()
            .filter(|(_, _, device_type)| matches!(device_type, DeviceType::Server));
        let mut checked = 0;
        for (key, _, _) in generic {
            let hit = Hit {
                id: "x",
                product: key,
                longest: CONFIRMED_PATTERN_BYTES,
                labels: Vec::new(),
                evidence: String::new(),
            };
            assert_eq!(
                device_hint(&hit, DeviceType::Nas).unwrap().device_type,
                None,
                "{key}"
            );
            assert_eq!(
                device_hint(&hit, DeviceType::Unknown).unwrap().device_type,
                Some(DeviceType::Server),
                "{key}"
            );
            checked += 1;
        }
        assert!(checked >= 3, "only {checked} generic rows checked");
    }

    #[test]
    fn an_unrecognised_product_carries_no_hint() {
        let hit = Hit {
            id: "x",
            product: "Some Unmapped Service",
            longest: 9,
            labels: Vec::new(),
            evidence: String::new(),
        };
        assert!(device_hint(&hit, DeviceType::Unknown).is_none());
    }

    #[test]
    fn confidence_tracks_how_specific_the_match_was() {
        assert_eq!(confidence_for(0), Confidence::Inferred);
        assert_eq!(confidence_for(3), Confidence::Inferred);
        assert_eq!(confidence_for(PROBABLE_PATTERN_BYTES), Confidence::Probable);
        assert_eq!(
            confidence_for(CONFIRMED_PATTERN_BYTES),
            Confidence::Confirmed
        );
    }

    #[test]
    fn service_slug_is_a_lowercase_slug() {
        assert_eq!(
            service_slug("DiskStation FTP Service"),
            "diskstation-ftp-service"
        );
        assert_eq!(service_slug("Pi-hole Login Panel"), "pi-hole-login-panel");
        assert_eq!(service_slug("  "), "");
        // No leading separator, and consecutive separators collapse to one.
        assert_eq!(service_slug(" nginx"), "nginx");
        assert_eq!(service_slug("a  b"), "a-b");
        assert_eq!(service_slug("abc!"), "abc");
    }

    #[test]
    fn binary_patterns_are_escaped_for_evidence() {
        assert_eq!(escape_pattern(b"6ES7"), "6ES7");
        assert_eq!(escape_pattern(b"\x00\xff"), "\\x00\\xff");
        assert_eq!(escape_pattern(&[b'a'; 60]).chars().count(), 49);
    }

    #[test]
    fn scanner_metadata_is_stable() {
        let s = NucleiDetectScanner;
        assert_eq!(s.id(), "nuclei-detect");
        assert_eq!(s.name(), "Nuclei Detection Templates");
        assert_eq!(s.estimated_duration_secs(), 20);
        assert_eq!(
            s.supported_perspectives(),
            &[
                Perspective::Unauthenticated,
                Perspective::Authenticated,
                Perspective::Privileged,
            ]
        );
        assert_eq!(s.relevant_ports(), crate::nuclei_db::NUCLEI_PORTS);
        assert!(!s.relevant_ports().is_empty());
    }

    // ── Targeting ───────────────────────────────────────────────────

    fn device_with(ip: &str, ports: &[u16]) -> rikitikitavi_models::Device {
        let mut device = rikitikitavi_models::Device::new(ip.parse().unwrap());
        device.open_ports = ports
            .iter()
            .map(|&port| rikitikitavi_models::device::OpenPort {
                port,
                protocol: rikitikitavi_models::device::PortProtocol::Tcp,
                service: None,
                version: None,
                banner: None,
            })
            .collect();
        device
    }

    fn context_with(devices: Vec<rikitikitavi_models::Device>) -> ScanContext {
        ScanContext {
            target_network: None,
            gateway: None,
            perspective: Perspective::Unauthenticated,
            network_mode: rikitikitavi_core::NetworkMode::Auto,
            config: rikitikitavi_models::config::ScanConfig::default(),
            discovered_devices: devices,
        }
    }

    #[test]
    fn only_ports_the_table_covers_are_probed() {
        let ctx = context_with(vec![device_with(
            "192.168.1.5",
            &[21, 22, 5353, 9999, 8080],
        )]);
        let targets = targets_for(&ctx, &ExclusionSet::default());
        let ports: Vec<u16> = targets.iter().map(|t| t.port).collect();
        // 5353 and 9999 appear in no template and are not HTTP ports.
        assert_eq!(ports, vec![21, 22, 8080]);
    }

    #[test]
    fn excluded_devices_are_never_targeted() {
        let ctx = context_with(vec![
            device_with("192.168.1.5", &[22]),
            device_with("192.168.1.6", &[22]),
        ]);
        let exclusions =
            ExclusionSet::parse(&[], &["192.168.1.5".to_owned()]).expect("valid exclusion");
        let targets = targets_for(&ctx, &exclusions);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].ip.to_string(), "192.168.1.6");
    }

    #[test]
    fn matcher_names_go_to_the_evidence_not_the_title() {
        let hits = vec![Hit {
            id: "nfs-v3-exposed",
            product: "NFSv3 Exposed",
            longest: 24,
            labels: vec!["nfs-v3-success"],
            evidence: "body~\"VER3\"".to_owned(),
        }];
        let finding = identification_finding(
            "10.0.0.2".parse().unwrap(),
            2049,
            &hits,
            DeviceType::Unknown,
        );
        assert_eq!(finding.title, "NFSv3 Exposed identified on 10.0.0.2:2049");
        assert!(finding.evidence.unwrap().contains("[nfs-v3-success]"));
    }

    // ── Properties ──────────────────────────────────────────────────

    proptest! {
        /// No response from a hostile peer can panic the TCP matcher.
        #[test]
        fn prop_tcp_matching_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let parts = body(&data);
            for template in TCP_TEMPLATES {
                let _ = template_hit(template, &parts);
            }
        }

        /// Named parts, including names no template declares, are equally safe.
        #[test]
        fn prop_named_parts_never_panic(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            name in prop_oneof![Just("body"), Just("info"), Just("szl"), Just("zzz")],
        ) {
            let mut parts = TcpParts::default();
            parts.push(Some(name), &data);
            for template in TCP_TEMPLATES {
                let _ = template_hit(template, &parts);
            }
        }

        /// Arbitrary HTTP responses are equally safe.
        #[test]
        fn prop_http_matching_never_panics(
            status in any::<u16>(),
            headers in ".{0,128}",
            page in ".{0,512}",
            path in prop_oneof![Just("/"), Just("/favicon.ico"), Just("/nope")],
        ) {
            let parts = http(path, status, &headers, &page);
            for template in HTTP_TEMPLATES {
                let _ = http_template_hit(template, &parts);
            }
        }

        /// The substring search agrees with a naive scan.
        #[test]
        fn prop_contains_agrees_with_naive_scan(
            haystack in proptest::collection::vec(0u8..4, 0..64),
            needle in proptest::collection::vec(0u8..4, 0..5),
        ) {
            let naive = !needle.is_empty()
                && needle.len() <= haystack.len()
                && (0..=haystack.len() - needle.len().min(haystack.len()))
                    .any(|i| i + needle.len() <= haystack.len()
                        && haystack[i..i + needle.len()] == needle[..]);
            prop_assert_eq!(contains(&haystack, &needle), naive);
        }

        /// A pattern grafted into random noise is always found.
        #[test]
        fn prop_grafted_pattern_is_found(
            prefix in proptest::collection::vec(any::<u8>(), 0..64),
            suffix in proptest::collection::vec(any::<u8>(), 0..64),
            index in 0..TCP_TEMPLATES.len(),
        ) {
            let template = TCP_TEMPLATES[index];
            let matcher = template.matchers[0];
            let pattern = matcher.patterns[0];
            let mut data = prefix;
            data.extend_from_slice(pattern);
            data.extend_from_slice(&suffix);
            let parts = body(&data);
            let haystack = parts.part("body", matcher.case_insensitive);
            prop_assert!(contains(haystack, pattern));
        }
    }
}
