//! `UPnP` Internet Gateway Device (IGD) port-forwarding exposure scanner.
//!
//! Answers a simple but important question: **what has my router forwarded to
//! the internet?** Many consumer routers ship with `UPnP` IGD enabled by
//! default, letting any device or application on the LAN — games and
//! consoles, torrent/P2P clients, smart-home hubs, or malware on a compromised
//! `IoT` device — punch a hole through the router's firewall and expose an
//! internal host directly to the internet, with no further user confirmation.
//! These forwards accumulate silently and are rarely audited.
//!
//! This scanner:
//! 1. Discovers the Internet Gateway Device via an SSDP M-SEARCH multicast
//!    for `urn:schemas-upnp-org:device:InternetGatewayDevice:1` and `:2`.
//! 2. Fetches the device description `XML` from the SSDP `LOCATION` and finds
//!    the `WANIPConnection` (or `WANPPPConnection`) service's control `URL`.
//! 3. Enumerates active port mappings via repeated SOAP
//!    `GetGenericPortMappingEntry` calls, stopping at the first SOAP fault
//!    (typically error 713, `SpecifiedArrayIndexInvalid`) or non-200 response.
//! 4. Emits one finding per active mapping, plus an informational summary.
//!
//! It never adds, removes, or modifies a mapping — this is read-only
//! enumeration of what the router already reports.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, ScanContext};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::Scanner;

/// `UPnP` IGD port-forwarding exposure scanner.
pub struct UpnpIgdScanner;

/// SSDP multicast address and port.
const SSDP_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);

/// Search targets for Internet Gateway Devices. SSDP matches the search
/// target exactly (unless using `ssdp:all`/`upnp:rootdevice`), so a v2-only
/// IGD will not answer an M-SEARCH for `:1` — both are searched explicitly.
const IGD_SEARCH_TARGETS: &[&str] = &[
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];

/// Bound for sending each M-SEARCH datagram.
const SSDP_SEND_TIMEOUT: Duration = Duration::from_secs(1);

/// Bound for the whole SSDP response-collection window.
const SSDP_COLLECT_WINDOW: Duration = Duration::from_secs(3);

/// Bound for each HTTP request (device description fetch, SOAP call).
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// SOAP responses are a handful of short XML elements; 64 `KiB` is generous
/// while bounding a hostile or malfunctioning router.
const SOAP_BODY_CAP: usize = 64 * 1024;

/// Hard ceiling on `GetGenericPortMappingEntry` calls per WAN connection
/// service, so a router that never returns a fault cannot hang the scan.
const MAX_PORT_MAPPINGS: u32 = 100;

// ── SSDP discovery ───────────────────────────────────────────────────

/// Build an SSDP M-SEARCH request for a specific search target.
fn build_msearch(search_target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {search_target}\r\n\
         \r\n"
    )
}

/// Extract the `LOCATION` and `ST` headers from an SSDP M-SEARCH response.
///
/// Returns `None` if no `LOCATION` header is present — a response we cannot
/// act on. `ST` defaults to an empty string when absent.
fn parse_msearch_location(response: &str) -> Option<(String, String)> {
    let mut location = None;
    let mut search_target = String::new();

    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("location:") {
            location = Some(line[9..].trim().to_owned());
        } else if lower.starts_with("st:") {
            line[3..].trim().clone_into(&mut search_target);
        }
    }

    location.map(|loc| (loc, search_target))
}

/// Send SSDP M-SEARCH for both IGD search targets and collect distinct
/// `LOCATION` URLs from matching responses.
///
/// All socket I/O is bounded: sends by [`SSDP_SEND_TIMEOUT`], the whole
/// response-collection window by [`SSDP_COLLECT_WINDOW`].
async fn discover_igd_locations() -> Vec<String> {
    let mut locations: Vec<String> = Vec::new();

    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        tracing::warn!("could not bind SSDP socket for IGD discovery");
        return locations;
    };

    let dest = SocketAddr::new(IpAddr::V4(SSDP_ADDR.0), SSDP_ADDR.1);
    for st in IGD_SEARCH_TARGETS {
        let msg = build_msearch(st);
        let send_result =
            tokio::time::timeout(SSDP_SEND_TIMEOUT, socket.send_to(msg.as_bytes(), dest)).await;
        if !matches!(send_result, Ok(Ok(_))) {
            tracing::warn!("could not send SSDP M-SEARCH for {st}");
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = [0u8; 2048];
    let collect = async {
        while let Ok((n, _addr)) = socket.recv_from(&mut buf).await {
            let response = String::from_utf8_lossy(&buf[..n]);
            if let Some((location, search_target)) = parse_msearch_location(&response)
                && search_target.contains("InternetGatewayDevice")
                && seen.insert(location.clone())
            {
                locations.push(location);
            }
        }
    };
    let _ = tokio::time::timeout(SSDP_COLLECT_WINDOW, collect).await;

    locations
}

// ── UPnP device description parsing ─────────────────────────────────

/// Extract the text content between simple XML tags (non-recursive).
///
/// Looks for `<tag>content</tag>` and returns `content`. Mirrors
/// [`crate::mdns::parse_upnp_device_xml`]'s helper of the same shape.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let content = xml[start..end].trim();
    if content.is_empty() {
        None
    } else {
        Some(content.to_owned())
    }
}

/// Find the `WANIPConnection`/`WANPPPConnection` service inside a `UPnP`
/// device description `XML` and return its `(serviceType, controlURL)`.
///
/// Scans each `<service>...</service>` block (attribute-free, per the `UPnP`
/// device schema) rather than parsing the full document tree, since only the
/// service type and control `URL` are needed.
fn find_wan_connection_service(xml: &str) -> Option<(String, String)> {
    let mut idx = 0;
    while let Some(rel_start) = xml[idx..].find("<service>") {
        let start = idx + rel_start;
        let Some(rel_end) = xml[start..].find("</service>") else {
            break;
        };
        let end = start + rel_end + "</service>".len();
        let block = &xml[start..end];

        if let Some(service_type) = extract_xml_tag(block, "serviceType") {
            let is_wan_connection = service_type.contains("WANIPConnection")
                || service_type.contains("WANPPPConnection");
            if is_wan_connection && let Some(control_url) = extract_xml_tag(block, "controlURL") {
                return Some((service_type, control_url));
            }
        }
        idx = end;
    }
    None
}

/// Resolve a (possibly relative) `controlURL` against the SSDP `LOCATION`
/// base `URL`.
///
/// Absolute URLs are returned unchanged. Relative URLs are resolved against
/// the scheme and authority (`scheme://host:port`) of `location` — routers
/// overwhelmingly use root-relative control paths (e.g.
/// `/upnp/control/WANIPConn1`), so this simple join is correct in practice
/// without pulling in a full `URL`-resolution crate.
fn resolve_control_url(location: &str, control_url: &str) -> Option<String> {
    if control_url.starts_with("http://") || control_url.starts_with("https://") {
        return Some(control_url.to_owned());
    }

    let scheme_end = location.find("://")? + 3;
    let path_start = location[scheme_end..]
        .find('/')
        .map_or(location.len(), |i| scheme_end + i);
    let authority = &location[..path_start];
    let path = control_url.strip_prefix('/').unwrap_or(control_url);
    Some(format!("{authority}/{path}"))
}

/// Extract the host `IP` address from a `LOCATION` `URL` such as
/// `http://192.168.1.1:49152/desc.xml`.
///
/// `IPv4`-only (routers overwhelmingly advertise `IPv4` `LOCATION`s on the
/// LAN); an `IPv6` literal in brackets will fail to parse and yield `None`.
fn extract_host_ip(location: &str) -> Option<IpAddr> {
    let after_scheme = location.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h);
    host.parse().ok()
}

/// Fetch and return a `UPnP` device description document, or `None` on any
/// network error, non-2xx status, or empty body.
async fn fetch_device_description(client: &reqwest::Client, location: &str) -> Option<String> {
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(location).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = tokio::time::timeout(
        HTTP_TIMEOUT,
        crate::http_util::read_body_capped(resp, crate::http_util::MAX_BODY_BYTES),
    )
    .await
    .unwrap_or_default();

    if body.is_empty() { None } else { Some(body) }
}

// ── SOAP GetGenericPortMappingEntry ─────────────────────────────────

/// Build a `GetGenericPortMappingEntry` SOAP request body for a given
/// service type and mapping index.
fn build_get_port_mapping_soap(service_type: &str, index: u32) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:GetGenericPortMappingEntry xmlns:u=\"{service_type}\">\
         <NewPortMappingIndex>{index}</NewPortMappingIndex>\
         </u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
    )
}

/// Whether a SOAP response body is a fault (e.g. error 713
/// `SpecifiedArrayIndexInvalid`, returned once the index runs past the last
/// mapping) rather than a successful `GetGenericPortMappingEntryResponse`.
fn is_soap_fault(xml: &str) -> bool {
    xml.contains("Fault>") || xml.contains("<faultcode") || xml.contains("errorCode")
}

/// A single active (or inactive) port mapping as reported by
/// `GetGenericPortMappingEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMappingEntry {
    /// Remote host the mapping is restricted to; empty/absent means "any".
    remote_host: Option<String>,
    external_port: u16,
    protocol: String,
    internal_client: String,
    internal_port: u16,
    enabled: bool,
    description: String,
}

/// Parse a `GetGenericPortMappingEntryResponse` `SOAP` body into a
/// [`PortMappingEntry`].
///
/// Returns `None` if any field essential to describing the mapping
/// (`NewExternalPort`, `NewInternalPort`, `NewProtocol`, `NewInternalClient`)
/// is missing or unparsable. `NewEnabled` defaults to `true` when absent
/// (some minimal implementations omit it for active mappings); `NewEnabled`
/// values of `1` or `true` (case-insensitive) count as enabled.
fn parse_port_mapping_response(xml: &str) -> Option<PortMappingEntry> {
    let external_port: u16 = extract_xml_tag(xml, "NewExternalPort")?.parse().ok()?;
    let internal_port: u16 = extract_xml_tag(xml, "NewInternalPort")?.parse().ok()?;
    let protocol = extract_xml_tag(xml, "NewProtocol")?;
    let internal_client = extract_xml_tag(xml, "NewInternalClient")?;
    let enabled = extract_xml_tag(xml, "NewEnabled").is_none_or(|v| {
        let trimmed = v.trim();
        trimmed == "1" || trimmed.eq_ignore_ascii_case("true")
    });
    let description = extract_xml_tag(xml, "NewPortMappingDescription").unwrap_or_default();
    let remote_host = extract_xml_tag(xml, "NewRemoteHost");

    Some(PortMappingEntry {
        remote_host,
        external_port,
        protocol,
        internal_client,
        internal_port,
        enabled,
        description,
    })
}

/// Enumerate active port mappings on a `WANIPConnection`/`WANPPPConnection`
/// service by calling `GetGenericPortMappingEntry` for indices `0, 1, 2, ...`
/// until the router returns a SOAP fault, a non-200 response, or an
/// unparsable body — whichever comes first — bounded overall by
/// [`MAX_PORT_MAPPINGS`]. Every request is bounded by [`HTTP_TIMEOUT`].
async fn enumerate_port_mappings(
    client: &reqwest::Client,
    control_url: &str,
    service_type: &str,
) -> Vec<PortMappingEntry> {
    let mut mappings = Vec::new();

    for index in 0..MAX_PORT_MAPPINGS {
        let soap_body = build_get_port_mapping_soap(service_type, index);
        let soap_action = format!("\"{service_type}#GetGenericPortMappingEntry\"");

        let send_result = tokio::time::timeout(
            HTTP_TIMEOUT,
            client
                .post(control_url)
                .header("Content-Type", "text/xml; charset=\"utf-8\"")
                .header("SOAPAction", soap_action)
                .body(soap_body)
                .send(),
        )
        .await;

        let Ok(Ok(resp)) = send_result else {
            break;
        };

        let status_ok = resp.status().is_success();
        let body = tokio::time::timeout(
            HTTP_TIMEOUT,
            crate::http_util::read_body_capped(resp, SOAP_BODY_CAP),
        )
        .await
        .unwrap_or_default();

        if !status_ok || is_soap_fault(&body) {
            break;
        }

        match parse_port_mapping_response(&body) {
            Some(entry) => mappings.push(entry),
            None => break,
        }
    }

    mappings
}

// ── Severity classification ──────────────────────────────────────────

/// Ports whose exposure to the internet is especially dangerous:
/// remote-management, remote-desktop, and file-sharing protocols that are
/// frequently targeted by mass internet scanners and rarely intended to be
/// internet-facing.
const fn is_sensitive_port(port: u16) -> bool {
    matches!(port, 22 | 23 | 80 | 445 | 3389 | 5900 | 8080)
}

/// Severity for a port-forward mapping to a given internal port: `High` for
/// [`is_sensitive_port`] targets, `Medium` otherwise.
const fn mapping_severity(internal_port: u16) -> Severity {
    if is_sensitive_port(internal_port) {
        Severity::High
    } else {
        Severity::Medium
    }
}

// ── Findings ──────────────────────────────────────────────────────────

/// Build the finding for one active port-forward mapping.
fn build_mapping_finding(router_ip: IpAddr, entry: &PortMappingEntry) -> Finding {
    let desc_display = if entry.description.trim().is_empty() {
        "no description"
    } else {
        entry.description.trim()
    };

    let title = format!(
        "Router forwards WAN {}/{} -> {}:{} ({desc_display})",
        entry.protocol, entry.external_port, entry.internal_client, entry.internal_port
    );

    let severity = mapping_severity(entry.internal_port);
    let sensitivity_note = if severity == Severity::High {
        " This forwards a port that is commonly targeted by mass internet \
          scanners and is rarely meant to be internet-facing (remote \
          management, file sharing, or remote desktop) — treat this as a \
          priority to review."
    } else {
        ""
    };
    let remote_host_note = entry.remote_host.as_ref().map_or_else(String::new, |host| {
        format!(" The mapping is restricted to remote host {host}.")
    });

    let description = format!(
        "The router's UPnP Internet Gateway Device (IGD) service reports an active \
         port forward from the internet (WAN) on {proto}/{ext_port} to internal host \
         {client}:{int_port} ({desc_display}). UPnP lets any device or application on \
         the LAN — games and consoles, torrent/P2P clients, smart-home hubs, or \
         malware on a compromised IoT device — punch a hole through the router's \
         firewall without any further user confirmation. Review this mapping on the \
         router's UPnP/port-forwarding admin page and remove it if it is not \
         something you intentionally configured or still need.{sensitivity_note}\
         {remote_host_note}",
        proto = entry.protocol,
        ext_port = entry.external_port,
        client = entry.internal_client,
        int_port = entry.internal_port,
    );

    Finding::new("upnp_igd", &title, &description, severity)
        .with_confidence(Confidence::Confirmed)
        .with_ip(router_ip)
        .with_port(entry.external_port)
        .with_service(entry.protocol.clone())
        .with_cwe("CWE-284")
        .with_evidence(format!(
            "GetGenericPortMappingEntry: {}/{} -> {}:{}, enabled={}, description=\"{}\"",
            entry.protocol,
            entry.external_port,
            entry.internal_client,
            entry.internal_port,
            entry.enabled,
            entry.description,
        ))
        .with_references(refs![
            "https://cwe.mitre.org/data/definitions/284.html",
            "https://www.rapid7.com/blog/post/2013/01/29/security-flaws-in-universal-plug-and-play-unplug-dont-play/",
        ])
        .with_device_hint(DeviceHint::new().with_device_type(DeviceType::Router))
}

/// Build the informational summary finding for one Internet Gateway Device.
fn build_summary_finding(router_ip: IpAddr, active_count: usize) -> Finding {
    Finding::new(
        "upnp_igd",
        &format!("{active_count} UPnP port forward(s) active on the router"),
        &format!(
            "The router at {router_ip} reports {active_count} active UPnP-created port \
             forward(s) exposing internal hosts to the internet. Each is reported as its \
             own finding when present; review them and remove any that are not \
             intentionally required. Games and consoles, torrent/P2P clients, and \
             occasionally malware or compromised IoT devices commonly request port \
             forwards via UPnP without further user confirmation."
        ),
        Severity::Info,
    )
    .with_confidence(Confidence::Confirmed)
    .with_ip(router_ip)
    .with_service("UPnP IGD")
    .with_device_hint(DeviceHint::new().with_device_type(DeviceType::Router))
}

#[async_trait]
impl Scanner for UpnpIgdScanner {
    fn id(&self) -> &'static str {
        "upnp_igd"
    }

    fn name(&self) -> &'static str {
        "UPnP IGD Port Forwarding"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running UPnP IGD port-forward scan");
        let mut findings = Vec::new();

        // This performs active SSDP discovery plus SOAP calls against the
        // router — skip it in quick/passive scans.
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping UPnP IGD scan in quick scan mode");
            return Ok(findings);
        }

        let locations = discover_igd_locations().await;
        if locations.is_empty() {
            tracing::info!("no Internet Gateway Device found via SSDP");
            return Ok(findings);
        }

        let Ok(client) = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(HTTP_TIMEOUT)
            .build()
        else {
            tracing::warn!("could not build HTTP client for UPnP IGD scan");
            return Ok(findings);
        };

        for location in &locations {
            let Some(router_ip) = extract_host_ip(location) else {
                tracing::debug!(%location, "could not parse host IP from LOCATION");
                continue;
            };
            let Some(desc_xml) = fetch_device_description(&client, location).await else {
                tracing::debug!(%location, "could not fetch UPnP device description");
                continue;
            };
            let Some((service_type, raw_control_url)) = find_wan_connection_service(&desc_xml)
            else {
                tracing::debug!(
                    %location,
                    "no WANIPConnection/WANPPPConnection service found"
                );
                continue;
            };
            let Some(control_url) = resolve_control_url(location, &raw_control_url) else {
                continue;
            };

            let mappings = enumerate_port_mappings(&client, &control_url, &service_type).await;
            let active_mappings: Vec<&PortMappingEntry> =
                mappings.iter().filter(|m| m.enabled).collect();

            for entry in &active_mappings {
                findings.push(build_mapping_finding(router_ip, entry));
            }
            findings.push(build_summary_finding(router_ip, active_mappings.len()));
        }

        tracing::info!(findings_count = findings.len(), "UPnP IGD scan complete");
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── M-SEARCH builder ─────────────────────────────────────────────

    #[test]
    fn test_build_msearch_contains_search_target() {
        let msg = build_msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:1");
        assert!(msg.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(msg.contains("HOST: 239.255.255.250:1900"));
        assert!(msg.contains("MAN: \"ssdp:discover\""));
        assert!(msg.contains("MX: 2"));
        assert!(msg.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"));
    }

    #[test]
    fn test_build_msearch_igd_v2() {
        let msg = build_msearch("urn:schemas-upnp-org:device:InternetGatewayDevice:2");
        assert!(msg.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2"));
    }

    // ── SSDP response parsing ────────────────────────────────────────

    #[test]
    fn test_parse_msearch_location_full() {
        let response = "HTTP/1.1 200 OK\r\n\
                         CACHE-CONTROL: max-age=1800\r\n\
                         ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                         USN: uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                         LOCATION: http://192.168.1.1:49152/rootDesc.xml\r\n\
                         SERVER: Linux/3.10 UPnP/1.1 MiniUPnPd/2.1\r\n\r\n";
        let (location, st) = parse_msearch_location(response).unwrap();
        assert_eq!(location, "http://192.168.1.1:49152/rootDesc.xml");
        assert_eq!(st, "urn:schemas-upnp-org:device:InternetGatewayDevice:1");
    }

    #[test]
    fn test_parse_msearch_location_missing_location() {
        let response = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n";
        assert!(parse_msearch_location(response).is_none());
    }

    #[test]
    fn test_parse_msearch_location_missing_st_defaults_empty() {
        let response = "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/desc.xml\r\n\r\n";
        let (location, st) = parse_msearch_location(response).unwrap();
        assert_eq!(location, "http://10.0.0.1/desc.xml");
        assert_eq!(st, "");
    }

    // ── device description / WAN connection service extraction ───────

    const SAMPLE_DEVICE_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
                <controlURL>/upnp/control/WANCommonIFC1</controlURL>
              </service>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/upnp/control/WANIPConn1</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn test_find_wan_connection_service_picks_wanip() {
        let (service_type, control_url) = find_wan_connection_service(SAMPLE_DEVICE_DESC).unwrap();
        assert_eq!(
            service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(control_url, "/upnp/control/WANIPConn1");
    }

    #[test]
    fn test_find_wan_connection_service_pppoe_variant() {
        let xml = "<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
                   <controlURL>/ctl/WANPPPConn1</controlURL></service></serviceList>";
        let (service_type, control_url) = find_wan_connection_service(xml).unwrap();
        assert_eq!(
            service_type,
            "urn:schemas-upnp-org:service:WANPPPConnection:1"
        );
        assert_eq!(control_url, "/ctl/WANPPPConn1");
    }

    #[test]
    fn test_find_wan_connection_service_absent() {
        let xml = "<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
                   <controlURL>/ctl/L3F</controlURL></service></serviceList>";
        assert!(find_wan_connection_service(xml).is_none());
    }

    #[test]
    fn test_find_wan_connection_service_no_service_tags() {
        assert!(find_wan_connection_service("<root><device/></root>").is_none());
        assert!(find_wan_connection_service("").is_none());
    }

    // ── control URL resolution ─────────────────────────────────────

    #[test]
    fn test_resolve_control_url_root_relative() {
        let resolved = resolve_control_url(
            "http://192.168.1.1:49152/rootDesc.xml",
            "/upnp/control/WANIPConn1",
        )
        .unwrap();
        assert_eq!(resolved, "http://192.168.1.1:49152/upnp/control/WANIPConn1");
    }

    #[test]
    fn test_resolve_control_url_relative_no_leading_slash() {
        let resolved = resolve_control_url(
            "http://192.168.1.1:49152/rootDesc.xml",
            "upnp/control/WANIPConn1",
        )
        .unwrap();
        assert_eq!(resolved, "http://192.168.1.1:49152/upnp/control/WANIPConn1");
    }

    #[test]
    fn test_resolve_control_url_absolute_passthrough() {
        let resolved = resolve_control_url(
            "http://192.168.1.1:49152/rootDesc.xml",
            "https://other-host/ctl",
        )
        .unwrap();
        assert_eq!(resolved, "https://other-host/ctl");
    }

    #[test]
    fn test_resolve_control_url_location_without_path() {
        let resolved =
            resolve_control_url("http://192.168.1.1:49152", "/upnp/control/WANIPConn1").unwrap();
        assert_eq!(resolved, "http://192.168.1.1:49152/upnp/control/WANIPConn1");
    }

    #[test]
    fn test_resolve_control_url_malformed_location() {
        assert!(resolve_control_url("not-a-url", "/ctl").is_none());
    }

    // ── host IP extraction ───────────────────────────────────────────

    #[test]
    fn test_extract_host_ip_with_port() {
        assert_eq!(
            extract_host_ip("http://192.168.1.1:49152/desc.xml"),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_host_ip_no_port() {
        assert_eq!(
            extract_host_ip("http://10.0.0.1/desc.xml"),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_host_ip_https() {
        assert_eq!(
            extract_host_ip("https://10.0.0.1:8443/desc.xml"),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_host_ip_malformed() {
        assert!(extract_host_ip("not-a-url").is_none());
        assert!(extract_host_ip("").is_none());
    }

    // ── SOAP request builder ─────────────────────────────────────────

    #[test]
    fn test_build_get_port_mapping_soap_contains_index_and_service_type() {
        let body = build_get_port_mapping_soap("urn:schemas-upnp-org:service:WANIPConnection:1", 3);
        assert!(body.contains("<NewPortMappingIndex>3</NewPortMappingIndex>"));
        assert!(body.contains("xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\""));
        assert!(body.contains("GetGenericPortMappingEntry"));
        assert!(body.starts_with("<?xml version=\"1.0\"?>"));
    }

    #[test]
    fn test_build_get_port_mapping_soap_index_zero() {
        let body = build_get_port_mapping_soap("urn:test:Service:1", 0);
        assert!(body.contains("<NewPortMappingIndex>0</NewPortMappingIndex>"));
    }

    // ── SOAP fault detection ─────────────────────────────────────────

    const SAMPLE_SOAP_FAULT: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<s:Fault>
<faultcode>s:Client</faultcode>
<faultstring>UPnPError</faultstring>
<detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>713</errorCode>
<errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
</UPnPError>
</detail>
</s:Fault>
</s:Body>
</s:Envelope>"#;

    const SAMPLE_MAPPING_RESPONSE: &str = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>25565</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>25565</NewInternalPort>
<NewInternalClient>192.168.1.50</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Minecraft</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse>
</s:Body>
</s:Envelope>"#;

    #[test]
    fn test_is_soap_fault_detects_713() {
        assert!(is_soap_fault(SAMPLE_SOAP_FAULT));
    }

    #[test]
    fn test_is_soap_fault_false_for_success() {
        assert!(!is_soap_fault(SAMPLE_MAPPING_RESPONSE));
    }

    #[test]
    fn test_is_soap_fault_empty_body() {
        assert!(!is_soap_fault(""));
    }

    // ── port mapping response parsing ─────────────────────────────────

    #[test]
    fn test_parse_port_mapping_response_full() {
        let entry = parse_port_mapping_response(SAMPLE_MAPPING_RESPONSE).unwrap();
        assert_eq!(entry.external_port, 25565);
        assert_eq!(entry.protocol, "TCP");
        assert_eq!(entry.internal_port, 25565);
        assert_eq!(entry.internal_client, "192.168.1.50");
        assert!(entry.enabled);
        assert_eq!(entry.description, "Minecraft");
        assert!(entry.remote_host.is_none());
    }

    #[test]
    fn test_parse_port_mapping_response_disabled_true_false() {
        let xml = "<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>\
                   <NewEnabled>0</NewEnabled>";
        let entry = parse_port_mapping_response(xml).unwrap();
        assert!(!entry.enabled);
    }

    #[test]
    fn test_parse_port_mapping_response_enabled_word_true() {
        let xml = "<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>\
                   <NewEnabled>true</NewEnabled>";
        let entry = parse_port_mapping_response(xml).unwrap();
        assert!(entry.enabled);
    }

    #[test]
    fn test_parse_port_mapping_response_missing_enabled_defaults_true() {
        let xml = "<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>";
        let entry = parse_port_mapping_response(xml).unwrap();
        assert!(entry.enabled);
    }

    #[test]
    fn test_parse_port_mapping_response_missing_description_defaults_empty() {
        let xml = "<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>";
        let entry = parse_port_mapping_response(xml).unwrap();
        assert_eq!(entry.description, "");
    }

    #[test]
    fn test_parse_port_mapping_response_with_remote_host() {
        let xml = "<NewRemoteHost>203.0.113.5</NewRemoteHost>\
                   <NewExternalPort>443</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>443</NewInternalPort><NewInternalClient>192.168.1.9</NewInternalClient>";
        let entry = parse_port_mapping_response(xml).unwrap();
        assert_eq!(entry.remote_host.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn test_parse_port_mapping_response_missing_essential_field_is_none() {
        // Missing NewInternalClient entirely.
        let xml = "<NewExternalPort>80</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort>";
        assert!(parse_port_mapping_response(xml).is_none());
    }

    #[test]
    fn test_parse_port_mapping_response_unparsable_port_is_none() {
        let xml = "<NewExternalPort>not-a-number</NewExternalPort><NewProtocol>TCP</NewProtocol>\
                   <NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>";
        assert!(parse_port_mapping_response(xml).is_none());
    }

    #[test]
    fn test_parse_port_mapping_response_fault_is_none() {
        assert!(parse_port_mapping_response(SAMPLE_SOAP_FAULT).is_none());
    }

    // ── sensitive-port severity classifier ────────────────────────────

    #[test]
    fn test_is_sensitive_port() {
        for port in [22, 23, 80, 445, 3389, 5900, 8080] {
            assert!(is_sensitive_port(port), "{port} should be sensitive");
        }
        for port in [25565, 443, 51820, 32400] {
            assert!(!is_sensitive_port(port), "{port} should not be sensitive");
        }
    }

    #[test]
    fn test_mapping_severity_sensitive_is_high() {
        assert_eq!(mapping_severity(22), Severity::High);
        assert_eq!(mapping_severity(3389), Severity::High);
        assert_eq!(mapping_severity(5900), Severity::High);
    }

    #[test]
    fn test_mapping_severity_ordinary_is_medium() {
        assert_eq!(mapping_severity(25565), Severity::Medium);
        assert_eq!(mapping_severity(443), Severity::Medium);
    }

    // ── finding builders ───────────────────────────────────────────

    #[test]
    fn test_build_mapping_finding_ordinary_port() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let entry = PortMappingEntry {
            remote_host: None,
            external_port: 25565,
            protocol: "TCP".to_owned(),
            internal_client: "192.168.1.50".to_owned(),
            internal_port: 25565,
            enabled: true,
            description: "Minecraft".to_owned(),
        };
        let finding = build_mapping_finding(ip, &entry);
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert_eq!(finding.affected_ip, Some(ip));
        assert_eq!(finding.affected_port, Some(25565));
        assert_eq!(finding.cwe_id.as_deref(), Some("CWE-284"));
        assert!(finding.cve_ids.is_empty());
        assert!(
            finding
                .title
                .contains("Router forwards WAN TCP/25565 -> 192.168.1.50:25565 (Minecraft)")
        );
    }

    #[test]
    fn test_build_mapping_finding_sensitive_port_is_high() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let entry = PortMappingEntry {
            remote_host: None,
            external_port: 3389,
            protocol: "TCP".to_owned(),
            internal_client: "192.168.1.20".to_owned(),
            internal_port: 3389,
            enabled: true,
            description: String::new(),
        };
        let finding = build_mapping_finding(ip, &entry);
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("no description"));
        assert!(finding.description.contains("priority to review"));
    }

    #[test]
    fn test_build_mapping_finding_has_router_device_hint() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let entry = PortMappingEntry {
            remote_host: None,
            external_port: 80,
            protocol: "TCP".to_owned(),
            internal_client: "192.168.1.5".to_owned(),
            internal_port: 8080,
            enabled: true,
            description: "Web".to_owned(),
        };
        let finding = build_mapping_finding(ip, &entry);
        let hint = finding.device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Router));
    }

    #[test]
    fn test_build_mapping_finding_remote_host_noted() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let entry = PortMappingEntry {
            remote_host: Some("203.0.113.5".to_owned()),
            external_port: 443,
            protocol: "TCP".to_owned(),
            internal_client: "192.168.1.9".to_owned(),
            internal_port: 443,
            enabled: true,
            description: "VPN".to_owned(),
        };
        let finding = build_mapping_finding(ip, &entry);
        assert!(finding.description.contains("203.0.113.5"));
    }

    #[test]
    fn test_build_summary_finding() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let finding = build_summary_finding(ip, 3);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.title.contains("3 UPnP port forward(s) active"));
        assert_eq!(finding.affected_ip, Some(ip));
    }

    #[test]
    fn test_build_summary_finding_zero() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let finding = build_summary_finding(ip, 0);
        assert!(finding.title.contains("0 UPnP port forward(s) active"));
    }

    // ── scanner metadata ─────────────────────────────────────────────

    #[test]
    fn test_scanner_metadata() {
        let scanner = UpnpIgdScanner;
        assert_eq!(scanner.id(), "upnp_igd");
        assert_eq!(scanner.name(), "UPnP IGD Port Forwarding");
        assert!(
            scanner
                .supported_perspectives()
                .contains(&Perspective::Unauthenticated)
        );
    }

    // ── proptests: parsers never panic on arbitrary input ─────────────

    proptest! {
        #[test]
        fn prop_parse_msearch_location_no_panic(response in ".*") {
            let _ = parse_msearch_location(&response);
        }

        #[test]
        fn prop_find_wan_connection_service_no_panic(xml in ".*") {
            let _ = find_wan_connection_service(&xml);
        }

        #[test]
        fn prop_resolve_control_url_no_panic(location in ".*", control_url in ".*") {
            let _ = resolve_control_url(&location, &control_url);
        }

        #[test]
        fn prop_extract_host_ip_no_panic(location in ".*") {
            let _ = extract_host_ip(&location);
        }

        #[test]
        fn prop_parse_port_mapping_response_no_panic(xml in ".*") {
            let _ = parse_port_mapping_response(&xml);
        }

        #[test]
        fn prop_is_soap_fault_no_panic(xml in ".*") {
            let _ = is_soap_fault(&xml);
        }

        #[test]
        fn prop_mapping_severity_matches_sensitivity(port in 0_u16..=u16::MAX) {
            let severity = mapping_severity(port);
            if is_sensitive_port(port) {
                prop_assert_eq!(severity, Severity::High);
            } else {
                prop_assert_eq!(severity, Severity::Medium);
            }
        }
    }
}
