use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::Scanner;

// ── UPnP device description parsing ─────────────────────────────────

/// Parsed `UPnP` device description fields from `device.xml`.
#[derive(Debug, Default, Clone)]
pub struct UpnpDeviceInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub serial_number: Option<String>,
    pub firmware_version: Option<String>,
    pub device_type: Option<String>,
}

/// Extract the text content between simple XML tags (non-recursive).
///
/// Looks for `<tag>content</tag>` and returns `content`.
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

/// Parse a `UPnP` device description XML into structured fields.
pub fn parse_upnp_device_xml(xml: &str) -> UpnpDeviceInfo {
    UpnpDeviceInfo {
        friendly_name: extract_xml_tag(xml, "friendlyName"),
        manufacturer: extract_xml_tag(xml, "manufacturer"),
        model_name: extract_xml_tag(xml, "modelName"),
        model_number: extract_xml_tag(xml, "modelNumber"),
        serial_number: extract_xml_tag(xml, "serialNumber"),
        firmware_version: extract_xml_tag(xml, "firmwareVersion")
            .or_else(|| extract_xml_tag(xml, "modelDescription")),
        device_type: extract_xml_tag(xml, "deviceType"),
    }
}

/// Classify a `UPnP` device description into findings.
pub fn classify_upnp_device(ip: IpAddr, location: &str, info: &UpnpDeviceInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    let name = info.friendly_name.as_deref().unwrap_or("Unknown device");
    let manufacturer = info.manufacturer.as_deref().unwrap_or("unknown");
    let model = info.model_name.as_deref().unwrap_or("unknown");

    // Detailed device info finding
    let mut desc_parts = vec![format!("UPnP device at {ip} ({location})")];
    desc_parts.push(format!(
        "Name: {name}, Manufacturer: {manufacturer}, Model: {model}"
    ));

    if let Some(model_num) = &info.model_number {
        desc_parts.push(format!("Model #: {model_num}"));
    }
    if let Some(fw) = &info.firmware_version {
        desc_parts.push(format!("Firmware: {fw}"));
    }
    if let Some(serial) = &info.serial_number {
        desc_parts.push(format!("Serial: {serial}"));
    }

    findings.push(
        Finding::new(
            "mdns",
            &format!("UPnP device: {name} ({manufacturer} {model}) on {ip}"),
            &desc_parts.join(". "),
            Severity::Info,
        )
        .with_ip(ip)
        .with_service("UPnP"),
    );

    // Serial number exposure is a privacy concern
    if info.serial_number.is_some() {
        findings.push(
            Finding::new(
                "mdns",
                &format!("UPnP exposes serial number on {ip}"),
                &format!(
                    "Device {name} at {ip} exposes its serial number via UPnP \
                     device description. Serial numbers can be used for device \
                     tracking and warranty fraud."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_service("UPnP")
            .with_cwe("CWE-200"),
        );
    }

    findings
}

/// Fetch a `UPnP` device description XML from a LOCATION URL.
async fn fetch_upnp_description(location: &str) -> Option<UpnpDeviceInfo> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    let resp = client.get(location).send().await.ok()?;
    let body = resp.text().await.ok()?;
    let info = parse_upnp_device_xml(&body);

    // Only return if we actually got useful data
    if info.friendly_name.is_some() || info.manufacturer.is_some() || info.model_name.is_some() {
        Some(info)
    } else {
        None
    }
}

/// mDNS/SSDP discovery scanner — discovers services advertised via
/// multicast DNS and UPnP/SSDP on the local network.
pub struct MdnsScanner;

/// SSDP multicast address and port.
const SSDP_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);

/// mDNS multicast address and port.
const MDNS_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::new(224, 0, 0, 251), 5353);

/// Parse an SSDP M-SEARCH response to extract service info.
///
/// Typical SSDP response:
/// ```text
/// HTTP/1.1 200 OK
/// CACHE-CONTROL: max-age=1800
/// ST: upnp:rootdevice
/// USN: uuid:abc-123::upnp:rootdevice
/// LOCATION: http://192.168.1.50:49152/desc.xml
/// SERVER: Linux/3.10 UPnP/1.1 MiniUPnPd/2.1
/// ```
pub fn parse_ssdp_response(response: &str) -> Option<SsdpService> {
    let mut location = None;
    let mut server = None;
    let mut st = None;

    for line in response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("location:") {
            location = Some(line[9..].trim().to_owned());
        } else if lower.starts_with("server:") {
            server = Some(line[7..].trim().to_owned());
        } else if lower.starts_with("st:") {
            st = Some(line[3..].trim().to_owned());
        }
    }

    // Need at least a location or server to be useful
    if location.is_none() && server.is_none() {
        return None;
    }

    Some(SsdpService {
        location,
        server,
        service_type: st,
    })
}

/// Parsed SSDP service information.
#[derive(Debug, Clone)]
pub struct SsdpService {
    pub location: Option<String>,
    pub server: Option<String>,
    pub service_type: Option<String>,
}

/// Parse an mDNS response to extract advertised service names.
///
/// mDNS responses are DNS packets; we do a simple text scan of the
/// response bytes for `.local` names since full DNS parsing is complex.
pub fn parse_mdns_names(data: &[u8]) -> Vec<String> {
    // Simple heuristic: scan for printable ASCII sequences ending in ".local"
    let text = String::from_utf8_lossy(data);
    let mut names = Vec::new();

    for segment in text.split(|c: char| !c.is_ascii_graphic() || c == '\0') {
        let trimmed = segment.trim();
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if trimmed.len() > 6 && trimmed.ends_with(".local") {
            // Filter out common noise
            let name = trimmed.to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    names
}

/// Classify a discovered SSDP service.
fn classify_ssdp_service(ip: IpAddr, service: &SsdpService) -> Finding {
    let server_info = service.server.as_deref().unwrap_or("unknown");
    let svc_type = service.service_type.as_deref().unwrap_or("unknown");

    // UPnP on a router is particularly risky
    let severity = if svc_type.contains("InternetGatewayDevice") {
        Severity::Medium
    } else {
        Severity::Info
    };

    let title = service.location.as_ref().map_or_else(
        || format!("UPnP/SSDP service on {ip}: {svc_type}"),
        |loc| format!("UPnP/SSDP service on {ip}: {svc_type} at {loc}"),
    );

    Finding::new(
        "mdns",
        &title,
        &format!(
            "UPnP/SSDP service discovered on {ip}. Server: {server_info}, \
             Type: {svc_type}. UPnP services can expose device control \
             interfaces and automatically open ports on routers."
        ),
        severity,
    )
    .with_ip(ip)
    .with_service("SSDP")
    .with_cwe("CWE-284")
}

/// Send SSDP M-SEARCH and collect responses.
#[allow(clippy::unused_async)]
async fn discover_ssdp() -> Vec<(IpAddr, SsdpService)> {
    let mut results = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not bind SSDP socket: {e}");
            return results;
        }
    };

    // Set receive timeout
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

    let search = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 2\r\n\
                   ST: ssdp:all\r\n\
                   \r\n";

    let dest = SocketAddr::new(IpAddr::V4(SSDP_ADDR.0), SSDP_ADDR.1);
    if socket.send_to(search.as_bytes(), dest).is_err() {
        tracing::warn!("could not send SSDP M-SEARCH");
        return results;
    }

    // Collect responses for a few seconds
    let mut buf = [0u8; 2048];
    while let Ok((n, addr)) = socket.recv_from(&mut buf) {
        let response = String::from_utf8_lossy(&buf[..n]);
        if let Some(service) = parse_ssdp_response(&response) {
            results.push((addr.ip(), service));
        }
    }

    results
}

/// Send mDNS query and collect responses.
#[allow(clippy::unused_async)]
async fn discover_mdns() -> Vec<(IpAddr, Vec<String>)> {
    let mut results = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not bind mDNS socket: {e}");
            return results;
        }
    };

    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));

    // Minimal mDNS query for _services._dns-sd._udp.local (service enumeration)
    // DNS header: ID=0, flags=0x0000, qdcount=1
    // Question: _services._dns-sd._udp.local, type PTR (12), class IN (1)
    let query: &[u8] = &[
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answers: 0
        0x00, 0x00, // Authority: 0
        0x00, 0x00, // Additional: 0
        // _services._dns-sd._udp.local
        0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's',
        b'-', b's', b'd', 0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l',
        0x00, // Root label
        0x00, 0x0C, // Type: PTR
        0x00, 0x01, // Class: IN
    ];

    let dest = SocketAddr::new(IpAddr::V4(MDNS_ADDR.0), MDNS_ADDR.1);
    if socket.send_to(query, dest).is_err() {
        tracing::warn!("could not send mDNS query");
        return results;
    }

    let mut buf = [0u8; 4096];
    while let Ok((n, addr)) = socket.recv_from(&mut buf) {
        let names = parse_mdns_names(&buf[..n]);
        if !names.is_empty() {
            results.push((addr.ip(), names));
        }
    }

    results
}

#[async_trait]
impl Scanner for MdnsScanner {
    fn id(&self) -> &'static str {
        "mdns"
    }

    fn name(&self) -> &'static str {
        "mDNS/SSDP Discovery"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        tracing::info!("running mDNS/SSDP discovery scan");
        let mut findings = Vec::new();

        // SSDP discovery
        let ssdp_results = discover_ssdp().await;
        tracing::info!(ssdp_count = ssdp_results.len(), "SSDP discovery complete");
        for (ip, service) in &ssdp_results {
            findings.push(classify_ssdp_service(*ip, service));

            // Fetch UPnP device description if a LOCATION URL is available
            // (skipped in Passive mode — HTTP fetches slow down quick scans)
            if ctx
                .config
                .intensity
                .at_least(rikitikitavi_models::config::ScanIntensity::Active)
            {
                if let Some(location) = &service.location {
                    if let Some(device_info) = fetch_upnp_description(location).await {
                        tracing::debug!(
                            ip = %ip,
                            name = ?device_info.friendly_name,
                            "fetched UPnP device description"
                        );
                        findings.extend(classify_upnp_device(*ip, location, &device_info));
                    }
                }
            }
        }

        // mDNS discovery
        let mdns_results = discover_mdns().await;
        tracing::info!(mdns_count = mdns_results.len(), "mDNS discovery complete");
        for (ip, names) in &mdns_results {
            for name in names {
                findings.push(
                    Finding::new(
                        "mdns",
                        &format!("mDNS service: {name} on {ip}"),
                        &format!(
                            "Device at {ip} advertises mDNS service '{name}'. \
                             mDNS service advertisement reveals device capabilities \
                             and can help attackers map the network."
                        ),
                        Severity::Info,
                    )
                    .with_ip(*ip)
                    .with_service("mDNS"),
                );
            }
        }

        tracing::info!(findings_count = findings.len(), "mDNS/SSDP scan complete");
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

    #[test]
    fn test_parse_ssdp_response_full() {
        let response = "HTTP/1.1 200 OK\r\n\
                         CACHE-CONTROL: max-age=1800\r\n\
                         ST: upnp:rootdevice\r\n\
                         USN: uuid:abc::upnp:rootdevice\r\n\
                         LOCATION: http://192.168.1.50:49152/desc.xml\r\n\
                         SERVER: Linux/3.10 UPnP/1.1 MiniUPnPd/2.1\r\n\r\n";
        let svc = parse_ssdp_response(response).unwrap();
        assert_eq!(
            svc.location.as_deref(),
            Some("http://192.168.1.50:49152/desc.xml")
        );
        assert_eq!(
            svc.server.as_deref(),
            Some("Linux/3.10 UPnP/1.1 MiniUPnPd/2.1")
        );
        assert_eq!(svc.service_type.as_deref(), Some("upnp:rootdevice"));
    }

    #[test]
    fn test_parse_ssdp_response_minimal() {
        let response = "HTTP/1.1 200 OK\r\nSERVER: foo/1.0\r\n\r\n";
        let svc = parse_ssdp_response(response).unwrap();
        assert!(svc.location.is_none());
        assert_eq!(svc.server.as_deref(), Some("foo/1.0"));
    }

    #[test]
    fn test_parse_ssdp_response_empty() {
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        assert!(parse_ssdp_response(response).is_none());
    }

    #[test]
    fn test_parse_mdns_names() {
        // Simulate a response containing .local names embedded in binary
        let data = b"\x00\x00printer._ipp._tcp.local\x00\x00\x0cnas.local\x00";
        let names = parse_mdns_names(data);
        assert!(names.iter().any(|n| n.contains(".local")));
    }

    #[test]
    fn test_parse_mdns_names_empty() {
        let data = b"\x00\x00\x00\x01\x02\x03";
        let names = parse_mdns_names(data);
        assert!(names.is_empty());
    }

    #[test]
    fn test_parse_mdns_names_no_duplicates() {
        let data = b"foo.local\x00foo.local\x00bar.local\x00";
        let names = parse_mdns_names(data);
        // foo.local should appear only once
        assert_eq!(names.iter().filter(|n| n == &"foo.local").count(), 1);
    }

    #[test]
    fn test_classify_ssdp_gateway() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let svc = SsdpService {
            location: Some("http://192.168.1.1:49152/desc.xml".to_owned()),
            server: Some("Linux UPnP/1.1 MiniUPnPd/2.2".to_owned()),
            service_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_owned()),
        };
        let finding = classify_ssdp_service(ip, &svc);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_classify_ssdp_generic() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let svc = SsdpService {
            location: Some("http://192.168.1.50:8080/".to_owned()),
            server: Some("Chromecast/1.0".to_owned()),
            service_type: Some("urn:dial-multiscreen-org:service:dial:1".to_owned()),
        };
        let finding = classify_ssdp_service(ip, &svc);
        assert_eq!(finding.severity, Severity::Info);
    }

    // ── UPnP device description tests ─────────────────────────────

    #[test]
    fn test_extract_xml_tag() {
        let xml = "<root><friendlyName>My Router</friendlyName></root>";
        assert_eq!(
            extract_xml_tag(xml, "friendlyName"),
            Some("My Router".to_owned())
        );
    }

    #[test]
    fn test_extract_xml_tag_missing() {
        let xml = "<root><modelName>RT-AC68U</modelName></root>";
        assert!(extract_xml_tag(xml, "friendlyName").is_none());
    }

    #[test]
    fn test_extract_xml_tag_empty() {
        let xml = "<root><friendlyName></friendlyName></root>";
        assert!(extract_xml_tag(xml, "friendlyName").is_none());
    }

    #[test]
    fn test_parse_upnp_device_xml_full() {
        let xml = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>ASUS RT-AC68U</friendlyName>
    <manufacturer>ASUSTeK Computer Inc.</manufacturer>
    <modelName>RT-AC68U</modelName>
    <modelNumber>3.0.0.4</modelNumber>
    <serialNumber>ABC123456</serialNumber>
    <firmwareVersion>3.0.0.4.386_51685</firmwareVersion>
  </device>
</root>"#;
        let info = parse_upnp_device_xml(xml);
        assert_eq!(info.friendly_name.as_deref(), Some("ASUS RT-AC68U"));
        assert_eq!(info.manufacturer.as_deref(), Some("ASUSTeK Computer Inc."));
        assert_eq!(info.model_name.as_deref(), Some("RT-AC68U"));
        assert_eq!(info.model_number.as_deref(), Some("3.0.0.4"));
        assert_eq!(info.serial_number.as_deref(), Some("ABC123456"));
        assert_eq!(info.firmware_version.as_deref(), Some("3.0.0.4.386_51685"));
    }

    #[test]
    fn test_parse_upnp_device_xml_minimal() {
        let xml = "<root><device><friendlyName>Chromecast</friendlyName></device></root>";
        let info = parse_upnp_device_xml(xml);
        assert_eq!(info.friendly_name.as_deref(), Some("Chromecast"));
        assert!(info.manufacturer.is_none());
        assert!(info.serial_number.is_none());
    }

    #[test]
    fn test_parse_upnp_device_xml_empty() {
        let info = parse_upnp_device_xml("");
        assert!(info.friendly_name.is_none());
        assert!(info.manufacturer.is_none());
    }

    #[test]
    fn test_classify_upnp_device_with_serial() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("My Router".to_owned()),
            manufacturer: Some("ASUS".to_owned()),
            model_name: Some("RT-AC68U".to_owned()),
            serial_number: Some("SN12345".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.1:49152/desc.xml", &info);
        // Info device listing + serial exposure warning
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Low));
    }

    #[test]
    fn test_classify_upnp_device_no_serial() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("Chromecast".to_owned()),
            manufacturer: Some("Google".to_owned()),
            ..Default::default()
        };
        let findings =
            classify_upnp_device(ip, "http://192.168.1.50:8008/setup/eureka_info", &info);
        // Only info listing
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    proptest! {
        /// `parse_ssdp_response` never panics on arbitrary strings
        #[test]
        fn prop_parse_ssdp_no_panic(response in ".*") {
            let _ = parse_ssdp_response(&response);
        }

        /// `parse_mdns_names` never panics on arbitrary bytes
        #[test]
        fn prop_parse_mdns_names_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse_mdns_names(&data);
        }

        /// `classify_ssdp_service` never panics with arbitrary service data
        #[test]
        fn prop_classify_ssdp_no_panic(
            location in proptest::option::of(".*"),
            server in proptest::option::of(".*"),
            service_type in proptest::option::of(".*"),
        ) {
            let ip: IpAddr = "10.0.0.1".parse().unwrap();
            let svc = SsdpService { location, server, service_type };
            let _ = classify_ssdp_service(ip, &svc);
        }

        /// `parse_upnp_device_xml` never panics on arbitrary strings
        #[test]
        fn prop_parse_upnp_device_xml_no_panic(xml in ".*") {
            let _ = parse_upnp_device_xml(&xml);
        }

        /// `extract_xml_tag` never panics on arbitrary strings
        #[test]
        fn prop_extract_xml_tag_no_panic(xml in ".*", tag in "[a-zA-Z]{1,20}") {
            let _ = extract_xml_tag(&xml, &tag);
        }
    }
}
