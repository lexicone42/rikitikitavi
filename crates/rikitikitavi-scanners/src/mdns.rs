use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::{Finding, ScanContext};
use rikitikitavi_network::MdnsService;
use std::collections::{HashMap, HashSet};
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

// ── mDNS service classification ─────────────────────────────────────

/// Classify a discovered mDNS service into security findings.
#[allow(clippy::too_many_lines)]
fn classify_mdns_service(service: &MdnsService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ip = service.ip;
    let svc_type = &service.service_type;

    // Build a display name
    let display_name = if service.name.is_empty() {
        service.hostname.clone()
    } else {
        service.name.clone()
    };

    // TXT metadata summary
    let txt_summary = if service.txt_records.is_empty() {
        String::new()
    } else {
        format!(" TXT: [{}]", service.txt_records.join(", "))
    };

    // Base finding for every discovered service
    let base_desc = format!(
        "mDNS service '{display_name}' of type {svc_type} on {ip}:{port} \
         (hostname: {hostname}).{txt_summary} \
         mDNS service advertisement reveals device capabilities \
         and can help attackers map the network.",
        port = service.port,
        hostname = service.hostname,
    );

    // Classify by service type
    if svc_type.contains("_ssh._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("SSH service advertised: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} SSH access advertised via mDNS makes this host \
                     easily discoverable. Ensure strong authentication (key-based) \
                     is required and password auth is disabled."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("SSH")
            .with_cwe("CWE-200"),
        );
    } else if svc_type.contains("_http._tcp") {
        let severity = if service
            .txt_records
            .iter()
            .any(|t| t.contains("admin") || t.contains("path=/"))
        {
            Severity::Low
        } else {
            Severity::Info
        };

        findings.push(
            Finding::new(
                "mdns",
                &format!("HTTP service advertised: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} HTTP service discovered via mDNS. Web interfaces \
                     may expose admin panels, configuration pages, or APIs."
                ),
                severity,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("HTTP")
            .with_cwe("CWE-200"),
        );
    } else if svc_type.contains("_ipp._tcp") || svc_type.contains("_printer._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("Printer service advertised: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} Network printers can leak document contents, \
                     user information, and internal network details through their \
                     management interfaces."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("IPP")
            .with_cwe("CWE-200"),
        );
    } else if svc_type.contains("_smb._tcp") || svc_type.contains("_afpovertcp._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("File sharing service: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} File sharing service discovered via mDNS. \
                     Shared folders may expose sensitive documents or allow \
                     unauthorized access if permissions are misconfigured."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("SMB")
            .with_cwe("CWE-732"),
        );
    } else if svc_type.contains("_airplay._tcp") || svc_type.contains("_raop._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("AirPlay device: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} AirPlay service allows screen mirroring and \
                     media streaming. Unauthorized users on the network can \
                     stream content to this device."
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("AirPlay"),
        );
    } else if svc_type.contains("_googlecast._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("Chromecast/Google Cast: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} Google Cast device allows media casting from \
                     any device on the network."
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("Google Cast"),
        );
    } else if svc_type.contains("_hap._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("HomeKit device: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} Apple HomeKit accessory discovered. HomeKit \
                     devices control physical home functions (locks, cameras, \
                     lights). Ensure pairing is restricted."
                ),
                Severity::Low,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("HomeKit")
            .with_cwe("CWE-287"),
        );
    } else {
        // Generic mDNS service
        findings.push(
            Finding::new(
                "mdns",
                &format!("mDNS service: {display_name} ({svc_type}) on {ip}:{}", service.port),
                &base_desc,
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("mDNS"),
        );
    }

    findings
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

        // Deduplicate SSDP service findings by (IP, service_type)
        let mut seen_ssdp_services: HashSet<(IpAddr, String)> = HashSet::new();
        for (ip, service) in &ssdp_results {
            let svc_type = service
                .service_type
                .as_deref()
                .unwrap_or("unknown")
                .to_owned();
            if seen_ssdp_services.insert((*ip, svc_type)) {
                findings.push(classify_ssdp_service(*ip, service));
            }
        }

        // Group SSDP responses by (IP, LOCATION) for UPnP device description
        // fetching — same device advertising multiple service URNs should only
        // produce one info finding and one serial-number finding.
        if ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            let mut device_groups: HashMap<(IpAddr, String), Vec<SsdpService>> = HashMap::new();
            for (ip, service) in &ssdp_results {
                if let Some(location) = &service.location {
                    device_groups
                        .entry((*ip, location.clone()))
                        .or_default()
                        .push(service.clone());
                }
            }

            for (ip, location) in device_groups.keys() {
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

        // mDNS discovery — proper DNS packet parsing via network crate
        match rikitikitavi_network::discover_services(3).await {
            Ok(mdns_services) => {
                tracing::info!(
                    mdns_count = mdns_services.len(),
                    "mDNS discovery complete"
                );
                for service in &mdns_services {
                    findings.extend(classify_mdns_service(service));
                }
            }
            Err(e) => {
                tracing::warn!("mDNS discovery failed: {e}");
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

    // ── mDNS service classification tests ────────────────────────

    #[test]
    fn test_classify_ssh_service() {
        let svc = MdnsService {
            name: "NAS".to_owned(),
            service_type: "_ssh._tcp.local".to_owned(),
            hostname: "nas.local".to_owned(),
            ip: "192.168.1.10".parse().unwrap(),
            port: 22,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("SSH"));
    }

    #[test]
    fn test_classify_http_service() {
        let svc = MdnsService {
            name: "Router".to_owned(),
            service_type: "_http._tcp.local".to_owned(),
            hostname: "router.local".to_owned(),
            ip: "192.168.1.1".parse().unwrap(),
            port: 80,
            txt_records: vec!["path=/admin".to_owned()],
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings.len(), 1);
        // Admin path bumps severity to Low
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_classify_http_service_generic() {
        let svc = MdnsService {
            name: "Web App".to_owned(),
            service_type: "_http._tcp.local".to_owned(),
            hostname: "app.local".to_owned(),
            ip: "192.168.1.50".parse().unwrap(),
            port: 8080,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_classify_printer_service() {
        let svc = MdnsService {
            name: "EPSON XP-440".to_owned(),
            service_type: "_ipp._tcp.local".to_owned(),
            hostname: "printer.local".to_owned(),
            ip: "192.168.1.100".parse().unwrap(),
            port: 631,
            txt_records: vec!["rp=ipp/print".to_owned(), "ty=EPSON XP-440".to_owned()],
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("Printer"));
    }

    #[test]
    fn test_classify_smb_service() {
        let svc = MdnsService {
            name: "NAS Share".to_owned(),
            service_type: "_smb._tcp.local".to_owned(),
            hostname: "nas.local".to_owned(),
            ip: "192.168.1.20".parse().unwrap(),
            port: 445,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("File sharing"));
    }

    #[test]
    fn test_classify_airplay_service() {
        let svc = MdnsService {
            name: "Living Room TV".to_owned(),
            service_type: "_airplay._tcp.local".to_owned(),
            hostname: "appletv.local".to_owned(),
            ip: "192.168.1.30".parse().unwrap(),
            port: 7000,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("AirPlay"));
    }

    #[test]
    fn test_classify_googlecast_service() {
        let svc = MdnsService {
            name: "Kitchen Display".to_owned(),
            service_type: "_googlecast._tcp.local".to_owned(),
            hostname: "chromecast.local".to_owned(),
            ip: "192.168.1.40".parse().unwrap(),
            port: 8009,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("Chromecast"));
    }

    #[test]
    fn test_classify_homekit_service() {
        let svc = MdnsService {
            name: "Front Door Lock".to_owned(),
            service_type: "_hap._tcp.local".to_owned(),
            hostname: "lock.local".to_owned(),
            ip: "192.168.1.60".parse().unwrap(),
            port: 8080,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("HomeKit"));
    }

    #[test]
    fn test_classify_generic_service() {
        let svc = MdnsService {
            name: "Unknown Thing".to_owned(),
            service_type: "_custom._tcp.local".to_owned(),
            hostname: "thing.local".to_owned(),
            ip: "192.168.1.99".parse().unwrap(),
            port: 9999,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_classify_empty_name_uses_hostname() {
        let svc = MdnsService {
            name: String::new(),
            service_type: "_ssh._tcp.local".to_owned(),
            hostname: "server.local".to_owned(),
            ip: "10.0.0.1".parse().unwrap(),
            port: 22,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        assert!(findings[0].title.contains("server.local"));
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
