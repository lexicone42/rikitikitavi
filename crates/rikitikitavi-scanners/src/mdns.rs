use async_trait::async_trait;
use rikitikitavi_core::{Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, ScanContext};
use rikitikitavi_network::MdnsService;
use rikitikitavi_network::mdns::{MdnsTxt, ThreadStateBitmap};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use crate::Scanner;
use crate::ha_discovery_db::{
    SsdpFields, consensus_device_type, homekit_domain, ssdp_domains, ssdp_hits, zeroconf_domains,
};
use crate::http_util::unauthenticated_probe_client;

// ── UPnP device description parsing ─────────────────────────────────

/// Parsed `UPnP` device description fields from `device.xml`.
#[derive(Debug, Default, Clone)]
pub struct UpnpDeviceInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub model_description: Option<String>,
    pub serial_number: Option<String>,
    pub firmware_version: Option<String>,
    pub device_type: Option<String>,
}

/// Text between the first `<tag>` and following `</tag>` (non-recursive).
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
        model_description: extract_xml_tag(xml, "modelDescription"),
        serial_number: extract_xml_tag(xml, "serialNumber"),
        firmware_version: extract_xml_tag(xml, "firmwareVersion"),
        device_type: extract_xml_tag(xml, "deviceType"),
    }
}

/// Map a `UPnP` device type URN to a `DeviceType`.
fn upnp_type_to_device_type(urn: &str) -> DeviceType {
    if urn.contains("InternetGatewayDevice") || urn.contains("WANDevice") {
        DeviceType::Router
    } else if urn.contains("MediaRenderer") || urn.contains("MediaServer") {
        DeviceType::MediaPlayer
    } else if urn.contains("Printer") {
        DeviceType::Printer
    } else if urn.contains("Camera") {
        DeviceType::Camera
    } else {
        DeviceType::Unknown
    }
}

/// Manufacturer/model overrides for the `UPnP` device type (e.g. Synology
/// advertises `MediaServer` but is classified NAS).
fn manufacturer_override_device_type(
    manufacturer: &str,
    model: &str,
    upnp_type: DeviceType,
) -> DeviceType {
    let mfr_lower = manufacturer.to_lowercase();
    if mfr_lower.contains("synology")
        || mfr_lower.contains("qnap")
        || mfr_lower.contains("western digital")
    {
        return DeviceType::Nas;
    }
    if mfr_lower.contains("lg electronics") {
        return DeviceType::SmartTv;
    }
    if mfr_lower.contains("signify") || mfr_lower.contains("philips") {
        return DeviceType::IoT;
    }

    if upnp_type == DeviceType::Unknown {
        let model_lower = model.to_lowercase();
        if model_lower.contains("tv") || model_lower.contains("android tv") {
            return DeviceType::SmartTv;
        }
    }

    upnp_type
}

/// Classify a `UPnP` device description into findings.
pub fn classify_upnp_device(ip: IpAddr, location: &str, info: &UpnpDeviceInfo) -> Vec<Finding> {
    let mut findings = Vec::new();

    let name = info.friendly_name.as_deref().unwrap_or("Unknown device");
    let manufacturer = info.manufacturer.as_deref().unwrap_or("unknown");
    let model = info.model_name.as_deref().unwrap_or("unknown");

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

    let mut hint = DeviceHint::new().with_hostname(name);
    if manufacturer != "unknown" {
        hint = hint.with_vendor(manufacturer);
    }
    if model != "unknown" {
        hint = hint.with_model(model);
    }
    let base_type = info
        .device_type
        .as_deref()
        .map_or(DeviceType::Unknown, upnp_type_to_device_type);
    let mut device_type = manufacturer_override_device_type(manufacturer, model, base_type);

    // HA's SSDP table names a product family where the URN names only a role.
    let hits = ssdp_hits(&SsdpFields {
        device_type: info.device_type.as_deref(),
        manufacturer: info.manufacturer.as_deref(),
        model_name: info.model_name.as_deref(),
        model_description: info.model_description.as_deref(),
        ..SsdpFields::default()
    });
    if !hits.is_empty() {
        let ha_domains: Vec<&str> = hits.iter().map(|h| h.domain).collect();
        let ha_type = consensus_device_type(&ha_domains);
        // A vendor-only matcher (`wemo` on Belkin, `axis` on AXIS) covers the
        // whole catalogue, so it must not retype a device the URN already
        // classed — a Belkin IGD is a router, not a smart plug.
        let may_retype = device_type == DeviceType::Unknown || hits.iter().any(|h| h.specific);
        if ha_type != DeviceType::Unknown && may_retype {
            device_type = ha_type;
        }
        hint = hint.with_device_subtype(ha_domains.join("/"));
        desc_parts.push(format!("Integration match: {}", ha_domains.join(", ")));
    }

    if device_type != DeviceType::Unknown {
        hint = hint.with_device_type(device_type);
    }

    findings.push(
        Finding::new(
            "mdns",
            &format!("UPnP device: {name} ({manufacturer} {model}) on {ip}"),
            &desc_parts.join(". "),
            Severity::Info,
        )
        .with_ip(ip)
        .with_service("UPnP")
        .with_device_hint(hint),
    );

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
            .with_cwe("CWE-200")
            .with_references(refs!["https://owasp.org/www-project-internet-of-things/",]),
        );
    }

    findings
}

/// Responder `ip` or the LOCATION host is excluded.
fn upnp_target_excluded(ip: IpAddr, location: &str, exclusions: &ExclusionSet) -> bool {
    exclusions.excludes_ip(ip)
        || crate::upnp_igd::extract_host_ip(location).is_some_and(|h| exclusions.excludes_ip(h))
}

/// Fetch a `UPnP` device description XML from a LOCATION URL.
async fn fetch_upnp_description(location: &str) -> Option<UpnpDeviceInfo> {
    let client =
        unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::default()).ok()?;

    let resp = client.get(location).send().await.ok()?;
    let body = crate::http_util::read_body_capped(resp, crate::http_util::MAX_BODY_BYTES).await;
    let info = parse_upnp_device_xml(&body);

    if info.friendly_name.is_some() || info.manufacturer.is_some() || info.model_name.is_some() {
        Some(info)
    } else {
        None
    }
}

/// mDNS/SSDP discovery scanner; fetches `UPnP` device descriptions in Active mode.
pub struct MdnsScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// SSDP multicast address and port.
const SSDP_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);

/// Parse an SSDP M-SEARCH response (`LOCATION`, `SERVER`, `ST` headers).
///
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

    let severity = if svc_type.contains("InternetGatewayDevice") {
        Severity::Medium
    } else {
        Severity::Info
    };

    let title = service.location.as_ref().map_or_else(
        || format!("UPnP/SSDP service on {ip}: {svc_type}"),
        |loc| format!("UPnP/SSDP service on {ip}: {svc_type} at {loc}"),
    );

    // 21 of HA's 91 SSDP matchers are `st`-only, so they fire on the M-SEARCH
    // response alone, without fetching the device description.
    let ha_domains = ssdp_domains(&SsdpFields {
        st: service.service_type.as_deref(),
        ..SsdpFields::default()
    });
    let ha_note = if ha_domains.is_empty() {
        String::new()
    } else {
        format!(" Integration match: {}.", ha_domains.join(", "))
    };

    let mut finding = Finding::new(
        "mdns",
        &title,
        &format!(
            "UPnP/SSDP service discovered on {ip}. Server: {server_info}, \
             Type: {svc_type}. UPnP services can expose device control \
             interfaces and automatically open ports on routers.{ha_note}"
        ),
        severity,
    )
    .with_ip(ip)
    .with_service("SSDP")
    .with_cwe("CWE-284");

    let ha_type = consensus_device_type(&ha_domains);
    if !ha_domains.is_empty() {
        let mut hint = DeviceHint::new().with_device_subtype(ha_domains.join("/"));
        if ha_type == DeviceType::Unknown && svc_type.contains("InternetGatewayDevice") {
            hint = hint.with_device_type(DeviceType::Router);
        } else if ha_type != DeviceType::Unknown {
            hint = hint.with_device_type(ha_type);
        }
        finding = finding.with_device_hint(hint);
    } else if svc_type.contains("InternetGatewayDevice") {
        finding = finding.with_device_hint(DeviceHint::new().with_device_type(DeviceType::Router));
    }

    finding
}

/// SSDP receive window after the M-SEARCH is sent.
const SSDP_DEADLINE: Duration = Duration::from_secs(3);

/// mDNS receive budget. The query list is ~130 service types sent in batches, so
/// this is spread across the batches rather than spent on one burst.
const MDNS_DISCOVERY_SECS: u64 = 6;

/// Maximum SSDP responses collected per scan.
const SSDP_MAX_RESPONSES: usize = 256;

/// Send SSDP M-SEARCH and collect responses.
async fn discover_ssdp() -> Vec<(IpAddr, SsdpService)> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not bind SSDP socket: {e}");
            return Vec::new();
        }
    };

    let search = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 2\r\n\
                   ST: ssdp:all\r\n\
                   \r\n";

    let dest = SocketAddr::new(IpAddr::V4(SSDP_ADDR.0), SSDP_ADDR.1);
    if socket.send_to(search.as_bytes(), dest).await.is_err() {
        tracing::warn!("could not send SSDP M-SEARCH");
        return Vec::new();
    }

    collect_ssdp_responses(&socket, Instant::now() + SSDP_DEADLINE, SSDP_MAX_RESPONSES).await
}

/// Parsed responses received on `socket` until `deadline`, at most `max`.
async fn collect_ssdp_responses(
    socket: &UdpSocket,
    deadline: Instant,
    max: usize,
) -> Vec<(IpAddr, SsdpService)> {
    let mut results = Vec::new();
    let mut buf = [0u8; 2048];

    while results.len() < max {
        let Ok(Ok((n, addr))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        if let Some(service) = parse_ssdp_response(&String::from_utf8_lossy(&buf[..n])) {
            results.push((addr.ip(), service));
        }
    }

    results
}

// ── mDNS service classification ─────────────────────────────────────

/// Product identity for an mDNS service: HA's zeroconf table plus interpreted TXT.
struct MdnsIdentity {
    device_type: DeviceType,
    /// HA integration domains, `/`-joined; `None` when nothing matched.
    subtype: Option<String>,
    /// Hostname, for the `DeviceHint`.
    hostname: Option<String>,
    /// Interpreted well-known TXT keys.
    txt: MdnsTxt,
}

impl MdnsIdentity {
    fn of(service: &MdnsService) -> Self {
        let txt = MdnsTxt::parse(&service.txt_records);
        // HA matches the full instance name, trailing dot included.
        let full_name = format!("{}.{}.", service.name, service.service_type);
        let mut domains = zeroconf_domains(&service.service_type, &full_name, &service.txt_records);

        // A HomeKit accessory names its product in `md`.
        if service.service_type.contains("_hap.")
            && let Some(model) = &txt.model
            && let Some(domain) = homekit_domain(model)
            && !domains.contains(&domain)
        {
            domains.push(domain);
        }

        Self {
            device_type: consensus_device_type(&domains),
            subtype: (!domains.is_empty()).then(|| domains.join("/")),
            hostname: (!service.hostname.is_empty()).then(|| service.hostname.clone()),
            txt,
        }
    }

    /// A hint carrying hostname, model and HA identity; `fallback` is used only
    /// when the HA tables did not agree on a type.
    fn hint(&self, fallback: DeviceType) -> DeviceHint {
        let mut hint = DeviceHint::new();
        if let Some(hostname) = &self.hostname {
            hint = hint.with_hostname(hostname);
        }
        if let Some(model) = &self.txt.model {
            hint = hint.with_model(model);
        }
        if let Some(subtype) = &self.subtype {
            hint = hint.with_device_subtype(subtype);
        }
        let device_type = if self.device_type == DeviceType::Unknown {
            fallback
        } else {
            self.device_type
        };
        if device_type == DeviceType::Unknown {
            hint
        } else {
            hint.with_device_type(device_type)
        }
    }

    /// Sentence naming the matching integrations, or empty.
    fn note(&self) -> String {
        self.subtype
            .as_ref()
            .map_or_else(String::new, |s| format!(" Integration match: {s}."))
    }
}

/// The Matter identity TXT keys, as a sentence fragment.
fn matter_advertised(txt: &MdnsTxt) -> String {
    let mut details = Vec::new();
    if let Some(vp) = &txt.vendor_product {
        details.push(format!("vendor+product {vp}"));
    }
    if let Some(dt) = &txt.device_type_id {
        details.push(format!("device type {dt}"));
    }
    if let Some(dn) = &txt.device_name {
        details.push(format!("name {dn}"));
    }
    if let Some(d) = &txt.discriminator {
        details.push(format!("discriminator {d}"));
    }
    if details.is_empty() {
        String::new()
    } else {
        format!(" Advertised: {}.", details.join(", "))
    }
}

/// Matter commissioner advertisement (`_matterd._udp`).
///
/// Commissioner discovery, not commissionable-node discovery: the record carries
/// no `CM` key, so it says nothing about any commissioning window.
fn classify_matter_commissioner(
    service: &MdnsService,
    identity: &MdnsIdentity,
    base_desc: &str,
) -> Finding {
    let (ip, port) = (service.ip, service.port);
    let display_name = display_name(service);
    let details = matter_advertised(&identity.txt);

    Finding::new(
        "mdns",
        &format!("Matter commissioner: {display_name} on {ip}:{port}"),
        &format!(
            "{base_desc} This host advertises itself as a Matter commissioner: it \
             offers to put new devices onto a fabric, so it holds that fabric's \
             credentials. Commissioner discovery carries no commissioning-mode key; \
             an open window is advertised by the joining device on \
             _matterc._udp.{details}"
        ),
        Severity::Info,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Matter")
    .with_device_hint(identity.hint(DeviceType::Hub))
}

/// Matter commissionable-node advertisement (`_matterc._udp`).
///
/// Reports posture only: no commissioning is attempted, and an open window is an
/// exposed authentication surface (PASE still requires the setup passcode), not
/// an open join.
fn classify_matter_commissionable(
    service: &MdnsService,
    identity: &MdnsIdentity,
    base_desc: &str,
) -> Finding {
    let (ip, port) = (service.ip, service.port);
    let display_name = display_name(service);
    let txt = &identity.txt;
    let details = matter_advertised(txt);

    // `CM` is an enum, not a flag set: 1 = Basic (static factory passcode),
    // 2 = Enhanced (dynamic, time-boxed), 3 = joint fabric. Any non-zero value
    // means a window is open. Absent is not the same as zero.
    let Some(mode) = txt.commissioning_mode.filter(|&m| m != 0) else {
        let window = if txt.commissioning_mode.is_some() {
            "its commissioning window closed (CM=0)"
        } else {
            "no commissioning mode advertised (no CM key), so no window is asserted \
             either way"
        };
        return Finding::new(
            "mdns",
            &format!("Matter commissionable device: {display_name} on {ip}:{port}"),
            &format!(
                "{base_desc} Matter node advertising commissionable discovery with \
                 {window}.{details}"
            ),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Matter")
        .with_device_hint(identity.hint(DeviceType::IoT));
    };

    let mode_note = match mode {
        1 => {
            "CM=1 is Basic mode: the window opens against the static factory \
             passcode printed on the device, which never changes"
        }
        2 => {
            "CM=2 is Enhanced mode: the passcode is generated per window and the \
             window is time-boxed"
        }
        _ => "the commissioning mode is a value this build does not recognise",
    };

    Finding::new(
        "mdns",
        &format!("Matter commissioning window open on {ip}:{port}"),
        &format!(
            "{base_desc} {display_name} is advertising an open Matter commissioning \
             window (CM={mode}). {mode_note}. Joining still requires the setup \
             passcode via PASE/SPAKE2+, so this is an exposed authentication \
             surface rather than an open join, but the window should be closed \
             once commissioning is finished.{details}"
        ),
        Severity::Low,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Matter")
    .with_cwe("CWE-287")
    .with_device_hint(identity.hint(DeviceType::IoT))
}

/// Thread border-agent advertisement (`_meshcop._udp`, `_meshcop-e._udp`).
fn classify_thread_border_agent(
    service: &MdnsService,
    identity: &MdnsIdentity,
    base_desc: &str,
) -> Finding {
    let (ip, port) = (service.ip, service.port);
    let display_name = display_name(service);
    let txt = &identity.txt;

    // `_meshcop-e` is published with an empty TXT record, so identity fields
    // have to come from the sibling `_meshcop` service.
    if service.service_type.contains("_meshcop-e._udp") {
        return Finding::new(
            "mdns",
            &format!("Thread ephemeral-key commissioning session on {ip}:{port}"),
            &format!(
                "{base_desc} A Thread border agent at {ip} is advertising an \
                 ephemeral-key commissioning session. The window defaults to two \
                 minutes (ten at most) and stops on the first failed connection, so \
                 a scheduled scan catching one usually means commissioning is \
                 happening right now. This record carries no TXT data; vendor and \
                 network fields come from the sibling _meshcop service."
            ),
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(port)
        .with_service("Thread")
        .with_cwe("CWE-287")
        .with_device_hint(identity.hint(DeviceType::Hub));
    }

    let mut details = Vec::new();
    if let Some(vendor) = &txt.manufacturer {
        details.push(format!("vendor {vendor}"));
    }
    if let Some(model) = &txt.model {
        details.push(format!("model {model}"));
    }
    if let Some(nn) = &txt.thread_network_name {
        details.push(format!("network name {nn}"));
    }
    if let Some(xp) = &txt.thread_extended_pan_id {
        details.push(format!("extended PAN id {xp}"));
    }
    if let Some(omr) = &txt.thread_omr_prefix {
        details.push(format!("off-mesh-routable prefix {omr}"));
    }
    let state = txt
        .thread_state_bitmap
        .as_deref()
        .and_then(ThreadStateBitmap::parse);
    if let Some(sb) = &txt.thread_state_bitmap {
        details.push(format!("state bitmap {sb}"));
    }
    if let Some(tv) = &txt.thread_version {
        details.push(format!("Thread version {tv}"));
    }
    let details = if details.is_empty() {
        String::new()
    } else {
        format!(" Advertised in the clear: {}.", details.join(", "))
    };

    // The `sb` bits carry the commissioning posture; without them the severity
    // would rest on the network-identity disclosure alone.
    let posture = state.map_or_else(String::new, |s| {
        let epskc = if s.epskc_supported {
            " It also accepts ephemeral-key commissioning."
        } else {
            ""
        };
        let path = if s.commissioning_path_open() {
            " Interface and connection mode together mean a commissioner could \
             open a session against it now."
        } else {
            ""
        };
        format!(
            " Its state bitmap decodes to: Thread interface {}, commissioner \
             connection via {}.{path}{epskc}",
            s.interface_status_name(),
            s.connection_mode_name(),
        )
    });

    Finding::new(
        "mdns",
        &format!("Thread border router: {display_name} on {ip}:{port}"),
        &format!(
            "{base_desc} This host is a Thread border router: it bridges a Thread \
             mesh of low-power devices onto this network. Its border-agent record \
             discloses the Thread network's identity and its routable IPv6 prefix \
             to anyone on the LAN, which is enough to enumerate and address the \
             mesh behind it.{posture}{details}"
        ),
        Severity::Low,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Thread")
    .with_cwe("CWE-200")
    .with_device_hint(identity.hint(DeviceType::Hub))
}

/// Instance name, falling back to the hostname.
fn display_name(service: &MdnsService) -> String {
    if service.name.is_empty() {
        service.hostname.clone()
    } else {
        service.name.clone()
    }
}

/// Classify a discovered mDNS service into security findings.
#[allow(clippy::too_many_lines)]
fn classify_mdns_service(service: &MdnsService) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ip = service.ip;
    let svc_type = &service.service_type;
    let identity = MdnsIdentity::of(service);

    let display_name = display_name(service);

    let txt_summary = if service.txt_records.is_empty() {
        String::new()
    } else {
        format!(" TXT: [{}]", service.txt_records.join(", "))
    };

    let base_desc = format!(
        "mDNS service '{display_name}' of type {svc_type} on {ip}:{port} \
         (hostname: {hostname}).{txt_summary} \
         mDNS service advertisement reveals device capabilities \
         and can help attackers map the network.{note}",
        port = service.port,
        hostname = service.hostname,
        note = identity.note(),
    );

    if svc_type.contains("_ssh._tcp") {
        let finding = Finding::new(
            "mdns",
            &format!(
                "SSH service advertised: {display_name} on {ip}:{}",
                service.port
            ),
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
        .with_cwe("CWE-200")
        .with_device_hint(identity.hint(DeviceType::Unknown));
        findings.push(finding);
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

        let finding = Finding::new(
            "mdns",
            &format!(
                "HTTP service advertised: {display_name} on {ip}:{}",
                service.port
            ),
            &format!(
                "{base_desc} HTTP service discovered via mDNS. Web interfaces \
                     may expose admin panels, configuration pages, or APIs."
            ),
            severity,
        )
        .with_ip(ip)
        .with_port(service.port)
        .with_service("HTTP")
        .with_cwe("CWE-200")
        .with_references(refs!["https://owasp.org/www-project-internet-of-things/",])
        .with_device_hint(identity.hint(DeviceType::Unknown));
        findings.push(finding);
    } else if svc_type.contains("_ipp._tcp") || svc_type.contains("_printer._tcp") {
        let hint = identity.hint(DeviceType::Printer);
        findings.push(
            Finding::new(
                "mdns",
                &format!(
                    "Printer service advertised: {display_name} on {ip}:{}",
                    service.port
                ),
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
            .with_cwe("CWE-200")
            .with_references(refs!["https://owasp.org/www-project-internet-of-things/",])
            .with_device_hint(hint),
        );
    } else if svc_type.contains("_smb._tcp") || svc_type.contains("_afpovertcp._tcp") {
        let finding = Finding::new(
            "mdns",
            &format!(
                "File sharing service: {display_name} on {ip}:{}",
                service.port
            ),
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
        .with_cwe("CWE-732")
        .with_device_hint(identity.hint(DeviceType::Unknown));
        findings.push(finding);
    } else if svc_type.contains("_airplay._tcp") || svc_type.contains("_raop._tcp") {
        let airplay_type = if display_name.contains("MacBook") || display_name.contains("macbook") {
            DeviceType::Laptop
        } else if display_name.contains("iMac")
            || display_name.contains("Mac Pro")
            || display_name.contains("Mac mini")
            || display_name.contains("Mac Studio")
        {
            DeviceType::Desktop
        } else {
            DeviceType::MediaPlayer
        };
        let hint = identity.hint(airplay_type);
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
            .with_service("AirPlay")
            .with_device_hint(hint),
        );
    } else if svc_type.contains("_googlecast._tcp") {
        let hint = identity.hint(DeviceType::MediaPlayer);
        findings.push(
            Finding::new(
                "mdns",
                &format!(
                    "Chromecast/Google Cast: {display_name} on {ip}:{}",
                    service.port
                ),
                &format!(
                    "{base_desc} Google Cast device allows media casting from \
                     any device on the network."
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("Google Cast")
            .with_device_hint(hint),
        );
    } else if svc_type.contains("_hap._tcp") {
        let hint = identity.hint(DeviceType::IoT);
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
            .with_cwe("CWE-287")
            .with_device_hint(hint),
        );
    } else if svc_type.contains("_matterd._udp") {
        findings.push(classify_matter_commissioner(service, &identity, &base_desc));
    } else if svc_type.contains("_matterc._udp") {
        findings.push(classify_matter_commissionable(
            service, &identity, &base_desc,
        ));
    } else if svc_type.contains("_matter._tcp") {
        findings.push(
            Finding::new(
                "mdns",
                &format!("Matter device: {display_name} on {ip}:{}", service.port),
                &format!(
                    "{base_desc} Operational Matter node. It is already commissioned \
                     onto a fabric; its advertisement discloses fabric and node \
                     identifiers but not credentials."
                ),
                Severity::Info,
            )
            .with_ip(ip)
            .with_port(service.port)
            .with_service("Matter")
            .with_device_hint(identity.hint(DeviceType::IoT)),
        );
    } else if svc_type.contains("_meshcop._udp") || svc_type.contains("_meshcop-e._udp") {
        findings.push(classify_thread_border_agent(service, &identity, &base_desc));
    } else {
        let finding = Finding::new(
            "mdns",
            &format!(
                "mDNS service: {display_name} ({svc_type}) on {ip}:{}",
                service.port
            ),
            &base_desc,
            Severity::Info,
        )
        .with_ip(ip)
        .with_port(service.port)
        .with_service("mDNS")
        .with_device_hint(identity.hint(DeviceType::Unknown));
        findings.push(finding);
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

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "mdns".to_owned(),
                message: e.to_string(),
            })?;

        let ssdp_results = discover_ssdp().await;
        tracing::info!(ssdp_count = ssdp_results.len(), "SSDP discovery complete");

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

        // One description fetch per (IP, LOCATION).
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
                if upnp_target_excluded(*ip, location, &exclusions) {
                    tracing::debug!(%ip, %location, "UPnP description fetch skipped: excluded");
                    continue;
                }
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

        match rikitikitavi_network::discover_services(MDNS_DISCOVERY_SECS).await {
            Ok(mdns_services) => {
                tracing::info!(mdns_count = mdns_services.len(), "mDNS discovery complete");
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
        // SSDP window + mDNS budget + UPnP description fetches in Active mode.
        SSDP_DEADLINE.as_secs() + MDNS_DISCOVERY_SECS + 6
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
    fn test_upnp_target_excluded() {
        let ex =
            ExclusionSet::parse(&["10.0.0.0/24".to_owned()], &["192.168.1.40".to_owned()]).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(upnp_target_excluded(
            ip("192.168.1.40"),
            "http://192.168.1.40:1900/d.xml",
            &ex
        ));
        assert!(upnp_target_excluded(
            ip("192.168.1.10"),
            "http://10.0.0.7:1900/d.xml",
            &ex
        ));
        assert!(upnp_target_excluded(ip("10.0.0.3"), "not-a-url", &ex));
        assert!(!upnp_target_excluded(
            ip("192.168.1.10"),
            "http://192.168.1.10:1900/d.xml",
            &ex
        ));
        assert!(!upnp_target_excluded(ip("192.168.1.10"), "not-a-url", &ex));
    }

    // ── SSDP response collection tests ───────────────────────────

    async fn loopback_pair() -> (UdpSocket, UdpSocket, SocketAddr) {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();
        (receiver, sender, dest)
    }

    #[tokio::test]
    async fn test_collect_ssdp_responses_capped() {
        let (receiver, sender, dest) = loopback_pair().await;
        for i in 0..12 {
            let msg = format!("HTTP/1.1 200 OK\r\nSERVER: dev/{i}\r\nST: upnp:rootdevice\r\n\r\n");
            sender.send_to(msg.as_bytes(), dest).await.unwrap();
        }
        let results =
            collect_ssdp_responses(&receiver, Instant::now() + Duration::from_secs(2), 8).await;
        assert_eq!(results.len(), 8);
        assert!(results.iter().all(|(ip, _)| ip.is_loopback()));
    }

    #[tokio::test]
    async fn test_collect_ssdp_responses_stops_at_deadline() {
        let (receiver, _sender, _dest) = loopback_pair().await;
        let start = Instant::now();
        let results =
            collect_ssdp_responses(&receiver, start + Duration::from_millis(200), 8).await;
        assert!(results.is_empty());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_collect_ssdp_responses_skips_unparseable() {
        let (receiver, sender, dest) = loopback_pair().await;
        sender.send_to(b"not an ssdp response", dest).await.unwrap();
        sender
            .send_to(b"HTTP/1.1 200 OK\r\nSERVER: dev/1\r\n\r\n", dest)
            .await
            .unwrap();
        let results =
            collect_ssdp_responses(&receiver, Instant::now() + Duration::from_millis(300), 8).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.server.as_deref(), Some("dev/1"));
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

    #[test]
    fn test_upnp_type_to_device_type() {
        assert_eq!(
            upnp_type_to_device_type("urn:schemas-upnp-org:device:InternetGatewayDevice:1"),
            DeviceType::Router
        );
        assert_eq!(
            upnp_type_to_device_type("urn:schemas-upnp-org:device:MediaRenderer:1"),
            DeviceType::MediaPlayer
        );
        assert_eq!(
            upnp_type_to_device_type("urn:schemas-upnp-org:device:Printer:1"),
            DeviceType::Printer
        );
        assert_eq!(
            upnp_type_to_device_type("urn:dial-multiscreen-org:service:dial:1"),
            DeviceType::Unknown
        );
    }

    #[test]
    fn test_upnp_finding_has_device_hint() {
        let ip: IpAddr = "192.168.1.220".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("rudiger".to_owned()),
            manufacturer: Some("Synology".to_owned()),
            model_name: Some("DS418play".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:MediaServer:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.220:5000/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("Synology"));
        assert_eq!(hint.model.as_deref(), Some("DS418play"));
        assert_eq!(hint.hostname.as_deref(), Some("rudiger"));
        // Synology manufactures NAS devices; their MediaServer UPnP role is
        // overridden by the manufacturer-based classification.
        assert_eq!(hint.device_type, Some(DeviceType::Nas));
    }

    /// `modelDescription` is prose, not a version — it must not become firmware.
    #[test]
    fn test_model_description_is_not_read_as_firmware() {
        let xml = "<root><device><friendlyName>rudiger</friendlyName>\
                   <modelDescription>Synology DiskStation</modelDescription></device></root>";
        let info = parse_upnp_device_xml(xml);
        assert_eq!(
            info.model_description.as_deref(),
            Some("Synology DiskStation")
        );
        assert!(info.firmware_version.is_none());
        let findings = classify_upnp_device(
            "192.168.1.220".parse().unwrap(),
            "http://192.168.1.220:5000/desc.xml",
            &info,
        );
        assert!(!findings[0].description.contains("Firmware:"));
    }

    /// HA's `wemo` matcher is keyed on the Belkin manufacturer alone, so it must
    /// not retype a device whose URN already said `InternetGatewayDevice`.
    #[test]
    fn test_vendor_only_ssdp_match_does_not_retype_a_gateway() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("Belkin Router".to_owned()),
            manufacturer: Some("Belkin International Inc.".to_owned()),
            model_name: Some("F9K1102".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.1/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Router));
        // The integration is still reported, just not as a device class.
        assert_eq!(hint.device_subtype.as_deref(), Some("wemo"));
    }

    /// With no URN to contradict, the vendor-only matcher still types the device.
    #[test]
    fn test_vendor_only_ssdp_match_types_an_otherwise_unknown_device() {
        let ip: IpAddr = "192.168.1.60".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("WeMo Switch".to_owned()),
            manufacturer: Some("Belkin International Inc.".to_owned()),
            model_name: Some("Socket".to_owned()),
            device_type: Some("urn:Belkin:device:controllee:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.60:49153/setup.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::SmartPlug));
    }

    /// A `modelDescription` matcher is specific, so it may retype.
    #[test]
    fn test_model_description_ssdp_match_may_retype() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("UDM Pro".to_owned()),
            manufacturer: Some("Ubiquiti Networks".to_owned()),
            model_description: Some("UniFi Dream Machine Pro".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.1/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_subtype.as_deref(), Some("unifi_discovery"));
        // `unifi_discovery` carries no `DeviceType`, so the URN's Router stands.
        assert_eq!(hint.device_type, Some(DeviceType::Router));
    }

    #[test]
    fn test_upnp_lg_tv_classified_as_smart_tv() {
        let ip: IpAddr = "192.168.2.11".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("[LG] webOS TV".to_owned()),
            manufacturer: Some("LG Electronics".to_owned()),
            model_name: Some("OLED55C7P".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.2.11/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::SmartTv));
    }

    #[test]
    fn test_manufacturer_override_preserves_generic() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("My Router".to_owned()),
            manufacturer: Some("Netgear".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.50/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Router));
    }

    #[test]
    fn test_signify_hue_bridge_classified_as_iot() {
        let ip: IpAddr = "192.168.1.169".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("Hue Bridge (192.168.1.169)".to_owned()),
            manufacturer: Some("Signify".to_owned()),
            model_name: Some("Philips hue bridge 2015".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:Basic:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.1.169/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::IoT));
        assert_eq!(hint.vendor.as_deref(), Some("Signify"));
    }

    #[test]
    fn test_android_tv_box_classified_as_smart_tv() {
        let ip: IpAddr = "192.168.2.18".parse().unwrap();
        let info = UpnpDeviceInfo {
            friendly_name: Some("4K Android TV Box".to_owned()),
            manufacturer: Some("SkyworthDigital".to_owned()),
            model_name: Some("4K Android TV Box".to_owned()),
            device_type: Some("urn:schemas-upnp-org:device:Basic:1".to_owned()),
            ..Default::default()
        };
        let findings = classify_upnp_device(ip, "http://192.168.2.18/desc.xml", &info);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::SmartTv));
    }

    #[test]
    fn test_airplay_macbook_classified_as_laptop() {
        let svc = MdnsService {
            name: "Kathryn's MacBook Pro".to_owned(),
            service_type: "_airplay._tcp.local".to_owned(),
            hostname: "Kathryns-MacBook-Pro.local".to_owned(),
            ip: "192.168.3.235".parse().unwrap(),
            port: 7000,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Laptop));
    }

    #[test]
    fn test_mdns_printer_has_device_hint() {
        let svc = MdnsService {
            name: "HP Color LaserJet".to_owned(),
            service_type: "_ipp._tcp.local".to_owned(),
            hostname: "printer.local".to_owned(),
            ip: "192.168.1.100".parse().unwrap(),
            port: 631,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.hostname.as_deref(), Some("printer.local"));
        assert_eq!(hint.device_type, Some(DeviceType::Printer));
    }

    #[test]
    fn test_mdns_airplay_has_device_hint() {
        let svc = MdnsService {
            name: "Denon AVR-X1800H".to_owned(),
            service_type: "_airplay._tcp.local".to_owned(),
            hostname: "denon.local".to_owned(),
            ip: "192.168.1.30".parse().unwrap(),
            port: 7000,
            txt_records: Vec::new(),
        };
        let findings = classify_mdns_service(&svc);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.hostname.as_deref(), Some("denon.local"));
        assert_eq!(hint.device_type, Some(DeviceType::MediaPlayer));
    }

    #[test]
    fn test_ssdp_gateway_has_device_hint() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let svc = SsdpService {
            location: Some("http://192.168.1.1:49152/desc.xml".to_owned()),
            server: Some("Linux UPnP/1.1 MiniUPnPd/2.2".to_owned()),
            service_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_owned()),
        };
        let finding = classify_ssdp_service(ip, &svc);
        let hint = finding.device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Router));
    }

    #[test]
    fn test_ssdp_generic_no_device_hint() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let svc = SsdpService {
            location: Some("http://192.168.1.50:8080/".to_owned()),
            server: Some("Chromecast/1.0".to_owned()),
            service_type: Some("urn:dial-multiscreen-org:service:dial:1".to_owned()),
        };
        let finding = classify_ssdp_service(ip, &svc);
        assert!(finding.device_hint.is_none());
    }

    // ── HA discovery tables and Matter/Thread ──────────────────────

    /// Build an `MdnsService` for classification tests.
    fn svc(name: &str, service_type: &str, port: u16, txt: &[&str]) -> MdnsService {
        MdnsService {
            name: name.to_owned(),
            service_type: service_type.to_owned(),
            hostname: "node.local".to_owned(),
            ip: "192.168.1.77".parse().unwrap(),
            port,
            txt_records: txt.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Fixture: a Shelly Plus 1PM `_http._tcp` announcement.
    #[test]
    fn shelly_http_announcement_is_typed_by_the_ha_table() {
        let service = svc(
            "shellyplus1pm-a8032abd1234",
            "_http._tcp.local",
            80,
            &["gen=2", "app=Plus1PM", "ver=1.4.4"],
        );
        let findings = classify_mdns_service(&service);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::SmartPlug));
        assert_eq!(hint.device_subtype.as_deref(), Some("shelly"));
    }

    /// A plain HTTP responder must not inherit Shelly's `_http._tcp` matcher.
    #[test]
    fn generic_http_announcement_gets_no_device_type() {
        let service = svc("officeprinter", "_http._tcp.local", 80, &[]);
        let findings = classify_mdns_service(&service);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, None);
        assert_eq!(hint.device_subtype, None);
    }

    /// `md` on a `_hap._tcp` accessory names the product; BSB002 is a Hue bridge.
    #[test]
    fn homekit_md_key_identifies_the_product() {
        let service = svc(
            "Hue Bridge",
            "_hap._tcp.local",
            8080,
            &["md=BSB002", "ci=2"],
        );
        let findings = classify_mdns_service(&service);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Hub));
        assert_eq!(
            hint.device_subtype.as_deref(),
            Some("homekit_controller/hue")
        );
        assert_eq!(hint.model.as_deref(), Some("BSB002"));
    }

    #[test]
    fn matter_closed_window_is_informational() {
        let service = svc(
            "ABCD1234",
            "_matterc._udp.local",
            5540,
            &["CM=0", "VP=65521+32769", "DT=266"],
        );
        let findings = classify_mdns_service(&service);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("Matter commissionable device"));
    }

    /// `CM != 0` is the test, not `CM in {1, 2}` — 3 (joint fabric) exists.
    #[test]
    fn matter_open_window_is_reported_for_every_non_zero_mode() {
        for mode in ["1", "2", "3"] {
            let service = svc(
                "ABCD1234",
                "_matterc._udp.local",
                5540,
                &[&format!("CM={mode}"), "D=3840"],
            );
            let findings = classify_mdns_service(&service);
            assert_eq!(findings[0].severity, Severity::Low, "CM={mode}");
            assert!(
                findings[0]
                    .title
                    .contains("Matter commissioning window open"),
                "CM={mode}"
            );
            assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-287"));
        }
    }

    /// Wording must not claim an open window is an unauthenticated join.
    #[test]
    fn matter_open_window_wording_names_the_passcode_requirement() {
        let service = svc("ABCD1234", "_matterc._udp.local", 5540, &["CM=1"]);
        let findings = classify_mdns_service(&service);
        let desc = &findings[0].description;
        assert!(desc.contains("PASE"), "{desc}");
        assert!(desc.contains("setup passcode"), "{desc}");
    }

    /// `_matterd._udp` is commissioner discovery: it carries no `CM` key, so the
    /// finding must not report a commissioning window either way.
    #[test]
    fn matter_commissioner_is_not_described_as_commissionable() {
        let service = svc(
            "ABCD1234",
            "_matterd._udp.local",
            5540,
            &["VP=65521+32769", "DT=22", "DN=Home Hub"],
        );
        let findings = classify_mdns_service(&service);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("Matter commissioner"));
        let desc = &findings[0].description;
        assert!(!desc.contains("CM=0"), "{desc}");
        assert!(desc.contains("Home Hub"), "{desc}");
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Hub));
    }

    /// An absent `CM` is not `CM=0`; the wording must not invent the key.
    #[test]
    fn matter_commissionable_without_cm_does_not_claim_a_value() {
        let service = svc("ABCD1234", "_matterc._udp.local", 5540, &["D=3840"]);
        let findings = classify_mdns_service(&service);
        assert_eq!(findings[0].severity, Severity::Info);
        let desc = &findings[0].description;
        assert!(!desc.contains("CM=0"), "{desc}");
        assert!(desc.contains("no CM key"), "{desc}");
    }

    /// Fixture: an `ot-br-posix` border agent, binary TXT values hex-rendered.
    #[test]
    fn thread_border_agent_reports_network_identity() {
        let service = svc(
            "OpenThread BorderRouter",
            "_meshcop._udp.local",
            49191,
            &[
                "rv=1",
                "tv=1.3.0",
                "nn=HomeThread",
                "xp=0xdead00beef00cafe",
                "sb=0x00000131",
                "omr=0xfd11223300000000",
            ],
        );
        let findings = classify_mdns_service(&service);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("Thread border router"));
        let desc = &findings[0].description;
        assert!(desc.contains("HomeThread"), "{desc}");
        assert!(desc.contains("0xdead00beef00cafe"), "{desc}");
        assert!(desc.contains("0x00000131"), "{desc}");
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Hub));
    }

    /// The `sb` bits carry the commissioning posture; reporting the hex alone
    /// leaves the reader an opaque number.
    #[test]
    fn thread_state_bitmap_is_decoded_into_the_finding() {
        // Live value: PSKc connection mode, interface active, ePSKc supported.
        let open = svc(
            "OpenThread BorderRouter",
            "_meshcop._udp.local",
            49191,
            &["nn=HomeThread", "sb=0x00000fb1"],
        );
        let desc = classify_mdns_service(&open)[0].description.clone();
        assert!(desc.contains("active on a mesh"), "{desc}");
        assert!(desc.contains("PSKc"), "{desc}");
        assert!(desc.contains("could open a session"), "{desc}");
        assert!(desc.contains("ephemeral-key commissioning"), "{desc}");

        // Connection mode 0: nothing may connect, so no open-path sentence.
        let closed = svc(
            "OpenThread BorderRouter",
            "_meshcop._udp.local",
            49191,
            &["nn=HomeThread", "sb=0x00000010"],
        );
        let desc = classify_mdns_service(&closed)[0].description.clone();
        assert!(
            desc.contains("no commissioner connection allowed"),
            "{desc}"
        );
        assert!(!desc.contains("could open a session"), "{desc}");
    }

    /// An unparseable `sb` is still printed raw, with no decoded claims.
    #[test]
    fn thread_undecodable_state_bitmap_makes_no_claims() {
        let service = svc(
            "OpenThread BorderRouter",
            "_meshcop._udp.local",
            49191,
            &["nn=HomeThread", "sb=notahexvalue"],
        );
        let desc = classify_mdns_service(&service)[0].description.clone();
        assert!(desc.contains("notahexvalue"), "{desc}");
        assert!(!desc.contains("state bitmap decodes"), "{desc}");
    }

    /// `_meshcop-e` is published with an empty TXT record.
    #[test]
    fn thread_ephemeral_key_service_needs_no_txt() {
        let service = svc(
            "OpenThread BorderRouter",
            "_meshcop-e._udp.local",
            49192,
            &[],
        );
        let findings = classify_mdns_service(&service);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("ephemeral-key"));
    }

    #[test]
    fn operational_matter_node_is_informational() {
        let service = svc("1234ABCD-0000000000000001", "_matter._tcp.local", 5540, &[]);
        let findings = classify_mdns_service(&service);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("Matter device"));
    }

    /// `_axis-video` announcements are separated by the `macaddress` TXT key.
    #[test]
    fn axis_video_service_is_typed_from_txt() {
        let service = svc(
            "cam",
            "_axis-video._tcp.local",
            80,
            &["macaddress=1CCAE3AABBCC"],
        );
        let findings = classify_mdns_service(&service);
        let hint = findings[0].device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Doorbell));
        assert_eq!(hint.device_subtype.as_deref(), Some("doorbird"));
    }

    /// The `st`-only half of HA's SSDP table fires without a description fetch.
    #[test]
    fn ssdp_zoneplayer_st_types_a_speaker() {
        let service = SsdpService {
            location: Some("http://192.168.1.31:1400/xml/device_description.xml".to_owned()),
            server: Some("Linux UPnP/1.0 Sonos/84.1-59230".to_owned()),
            service_type: Some("urn:schemas-upnp-org:device:ZonePlayer:1".to_owned()),
        };
        let finding = classify_ssdp_service("192.168.1.31".parse().unwrap(), &service);
        let hint = finding.device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::Speaker));
        assert_eq!(hint.device_subtype.as_deref(), Some("sonos"));
    }

    proptest! {
        #[test]
        fn prop_classify_mdns_service_no_panic(
            name in ".*",
            service_type in ".*",
            port in any::<u16>(),
            txt in proptest::collection::vec(".*", 0..6),
        ) {
            let refs: Vec<&str> = txt.iter().map(String::as_str).collect();
            let _ = classify_mdns_service(&svc(&name, &service_type, port, &refs));
        }

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
