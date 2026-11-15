//! Markdown network-segmentation proposal: zones, evidence, inter-zone allow rules.

use crate::fix_plan::escape_md;
use rikitikitavi_core::Severity;
use rikitikitavi_models::device::PortProtocol;
use rikitikitavi_models::{Device, DeviceType, Finding, ScanResults};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

const HA_MATTER: &str = "https://www.home-assistant.io/integrations/matter/";
const HA_DENON: &str = "https://www.home-assistant.io/integrations/denonavr/";
const UNIFI_MDNS: &str =
    "https://help.ui.com/hc/en-us/articles/12648701398807-UniFi-Gateway-Multicast-DNS-mDNS-Proxy";
const UNIFI_ISOLATION: &str = "https://help.ui.com/hc/en-us/articles/18965560820247-Implementing-Network-and-Client-Isolation-in-UniFi";

const MITIGATED_CWES: &[&str] = &[
    "CWE-200", "CWE-284", "CWE-287", "CWE-306", "CWE-319", "CWE-521", "CWE-798", "CWE-1104",
    "CWE-1188", "CWE-1392", "CWE-1395",
];
const MITIGATED_WORDS: &[&str] = &[
    "unauthenticated",
    "without auth",
    "cleartext",
    "unencrypted",
    "admin panel",
    "admin page",
];
const CAST_PORTS: &[u16] = &[1400, 3689, 4070, 7000, 8008, 8009];
const PRINT_PORTS: &[u16] = &[515, 631, 9100];
const FILE_PORTS: &[u16] = &[139, 445, 548, 873, 2049];
const CONTROL_PORTS: &[u16] = &[1883, 6668, 9999];
const LOGIN_PORTS: &[u16] = &[22, 3389, 5900];

/// Proposed network zone; declaration order is output order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Zone {
    Trusted,
    IoT,
    Infrastructure,
    Unassigned,
}

impl Zone {
    pub const ALL: [Self; 4] = [
        Self::Trusted,
        Self::IoT,
        Self::Infrastructure,
        Self::Unassigned,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::IoT => "IoT",
            Self::Infrastructure => "Infrastructure",
            Self::Unassigned => "Unassigned",
        }
    }
}

const fn type_zone(t: DeviceType) -> (Zone, &'static str) {
    match t {
        DeviceType::Desktop | DeviceType::Laptop | DeviceType::Phone | DeviceType::Tablet => {
            (Zone::Trusted, "personal device")
        }
        DeviceType::Router => (Zone::Infrastructure, "routes between the zones"),
        DeviceType::Switch | DeviceType::AccessPoint => (
            Zone::Infrastructure,
            "network gear; management reachable only from an admin host",
        ),
        DeviceType::Server => (
            Zone::Infrastructure,
            "shared service reached from Trusted, kept apart from personal devices",
        ),
        DeviceType::Nas => (
            Zone::Infrastructure,
            "shared storage reached from Trusted, kept out of IoT",
        ),
        DeviceType::Printer => (
            Zone::Infrastructure,
            "shared by Trusted devices; print channels are unauthenticated, so not in Trusted",
        ),
        DeviceType::Nvr => (
            Zone::IoT,
            "recorder kept with the cameras it records, so no IoT to Infrastructure rule is needed",
        ),
        DeviceType::Hub => (
            Zone::IoT,
            "holds other devices' credentials; reachable only from its controller",
        ),
        DeviceType::SmartTv | DeviceType::MediaPlayer | DeviceType::Speaker => (
            Zone::IoT,
            "casting target; the mDNS proxy keeps discovery working from Trusted",
        ),
        DeviceType::GameConsole => (
            Zone::IoT,
            "needs the Internet and casting, not access to personal devices",
        ),
        DeviceType::Printer3d => (
            Zone::IoT,
            "controlled from a computer; reachable only from that controller",
        ),
        DeviceType::Camera
        | DeviceType::Doorbell
        | DeviceType::IoT
        | DeviceType::SmartLock
        | DeviceType::Thermostat
        | DeviceType::EvCharger
        | DeviceType::Inverter
        | DeviceType::Vacuum
        | DeviceType::SmartPlug
        | DeviceType::Appliance
        | DeviceType::Sensor => (
            Zone::IoT,
            "smart-home device controlled by an app, hub or cloud",
        ),
        DeviceType::Unknown => (Zone::Unassigned, "type not identified"),
    }
}

fn has_port(d: &Device, set: &[u16]) -> bool {
    d.open_ports.iter().any(|p| set.contains(&p.port))
}

fn unassigned_hints(d: &Device) -> Vec<&'static str> {
    let mut hints = Vec::new();
    if has_port(d, PRINT_PORTS) {
        hints.push("print ports open: may be a printer (Infrastructure)");
    }
    if has_port(d, CONTROL_PORTS) {
        hints.push("IoT control port open (IoT)");
    }
    if has_port(d, FILE_PORTS) {
        hints.push("file-sharing ports open: may be a NAS or computer");
    }
    if has_port(d, CAST_PORTS) {
        hints.push("casting port open: may be a media device (IoT)");
    }
    if has_port(d, LOGIN_PORTS) {
        hints.push("remote-login ports open: likely a computer (Trusted or Infrastructure)");
    }
    let vendor = d.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
    if ["espressif", "tuya", "shelly", "signify"]
        .iter()
        .any(|v| vendor.starts_with(v))
    {
        hints.push("vendor mainly builds IoT modules (IoT)");
    }
    hints
}

/// `_name._tcp` / `_name._udp` after each "of type " in `text`, lowercased.
fn service_types(text: &str) -> Vec<String> {
    text.match_indices("of type ")
        .filter_map(|(i, m)| {
            let rest = &text[i + m.len()..];
            let tok: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .collect();
            normalize_service(&tok)
        })
        .collect()
}

fn normalize_service(tok: &str) -> Option<String> {
    let tok = tok.to_ascii_lowercase();
    let tok = tok.trim_end_matches('.');
    let tok = tok.strip_suffix(".local").unwrap_or(tok);
    let (name, proto) = tok.split_once('.')?;
    let label = name.strip_prefix('_')?;
    let ok = (1..=15).contains(&label.len())
        && label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && matches!(proto, "_tcp" | "_udp");
    ok.then(|| format!("{name}.{proto}"))
}

fn matter_role(d: &Device, findings: &[&Finding]) -> Option<&'static str> {
    let types: Vec<String> = findings
        .iter()
        .flat_map(|f| service_types(&f.description))
        .collect();
    let subtype = d.device_subtype.as_deref().unwrap_or("");
    if subtype.eq_ignore_ascii_case("thread")
        || types.iter().any(|t| t == "_meshcop._udp")
        || findings
            .iter()
            .any(|f| f.title.starts_with("Thread border router"))
    {
        Some("Thread border router")
    } else if subtype.eq_ignore_ascii_case("matter")
        || types.iter().any(|t| t == "_matter._tcp")
        || findings
            .iter()
            .any(|f| f.title.starts_with("Matter device"))
    {
        Some("Matter device")
    } else {
        None
    }
}

/// Zone and the reason shown to the owner.
#[must_use]
pub fn zone_for(device: &Device, findings: &[&Finding]) -> (Zone, String) {
    let (zone, base) = type_zone(device.device_type);
    let mut reason = format!("{}: {base}", device.device_type.label());
    if zone == Zone::Unassigned {
        for h in unassigned_hints(device) {
            let _ = write!(reason, "; {h}");
        }
    }
    if let Some(role) = matter_role(device, findings) {
        let _ = write!(
            reason,
            "; {role}: keep it on the same network as its Matter controller (see Constraints)"
        );
    }
    (zone, reason)
}

fn mitigated(f: &Finding) -> bool {
    if f.severity < Severity::Medium {
        return false;
    }
    let title = f.title.to_ascii_lowercase();
    f.cwe_id
        .as_deref()
        .is_some_and(|c| MITIGATED_CWES.contains(&c))
        || MITIGATED_WORDS.iter().any(|w| title.contains(w))
}

fn unauth_control(f: &Finding) -> bool {
    let title = f.title.to_ascii_lowercase();
    f.severity >= Severity::Medium
        && title.contains("control")
        && (title.contains("unauthenticated") || title.contains("without auth"))
}

struct Placed<'a> {
    device: &'a Device,
    zone: Zone,
    reason: String,
    findings: Vec<&'a Finding>,
    unauth: bool,
}

impl Placed<'_> {
    fn label(&self) -> String {
        self.device
            .hostname
            .as_deref()
            .filter(|h| !h.trim().is_empty())
            .map_or_else(|| self.device.ip.to_string(), escape_md)
    }

    fn heading(&self) -> String {
        let label = self.label();
        if label == self.device.ip.to_string() {
            format!("`{label}`")
        } else {
            format!("{label} (`{}`)", self.device.ip)
        }
    }

    /// Medium+ findings segmentation mitigates; severity desc, then title, deduplicated.
    fn evidence(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self
            .findings
            .iter()
            .copied()
            .filter(|f| mitigated(f))
            .collect();
        v.sort_by(|a, b| {
            (unauth_control(b), b.severity, &a.title).cmp(&(
                unauth_control(a),
                a.severity,
                &b.title,
            ))
        });
        let mut seen = HashSet::new();
        v.retain(|f| seen.insert(f.title.as_str()));
        v
    }

    fn ports(&self) -> Vec<(PortProtocol, u16, String)> {
        let mut out: BTreeMap<(u8, u16), String> = BTreeMap::new();
        for p in &self.device.open_ports {
            let proto = u8::from(p.protocol == PortProtocol::Udp);
            out.entry((proto, p.port)).or_insert_with(|| {
                p.service
                    .as_deref()
                    .filter(|s| !s.trim().is_empty() && *s != "Unknown")
                    .map_or_else(|| "unknown".to_owned(), escape_md)
            });
        }
        out.into_iter()
            .map(|((proto, port), svc)| {
                let proto = if proto == 1 {
                    PortProtocol::Udp
                } else {
                    PortProtocol::Tcp
                };
                (proto, port, svc)
            })
            .collect()
    }
}

fn place(results: &ScanResults) -> Vec<Placed<'_>> {
    let mut by_ip: BTreeMap<IpAddr, Vec<&Finding>> = BTreeMap::new();
    for f in &results.findings {
        if let Some(ip) = f.affected_ip {
            by_ip.entry(ip).or_default().push(f);
        }
    }
    let mut seen = HashSet::new();
    let mut placed: Vec<Placed<'_>> = results
        .devices
        .iter()
        .filter(|d| seen.insert(d.ip))
        .map(|d| {
            let findings = by_ip.remove(&d.ip).unwrap_or_default();
            let (zone, reason) = zone_for(d, &findings);
            let unauth = findings.iter().any(|f| unauth_control(f));
            Placed {
                device: d,
                zone,
                reason,
                findings,
                unauth,
            }
        })
        .collect();
    placed.sort_by_key(|p| (p.zone, !p.unauth, p.device.ip));
    placed
}

const fn proto_name(p: PortProtocol) -> &'static str {
    match p {
        PortProtocol::Tcp => "TCP",
        PortProtocol::Udp => "UDP",
    }
}

const CONTROLLER: &str = "Controller host(s) in Trusted";
const ADMIN: &str = "Admin host(s) in Trusted";
const ANY_TRUSTED: &str = "Trusted";

/// (source, reason) for traffic to an observed open port, or `None` for no rule.
fn rule_source(p: &Placed<'_>, port: u16) -> Option<(&'static str, &'static str)> {
    match (p.zone, p.device.device_type) {
        (Zone::IoT, _) if CAST_PORTS.contains(&port) => Some((
            ANY_TRUSTED,
            "casting or streaming from phones and computers",
        )),
        (Zone::IoT, _) => Some((CONTROLLER, "device control or app access")),
        (Zone::Infrastructure, DeviceType::Printer) if PRINT_PORTS.contains(&port) => {
            Some((ANY_TRUSTED, "printing"))
        }
        (Zone::Infrastructure, DeviceType::Nas | DeviceType::Server)
            if FILE_PORTS.contains(&port) =>
        {
            Some((ANY_TRUSTED, "file sharing"))
        }
        (Zone::Infrastructure, DeviceType::Router) if port == 53 => {
            Some(("All zones", "DNS from the gateway"))
        }
        (Zone::Infrastructure, _) => Some((ADMIN, "management")),
        (Zone::Trusted | Zone::Unassigned, _) => None,
    }
}

fn write_rules(out: &mut String, placed: &[Placed<'_>]) {
    out.push_str("## Allow rules\n\n");
    out.push_str(
        "Everything between zones is denied unless a row below allows it. Replies to an \
         allowed connection are permitted. Each device row is a port observed open in this \
         scan; delete the rows for services you do not use.\n\n",
    );
    out.push_str("### Between zones\n\n| From | To | Action |\n| --- | --- | --- |\n");
    for (from, to, action) in [
        ("Trusted", "Internet", "Allow"),
        ("IoT", "Internet", "Allow"),
        ("Infrastructure", "Internet", "Allow (firmware updates)"),
        ("IoT", "Trusted", "Deny new connections"),
        (
            "IoT",
            "Infrastructure",
            "Deny new connections, except DNS and DHCP from the gateway",
        ),
        ("Any other pair", "Any", "Deny"),
    ] {
        let _ = writeln!(out, "| {from} | {to} | {action} |");
    }
    out.push('\n');

    let mut rows = Vec::new();
    for p in placed {
        for (proto, port, svc) in p.ports() {
            if let Some((from, why)) = rule_source(p, port) {
                let unauth = p
                    .findings
                    .iter()
                    .any(|f| f.affected_port == Some(port) && unauth_control(f));
                let note = if unauth {
                    "; accepts unauthenticated control"
                } else {
                    ""
                };
                rows.push(format!(
                    "| {from} | {} | {} {port} | {svc} | {why}; observed open in this scan{note} |",
                    p.heading(),
                    proto_name(proto)
                ));
            }
        }
    }
    out.push_str("### To devices\n\n");
    if rows.is_empty() {
        out.push_str("No open ports were observed on IoT or Infrastructure devices.\n\n");
        return;
    }
    out.push_str("| From | To | Port | Service | Why |\n| --- | --- | --- | --- | --- |\n");
    for r in rows {
        out.push_str(&r);
        out.push('\n');
    }
    out.push('\n');
}

fn write_mdns(out: &mut String, placed: &[Placed<'_>]) {
    let mut map: BTreeMap<String, BTreeSet<(Zone, IpAddr)>> = BTreeMap::new();
    let mut labels: BTreeMap<IpAddr, String> = BTreeMap::new();
    for p in placed
        .iter()
        .filter(|p| matches!(p.zone, Zone::IoT | Zone::Infrastructure))
    {
        for f in &p.findings {
            for t in service_types(&f.description) {
                map.entry(t).or_default().insert((p.zone, p.device.ip));
                labels.insert(p.device.ip, p.heading());
            }
        }
    }
    out.push_str("## mDNS proxy allow-list\n\n");
    if map.is_empty() {
        out.push_str(
            "No mDNS services were seen from IoT or Infrastructure devices. If casting or \
             printing across zones stops working, re-scan and check this list again.\n\n",
        );
        return;
    }
    out.push_str(
        "Service types advertised by IoT and Infrastructure devices in this scan. Repeat only \
         these into Trusted so casting, AirPlay and printer discovery keep working across \
         zones.\n\n| Service type | Advertised by |\n| --- | --- |\n",
    );
    for (t, devs) in map {
        let who: Vec<String> = devs
            .iter()
            .map(|(z, ip)| format!("{} ({})", labels[ip], z.label()))
            .collect();
        let _ = writeln!(out, "| `{t}` | {} |", who.join(", "));
    }
    out.push('\n');
}

fn is_unifi(d: &Device) -> bool {
    d.vendor
        .as_deref()
        .is_some_and(|v| v.to_ascii_lowercase().contains("ubiquiti"))
        || d.device_subtype
            .as_deref()
            .is_some_and(|s| s.to_ascii_lowercase().contains("unifi"))
}

fn is_denon(p: &Placed<'_>) -> bool {
    let vendor = p
        .device
        .vendor
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    vendor.starts_with("d&m")
        || vendor.contains("denon")
        || vendor.contains("marantz")
        || p.findings.iter().any(|f| f.title.contains("Denon/Marantz"))
}

fn write_constraints(out: &mut String, placed: &[Placed<'_>], unifi: bool) {
    out.push_str("## Constraints\n\n");
    let matter: Vec<String> = placed
        .iter()
        .filter_map(|p| {
            matter_role(p.device, &p.findings)
                .map(|r| format!("{} ({r}, proposed {})", p.heading(), p.zone.label()))
        })
        .collect();
    let _ = writeln!(
        out,
        "- **Matter and Thread.** Home Assistant: \"Make sure that Matter devices that use \
         Wi-Fi (including Thread border router) are on the same VLANs/VLAN as Home \
         Assistant\", and Matter \"relies on (local) IPv6 and mDNS (multicast traffic) \
         traveling freely in your network\". Put your Matter controller in the same zone as \
         these devices, or keep them with it. <{HA_MATTER}>"
    );
    if matter.is_empty() {
        out.push_str("  - None seen in this scan.\n");
    } else {
        for m in matter {
            let _ = writeln!(out, "  - {m}");
        }
    }
    if unifi {
        let _ = writeln!(
            out,
            "- **mDNS proxy.** The gateway repeats discovery between networks. The number of \
             networks that can use mDNS proxy depends on the gateway model; check the limit \
             for yours before splitting into more networks. <{UNIFI_MDNS}>"
        );
    } else {
        let _ = writeln!(
            out,
            "- **mDNS proxy.** Discovery does not cross zones on its own; the router needs an \
             mDNS reflector or proxy, limited to the service types listed above. Routers \
             differ in how many networks it can serve. UniFi's description for reference: \
             <{UNIFI_MDNS}>"
        );
    }
    if placed.iter().any(|p| {
        matches!(
            p.device.device_type,
            DeviceType::Camera | DeviceType::Doorbell
        )
    }) {
        out.push_str(
            "- **Cameras and recorders.** A camera recorded by an NVR or console in another \
             zone needs an allow rule from the camera to that recorder. The scan cannot see \
             which recorder each camera uses.\n",
        );
    }
    let denon: Vec<String> = placed
        .iter()
        .filter(|p| is_denon(p))
        .map(Placed::heading)
        .collect();
    if !denon.is_empty() {
        let _ = writeln!(
            out,
            "- **Denon/Marantz receivers** ({}). Home Assistant: telnet control \"is limited \
             to a single connection\", and across VLANs it needs TCP 23, 8080 and 60006 on \
             the receiver. Allow these from one controller only. <{HA_DENON}>",
            denon.join(", ")
        );
    }
    out.push_str(
        "- **Vendor ports.** Device ports in the rule table are the ones observed open in \
         this scan, not vendor requirements.\n\n",
    );
}

fn write_how(out: &mut String, unifi: bool) {
    if unifi {
        let _ = writeln!(
            out,
            "## On UniFi\n\nThe gateway looks like a UniFi device. Create one network per \
             zone, turn on isolation for the IoT network, add the allow rules above, and \
             enable mDNS proxy for the service types listed. Isolation: <{UNIFI_ISOLATION}>. \
             mDNS proxy: <{UNIFI_MDNS}>.\n"
        );
    } else {
        out.push_str(
            "## On your router\n\nIf the router supports VLANs or several isolated networks, \
             create one per zone, deny traffic between them by default, then add the allow \
             rules above. A guest network can stand in for the IoT zone only if it lets you \
             add the controller exceptions.\n\n",
        );
    }
}

fn write_device(out: &mut String, p: &Placed<'_>) {
    let _ = write!(out, "- **{}**", p.heading());
    if let Some(v) = p.device.vendor.as_deref().filter(|v| !v.trim().is_empty()) {
        let _ = write!(out, ", {}", escape_md(v));
    }
    let _ = writeln!(out, ": {}", escape_md(&p.reason));
    if p.zone == Zone::Unassigned {
        let ports: Vec<String> = p
            .ports()
            .into_iter()
            .map(|(proto, port, svc)| format!("{} {port} ({svc})", proto_name(proto)))
            .collect();
        if !ports.is_empty() {
            let _ = writeln!(out, "  - Open ports: {}", ports.join(", "));
        }
        return;
    }
    if p.zone == Zone::Trusted {
        return;
    }
    let ev = p.evidence();
    if !ev.is_empty() {
        out.push_str("  - Segmentation limits who can reach:\n");
        for f in ev {
            let _ = writeln!(out, "    - {} ({})", escape_md(&f.title), f.severity);
        }
    }
}

fn write_zones(out: &mut String, placed: &[Placed<'_>]) {
    for zone in Zone::ALL {
        let members: Vec<&Placed<'_>> = placed.iter().filter(|p| p.zone == zone).collect();
        let _ = writeln!(out, "## {} ({})\n", zone.label(), members.len());
        if zone == Zone::Unassigned && !members.is_empty() {
            out.push_str("Place these yourself; what the scan knows is listed.\n\n");
        }
        if members.is_empty() {
            out.push_str("None.\n\n");
            continue;
        }
        for p in members {
            write_device(out, p);
        }
        out.push('\n');
    }
}

/// Render the plan. `generated` becomes one line under the title; everything else depends
/// only on the devices and findings.
#[must_use]
pub fn render_segment_plan(results: &ScanResults, generated: Option<&str>) -> String {
    let mut out = String::from("# Segmentation plan\n\n");
    if let Some(line) = generated {
        let _ = writeln!(out, "{}\n", escape_md(line));
    }
    out.push_str(
        "A proposal only: this tool does not contact or configure any device. Each device \
         shows why it was placed where it is; move it if you disagree.\n\n",
    );
    let placed = place(results);
    out.push_str("| Zone | Devices |\n| --- | --- |\n");
    for zone in Zone::ALL {
        let n = placed.iter().filter(|p| p.zone == zone).count();
        let _ = writeln!(out, "| {} | {n} |", zone.label());
    }
    out.push('\n');

    let unauth: Vec<&Placed<'_>> = placed.iter().filter(|p| p.unauth).collect();
    if !unauth.is_empty() {
        out.push_str(
            "## Start here\n\nThese devices accept unauthenticated local control; anyone on \
             their network can operate them.\n\n",
        );
        let mut sorted = unauth;
        sorted.sort_by_key(|p| p.device.ip);
        for p in sorted {
            let _ = writeln!(out, "- {} (proposed {})", p.heading(), p.zone.label());
        }
        out.push('\n');
    }

    write_zones(&mut out, &placed);
    write_rules(&mut out, &placed);
    write_mdns(&mut out, &placed);
    let unifi = placed
        .iter()
        .any(|p| p.device.device_type == DeviceType::Router && is_unifi(p.device));
    write_constraints(&mut out, &placed, unifi);
    write_how(&mut out, unifi);
    out.push_str(
        "## Limits\n\n- Built from one scan; devices that were offline then are missing.\n\
         - Moving a device to another zone changes its IP address. Re-scan afterwards and run \
         `rikitikitavi verify`.\n",
    );
    out
}

/// Write the plan with owner-only permissions.
pub fn export_segment_plan(
    results: &ScanResults,
    generated: Option<&str>,
    path: &Path,
) -> anyhow::Result<()> {
    rikitikitavi_core::fs::write_private(path, render_segment_plan(results, generated).as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::device::OpenPort;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn dev(
        addr: &str,
        t: DeviceType,
        host: Option<&str>,
        vendor: Option<&str>,
        ports: &[(u16, &str)],
    ) -> Device {
        let mut d = Device::new(ip(addr)).with_device_type(t);
        d.hostname = host.map(str::to_owned);
        d.vendor = vendor.map(str::to_owned);
        d.open_ports = ports
            .iter()
            .map(|&(port, svc)| OpenPort {
                port,
                protocol: PortProtocol::Tcp,
                service: Some(svc.to_owned()),
                version: None,
                banner: None,
            })
            .collect();
        d
    }

    fn mdns(addr: &str, name: &str, stype: &str, port: u16) -> Finding {
        Finding::new(
            "mdns",
            &format!("mDNS service: {name} ({stype}.local) on {addr}:{port}"),
            &format!("mDNS service '{name}' of type {stype}.local on {addr}:{port}."),
            Severity::Info,
        )
        .with_ip(ip(addr))
        .with_port(port)
    }

    fn finding(scanner: &str, title: &str, sev: Severity, addr: &str, port: u16) -> Finding {
        Finding::new(scanner, title, "d", sev)
            .with_ip(ip(addr))
            .with_port(port)
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> ScanResults {
        let devices = vec![
            dev(
                "192.168.1.1",
                DeviceType::Router,
                Some("unifi"),
                Some("Ubiquiti Inc"),
                &[(22, "SSH"), (53, "DNS"), (443, "HTTPS")],
            ),
            dev(
                "192.168.1.10",
                DeviceType::Laptop,
                Some("laptop"),
                Some("Apple"),
                &[(22, "SSH")],
            ),
            dev(
                "192.168.1.2",
                DeviceType::Printer,
                Some("printer"),
                Some("HP"),
                &[(80, "HTTP"), (631, "IPP"), (9100, "RAW-Printing")],
            ),
            dev(
                "192.168.1.20",
                DeviceType::Nas,
                Some("nas"),
                Some("Synology"),
                &[(445, "SMB"), (5001, "DSM-HTTPS")],
            ),
            dev(
                "192.168.1.50",
                DeviceType::IoT,
                Some("plug|1"),
                Some("TP-Link"),
                &[(9999, "Kasa")],
            ),
            dev(
                "192.168.1.34",
                DeviceType::Speaker,
                Some("Denon AVR"),
                Some("D&M Holdings"),
                &[(23, "Telnet"), (7000, "AirPlay"), (8080, "HTTP-Proxy")],
            ),
            dev(
                "192.168.1.169",
                DeviceType::IoT,
                None,
                Some("Signify"),
                &[(80, "HTTP"), (443, "HTTPS")],
            ),
            dev(
                "192.168.3.26",
                DeviceType::MediaPlayer,
                Some("Apple TV"),
                Some("Apple"),
                &[(7000, "AirPlay")],
            ),
            dev(
                "192.168.1.77",
                DeviceType::Camera,
                Some("cam"),
                Some("Ring"),
                &[],
            ),
            dev(
                "192.168.2.31",
                DeviceType::Unknown,
                Some("box_*x*"),
                Some("Cable Matters"),
                &[(22, "SSH"), (5900, "VNC")],
            ),
        ];
        let findings = vec![
            finding(
                "kasa",
                "TP-Link Kasa device accepts unauthenticated local control on 192.168.1.50:9999",
                Severity::High,
                "192.168.1.50",
                9999,
            )
            .with_cwe("CWE-306"),
            finding(
                "credentials",
                "Denon/Marantz receiver control port open without authentication on 192.168.1.34:23",
                Severity::Medium,
                "192.168.1.34",
                23,
            )
            .with_cwe("CWE-306"),
            finding(
                "ssl",
                "Excessive certificate validity on 192.168.1.34:443",
                Severity::Medium,
                "192.168.1.34",
                443,
            )
            .with_cwe("CWE-324"),
            finding(
                "printers",
                "Raw printing (JetDirect/PJL) port open — unauthenticated print/control channel on 192.168.1.2:9100",
                Severity::Medium,
                "192.168.1.2",
                9100,
            )
            .with_cwe("CWE-306"),
            finding(
                "credentials",
                "Web admin panel without auth on 192.168.1.169:80",
                Severity::Medium,
                "192.168.1.169",
                80,
            ),
            finding(
                "credentials",
                "SMB/CIFS exposed on 192.168.1.20:445",
                Severity::Medium,
                "192.168.1.20",
                445,
            )
            .with_cwe("CWE-287"),
            Finding::new(
                "mdns",
                "Thread border router: Entertainment Room on 192.168.3.26:49153",
                "mDNS service 'Entertainment Room' of type _meshcop._udp.local on 192.168.3.26:49153.",
                Severity::Low,
            )
            .with_ip(ip("192.168.3.26")),
            mdns("192.168.3.26", "Apple TV", "_airplay._tcp", 7000),
            mdns("192.168.1.34", "Denon", "_raop._tcp", 7000),
            mdns("192.168.1.169", "Hue Bridge", "_hue._tcp", 443),
            mdns("192.168.1.2", "HP", "_ipp._tcp", 631),
            mdns("192.168.1.10", "laptop", "_ssh._tcp", 22),
        ];
        ScanResults {
            devices,
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn golden() {
        let rendered = render_segment_plan(&fixture(), None);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/segment_plan/golden.md");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &rendered).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap();
        assert_eq!(rendered, expected, "set UPDATE_GOLDEN=1 to regenerate");
    }

    #[test]
    fn output_is_independent_of_input_order() {
        let a = fixture();
        let mut b = fixture();
        b.devices.reverse();
        b.findings.reverse();
        assert_eq!(render_segment_plan(&a, None), render_segment_plan(&b, None));
    }

    #[test]
    fn every_device_type_has_a_zone() {
        for t in DeviceType::ALL {
            let (zone, reason) = zone_for(&Device::new(ip("10.0.0.1")).with_device_type(t), &[]);
            let expected = match t {
                DeviceType::Desktop
                | DeviceType::Laptop
                | DeviceType::Phone
                | DeviceType::Tablet => Zone::Trusted,
                DeviceType::Router
                | DeviceType::Switch
                | DeviceType::AccessPoint
                | DeviceType::Server
                | DeviceType::Nas
                | DeviceType::Printer => Zone::Infrastructure,
                DeviceType::Unknown => Zone::Unassigned,
                _ => Zone::IoT,
            };
            assert_eq!(zone, expected, "{t:?}");
            assert!(reason.starts_with(t.label()), "{reason}");
        }
    }

    #[test]
    fn unassigned_reason_carries_port_and_vendor_hints() {
        let d = dev(
            "10.0.0.2",
            DeviceType::Unknown,
            None,
            Some("Espressif Inc."),
            &[(9100, "RAW-Printing")],
        );
        let (zone, reason) = zone_for(&d, &[]);
        assert_eq!(zone, Zone::Unassigned);
        assert!(reason.contains("may be a printer"), "{reason}");
        assert!(reason.contains("IoT modules"), "{reason}");
    }

    #[test]
    fn thread_border_router_reason_points_to_constraints() {
        let r = fixture();
        let tv = &r.devices[7];
        let f: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.affected_ip == Some(tv.ip))
            .collect();
        let (zone, reason) = zone_for(tv, &f);
        assert_eq!(zone, Zone::IoT);
        assert!(reason.contains("Thread border router"), "{reason}");
    }

    #[test]
    fn rules_follow_observed_ports() {
        let out = render_segment_plan(&fixture(), None);
        for row in [
            "| Controller host(s) in Trusted | plug\\|1 (`192.168.1.50`) | TCP 9999 | Kasa |",
            "| Trusted | printer (`192.168.1.2`) | TCP 9100 | RAW-Printing | printing",
            "| Admin host(s) in Trusted | printer (`192.168.1.2`) | TCP 80 |",
            "| Trusted | nas (`192.168.1.20`) | TCP 445 | SMB | file sharing",
            "| Admin host(s) in Trusted | nas (`192.168.1.20`) | TCP 5001 |",
            "| Trusted | Denon AVR (`192.168.1.34`) | TCP 7000 | AirPlay | casting",
            "| Controller host(s) in Trusted | Denon AVR (`192.168.1.34`) | TCP 23 |",
            "| All zones | unifi (`192.168.1.1`) | TCP 53 | DNS |",
            "| IoT | Trusted | Deny new connections |",
        ] {
            assert!(out.contains(row), "missing {row}\n{out}");
        }
        assert!(out.contains("observed open in this scan; accepts unauthenticated control |"));
        assert!(
            !out.contains("(`192.168.2.31`) | TCP"),
            "no rules to Unassigned"
        );
        assert!(!out.contains("laptop (`192.168.1.10`) | TCP"));
    }

    #[test]
    fn unauthenticated_control_devices_come_first() {
        let out = render_segment_plan(&fixture(), None);
        let start = out.find("## Start here").unwrap();
        let iot = out.find("## IoT").unwrap();
        let infra = out.find("## Infrastructure").unwrap();
        assert!(start < iot);
        let start_sec = &out[start..iot];
        for a in ["192.168.1.2`", "192.168.1.34", "192.168.1.50"] {
            assert!(start_sec.contains(a), "{a}");
        }
        assert!(!start_sec.contains("192.168.1.169"));
        let iot_sec = &out[iot..infra];
        let pos = |a: &str| iot_sec.find(a).unwrap();
        assert!(pos("192.168.1.34") < pos("192.168.1.50"));
        assert!(pos("192.168.1.50") < pos("192.168.1.77"));
        assert!(pos("192.168.1.169") < pos("192.168.3.26"));
        assert!(pos("Denon/Marantz receiver control port") > pos("192.168.1.34"));
        assert!(!iot_sec.contains("Excessive certificate validity"));
    }

    #[test]
    fn mdns_allow_list_comes_from_iot_and_infrastructure() {
        let out = render_segment_plan(&fixture(), None);
        let sec = &out
            [out.find("## mDNS proxy allow-list").unwrap()..out.find("## Constraints").unwrap()];
        for t in [
            "`_airplay._tcp`",
            "`_raop._tcp`",
            "`_hue._tcp`",
            "`_ipp._tcp`",
            "`_meshcop._udp`",
        ] {
            assert!(sec.contains(t), "{t} missing: {sec}");
        }
        assert!(
            !sec.contains("_ssh._tcp"),
            "Trusted services are not listed"
        );
    }

    #[test]
    fn service_type_parsing_validates_tokens() {
        assert_eq!(
            service_types("x of type _hue._tcp.local on y"),
            ["_hue._tcp"]
        );
        assert_eq!(
            service_types("of type _Spotify-Connect._TCP.local."),
            ["_spotify-connect._tcp"]
        );
        assert!(service_types("of type _a|b._tcp.local").is_empty());
        assert!(service_types("of type _waytoolongservicename._tcp").is_empty());
        assert!(service_types("of type _x._sctp.local").is_empty());
        assert!(service_types("of type hue._tcp").is_empty());
    }

    #[test]
    fn gateway_wording_depends_on_vendor() {
        let out = render_segment_plan(&fixture(), None);
        assert!(out.contains("## On UniFi") && out.contains(UNIFI_ISOLATION));
        let mut generic = fixture();
        generic.devices[0].vendor = Some("Netgear".to_owned());
        let out = render_segment_plan(&generic, None);
        assert!(out.contains("## On your router") && !out.contains("## On UniFi"));
        assert!(!out.contains(UNIFI_ISOLATION));
    }

    #[test]
    fn constraints_cite_sources() {
        let out = render_segment_plan(&fixture(), None);
        for url in [HA_MATTER, HA_DENON, UNIFI_MDNS] {
            assert!(out.contains(&format!("<{url}>")), "{url}");
        }
        let mut no_denon = fixture();
        no_denon.devices.retain(|d| d.ip != ip("192.168.1.34"));
        no_denon
            .findings
            .retain(|f| f.affected_ip != Some(ip("192.168.1.34")));
        assert!(!render_segment_plan(&no_denon, None).contains(HA_DENON));
    }

    #[test]
    fn empty_scan_renders() {
        let out = render_segment_plan(&ScanResults::default(), Some("Generated *now*"));
        assert!(out.contains("Generated \\*now\\*"));
        assert!(out.contains("| Unassigned | 0 |") && !out.contains("## Start here"));
    }

    #[cfg(unix)]
    #[test]
    fn export_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("segments.md");
        export_segment_plan(&fixture(), None, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn unescaped_pipes(line: &str) -> usize {
        let mut n = 0;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '|' => n += 1,
                _ => {}
            }
        }
        n
    }

    proptest! {
        /// Device and finding strings cannot add control characters or table cells.
        #[test]
        fn prop_device_strings_cannot_break_tables(
            host in "\\PC{0,24}|[|\\n\\r\\x00\\x1b`*]{1,8}",
            vendor in "\\PC{0,24}",
            svc in "\\PC{0,16}|\\|{1,4}",
            title in "\\PC{0,32}",
            inst in "\\PC{0,24}",
            ty in prop_oneof![
                Just(DeviceType::IoT),
                Just(DeviceType::Printer),
                Just(DeviceType::Unknown),
                Just(DeviceType::Router),
            ],
        ) {
            let mut d = dev(
                "192.168.9.9",
                ty,
                Some(&host),
                Some(&vendor),
                &[(9999, &svc), (631, &svc), (53, &svc)],
            );
            d.device_subtype = Some(inst.clone());
            let f = Finding::new(
                "x",
                &format!("{title} unauthenticated control"),
                &format!("'{inst}' of type _a._tcp.local {title}"),
                Severity::High,
            )
            .with_ip(d.ip)
            .with_port(9999);
            let r = ScanResults { devices: vec![d], findings: vec![f], ..Default::default() };
            let out = render_segment_plan(&r, Some(&title));
            let mut header_pipes = None;
            for line in out.lines() {
                prop_assert!(!line.chars().any(char::is_control), "control char in {:?}", line);
                if line.starts_with('|') {
                    let n = unescaped_pipes(line);
                    let h = *header_pipes.get_or_insert(n);
                    prop_assert_eq!(n, h, "{:?}", line);
                } else {
                    header_pipes = None;
                    prop_assert_eq!(unescaped_pipes(line), 0, "{:?}", line);
                }
            }
        }
    }
}
