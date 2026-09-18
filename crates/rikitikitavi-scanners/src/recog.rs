//! Recog fingerprint matching over strings the scanners already collect.
//!
//! [`recog_db`](crate::recog_db) holds the imported patterns; this module owns
//! the `RegexSet` per match key, capture resolution, and the translation from
//! Recog parameters to a [`DeviceHint`].
//!
//! A match is a banner claim, never a demonstration, so every finding built here
//! is [`Confidence::Probable`] and [`Severity::Info`].

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::OnceLock;

use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use rikitikitavi_core::{Confidence, Severity};
use rikitikitavi_models::{DeviceHint, DeviceType, Finding};

use crate::recog_db::{RecogField, RecogFingerprint, RecogKey};

/// Compiled-size ceiling for a whole key's `RegexSet`. Four of the imported
/// sets exceed the crate's 10 MB default.
const SET_SIZE_LIMIT: usize = 256 << 20;

/// Compiled-size ceiling for one pattern; two imported patterns exceed the
/// 10 MB default.
const REGEX_SIZE_LIMIT: usize = 64 << 20;

/// Longest input handed to the matcher. Banners are bounded upstream; this
/// caps anything that is not.
const MAX_INPUT: usize = 8192;

/// Evidence excerpt length.
const MAX_EVIDENCE: usize = 200;

/// One lazily built `RegexSet` per [`RecogKey`].
static SETS: [OnceLock<Option<RegexSet>>; RecogKey::ALL.len()] =
    [const { OnceLock::new() }; RecogKey::ALL.len()];

/// Build one key's `RegexSet`, or `None` if the table does not compile.
///
/// `None` is unreachable while `recog_db/tests.rs` passes; it exists so a bad
/// regeneration degrades to "no identification" instead of a panic.
fn build_set(key: RecogKey) -> Option<RegexSet> {
    let patterns = key.fingerprints().iter().map(|f| f.pattern);
    match RegexSetBuilder::new(patterns)
        .size_limit(SET_SIZE_LIMIT)
        .build()
    {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::warn!(key = key.as_str(), error = %e, "recog pattern set did not compile");
            None
        }
    }
}

/// This key's compiled pattern set, built on first use.
fn set_for(key: RecogKey) -> Option<&'static RegexSet> {
    SETS[key.index()].get_or_init(|| build_set(key)).as_ref()
}

/// Build every key's pattern set now, one thread per key. Idempotent.
pub fn warm_up() {
    std::thread::scope(|scope| {
        for key in RecogKey::ALL {
            scope.spawn(move || {
                let _ = set_for(key);
            });
        }
    });
}

/// A resolved Recog match: the fingerprint that claimed the input and the
/// parameter values it yields.
#[derive(Debug, Clone)]
pub struct RecogMatch {
    /// Match key the input came from.
    pub key: RecogKey,
    /// Index of the matching fingerprint in `key.fingerprints()`.
    pub index: usize,
    /// Upstream description of the fingerprint.
    pub description: &'static str,
    fields: BTreeMap<RecogField, String>,
}

/// Recog's device vocabulary mapped to [`DeviceType`].
///
/// Curated, not derived: a device string absent from this table yields no type
/// rather than a guess. Classes with no `DeviceType` variant (`VoIP`, PLC, KVM,
/// Firewall, UPS) are deliberately absent.
const fn device_type_for(device: &str) -> Option<DeviceType> {
    match device.as_bytes() {
        b"Printer" | b"Multifunction Device" | b"Print Server" => Some(DeviceType::Printer),
        b"Router" | b"Broadband Router" | b"Cable Modem" | b"ADSL Modem" | b"DSL Modem" => {
            Some(DeviceType::Router)
        }
        b"Switch" => Some(DeviceType::Switch),
        b"WAP" => Some(DeviceType::AccessPoint),
        b"IP Camera" | b"Web Cam" => Some(DeviceType::Camera),
        b"DVR" => Some(DeviceType::Nvr),
        b"NAS" | b"Storage" | b"Storage Appliance" => Some(DeviceType::Nas),
        b"Smart TV" => Some(DeviceType::SmartTv),
        b"Network Audio" => Some(DeviceType::Speaker),
        b"Light Bulb" => Some(DeviceType::IoT),
        // A baseboard management controller is a component of a server.
        b"Lights Out Management" | b"Hypervisor" => Some(DeviceType::Server),
        _ => None,
    }
}

impl RecogMatch {
    /// Value of one field.
    #[must_use]
    pub fn get(&self, field: RecogField) -> Option<&str> {
        self.fields.get(&field).map(String::as_str)
    }

    /// First non-empty value among `fields`, in order.
    fn first(&self, fields: &[RecogField]) -> Option<&str> {
        fields.iter().find_map(|f| self.get(*f))
    }

    /// Vendor of the device, not of the software on it.
    ///
    /// `service.vendor` is deliberately excluded: "nginx" is not the maker of
    /// the bridge nginx is running on, and this value feeds `DeviceHint`.
    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        self.first(&[RecogField::HwVendor, RecogField::OsVendor])
    }

    /// Product name of the listening software.
    #[must_use]
    pub fn product(&self) -> Option<&str> {
        self.first(&[RecogField::ServiceProduct, RecogField::ServiceFamily])
    }

    /// Version of the listening software.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.get(RecogField::ServiceVersion)
    }

    /// Upstream device class, e.g. `Printer`.
    #[must_use]
    pub fn device_class(&self) -> Option<&str> {
        self.first(&[RecogField::HwDevice, RecogField::OsDevice])
    }

    /// Structured device type, from the curated device-class map only.
    #[must_use]
    pub fn device_type(&self) -> Option<DeviceType> {
        self.device_class().and_then(device_type_for)
    }

    /// `"Vendor Product"`, or `None` when the fingerprint names no software.
    #[must_use]
    pub fn product_label(&self) -> Option<String> {
        let product = self.product()?;
        let mut label = String::new();
        if let Some(vendor) = self.first(&[RecogField::ServiceVendor, RecogField::OsVendor])
            && !product.starts_with(vendor)
        {
            label.push_str(vendor);
            label.push(' ');
        }
        label.push_str(product);
        Some(label)
    }

    /// `"Vendor Product Version"` for a service label, or `None` when the
    /// fingerprint names no software.
    #[must_use]
    pub fn service_label(&self) -> Option<String> {
        let mut label = self.product_label()?;
        if let Some(version) = self.version() {
            label.push(' ');
            label.push_str(version);
        }
        Some(label)
    }

    /// Operating-system sentence, e.g. `Cisco IOS 12.4`.
    #[must_use]
    pub fn os_label(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(v) = self.get(RecogField::OsVendor) {
            parts.push(v);
        }
        let product = self.first(&[RecogField::OsProduct, RecogField::OsFamily]);
        if let Some(p) = product
            && Some(p) != parts.first().copied()
        {
            parts.push(p);
        }
        if let Some(v) = self.get(RecogField::OsVersion) {
            parts.push(v);
        }
        if parts.is_empty() {
            return None;
        }
        Some(parts.join(" "))
    }

    /// Hardware label, e.g. `MikroTik RB951G`.
    #[must_use]
    pub fn hardware_label(&self) -> Option<String> {
        let product = self.first(&[
            RecogField::HwProduct,
            RecogField::HwModel,
            RecogField::HwFamily,
        ])?;
        self.get(RecogField::HwVendor).map_or_else(
            || Some(product.to_owned()),
            |vendor| {
                if product.starts_with(vendor) {
                    Some(product.to_owned())
                } else {
                    Some(format!("{vendor} {product}"))
                }
            },
        )
    }

    /// The best single label for this match: hardware, else software, else the
    /// upstream description.
    #[must_use]
    pub fn label(&self) -> String {
        self.hardware_label()
            .or_else(|| self.service_label())
            .unwrap_or_else(|| self.description.to_owned())
    }

    /// [`Self::label`] without the service version, for finding titles:
    /// `Finding::fingerprint` hashes the title, so a patch upgrade must not
    /// change it.
    #[must_use]
    pub fn stable_label(&self) -> String {
        self.hardware_label()
            .or_else(|| self.product_label())
            .unwrap_or_else(|| self.description.to_owned())
    }

    /// Device identification this match supports.
    ///
    /// `device_type` comes only from the curated class map; `device_subtype`
    /// carries Recog's own device vocabulary, not a free-text product name.
    #[must_use]
    pub fn device_hint(&self) -> DeviceHint {
        let mut hint = DeviceHint::new();
        if let Some(vendor) = self.vendor() {
            hint = hint.with_vendor(vendor);
        }
        if let Some(model) = self.first(&[
            RecogField::HwProduct,
            RecogField::HwModel,
            RecogField::HwFamily,
        ]) {
            hint = hint.with_model(model);
        }
        if let Some(hostname) = self.get(RecogField::HostName) {
            hint = hint.with_hostname(hostname);
        }
        if let Some(os) = self.os_label() {
            hint = hint.with_os_guess(os);
        }
        if let Some(device_type) = self.device_type() {
            hint = hint.with_device_type(device_type);
        }
        if let Some(class) = self.device_class() {
            hint = hint.with_device_subtype(class);
        }
        hint
    }

    /// True when the match yields nothing beyond the upstream description —
    /// a generic error page or a bare protocol greeting.
    #[must_use]
    pub fn is_bare(&self) -> bool {
        self.vendor().is_none()
            && self.product().is_none()
            && self.device_class().is_none()
            && self.get(RecogField::ServiceVendor).is_none()
    }
}

/// Resolve one fingerprint's parameters against an input.
fn resolve(key: RecogKey, index: usize, fp: &'static RecogFingerprint, input: &str) -> RecogMatch {
    let mut fields: BTreeMap<RecogField, String> = BTreeMap::new();
    let compiled = RegexBuilder::new(fp.pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .ok();
    let captures = compiled.as_ref().and_then(|re| re.captures(input));

    // Captures and untemplated literals first; templated literals need them.
    let mut templated = Vec::new();
    for param in fp.params {
        if param.pos == 0 {
            if param.value.contains('{') {
                templated.push(param);
            } else if !param.value.is_empty() {
                fields.insert(param.field, param.value.to_owned());
            }
            continue;
        }
        let Some(value) = captures
            .as_ref()
            .and_then(|c| c.get(usize::from(param.pos)))
            .map(|m| m.as_str().trim())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        fields.insert(param.field, value.to_owned());
    }
    for param in templated {
        if let Some(value) = interpolate(param.value, &fields) {
            fields.insert(param.field, value);
        }
    }

    RecogMatch {
        key,
        index,
        description: fp.description,
        fields,
    }
}

/// Substitute `{field.name}` references; `None` if any reference is unresolved.
fn interpolate(template: &str, fields: &BTreeMap<RecogField, String>) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}')? + open;
        let name = &rest[open + 1..close];
        let field = RecogField::ALL.into_iter().find(|f| f.as_str() == name)?;
        out.push_str(fields.get(&field)?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Identify `input` against one match key.
///
/// Recog resolves against the first pattern that matches in file order, so the
/// lowest matching index wins.
#[must_use]
pub fn identify(key: RecogKey, input: &str) -> Option<RecogMatch> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAX_INPUT {
        return None;
    }
    let index = set_for(key)?.matches(input).iter().next()?;
    let fp = key.fingerprints().get(index)?;
    Some(resolve(key, index, fp, input))
}

/// Identify several strings about the same endpoint, dropping bare matches.
#[must_use]
pub fn identify_all(inputs: &[(RecogKey, &str)]) -> Vec<RecogMatch> {
    inputs
        .iter()
        .filter_map(|(key, input)| identify(*key, input))
        .filter(|m| !m.is_bare())
        .collect()
}

/// Merge the hints of several matches, first non-empty value winning.
fn merge_hints(matches: &[RecogMatch]) -> DeviceHint {
    let mut merged = DeviceHint::new();
    for hint in matches.iter().map(RecogMatch::device_hint) {
        merged.vendor = merged.vendor.or(hint.vendor);
        merged.model = merged.model.or(hint.model);
        merged.hostname = merged.hostname.or(hint.hostname);
        merged.device_type = merged.device_type.or(hint.device_type);
        merged.device_subtype = merged.device_subtype.or(hint.device_subtype);
        merged.os_guess = merged.os_guess.or(hint.os_guess);
    }
    merged
}

/// Truncate at a character boundary and mark the cut.
fn excerpt(input: &str) -> String {
    let input = input.trim();
    if input.len() <= MAX_EVIDENCE {
        return input.to_owned();
    }
    let mut end = MAX_EVIDENCE;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &input[..end])
}

/// Build the identification finding for one endpoint from its matches.
///
/// Returns `None` when nothing matched or every match was bare. `Info` and
/// `Probable`: a banner is a claim the device makes about itself.
#[must_use]
pub fn identification_finding(
    scanner: &str,
    ip: IpAddr,
    port: Option<u16>,
    matches: &[RecogMatch],
) -> Option<Finding> {
    // A match that names hardware or a device class says more about the device
    // than one that only names the web server in front of it.
    let primary = matches
        .iter()
        .find(|m| m.device_class().is_some() || m.hardware_label().is_some())
        .or_else(|| matches.first())?;
    let where_ = port.map_or_else(|| ip.to_string(), |p| format!("{ip}:{p}"));

    let mut description = format!(
        "Rapid7 Recog fingerprints identify {where_} as {}.",
        primary.label()
    );
    if let Some(os) = primary.os_label() {
        let _ = write!(description, " Operating system or firmware: {os}.");
    }
    if let Some(class) = primary.device_class() {
        let _ = write!(description, " Upstream device class: {class}.");
    }
    description.push_str(
        " This is what the service says about itself in a banner, not a verified property.",
    );

    let mut evidence = String::new();
    for m in matches {
        let _ = writeln!(evidence, "{}: {}", m.key.as_str(), m.description);
    }

    let mut finding = Finding::new(
        scanner,
        &format!("{} identified at {where_}", primary.stable_label()),
        &description,
        Severity::Info,
    )
    .with_ip(ip)
    .with_confidence(Confidence::Probable)
    .with_evidence(excerpt(&evidence))
    .with_device_hint(merge_hints(matches));

    if let Some(port) = port {
        finding = finding.with_port(port);
    }
    if let Some(label) = primary.service_label() {
        finding = finding.with_service(label);
    }
    Some(finding)
}

/// Identify `input` and build the finding in one step.
#[must_use]
pub fn identify_finding(
    scanner: &str,
    ip: IpAddr,
    port: Option<u16>,
    key: RecogKey,
    input: &str,
) -> Option<Finding> {
    let matches = identify_all(&[(key, input)]);
    identification_finding(scanner, ip, port, &matches)
}

/// Strip the RFC 4253 `SSH-<protoversion>-` prefix, which Recog's `ssh.banner`
/// patterns assume is already removed.
#[must_use]
pub fn ssh_software(banner: &str) -> Option<&str> {
    let line = banner.lines().find(|l| {
        l.trim_start()
            .as_bytes()
            .first_chunk::<5>()
            .is_some_and(|p| p[..4].eq_ignore_ascii_case(b"SSH-") && p[4].is_ascii_digit())
    })?;
    let rest = line.trim().get(4..)?;
    let dash = rest.find('-')?;
    let software = rest.get(dash + 1..)?.trim();
    (!software.is_empty()).then_some(software)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ssh_software_strips_the_protocol_prefix() {
        assert_eq!(
            ssh_software("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"),
            Some("OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
        );
        assert_eq!(ssh_software("SSH-1.99-Cisco-1.25"), Some("Cisco-1.25"));
        assert_eq!(
            ssh_software("SSH-2.0-dropbear_2020.81"),
            Some("dropbear_2020.81")
        );
        assert_eq!(ssh_software("SSH-2.0-"), None);
        assert_eq!(ssh_software(""), None);
    }

    /// Public-key material is not an RFC 4253 identification string: the byte
    /// after `SSH-` must be a digit.
    #[test]
    fn ssh_software_rejects_key_material() {
        assert_eq!(ssh_software("ssh-rsa AAAAB3Nza"), None);
        assert_eq!(ssh_software("ssh-rsa AAAAB3Nza comment-with-dash"), None);
        assert_eq!(
            ssh_software("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@my-laptop"),
            None
        );
    }

    #[test]
    fn identifies_an_openssh_banner() {
        let m = identify(RecogKey::SshBanner, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4").unwrap();
        assert_eq!(m.get(RecogField::ServiceProduct), Some("OpenSSH"));
        assert_eq!(m.get(RecogField::ServiceVersion), Some("8.9p1"));
        assert_eq!(m.get(RecogField::OsVendor), Some("Ubuntu"));
        assert!(!m.is_bare());
    }

    #[test]
    fn identifies_a_server_header_and_types_the_device() {
        let m = identify(RecogKey::HttpServer, "HP-ChaiSOE/1.0").unwrap();
        assert_eq!(m.device_class(), Some("Printer"));
        assert_eq!(m.device_type(), Some(DeviceType::Printer));
        let hint = m.device_hint();
        assert_eq!(hint.device_type, Some(DeviceType::Printer));
        assert_eq!(hint.device_subtype.as_deref(), Some("Printer"));
    }

    #[test]
    fn identifies_a_chromecast_issuer() {
        let m = identify(
            RecogKey::X509Issuer,
            "CN=Eureka Gen1 ICA,OU=Google TV,O=Google Inc,L=Mountain View,ST=California,C=US",
        )
        .unwrap();
        assert_eq!(m.vendor(), Some("Google"));
    }

    /// A software vendor is not the device's vendor: a Hue bridge running nginx
    /// must not be attributed to nginx.
    #[test]
    fn software_vendor_never_becomes_the_device_vendor() {
        let m = identify(RecogKey::HttpServer, "nginx").unwrap();
        assert_eq!(m.get(RecogField::ServiceVendor), Some("nginx"));
        assert_eq!(m.vendor(), None);
        assert_eq!(m.device_hint().vendor, None);
        // It is still a useful service label.
        assert_eq!(m.service_label().as_deref(), Some("nginx"));
        assert!(!m.is_bare());
    }

    /// The hardware match leads the finding even when a software match came first.
    #[test]
    fn the_most_specific_match_names_the_finding() {
        let ip: IpAddr = "192.168.1.169".parse().unwrap();
        let matches = identify_all(&[
            (RecogKey::HttpServer, "nginx"),
            (RecogKey::HtmlTitle, "hue personal wireless lighting"),
        ]);
        assert_eq!(matches.len(), 2);
        let finding = identification_finding("http_audit", ip, Some(80), &matches).unwrap();
        assert!(finding.title.contains("Hue"), "{}", finding.title);
        let hint = finding.device_hint.as_ref().unwrap();
        assert_eq!(hint.vendor.as_deref(), Some("Philips"));
        // Both matches stay in the evidence.
        let evidence = finding.evidence.as_deref().unwrap_or_default();
        assert!(evidence.contains("http_header.server"));
        assert!(evidence.contains("html_title"));
    }

    /// The title is version-free, so a patch upgrade does not resolve the old
    /// finding and raise a new one.
    #[test]
    fn the_title_omits_the_service_version() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let fp = |server: &str| {
            let f = identify_finding("services", ip, Some(80), RecogKey::HttpServer, server)
                .expect(server);
            (f.title.clone(), f.fingerprint())
        };
        let (old_title, old_fp) = fp("nginx/1.18.0");
        let (new_title, new_fp) = fp("nginx/1.24.0");
        assert_eq!(old_title, "nginx identified at 192.168.1.5:80");
        assert_eq!(old_title, new_title);
        assert_eq!(old_fp, new_fp);
        // The version is still reported, just not in the hashed title.
        let f = identify_finding(
            "services",
            ip,
            Some(80),
            RecogKey::HttpServer,
            "nginx/1.24.0",
        )
        .unwrap();
        assert!(f.description.contains("1.24.0"), "{}", f.description);
        assert_eq!(f.affected_service.as_deref(), Some("nginx 1.24.0"));
    }

    /// Recog resolves against the first matching pattern in file order.
    #[test]
    fn lowest_index_wins() {
        let key = RecogKey::HttpServer;
        let input = "Apache/2.4.58 (Ubuntu)";
        let m = identify(key, input).unwrap();
        let set = set_for(key).unwrap();
        let first = set.matches(input).iter().next().unwrap();
        assert_eq!(m.index, first);
    }

    #[test]
    fn interpolation_needs_every_reference() {
        let mut fields = BTreeMap::new();
        fields.insert(RecogField::ServiceVersion, "1.2".to_owned());
        assert_eq!(
            interpolate("v{service.version}", &fields).as_deref(),
            Some("v1.2")
        );
        assert_eq!(interpolate("{hw.product}", &fields), None);
        assert_eq!(interpolate("{not.a.field}", &fields), None);
        assert_eq!(interpolate("plain", &fields).as_deref(), Some("plain"));
    }

    /// Every mapped class is a real Recog device string and an intended type.
    #[test]
    fn device_map_is_curated_and_conservative() {
        assert_eq!(device_type_for("Printer"), Some(DeviceType::Printer));
        assert_eq!(device_type_for("WAP"), Some(DeviceType::AccessPoint));
        assert_eq!(device_type_for("DVR"), Some(DeviceType::Nvr));
        // Classes with no DeviceType variant stay unmapped rather than guess.
        assert_eq!(device_type_for("Firewall"), None);
        assert_eq!(device_type_for("VoIP"), None);
        assert_eq!(device_type_for("PLC"), None);
        assert_eq!(device_type_for("Power Device"), None);
        assert_eq!(device_type_for(""), None);
    }

    /// Only classes that actually occur upstream are worth mapping.
    #[test]
    fn mapped_classes_occur_in_the_table() {
        let mut seen = std::collections::BTreeSet::new();
        for key in RecogKey::ALL {
            for fp in key.fingerprints() {
                for p in fp.params {
                    if matches!(p.field, RecogField::OsDevice | RecogField::HwDevice)
                        && p.pos == 0
                        && device_type_for(p.value).is_some()
                    {
                        seen.insert(p.value);
                    }
                }
            }
        }
        for class in [
            "Printer",
            "Multifunction Device",
            "Print Server",
            "Router",
            "Broadband Router",
            "Switch",
            "WAP",
            "IP Camera",
            "DVR",
            "NAS",
            "Storage",
            "Lights Out Management",
        ] {
            assert!(seen.contains(class), "{class} no longer appears upstream");
        }
    }

    #[test]
    fn bare_matches_produce_no_finding() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        assert!(identification_finding("services", ip, Some(22), &[]).is_none());
    }

    #[test]
    fn finding_is_info_and_probable() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let finding = identify_finding(
            "services",
            ip,
            Some(22),
            RecogKey::SshBanner,
            "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
        )
        .unwrap();
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Probable);
        assert_eq!(finding.affected_port, Some(22));
        assert!(finding.title.contains("192.168.1.5:22"));
    }

    #[test]
    fn oversized_input_is_refused() {
        let huge = "a".repeat(MAX_INPUT + 1);
        assert!(identify(RecogKey::HttpServer, &huge).is_none());
    }

    #[test]
    fn excerpt_cuts_on_a_char_boundary() {
        let s = "é".repeat(MAX_EVIDENCE);
        let cut = excerpt(&s);
        assert!(cut.ends_with("..."));
        assert!(cut.len() <= MAX_EVIDENCE + 3);
    }

    proptest! {
        /// Arbitrary bytes through every key: no panic, and a match always
        /// resolves to a real row.
        #[test]
        fn prop_identify_no_panic(input in ".*") {
            for key in RecogKey::ALL {
                if let Some(m) = identify(key, &input) {
                    prop_assert!(m.index < key.fingerprints().len());
                    let _ = m.label();
                    let _ = m.device_hint();
                }
            }
        }

        #[test]
        fn prop_ssh_software_no_panic(input in ".*") {
            let _ = ssh_software(&input);
        }

        /// Leading and trailing whitespace never changes the verdict.
        #[test]
        fn prop_identify_trims(input in "[ -~]{0,64}") {
            let padded = format!("  {input}\r\n");
            prop_assert_eq!(
                identify(RecogKey::HttpServer, &input).map(|m| m.index),
                identify(RecogKey::HttpServer, &padded).map(|m| m.index)
            );
        }
    }
}
