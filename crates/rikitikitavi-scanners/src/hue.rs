//! Philips Hue Bridge firmware check.
//!
//! One unauthenticated `GET /api/config` per candidate host. The endpoint is
//! public by design and returns `name`, `modelid`, `swversion` and `apiversion`.

use async_trait::async_trait;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::device::PortProtocol;
use rikitikitavi_models::{Device, DeviceHint, DeviceType, Finding, Remediation, ScanContext};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use crate::Scanner;
use crate::http_util::{read_body_capped, unauthenticated_probe_client};

/// Hue Bridge `/api/config` scanner.
pub struct HueScanner;

const HTTP_TIMEOUT: Duration = Duration::from_secs(4);

/// Unauthenticated `/api/config` is ~250 bytes.
const MAX_CONFIG_BYTES: usize = 16 * 1024;

/// Hue Bridge v2.
const BRIDGE_V2_MODEL: &str = "BSB002";

/// First Bridge v2 build with the ZDI-26-155 `HomeKit` fixes.
const FIXED_SWVERSION: u64 = 1_975_170_000;

/// `hk_hap` (`HomeKit` accessory protocol) port.
const HAP_PORT: u16 = 8080;

const API_PORTS: &[u16] = &[80, 443];

const CVES: &[&str] = &["CVE-2026-3557", "CVE-2026-3562"];

/// Fields read from `/api/config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HueConfig {
    pub name: Option<String>,
    pub modelid: Option<String>,
    pub bridgeid: Option<String>,
    pub apiversion: Option<String>,
    /// Raw `swversion` text.
    pub swversion_raw: Option<String>,
    pub swversion: Option<u64>,
    pub mac: Option<String>,
}

/// Firmware verdict for a parsed config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HueVerdict {
    /// Bridge v2 below [`FIXED_SWVERSION`].
    Vulnerable(u64),
    /// Bridge v2 at or above [`FIXED_SWVERSION`].
    Current(u64),
    /// A Hue bridge without a usable v2 version (v1 model or missing `swversion`).
    Unknown,
}

fn json_string(root: &serde_json::Value, key: &str) -> Option<String> {
    let text = root.get(key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Decimal `swversion`; leading zeros allowed, at most 20 digits.
fn parse_swversion(value: &serde_json::Value) -> Option<(String, u64)> {
    match value {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((s.to_owned(), s.parse().ok()?))
        }
        serde_json::Value::Number(n) => n.as_u64().map(|v| (v.to_string(), v)),
        _ => None,
    }
}

/// Parse an `/api/config` body. `None` unless it is a JSON object with a
/// `BSB`-prefixed `modelid` and a `bridgeid`.
pub fn parse_config(body: &str) -> Option<HueConfig> {
    if body.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    if !root.is_object() {
        return None;
    }
    let modelid = json_string(&root, "modelid")?;
    if !modelid.starts_with("BSB") {
        return None;
    }
    let bridgeid = json_string(&root, "bridgeid")?;
    let sw = root.get("swversion").and_then(parse_swversion);
    Some(HueConfig {
        name: json_string(&root, "name"),
        modelid: Some(modelid),
        bridgeid: Some(bridgeid),
        apiversion: json_string(&root, "apiversion"),
        swversion_raw: sw.as_ref().map(|(raw, _)| raw.clone()),
        swversion: sw.map(|(_, v)| v),
        mac: json_string(&root, "mac"),
    })
}

/// Firmware verdict. Only `BSB002` is compared against the fix build.
#[must_use]
pub fn classify_hue(config: &HueConfig) -> HueVerdict {
    if config.modelid.as_deref() != Some(BRIDGE_V2_MODEL) {
        return HueVerdict::Unknown;
    }
    match config.swversion {
        Some(v) if v < FIXED_SWVERSION => HueVerdict::Vulnerable(v),
        Some(v) => HueVerdict::Current(v),
        None => HueVerdict::Unknown,
    }
}

fn evidence(config: &HueConfig) -> String {
    format!(
        "/api/config: modelid={} swversion={} apiversion={} name={}",
        config.modelid.as_deref().unwrap_or("?"),
        config.swversion_raw.as_deref().unwrap_or("?"),
        config.apiversion.as_deref().unwrap_or("?"),
        config.name.as_deref().unwrap_or("?"),
    )
}

fn hint(config: &HueConfig) -> DeviceHint {
    let mut hint = DeviceHint::new()
        .with_vendor("Signify")
        .with_device_type(DeviceType::Hub)
        .with_device_subtype("hue");
    if let Some(model) = &config.modelid {
        hint = hint.with_model(model.clone());
    }
    hint
}

fn update_remediation() -> Remediation {
    Remediation {
        description: "Update the Hue Bridge firmware to 1975170000 or later.".to_owned(),
        steps: vec![
            "In the Hue app open Settings > Software update and turn on Automatic update."
                .to_owned(),
            "Confirm the bridge software version is 1975170000 or later.".to_owned(),
        ],
        effort: Some("10 minutes".to_owned()),
    }
}

/// Finding for one bridge. `port` is the API port that answered.
#[must_use]
pub fn build_finding(ip: IpAddr, port: u16, config: &HueConfig, hap_open: bool) -> Finding {
    let model = config.modelid.as_deref().unwrap_or("unknown model");
    let version = config.swversion_raw.as_deref().unwrap_or("unknown");
    let finding = match classify_hue(config) {
        HueVerdict::Vulnerable(_) => {
            let (severity, confidence, port_text, finding_port) = if hap_open {
                (
                    Severity::High,
                    Confidence::Confirmed,
                    format!("TCP {HAP_PORT} (hk_hap) is open on this bridge."),
                    HAP_PORT,
                )
            } else {
                (
                    Severity::Medium,
                    Confidence::Probable,
                    format!("TCP {HAP_PORT} (hk_hap) was not found open in this scan."),
                    port,
                )
            };
            Finding::new(
                "hue",
                &format!("Hue Bridge firmware {version} below the HomeKit fix on {ip}"),
                &format!(
                    "The Hue Bridge v2 ({model}) at {ip} reports swversion {version} on its \
                     unauthenticated /api/config endpoint. ZDI-26-155 names 1975170000 as the \
                     first build fixing CVE-2026-3557 (hk_hap authentication bypass, CVSS 8.0) \
                     and CVE-2026-3562 (hk_hap Ed25519 signature verification bypass, CVSS \
                     6.3), both reachable from the adjacent network. {port_text}"
                ),
                severity,
            )
            .with_confidence(confidence)
            .with_port(finding_port)
            .with_cve_ids(CVES.iter().map(|c| (*c).to_owned()).collect())
            .with_cwe("CWE-287")
            .with_remediation(update_remediation())
            .with_references(refs![
                "https://www.zerodayinitiative.com/advisories/ZDI-26-155/",
                "https://www.philips-hue.com/en-us/support/release-notes/bridge",
            ])
        }
        HueVerdict::Current(_) | HueVerdict::Unknown => Finding::new(
            "hue",
            &format!("Hue Bridge identified on {ip}"),
            &format!(
                "The Hue Bridge ({model}) at {ip}:{port} reports swversion {version} on its \
                 unauthenticated /api/config endpoint, which is public by design."
            ),
            Severity::Info,
        )
        .with_confidence(Confidence::Confirmed),
    };
    let finding = finding
        .with_ip(ip)
        .with_service("Hue Bridge")
        .with_evidence(evidence(config))
        .with_device_hint(hint(config));
    match config.mac.as_deref() {
        Some(mac) => finding.with_mac(mac),
        None => finding,
    }
}

fn is_hue_candidate(device: &Device) -> bool {
    let vendor = device.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
    vendor.contains("signify")
        || vendor.contains("philips lighting")
        || device.device_subtype.as_deref() == Some("hue")
}

/// Candidate hosts with their open API ports, plus whether 8080 is open.
fn select_targets(devices: &[Device], exclusions: &ExclusionSet) -> Vec<(IpAddr, Vec<u16>, bool)> {
    devices
        .iter()
        .filter(|d| is_hue_candidate(d))
        .filter(|d| !exclusions.excludes_device(d))
        .filter_map(|d| {
            let tcp: HashSet<u16> = d
                .open_ports
                .iter()
                .filter(|p| p.protocol == PortProtocol::Tcp)
                .map(|p| p.port)
                .collect();
            let ports: Vec<u16> = API_PORTS
                .iter()
                .copied()
                .filter(|p| tcp.contains(p))
                .collect();
            (!ports.is_empty()).then(|| (d.ip, ports, tcp.contains(&HAP_PORT)))
        })
        .collect()
}

async fn fetch_config(client: &reqwest::Client, ip: IpAddr, port: u16) -> Option<HueConfig> {
    let scheme = if port == 443 { "https" } else { "http" };
    let authority = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let url = format!("{scheme}://{authority}:{port}/api/config");
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(&url).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    parse_config(&read_body_capped(resp, MAX_CONFIG_BYTES).await)
}

/// Drops `credentials` "admin panel without auth" findings on hosts identified as
/// a Hue bridge (by this scanner or the nuclei `hue-wireless-lighting` template).
pub fn suppress_bridge_admin_no_auth(findings: &mut Vec<Finding>) {
    let bridges: HashSet<IpAddr> = findings
        .iter()
        .filter(|f| {
            f.scanner == "hue"
                || (f.scanner == "nuclei-detect"
                    && f.evidence
                        .as_deref()
                        .is_some_and(|e| e.contains("hue-wireless-lighting")))
        })
        .filter_map(|f| f.affected_ip)
        .collect();
    if bridges.is_empty() {
        return;
    }
    findings.retain(|f| {
        !(f.scanner == "credentials"
            && f.title.contains("admin panel without auth")
            && f.affected_ip.is_some_and(|ip| bridges.contains(&ip)))
    });
}

#[async_trait]
impl Scanner for HueScanner {
    fn id(&self) -> &'static str {
        "hue"
    }

    fn name(&self) -> &'static str {
        "Philips Hue Bridge Firmware"
    }

    fn supported_perspectives(&self) -> &[Perspective] {
        &[
            Perspective::Unauthenticated,
            Perspective::Authenticated,
            Perspective::Privileged,
        ]
    }

    async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        self.scan_collecting(ctx, &mut findings).await?;
        Ok(findings)
    }

    async fn scan_collecting(
        &self,
        ctx: &ScanContext,
        sink: &mut Vec<Finding>,
    ) -> Result<(), ScanError> {
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping Hue scan in quick scan mode");
            return Ok(());
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "hue".to_owned(),
                message: e.to_string(),
            })?;

        let targets = select_targets(&ctx.discovered_devices, &exclusions);
        if targets.is_empty() {
            tracing::info!("no Hue candidates found");
            return Ok(());
        }

        let client = unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::none())
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "hue".to_owned(),
                message: e.to_string(),
            })?;

        for (ip, ports, hap_open) in targets {
            for port in ports {
                if exclusions.excludes_ip(ip) {
                    break;
                }
                if let Some(config) = fetch_config(&client, ip, port).await {
                    sink.push(build_finding(ip, port, &config, hap_open));
                    break;
                }
            }
        }
        Ok(())
    }

    fn estimated_duration_secs(&self) -> u64 {
        8
    }

    fn relevant_ports(&self) -> &[u16] {
        API_PORTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rikitikitavi_models::device::OpenPort;

    /// Shape observed from a Bridge v2 (identifiers altered).
    const BSB002_CURRENT: &str = r#"{"name":"Hue Bridge","datastoreversion":"198",
        "swversion":"1978545030","apiversion":"1.78.0","mac":"00:17:88:aa:bb:cc",
        "bridgeid":"001788FFFEAABBCC","factorynew":false,"replacesbridgeid":null,
        "modelid":"BSB002","starterkitid":""}"#;

    fn config_with(model: &str, sw: &str) -> String {
        format!(
            r#"{{"name":"Hue Bridge","swversion":"{sw}","apiversion":"1.60.0",
            "bridgeid":"001788FFFE000001","modelid":"{model}"}}"#
        )
    }

    fn ip() -> IpAddr {
        "192.168.1.169".parse().unwrap()
    }

    #[test]
    fn parses_observed_bridge_config() {
        let c = parse_config(BSB002_CURRENT).unwrap();
        assert_eq!(c.modelid.as_deref(), Some("BSB002"));
        assert_eq!(c.swversion, Some(1_978_545_030));
        assert_eq!(c.apiversion.as_deref(), Some("1.78.0"));
        assert_eq!(c.name.as_deref(), Some("Hue Bridge"));
        assert_eq!(classify_hue(&c), HueVerdict::Current(1_978_545_030));
    }

    #[test]
    fn swversion_allows_leading_zeros_and_rejects_non_digits() {
        let c = parse_config(&config_with("BSB002", "01975169999")).unwrap();
        assert_eq!(classify_hue(&c), HueVerdict::Vulnerable(1_975_169_999));
        for bad in ["+1975170000", "1.975", "", "abc", "1975170000x"] {
            let c = parse_config(&config_with("BSB002", bad)).unwrap();
            assert_eq!(c.swversion, None, "{bad}");
            assert_eq!(classify_hue(&c), HueVerdict::Unknown);
        }
    }

    #[test]
    fn fix_boundary() {
        let at = parse_config(&config_with("BSB002", "1975170000")).unwrap();
        assert_eq!(classify_hue(&at), HueVerdict::Current(FIXED_SWVERSION));
        let below = parse_config(&config_with("BSB002", "1975169999")).unwrap();
        assert!(matches!(classify_hue(&below), HueVerdict::Vulnerable(_)));
    }

    #[test]
    fn only_bsb002_gets_a_version_verdict() {
        let v1 = parse_config(&config_with("BSB001", "01041302")).unwrap();
        assert_eq!(classify_hue(&v1), HueVerdict::Unknown);
    }

    #[test]
    fn non_bridge_json_is_rejected() {
        assert!(parse_config(r#"{"modelid":"LCT001","bridgeid":"x"}"#).is_none());
        assert!(parse_config(r#"{"name":"light bulb","swversion":"1"}"#).is_none());
        assert!(parse_config(r#"{"modelid":"BSB002"}"#).is_none());
        assert!(parse_config("[1,2]").is_none());
        assert!(parse_config("<html>hue personal wireless lighting</html>").is_none());
        assert!(parse_config(&" ".repeat(MAX_CONFIG_BYTES + 1)).is_none());
    }

    #[test]
    fn vulnerable_with_hap_open_is_high_confirmed() {
        let c = parse_config(&config_with("BSB002", "1972004020")).unwrap();
        let f = build_finding(ip(), 80, &c, true);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.affected_port, Some(HAP_PORT));
        assert_eq!(f.cve_ids, ["CVE-2026-3557", "CVE-2026-3562"]);
        assert!(f.remediation.is_some());
    }

    #[test]
    fn vulnerable_without_hap_is_medium() {
        let c = parse_config(&config_with("BSB002", "1972004020")).unwrap();
        let f = build_finding(ip(), 443, &c, false);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.affected_port, Some(443));
    }

    #[test]
    fn current_is_info_without_cves() {
        let c = parse_config(BSB002_CURRENT).unwrap();
        let f = build_finding(ip(), 80, &c, true);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.cve_ids.is_empty());
        assert!(
            f.evidence
                .as_deref()
                .unwrap()
                .contains("swversion=1978545030")
        );
    }

    fn device(vendor: &str, ports: &[u16]) -> Device {
        let mut d = Device::new(ip());
        d.vendor = Some(vendor.to_owned());
        d.open_ports = ports
            .iter()
            .map(|&port| OpenPort {
                port,
                protocol: PortProtocol::Tcp,
                service: None,
                version: None,
                banner: None,
            })
            .collect();
        d
    }

    #[test]
    fn targets_need_hue_vendor_and_api_port() {
        let ex = ExclusionSet::default();
        let t = select_targets(&[device("Philips Lighting", &[80, 443, 8080])], &ex);
        assert_eq!(t, vec![(ip(), vec![80, 443], true)]);
        assert!(select_targets(&[device("Philips Lighting", &[8080])], &ex).is_empty());
        assert!(select_targets(&[device("Synology", &[80])], &ex).is_empty());
    }

    #[test]
    fn suppresses_admin_no_auth_only_on_bridges() {
        let other: IpAddr = "192.168.1.2".parse().unwrap();
        let c = parse_config(BSB002_CURRENT).unwrap();
        let mk = |ip: IpAddr| {
            Finding::new(
                "credentials",
                &format!("Web admin panel without auth on {ip}:80"),
                "d",
                Severity::Medium,
            )
            .with_ip(ip)
            .with_port(80)
        };
        let mut findings = vec![build_finding(ip(), 80, &c, true), mk(ip()), mk(other)];
        suppress_bridge_admin_no_auth(&mut findings);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.affected_ip != Some(ip()) || f.scanner == "hue")
        );
    }

    proptest! {
        #[test]
        fn prop_parse_config_no_panic(body in ".{0,512}") {
            if let Some(c) = parse_config(&body) {
                let _ = classify_hue(&c);
                let _ = build_finding(ip(), 80, &c, true);
            }
        }

        #[test]
        fn prop_swversion_roundtrip(v in 0u64..10_000_000_000, model in "BSB00[0-9]") {
            let c = parse_config(&config_with(&model, &v.to_string())).unwrap();
            prop_assert_eq!(c.swversion, Some(v));
            if model == BRIDGE_V2_MODEL {
                prop_assert_eq!(classify_hue(&c) == HueVerdict::Vulnerable(v), v < FIXED_SWVERSION);
            } else {
                prop_assert_eq!(classify_hue(&c), HueVerdict::Unknown);
            }
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn config(text: &str) -> bool {
        super::parse_config(text).is_some_and(|c| {
            let _ = super::classify_hue(&c);
            true
        })
    }
}
