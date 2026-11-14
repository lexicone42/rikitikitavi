//! Spotify Connect identification through the `ZeroConf` `getInfo` endpoint.
//!
//! Responders come from an mDNS browse for `_spotify-connect._tcp`; each gets one
//! unauthenticated `GET {CPath}?action=getInfo`. Only `deviceType`,
//! `brandDisplayName`, `modelDisplayName` and `remoteName` are deserialized.

use async_trait::async_trait;
use futures::stream::StreamExt as _;
use rikitikitavi_core::{Confidence, Perspective, ScanError, Severity};
use rikitikitavi_models::config::ExclusionSet;
use rikitikitavi_models::{DeviceHint, DeviceType, Finding, MacAddr, ScanContext};
use rikitikitavi_network::mdns::{MdnsService, txt_get};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::Instant;

use crate::Scanner;
use crate::http_util::{read_body_capped, unauthenticated_probe_client};

/// Spotify Connect `ZeroConf` scanner.
pub struct SpotifyZcScanner;

/// mDNS query sent by this scanner.
pub const SERVICE_QUERY: &[&str] = &["_spotify-connect._tcp.local"];

const BROWSE_SECS: u64 = 2;
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_CPATH_LEN: usize = 128;
const MAX_FIELD_CHARS: usize = 96;
const MAX_TARGETS: usize = 64;
const MAX_PARALLELISM: usize = 16;
const PROBE_BUDGET: Duration = Duration::from_secs(20);

// ── Pure parsing / classification (unit-tested below) ───────────────────

/// `CPath` if it is a bare absolute path of `[A-Za-z0-9/._~-]`.
fn valid_cpath(raw: &str) -> Option<&str> {
    let ok = raw.starts_with('/')
        && !raw.starts_with("//")
        && raw.len() <= MAX_CPATH_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b));
    ok.then_some(raw)
}

/// Raw `getInfo` fields; every other key is skipped unparsed.
#[derive(Deserialize)]
struct RawInfo {
    #[serde(rename = "deviceType")]
    device_type: Option<serde_json::Value>,
    #[serde(rename = "brandDisplayName")]
    brand: Option<serde_json::Value>,
    #[serde(rename = "modelDisplayName")]
    model: Option<serde_json::Value>,
    #[serde(rename = "remoteName")]
    remote_name: Option<serde_json::Value>,
}

/// Fields of interest from a `getInfo` response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ZcInfo {
    device_type: Option<String>,
    brand: Option<String>,
    model: Option<String>,
    remote_name: Option<String>,
}

/// Trimmed, control-free, length-capped string value; `None` if empty or not a string.
fn clean_field(value: Option<&serde_json::Value>) -> Option<String> {
    let text: String = value?
        .as_str()?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD_CHARS)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Parse a `getInfo` body. `None` unless it is a JSON object with at least one
/// non-empty field of interest.
fn parse_get_info(body: &str) -> Option<ZcInfo> {
    if !body.trim_start().starts_with('{') {
        return None;
    }
    let raw: RawInfo = serde_json::from_str(body).ok()?;
    let info = ZcInfo {
        device_type: clean_field(raw.device_type.as_ref()),
        brand: clean_field(raw.brand.as_ref()),
        model: clean_field(raw.model.as_ref()),
        remote_name: clean_field(raw.remote_name.as_ref()),
    };
    (info != ZcInfo::default()).then_some(info)
}

/// Map a `deviceType` value, case- and separator-insensitively. Unknown is `None`.
fn map_device_type(raw: &str) -> Option<DeviceType> {
    let norm: String = raw
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    match norm.as_str() {
        "speaker" | "castaudio" => Some(DeviceType::Speaker),
        "avr" | "stb" | "castvideo" | "audiodongle" | "videodongle" => {
            Some(DeviceType::MediaPlayer)
        }
        "tv" => Some(DeviceType::SmartTv),
        "gameconsole" => Some(DeviceType::GameConsole),
        "smartphone" => Some(DeviceType::Phone),
        "tablet" => Some(DeviceType::Tablet),
        _ => None,
    }
}

/// A Spotify Connect responder to probe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ZcTarget {
    ip: IpAddr,
    port: u16,
    cpath: String,
}

fn is_spotify_service(service_type: &str) -> bool {
    let t = service_type.strip_suffix('.').unwrap_or(service_type);
    SERVICE_QUERY.iter().any(|q| q.eq_ignore_ascii_case(t))
}

/// Spotify Connect services with a valid `CPath`, in scope, deduplicated and capped.
fn select_targets(services: &[MdnsService], in_scope: impl Fn(IpAddr) -> bool) -> Vec<ZcTarget> {
    let set: BTreeSet<ZcTarget> = services
        .iter()
        .filter(|s| is_spotify_service(&s.service_type) && s.port != 0 && in_scope(s.ip))
        .filter_map(|s| {
            let cpath = valid_cpath(txt_get(&s.txt_records, "CPath")?)?;
            Some(ZcTarget {
                ip: s.ip,
                port: s.port,
                cpath: cpath.to_owned(),
            })
        })
        .collect();
    set.into_iter().take(MAX_TARGETS).collect()
}

fn get_info_url(target: &ZcTarget) -> String {
    format!(
        "http://{}{}?action=getInfo",
        SocketAddr::new(target.ip, target.port),
        target.cpath
    )
}

/// Identification finding carrying the device hint. `brandDisplayName` becomes
/// the vendor only when discovery has none for the host.
fn build_finding(
    target: &ZcTarget,
    info: &ZcInfo,
    known_vendor: bool,
    mac: Option<MacAddr>,
) -> Finding {
    let mut hint = DeviceHint::new();
    if let Some(dt) = info.device_type.as_deref().and_then(map_device_type) {
        hint = hint.with_device_type(dt);
    }
    if let Some(model) = &info.model {
        hint = hint.with_model(model.replace('_', " "));
    }
    if let Some(brand) = info.brand.as_ref().filter(|_| !known_vendor) {
        hint = hint.with_vendor(brand.clone());
    }
    if let Some(name) = &info.remote_name {
        hint = hint.with_hostname(name.clone());
    }

    let field = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".to_owned());
    let evidence = format!(
        "getInfo: deviceType={} brand={} model={} remoteName={}",
        field(&info.device_type),
        field(&info.brand),
        field(&info.model),
        field(&info.remote_name),
    );
    let ip = target.ip;
    let port = target.port;
    let finding = Finding::new(
        "spotify_zc",
        &format!("Spotify Connect device identified on {ip}:{port}"),
        &format!(
            "The host at {ip}:{port} answered an unauthenticated \
             GET {}?action=getInfo ({evidence}). Spotify Connect receivers \
             accept playback hand-off from clients on the same network.",
            target.cpath
        ),
        Severity::Info,
    )
    .with_ip(ip)
    .with_port(port)
    .with_service("Spotify Connect")
    .with_confidence(Confidence::Confirmed)
    .with_evidence(evidence)
    .with_device_hint(hint);
    match mac {
        Some(mac) => finding.with_mac(mac),
        None => finding,
    }
}

// ── Network ─────────────────────────────────────────────────────────────

/// MAC for each address known from discovery or the ARP cache.
fn known_macs(ctx: &ScanContext) -> BTreeMap<IpAddr, MacAddr> {
    let mut macs: BTreeMap<IpAddr, MacAddr> = ctx
        .discovered_devices
        .iter()
        .filter_map(|d| Some((d.ip, d.mac?)))
        .collect();
    match rikitikitavi_network::read_arp_cache() {
        Ok(entries) => {
            for entry in entries {
                if let Ok(mac) = entry.mac.parse::<MacAddr>() {
                    macs.insert(entry.ip, mac);
                }
            }
        }
        Err(e) => tracing::warn!("could not read ARP cache for Spotify exclusion check: {e}"),
    }
    macs
}

fn in_scope(
    ip: IpAddr,
    target_network: Option<&ipnetwork::IpNetwork>,
    exclusions: &ExclusionSet,
    macs: &BTreeMap<IpAddr, MacAddr>,
) -> bool {
    target_network.is_none_or(|n| n.contains(ip))
        && !exclusions.excludes_ip(ip)
        && !macs.get(&ip).is_some_and(|m| exclusions.excludes_mac(*m))
}

async fn fetch_get_info(client: &reqwest::Client, target: &ZcTarget) -> Option<ZcInfo> {
    let resp = tokio::time::timeout(HTTP_TIMEOUT, client.get(get_info_url(target)).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = tokio::time::timeout(HTTP_TIMEOUT, read_body_capped(resp, MAX_BODY_BYTES))
        .await
        .ok()?;
    parse_get_info(&body)
}

#[async_trait]
impl Scanner for SpotifyZcScanner {
    fn id(&self) -> &'static str {
        "spotify_zc"
    }

    fn name(&self) -> &'static str {
        "Spotify Connect Identification"
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
        if !ctx
            .config
            .intensity
            .at_least(rikitikitavi_models::config::ScanIntensity::Active)
        {
            tracing::info!("skipping Spotify Connect scan in quick scan mode");
            return Ok(findings);
        }

        let exclusions = ctx
            .config
            .exclusions()
            .map_err(|e| ScanError::ScannerFailed {
                scanner: "spotify_zc".to_owned(),
                message: e.to_string(),
            })?;

        let services =
            match rikitikitavi_network::mdns::discover_service_types(SERVICE_QUERY, BROWSE_SECS)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Spotify Connect mDNS browse failed: {e}");
                    return Ok(findings);
                }
            };

        let macs = known_macs(ctx);
        let targets = select_targets(&services, |ip| {
            in_scope(ip, ctx.target_network.as_ref(), &exclusions, &macs)
        });
        if targets.is_empty() {
            tracing::info!("no Spotify Connect responders found");
            return Ok(findings);
        }

        let Ok(client) =
            unauthenticated_probe_client(HTTP_TIMEOUT, reqwest::redirect::Policy::none())
        else {
            return Err(ScanError::ScannerFailed {
                scanner: "spotify_zc".to_owned(),
                message: "failed to build HTTP probe client".to_owned(),
            });
        };

        tracing::info!(
            target_count = targets.len(),
            "probing Spotify Connect responders"
        );
        let parallelism = ctx.config.parallelism.clamp(1, MAX_PARALLELISM);
        let deadline = Instant::now() + PROBE_BUDGET;
        let mut probes = futures::stream::iter(targets)
            .map(|target| {
                let client = client.clone();
                async move {
                    let info = fetch_get_info(&client, &target).await;
                    (target, info)
                }
            })
            .buffer_unordered(parallelism);
        loop {
            match tokio::time::timeout_at(deadline, probes.next()).await {
                Ok(Some((target, Some(info)))) => {
                    let known_vendor = ctx
                        .discovered_devices
                        .iter()
                        .any(|d| d.ip == target.ip && d.vendor.is_some());
                    let mac = macs.get(&target.ip).copied();
                    findings.push(build_finding(&target, &info, known_vendor, mac));
                }
                Ok(Some((_, None))) => {}
                Ok(None) => break,
                Err(_) => {
                    tracing::warn!(
                        budget_secs = PROBE_BUDGET.as_secs(),
                        "Spotify Connect probe phase timed out; keeping the findings collected so far"
                    );
                    break;
                }
            }
        }
        findings.sort_by_key(|f| (f.affected_ip, f.affected_port));
        tracing::info!(
            findings_count = findings.len(),
            "Spotify Connect scan complete"
        );
        Ok(findings)
    }

    fn estimated_duration_secs(&self) -> u64 {
        BROWSE_SECS + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Shape of a live Denon AVR response; identifiers replaced.
    const DENON_FIXTURE: &str = r#"{
      "status": 101, "statusString": "OK", "spotifyError": 0, "version": "2.9.0",
      "deviceID": "0000000000000000000000000000000000000000",
      "publicKey": "AAAA", "remoteName": "Denon AVR-X1800H",
      "deviceType": "AVR", "brandDisplayName": "Denon",
      "modelDisplayName": "Denon AVR-X1800H", "libraryVersion": "3.0.0",
      "resolverVersion": "1", "groupStatus": "NONE", "tokenType": "default",
      "clientID": "x", "productID": 0, "scope": "streaming", "availability": "",
      "aliases": []
    }"#;

    const ECHO_FIXTURE: &str = r#"{"status":101,"spotifyError":0,"deviceID":"x",
      "publicKey":"y","remoteName":"","deviceType":"SPEAKER",
      "brandDisplayName":"Amazon","modelDisplayName":"Echo_Show_8"}"#;

    const PS5_FIXTURE: &str = r#"{"status":101,"spotifyError":0,"deviceID":"x",
      "publicKey":"y","remoteName":"PS5-123","deviceType":"GAMECONSOLE",
      "brandDisplayName":"sony_tv","modelDisplayName":"ps5"}"#;

    fn service(ip: &str, port: u16, service_type: &str, txt: &[&str]) -> MdnsService {
        MdnsService {
            name: "x".to_owned(),
            service_type: service_type.to_owned(),
            hostname: "x.local".to_owned(),
            ip: ip.parse().unwrap(),
            port,
            txt_records: txt.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn target(cpath: &str) -> ZcTarget {
        ZcTarget {
            ip: "192.168.1.34".parse().unwrap(),
            port: 58057,
            cpath: cpath.to_owned(),
        }
    }

    #[test]
    fn parses_denon_response() {
        let info = parse_get_info(DENON_FIXTURE).expect("info");
        assert_eq!(info.device_type.as_deref(), Some("AVR"));
        assert_eq!(info.brand.as_deref(), Some("Denon"));
        assert_eq!(info.model.as_deref(), Some("Denon AVR-X1800H"));
        assert_eq!(info.remote_name.as_deref(), Some("Denon AVR-X1800H"));
    }

    #[test]
    fn empty_remote_name_is_none() {
        let info = parse_get_info(ECHO_FIXTURE).expect("info");
        assert_eq!(info.remote_name, None);
        assert_eq!(info.model.as_deref(), Some("Echo_Show_8"));
    }

    #[test]
    fn rejects_non_objects_and_irrelevant_json() {
        assert_eq!(parse_get_info(""), None);
        assert_eq!(parse_get_info("not json"), None);
        assert_eq!(parse_get_info(r#"["AVR","Denon","m","n"]"#), None);
        assert_eq!(parse_get_info(r#"{"status":101}"#), None);
        assert_eq!(
            parse_get_info(r#"{"deviceType":"","remoteName":"  "}"#),
            None
        );
    }

    #[test]
    fn wrongly_typed_fields_become_none() {
        let info = parse_get_info(r#"{"deviceType":7,"brandDisplayName":"Acme"}"#).unwrap();
        assert_eq!(info.device_type, None);
        assert_eq!(info.brand.as_deref(), Some("Acme"));
    }

    #[test]
    fn fields_are_stripped_of_control_chars_and_capped() {
        let long = "a".repeat(500);
        let body = format!(r#"{{"remoteName":"x\r\ny","modelDisplayName":"{long}"}}"#);
        let info = parse_get_info(&body).unwrap();
        assert_eq!(info.remote_name.as_deref(), Some("xy"));
        assert_eq!(info.model.unwrap().len(), MAX_FIELD_CHARS);
    }

    #[test]
    fn maps_device_types_case_insensitively() {
        assert_eq!(map_device_type("SPEAKER"), Some(DeviceType::Speaker));
        assert_eq!(map_device_type("Speaker"), Some(DeviceType::Speaker));
        assert_eq!(
            map_device_type("GAMECONSOLE"),
            Some(DeviceType::GameConsole)
        );
        assert_eq!(
            map_device_type("GameConsole"),
            Some(DeviceType::GameConsole)
        );
        assert_eq!(map_device_type("AVR"), Some(DeviceType::MediaPlayer));
        assert_eq!(map_device_type("STB"), Some(DeviceType::MediaPlayer));
        assert_eq!(map_device_type("CastVideo"), Some(DeviceType::MediaPlayer));
        assert_eq!(map_device_type("CAST_AUDIO"), Some(DeviceType::Speaker));
        assert_eq!(map_device_type("TV"), Some(DeviceType::SmartTv));
        assert_eq!(map_device_type("Smartphone"), Some(DeviceType::Phone));
        assert_eq!(map_device_type("TABLET"), Some(DeviceType::Tablet));
    }

    #[test]
    fn unknown_device_types_give_no_hint() {
        for raw in ["COMPUTER", "Automobile", "UNKNOWN", "", "speakers"] {
            assert_eq!(map_device_type(raw), None, "{raw}");
        }
    }

    #[test]
    fn cpath_validation() {
        for ok in ["/zc", "/spConn", "/spotifyConnect", "/a/b-c_d.e~f"] {
            assert_eq!(valid_cpath(ok), Some(ok));
        }
        for bad in [
            "",
            "zc",
            "//evil.example/x",
            "http://evil/x",
            "/zc\r\nHost: x",
            "/zc?x=1",
            "/zc#f",
            "/z c",
            "/\\evil",
            "/@evil",
            "/%2e",
        ] {
            assert_eq!(valid_cpath(bad), None, "{bad:?}");
        }
        assert_eq!(
            valid_cpath(&format!("/{}", "a".repeat(MAX_CPATH_LEN))),
            None
        );
    }

    #[test]
    fn selects_only_spotify_services_with_valid_cpath_in_scope() {
        let services = vec![
            service(
                "192.168.1.34",
                58057,
                "_spotify-connect._tcp.local",
                &["VERSION=1.0", "CPath=/zc"],
            ),
            service(
                "192.168.1.34",
                58057,
                "_spotify-connect._tcp.local",
                &["CPath=/zc"],
            ),
            service(
                "192.168.2.253",
                41800,
                "_spotify-connect._tcp.local.",
                &["cpath=/spConn"],
            ),
            service("192.168.1.40", 80, "_http._tcp.local", &["CPath=/zc"]),
            service("192.168.1.41", 4070, "_spotify-connect._tcp.local", &[]),
            service(
                "192.168.1.42",
                4070,
                "_spotify-connect._tcp.local",
                &["CPath=//evil/x"],
            ),
            service(
                "192.168.1.43",
                0,
                "_spotify-connect._tcp.local",
                &["CPath=/zc"],
            ),
            service(
                "10.0.0.5",
                4070,
                "_spotify-connect._tcp.local",
                &["CPath=/zc"],
            ),
        ];
        let net: ipnetwork::IpNetwork = "192.168.0.0/22".parse().unwrap();
        let targets = select_targets(&services, |ip| net.contains(ip));
        assert_eq!(
            targets,
            vec![
                ZcTarget {
                    ip: "192.168.1.34".parse().unwrap(),
                    port: 58057,
                    cpath: "/zc".to_owned()
                },
                ZcTarget {
                    ip: "192.168.2.253".parse().unwrap(),
                    port: 41800,
                    cpath: "/spConn".to_owned()
                },
            ]
        );
    }

    #[test]
    fn in_scope_honours_ip_and_mac_exclusions() {
        let ex = ExclusionSet::parse(
            &["10.0.0.0/24".to_owned()],
            &["aa:bb:cc:dd:ee:ff".to_owned()],
        )
        .unwrap();
        let mut macs = BTreeMap::new();
        macs.insert(
            "192.168.1.5".parse().unwrap(),
            "AA-BB-CC-DD-EE-FF".parse().unwrap(),
        );
        assert!(!in_scope("10.0.0.9".parse().unwrap(), None, &ex, &macs));
        assert!(!in_scope("192.168.1.5".parse().unwrap(), None, &ex, &macs));
        assert!(in_scope("192.168.1.6".parse().unwrap(), None, &ex, &macs));
    }

    #[test]
    fn get_info_url_brackets_ipv6() {
        assert_eq!(
            get_info_url(&target("/zc")),
            "http://192.168.1.34:58057/zc?action=getInfo"
        );
        let v6 = ZcTarget {
            ip: "fe80::1".parse().unwrap(),
            port: 4070,
            cpath: "/zc".to_owned(),
        };
        assert_eq!(get_info_url(&v6), "http://[fe80::1]:4070/zc?action=getInfo");
    }

    #[test]
    fn finding_carries_hint_and_never_identifiers() {
        let info = parse_get_info(DENON_FIXTURE).unwrap();
        let f = build_finding(&target("/zc"), &info, false, None);
        assert_eq!(f.scanner, "spotify_zc");
        assert_eq!(f.severity, Severity::Info);
        let hint = f.device_hint.as_ref().unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::MediaPlayer));
        assert_eq!(hint.vendor.as_deref(), Some("Denon"));
        assert_eq!(hint.model.as_deref(), Some("Denon AVR-X1800H"));
        assert_eq!(hint.hostname.as_deref(), Some("Denon AVR-X1800H"));
        let text = format!("{f:?}");
        assert!(!text.contains("0000000000000000"));
        assert!(!text.contains("publicKey"));
        assert!(!text.contains("deviceID"));
    }

    #[test]
    fn brand_does_not_override_known_vendor_and_model_underscores_become_spaces() {
        let info = parse_get_info(ECHO_FIXTURE).unwrap();
        let hint = build_finding(&target("/spotifyConnect"), &info, true, None)
            .device_hint
            .unwrap();
        assert_eq!(hint.vendor, None);
        assert_eq!(hint.model.as_deref(), Some("Echo Show 8"));
        assert_eq!(hint.device_type, Some(DeviceType::Speaker));
        assert_eq!(hint.hostname, None);
    }

    #[test]
    fn ps5_is_a_game_console() {
        let info = parse_get_info(PS5_FIXTURE).unwrap();
        let hint = build_finding(&target("/spConn"), &info, true, None)
            .device_hint
            .unwrap();
        assert_eq!(hint.device_type, Some(DeviceType::GameConsole));
        assert_eq!(hint.hostname.as_deref(), Some("PS5-123"));
    }

    #[test]
    fn unknown_type_still_reports_but_without_class() {
        let info = parse_get_info(r#"{"deviceType":"COMPUTER","remoteName":"desk"}"#).unwrap();
        let hint = build_finding(&target("/zc"), &info, true, None)
            .device_hint
            .unwrap();
        assert_eq!(hint.device_type, None);
    }

    #[test]
    fn service_query_is_in_the_shared_query_list() {
        for q in SERVICE_QUERY {
            assert!(
                rikitikitavi_network::mdns::SERVICE_QUERIES.contains(q),
                "{q}"
            );
        }
    }

    #[test]
    fn scanner_metadata_is_stable() {
        let s = SpotifyZcScanner;
        assert_eq!(s.id(), "spotify_zc");
        assert!(s.relevant_ports().is_empty());
        assert!(!s.requires_privileges());
    }

    proptest! {
        #[test]
        fn prop_parse_get_info_bytes_no_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse_get_info(&String::from_utf8_lossy(&data));
        }

        #[test]
        fn prop_parse_get_info_json_no_panic(
            dt in ".{0,32}", brand in ".{0,32}", model in ".{0,200}", name in ".{0,32}"
        ) {
            let body = serde_json::json!({
                "deviceType": dt, "brandDisplayName": brand,
                "modelDisplayName": model, "remoteName": name,
            })
            .to_string();
            if let Some(info) = parse_get_info(&body) {
                for f in [&info.device_type, &info.brand, &info.model, &info.remote_name]
                    .into_iter()
                    .flatten()
                {
                    prop_assert!(f.chars().count() <= MAX_FIELD_CHARS);
                    prop_assert!(!f.chars().any(char::is_control));
                }
            }
        }

        #[test]
        fn prop_valid_cpath_never_admits_authority_or_crlf(raw in ".{0,64}") {
            if let Some(p) = valid_cpath(&raw) {
                prop_assert!(p.starts_with('/') && !p.starts_with("//"));
                prop_assert!(!p.contains(['\r', '\n', '?', '#', '@', ':', '\\']));
            }
        }
    }
}

/// Parser entry points for the fuzz harness.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    #[must_use]
    pub fn get_info(body: &str) -> bool {
        super::parse_get_info(body).is_some()
    }
    #[must_use]
    pub fn cpath(raw: &str) -> bool {
        super::valid_cpath(raw).is_some()
    }
}
