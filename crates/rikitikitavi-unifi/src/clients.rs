//! Controller client inventory: `stat/sta` merged with `rest/user`.

use anyhow::{Context, Result, bail};
use rikitikitavi_models::MacAddr;
use rikitikitavi_models::config::UniFiControllerConfig;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use crate::api::UniFiClient;
use crate::models::UniFiClientInfo;

/// Bound on login plus both client requests.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// Character cap for names, networks and other short strings.
pub const NAME_MAX: usize = 64;
/// Character cap for notes.
pub const NOTE_MAX: usize = 128;

/// One controller client after merging and sanitising.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControllerClient {
    pub mac: Option<MacAddr>,
    pub ip: Option<IpAddr>,
    /// Alias set in the controller UI.
    pub alias: Option<String>,
    pub hostname: Option<String>,
    pub note: Option<String>,
    pub fixed_ip: Option<IpAddr>,
    pub oui: Option<String>,
    pub network: Option<String>,
    pub essid: Option<String>,
    pub vlan: Option<i64>,
    pub is_wired: bool,
    pub is_guest: bool,
    pub ap_mac: Option<MacAddr>,
    pub sw_mac: Option<MacAddr>,
    pub sw_port: Option<i64>,
    pub dev_cat: Option<i64>,
    pub dev_family: Option<i64>,
    pub dev_vendor: Option<i64>,
    pub dev_id: Option<i64>,
    pub os_name: Option<i64>,
    /// Listed in `stat/sta`.
    pub connected: bool,
}

/// `raw` without control or bidi/format characters, trimmed, at most `max` chars; `None` if empty.
#[must_use]
pub fn clean_text(raw: &str, max: usize) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .collect();
    let cleaned: String = cleaned.trim().chars().take(max).collect();
    let cleaned = cleaned.trim_end();
    (!cleaned.is_empty()).then(|| cleaned.to_owned())
}

const fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

fn text(raw: Option<&String>, max: usize) -> Option<String> {
    raw.and_then(|s| clean_text(s, max))
}

fn mac(raw: Option<&String>) -> Option<MacAddr> {
    raw.and_then(|s| s.trim().parse().ok())
}

fn ip(raw: Option<&String>) -> Option<IpAddr> {
    raw.and_then(|s| s.trim().parse().ok())
}

impl ControllerClient {
    fn from_info(info: &UniFiClientInfo, connected: bool) -> Option<Self> {
        Some(Self {
            mac: Some(mac(info.mac.as_ref())?),
            ip: ip(info.ip.as_ref()),
            alias: text(info.name.as_ref(), NAME_MAX),
            hostname: text(info.hostname.as_ref(), NAME_MAX),
            note: text(info.note.as_ref(), NOTE_MAX),
            fixed_ip: ip(info.fixed_ip.as_ref()),
            oui: text(info.oui.as_ref(), NAME_MAX),
            network: text(info.network.as_ref(), NAME_MAX),
            essid: text(info.essid.as_ref(), NAME_MAX),
            vlan: info.vlan,
            is_wired: info.is_wired,
            is_guest: info.is_guest,
            ap_mac: mac(info.ap_mac.as_ref()),
            sw_mac: mac(info.sw_mac.as_ref()),
            sw_port: info.sw_port,
            dev_cat: info.dev_cat,
            dev_family: info.dev_family,
            dev_vendor: info.dev_vendor,
            dev_id: info.dev_id,
            os_name: info.os_name,
            connected,
        })
    }

    /// Fill fields this client lacks from the `rest/user` record of the same MAC.
    fn fill_from(&mut self, known: Self) {
        fn fill<T>(slot: &mut Option<T>, from: Option<T>) {
            if slot.is_none() {
                *slot = from;
            }
        }
        fill(&mut self.alias, known.alias);
        fill(&mut self.hostname, known.hostname);
        fill(&mut self.note, known.note);
        fill(&mut self.fixed_ip, known.fixed_ip);
        fill(&mut self.oui, known.oui);
        fill(&mut self.network, known.network);
        fill(&mut self.dev_cat, known.dev_cat);
        fill(&mut self.dev_family, known.dev_family);
        fill(&mut self.dev_vendor, known.dev_vendor);
        fill(&mut self.dev_id, known.dev_id);
        fill(&mut self.os_name, known.os_name);
    }

    /// Alias, else hostname.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.alias.as_deref().or(self.hostname.as_deref())
    }

    /// Controller fields as `key=value` pairs, fingerprint codes first as raw integers and
    /// free-text fields last. Alias and note are left out.
    #[must_use]
    pub fn evidence(&self) -> String {
        let mut out = String::new();
        let mut put = |k: &str, v: &dyn std::fmt::Display| {
            if !out.is_empty() {
                out.push(' ');
            }
            let _ = write!(out, "{k}={v}");
        };
        if let Some(v) = &self.mac {
            put("mac", v);
        }
        for (k, v) in [
            ("dev_cat", self.dev_cat),
            ("dev_family", self.dev_family),
            ("dev_vendor", self.dev_vendor),
            ("dev_id", self.dev_id),
            ("os_name", self.os_name),
        ] {
            if let Some(v) = v {
                put(k, &v);
            }
        }
        if let Some(v) = &self.ip {
            put("ip", v);
        }
        if let Some(v) = &self.fixed_ip {
            put("fixed_ip", v);
        }
        if let Some(v) = &self.vlan {
            put("vlan", v);
        }
        put("wired", &self.is_wired);
        if self.is_guest {
            put("guest", &true);
        }
        if let Some(v) = &self.ap_mac {
            put("ap_mac", v);
        }
        if let Some(v) = &self.sw_mac {
            put("sw_mac", v);
        }
        if let Some(v) = &self.sw_port {
            put("sw_port", v);
        }
        for (k, v) in [
            ("network", &self.network),
            ("essid", &self.essid),
            ("oui", &self.oui),
            ("hostname", &self.hostname),
        ] {
            if let Some(v) = v {
                put(k, &format!("{v:?}"));
            }
        }
        out
    }
}

/// Connected clients first (one per MAC, first entry wins), each filled from its `rest/user`
/// record; known-only clients follow with `connected = false`. Entries without a valid MAC are
/// dropped.
#[must_use]
pub fn merge_clients(
    active: &[UniFiClientInfo],
    known: &[UniFiClientInfo],
) -> Vec<ControllerClient> {
    let mut out: Vec<ControllerClient> = Vec::new();
    let mut by_mac: HashMap<MacAddr, usize> = HashMap::new();
    for (infos, connected) in [(active, true), (known, false)] {
        for client in infos
            .iter()
            .filter_map(|i| ControllerClient::from_info(i, connected))
        {
            let Some(m) = client.mac else { continue };
            match by_mac.get(&m) {
                Some(&i) if !connected => out[i].fill_from(client),
                Some(_) => {}
                None => {
                    by_mac.insert(m, out.len());
                    out.push(client);
                }
            }
        }
    }
    out
}

fn nonempty(v: Option<&String>) -> Option<&str> {
    v.map(String::as_str).filter(|s| !s.trim().is_empty())
}

/// Log in with the configured token (preferred) or username/password and fetch the merged
/// inventory. A failed `rest/user` request leaves connected clients without alias data.
pub async fn fetch_inventory(cfg: &UniFiControllerConfig) -> Result<Vec<ControllerClient>> {
    let raw_url = cfg
        .url
        .as_deref()
        .context("unifi.controller.url is not set")?;
    let url = reqwest::Url::parse(raw_url).context("unifi.controller.url is not a valid URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("unifi.controller.url must not embed credentials");
    }
    let mut client = UniFiClient::connect(url.as_str(), &cfg.site, cfg.insecure)?;
    if let Some(token) = nonempty(cfg.api_token.as_ref()) {
        client.login_token(token).await?;
    } else if let (Some(user), Some(pass)) = (
        nonempty(cfg.username.as_ref()),
        nonempty(cfg.password.as_ref()),
    ) {
        client.login(user, pass).await?;
    } else {
        bail!("unifi.controller has no api_token or username/password");
    }
    let active = client.get_clients(false).await?;
    let known = client.get_clients(true).await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "UniFi known-client list unavailable");
        Vec::new()
    });
    Ok(merge_clients(&active, &known))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn infos(json: &str) -> Vec<UniFiClientInfo> {
        serde_json::from_str(json).unwrap()
    }

    const STA: &str = r#"[
        {"_id":"c1","mac":"AA:BB:CC:00:00:01","ip":"192.168.1.20","hostname":"android-7f3a",
         "oui":"Samsung","is_wired":false,"essid":"Home","network":"LAN","vlan":"",
         "ap_mac":"f4:92:bf:00:00:01","dev_cat":44,"dev_family":"9","dev_vendor":7,
         "os_name":56,"dev_id":1234,"satisfaction":98,"tx_bytes":123456,"uptime":3600,
         "last_seen":1700000000,"new_field_from_v9":{"nested":[1,2]}},
        {"mac":"aa:bb:cc:00:00:02","ip":"10.20.0.5","name":"Garage camera","is_wired":true,
         "sw_mac":"f4:92:bf:00:00:02","sw_port":7,"network":"IoT","vlan":20},
        {"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.99","hostname":"dup"},
        {"ip":"192.168.1.77","hostname":"no-mac"},
        {"mac":"not-a-mac","ip":"192.168.1.78"}
    ]"#;

    const USER: &str = r#"[
        {"_id":"u1","mac":"aa:bb:cc:00:00:01","name":"Anna phone","note":"bedroom",
         "noted":true,"use_fixedip":true,"fixed_ip":"192.168.1.20"},
        {"mac":"aa:bb:cc:00:00:09","name":"Old laptop","hostname":"oldlaptop"}
    ]"#;

    #[test]
    fn parses_missing_unknown_and_mistyped_fields() {
        let all = infos(
            r#"[{}, {"mac":5,"hostname":["x"],"is_wired":"true","vlan":"20","sw_port":"x",
                    "dev_cat":1.5,"is_guest":1,"last_seen":true}]"#,
        );
        assert!(all[0].mac.is_none() && !all[0].is_wired);
        assert!(all[1].mac.is_none() && all[1].hostname.is_none());
        assert!(all[1].is_wired && all[1].is_guest);
        assert_eq!(all[1].vlan, Some(20));
        assert_eq!(all[1].sw_port, None);
        assert_eq!(all[1].dev_cat, None);

        let sta = infos(STA);
        assert_eq!(sta[0].dev_family, Some(9));
        assert_eq!(sta[0].vlan, None);
        assert_eq!(sta[0].os_name, Some(56));
    }

    #[test]
    fn merge_fills_alias_from_known_and_keeps_known_only() {
        let merged = merge_clients(&infos(STA), &infos(USER));
        assert_eq!(merged.len(), 3);
        let anna = &merged[0];
        assert!(anna.connected);
        assert_eq!(anna.ip, "192.168.1.20".parse().ok());
        assert_eq!(anna.alias.as_deref(), Some("Anna phone"));
        assert_eq!(anna.hostname.as_deref(), Some("android-7f3a"));
        assert_eq!(anna.note.as_deref(), Some("bedroom"));
        assert_eq!(anna.display_name(), Some("Anna phone"));
        assert_eq!(merged[1].display_name(), Some("Garage camera"));
        assert_eq!(merged[1].sw_port, Some(7));
        let old = &merged[2];
        assert!(!old.connected);
        assert!(old.ip.is_none());
        assert_eq!(old.alias.as_deref(), Some("Old laptop"));
    }

    #[test]
    fn evidence_records_raw_codes() {
        let merged = merge_clients(&infos(STA), &[]);
        let ev = merged[0].evidence();
        for want in [
            "mac=aa:bb:cc:00:00:01",
            "dev_cat=44",
            "dev_family=9",
            "dev_vendor=7",
            "os_name=56",
            "dev_id=1234",
            "hostname=\"android-7f3a\"",
            "wired=false",
        ] {
            assert!(ev.contains(want), "{want} missing from {ev}");
        }
    }

    #[test]
    fn clean_text_strips_controls_and_caps() {
        assert_eq!(
            clean_text(" a\u{1b}[31mb\u{202e}c\n ", 64).as_deref(),
            Some("a[31mbc")
        );
        assert_eq!(clean_text("\u{7}\u{200b} ", 64), None);
        assert_eq!(
            clean_text(&"é".repeat(100), 64).unwrap().chars().count(),
            64
        );
        let merged = merge_clients(
            &infos(&format!(
                r#"[{{"mac":"aa:bb:cc:00:00:03","name":"{}","note":"{}"}}]"#,
                "n".repeat(500),
                "x\\u0000".repeat(500)
            )),
            &[],
        );
        assert_eq!(merged[0].alias.as_ref().unwrap().len(), NAME_MAX);
        assert_eq!(merged[0].note.as_ref().unwrap().len(), NOTE_MAX);
    }

    #[tokio::test]
    async fn fetch_rejects_url_with_credentials_before_connecting() {
        let cfg = UniFiControllerConfig {
            url: Some("https://admin:pw@127.0.0.1:1".to_owned()),
            api_token: Some("k".to_owned()),
            ..UniFiControllerConfig::default()
        };
        let err = fetch_inventory(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("must not embed credentials"), "{err}");
        assert!(!err.contains("pw"), "{err}");
    }

    fn arb_json() -> impl Strategy<Value = serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::from),
            any::<i64>().prop_map(serde_json::Value::from),
            any::<f64>().prop_map(serde_json::Value::from),
            ".{0,12}".prop_map(serde_json::Value::from),
        ];
        let keys = prop_oneof![
            Just("mac".to_owned()),
            Just("ip".to_owned()),
            Just("name".to_owned()),
            Just("hostname".to_owned()),
            Just("vlan".to_owned()),
            Just("is_wired".to_owned()),
            Just("dev_cat".to_owned()),
            Just("fixed_ip".to_owned()),
            "[a-z_]{1,8}",
        ];
        leaf.prop_recursive(3, 24, 6, move |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::from),
                proptest::collection::btree_map(keys.clone(), inner, 0..8)
                    .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// Any JSON object deserializes; merging never panics.
        #[test]
        fn prop_client_json_never_panics(values in proptest::collection::vec(arb_json(), 0..6)) {
            let parsed: Vec<UniFiClientInfo> = values
                .iter()
                .filter(|v| v.is_object())
                .map(|v| serde_json::from_value(v.clone()).unwrap())
                .collect();
            let text = serde_json::to_string(&values).unwrap();
            let _ = serde_json::from_str::<Vec<UniFiClientInfo>>(&text);
            let merged = merge_clients(&parsed, &parsed);
            prop_assert!(merged.len() <= parsed.len());
            for c in &merged {
                prop_assert!(c.alias.as_ref().is_none_or(|a| a.chars().count() <= NAME_MAX));
                let _ = c.evidence();
            }
        }
    }
}
