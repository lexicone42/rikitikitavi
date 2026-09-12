use serde::{Deserialize, Deserializer, Serialize};

/// `UniFi` device type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniFiDevice {
    DreamMachine,
    DreamMachinePro,
    DreamMachineProMax,
    DreamMachineSE,
    DreamRouter,
    DreamWall,
    CloudGatewayUltra,
    CloudGatewayMax,
    CloudKeyGen2Plus,
    SecurityGateway,
    SecurityGatewayPro4,
    AccessPoint,
    Switch,
    Unknown,
}

/// Integer field the controller may also emit as a numeric string or `""`.
#[derive(Deserialize)]
#[serde(untagged)]
enum FlexInt {
    Int(i64),
    Str(String),
}

impl FlexInt {
    fn value(self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(n),
            Self::Str(s) => s.trim().parse().ok(),
        }
    }
}

fn flex_i64<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    Ok(FlexInt::deserialize(d)?.value().unwrap_or(0))
}

fn flex_opt_u16<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u16>, D::Error> {
    Ok(Option::<FlexInt>::deserialize(d)?
        .and_then(FlexInt::value)
        .and_then(|n| u16::try_from(n).ok()))
}

/// Site from `/api/self/sites`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub desc: Option<String>,
}

/// Adopted device from `/api/s/{site}/stat/device`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdoptedDevice {
    pub mac: String,
    pub name: Option<String>,
    pub model: String,
    /// Firmware version string (`version` on the wire).
    #[serde(rename = "version", default)]
    pub firmware_version: String,
    /// Short type code: `uap`, `usw`, `ugw`, `udm`, `uxg`.
    #[serde(rename = "type", default)]
    pub device_type: String,
    #[serde(default)]
    pub adopted: bool,
    #[serde(default)]
    pub state: DeviceState,
    pub ip: Option<String>,
}

/// Device state; an integer code on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(from = "i64", into = "i64")]
pub enum DeviceState {
    #[default]
    Unknown,
    Connected,
    Pending,
    FirmwareMismatch,
    Upgrading,
    Provisioning,
    HeartbeatMissed,
    Adopting,
    Deleting,
    InformError,
    AdoptFailed,
    Isolated,
}

impl From<i64> for DeviceState {
    fn from(code: i64) -> Self {
        match code {
            1 => Self::Connected,
            2 => Self::Pending,
            3 => Self::FirmwareMismatch,
            4 => Self::Upgrading,
            5 => Self::Provisioning,
            6 => Self::HeartbeatMissed,
            7 => Self::Adopting,
            8 => Self::Deleting,
            9 => Self::InformError,
            10 => Self::AdoptFailed,
            11 => Self::Isolated,
            _ => Self::Unknown,
        }
    }
}

impl From<DeviceState> for i64 {
    fn from(state: DeviceState) -> Self {
        match state {
            DeviceState::Unknown => 0,
            DeviceState::Connected => 1,
            DeviceState::Pending => 2,
            DeviceState::FirmwareMismatch => 3,
            DeviceState::Upgrading => 4,
            DeviceState::Provisioning => 5,
            DeviceState::HeartbeatMissed => 6,
            DeviceState::Adopting => 7,
            DeviceState::Deleting => 8,
            DeviceState::InformError => 9,
            DeviceState::AdoptFailed => 10,
            DeviceState::Isolated => 11,
        }
    }
}

/// Client from `/api/s/{site}/stat/sta` or `rest/user`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniFiClientInfo {
    pub mac: String,
    pub hostname: Option<String>,
    pub ip: Option<String>,
    pub network: Option<String>,
    #[serde(default)]
    pub is_wired: bool,
    #[serde(default)]
    pub is_guest: bool,
}

/// WLAN from `/api/s/{site}/rest/wlanconf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WlanConfig {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    /// `open`, `wpapsk`, `wpaeap`, `wep`, or `osen`.
    #[serde(default)]
    pub security: String,
    /// `auto`, `wpa1`, or `wpa2`.
    pub wpa_mode: Option<String>,
    /// `disabled`, `optional`, or `required`.
    pub pmf_mode: Option<String>,
    #[serde(default)]
    pub is_guest: bool,
    #[serde(default)]
    pub enabled: bool,
}

/// Firewall rule from `/api/s/{site}/rest/firewallrule`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirewallRule {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: Option<String>,
    /// `accept`, `drop`, or `reject`.
    #[serde(default)]
    pub action: String,
    pub ruleset: Option<String>,
    pub src_address: Option<String>,
    pub src_networkconf_id: Option<String>,
    #[serde(default)]
    pub src_firewallgroup_ids: Vec<String>,
    pub dst_address: Option<String>,
    pub dst_networkconf_id: Option<String>,
    #[serde(default)]
    pub dst_firewallgroup_ids: Vec<String>,
    #[serde(default)]
    pub enabled: bool,
}

impl FirewallRule {
    fn is_any(address: Option<&str>, network_id: Option<&str>, group_ids: &[String]) -> bool {
        address.is_none_or(|a| a.is_empty() || a == "any")
            && network_id.is_none_or(str::is_empty)
            && group_ids.iter().all(String::is_empty)
    }

    /// True when no source address, network, or group restricts the rule.
    pub fn src_is_any(&self) -> bool {
        Self::is_any(
            self.src_address.as_deref(),
            self.src_networkconf_id.as_deref(),
            &self.src_firewallgroup_ids,
        )
    }

    /// True when no destination address, network, or group restricts the rule.
    pub fn dst_is_any(&self) -> bool {
        Self::is_any(
            self.dst_address.as_deref(),
            self.dst_networkconf_id.as_deref(),
            &self.dst_firewallgroup_ids,
        )
    }
}

/// Network from `/api/s/{site}/rest/networkconf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    /// `corporate`, `guest`, `wan`, `vlan-only`, or `remote-user-vpn`.
    #[serde(default)]
    pub purpose: String,
    #[serde(rename = "vlan", default, deserialize_with = "flex_opt_u16")]
    pub vlan_id: Option<u16>,
    /// CIDR such as `192.168.1.1/24`.
    #[serde(rename = "ip_subnet")]
    pub subnet: Option<String>,
    #[serde(rename = "dhcpd_enabled", default)]
    pub dhcp_enabled: bool,
}

/// IDS/IPS event from `/api/s/{site}/stat/ips/event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsEvent {
    /// Epoch seconds.
    #[serde(default, deserialize_with = "flex_i64")]
    pub timestamp: i64,
    #[serde(rename = "inner_alert_signature", default)]
    pub signature: String,
    #[serde(rename = "inner_alert_category", default)]
    pub category: String,
    pub src_ip: Option<String>,
    #[serde(rename = "dest_ip")]
    pub dst_ip: Option<String>,
    #[serde(rename = "inner_alert_action", default)]
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_uses_underscore_id() {
        let s: Site =
            serde_json::from_str(r#"{"_id":"5f1","name":"default","desc":"Default"}"#).unwrap();
        assert_eq!(s.id, "5f1");
    }

    #[test]
    fn device_wire_names_and_integer_state() {
        let json = r#"{"mac":"aa:bb:cc:dd:ee:ff","model":"UDMPRO","version":"3.2.12",
                       "type":"udm","adopted":true,"state":1,"ip":"192.168.1.1"}"#;
        let d: AdoptedDevice = serde_json::from_str(json).unwrap();
        assert_eq!(d.firmware_version, "3.2.12");
        assert_eq!(d.device_type, "udm");
        assert_eq!(d.state, DeviceState::Connected);
        assert!(d.name.is_none());
    }

    #[test]
    fn device_state_round_trip_and_unknown() {
        for code in 0..=12 {
            let state = DeviceState::from(code);
            let back = i64::from(state);
            assert!(back == code || state == DeviceState::Unknown);
        }
        assert_eq!(DeviceState::from(99), DeviceState::Unknown);
    }

    #[test]
    fn wlan_defaults_absent_bools() {
        let w: WlanConfig =
            serde_json::from_str(r#"{"_id":"w1","name":"Home","security":"wpapsk"}"#).unwrap();
        assert!(!w.is_guest);
        assert!(!w.enabled);
    }

    #[test]
    fn firewall_rule_any_detection() {
        let json = r#"{"_id":"r1","name":"Allow all","action":"accept","enabled":true,
                       "ruleset":"LAN_IN","src_firewallgroup_ids":[],"dst_firewallgroup_ids":[]}"#;
        let r: FirewallRule = serde_json::from_str(json).unwrap();
        assert!(r.src_is_any() && r.dst_is_any());

        let scoped = FirewallRule {
            src_networkconf_id: Some("net-iot".to_owned()),
            dst_firewallgroup_ids: vec!["grp-lan".to_owned()],
            ..r
        };
        assert!(!scoped.src_is_any());
        assert!(!scoped.dst_is_any());
    }

    #[test]
    fn network_vlan_accepts_int_string_and_empty() {
        for (raw, want) in [("10", Some(10)), ("\"20\"", Some(20)), ("\"\"", None)] {
            let json = format!(
                r#"{{"_id":"n1","name":"LAN","purpose":"corporate","vlan":{raw},
                    "ip_subnet":"192.168.1.1/24","dhcpd_enabled":true}}"#
            );
            let n: NetworkConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(n.vlan_id, want, "vlan={raw}");
            assert_eq!(n.subnet.as_deref(), Some("192.168.1.1/24"));
            assert!(n.dhcp_enabled);
        }
    }

    #[test]
    fn ids_event_wire_names() {
        let json = r#"{"timestamp":"1700000000","inner_alert_signature":"ET SCAN",
                       "inner_alert_category":"Attempted Recon","inner_alert_action":"allowed",
                       "src_ip":"10.0.0.5","dest_ip":"10.0.0.1"}"#;
        let e: IdsEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.timestamp, 1_700_000_000);
        assert_eq!(e.signature, "ET SCAN");
        assert_eq!(e.dst_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(e.action, "allowed");
    }
}
