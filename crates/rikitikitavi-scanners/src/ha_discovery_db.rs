//! Home Assistant discovery tables — auto-generated.
//!
//! Source: <https://github.com/home-assistant/core> `homeassistant/generated/`
//! Files: `zeroconf.py`, `ssdp.py`, `dhcp.py` | Commit: `8e2c2c3cf5c533fa8bc38d2a5432831c7e244ad8` | Retrieved: 2026-09-17
//! Licence: Apache-2.0 (<https://github.com/home-assistant/core/blob/dev/LICENSE.md>), no upstream NOTICE file.
//!
//! Entries: 164 zeroconf matchers over 113 service types, 71 `HomeKit` models, 89
//! SSDP matchers, 103 DHCP MAC prefixes, 169 domain -> `DeviceType` mappings.
//!
//! Not extracted, every DHCP entry naming a `hostname`: 154 AND it with a
//! `macaddress`, 89 use it alone. This tool sees no DHCP traffic and has no reverse
//! DNS, and keeping the MAC half of a two-condition matcher would widen it into a
//! false identification. Also dropped: 42 `registered_devices` entries (no
//! matcher), 2 SSDP matchers keyed on `X_*` vendor extensions, 1 zeroconf matcher
//! using fnmatch character classes.
//!
//! 1 of the 103 MAC prefixes is longer than a 24-bit OUI; the rest name a
//! registrant, whose catalogue usually spans several device classes, so no product
//! class may be read out of them (see [`MacPrefixMatch::finer_than_oui`]).
//!
//! The domain -> `DeviceType` map is ours, not upstream's; HA integration domains
//! are carried verbatim as `device_subtype`. Mapped domains that no carried table
//! can produce are omitted.
//!
//! Regenerate with `uv run python scripts/gen_ha_discovery_db.py --ref 8e2c2c3cf5c533fa8bc38d2a5432831c7e244ad8`.

use rikitikitavi_models::DeviceType;

/// A TXT-property predicate: key, and a `*`/`?` glob over the value.
pub type TxtPredicate = (&'static str, &'static str);

/// One matcher from HA's `generated/zeroconf.py`.
#[derive(Debug, Clone, Copy)]
pub struct ZeroconfMatcher {
    /// Service type, lowercase, no trailing dot (`_hap._tcp.local`).
    pub service_type: &'static str,
    /// HA integration domain.
    pub domain: &'static str,
    /// Glob over the full lowercase instance name, trailing dot included.
    pub name: Option<&'static str>,
    /// TXT predicates that must all hold.
    pub properties: &'static [TxtPredicate],
}

/// One matcher from HA's `generated/ssdp.py`. All present fields must match.
#[derive(Debug, Clone, Copy)]
pub struct SsdpMatcher {
    /// HA integration domain.
    pub domain: &'static str,
    /// Search target from the M-SEARCH response.
    pub st: Option<&'static str>,
    /// Notification type from an SSDP NOTIFY.
    pub nt: Option<&'static str>,
    /// `deviceType` from the `UPnP` device description.
    pub device_type: Option<&'static str>,
    /// `manufacturer` from the `UPnP` device description.
    pub manufacturer: Option<&'static str>,
    /// `manufacturerURL` from the `UPnP` device description.
    pub manufacturer_url: Option<&'static str>,
    /// `modelName` from the `UPnP` device description.
    pub model_name: Option<&'static str>,
    /// `modelDescription` from the `UPnP` device description.
    pub model_description: Option<&'static str>,
}

/// A MAC prefix glob from HA's `generated/dhcp.py`, in uppercase hex nibbles.
///
/// Nibble-granular: most are 6 nibbles (a 3-byte OUI) but some are longer and
/// not byte-aligned, so truncating to `[u8; 3]` would widen them. Only entries
/// whose sole upstream condition is the MAC are carried.
#[derive(Debug, Clone, Copy)]
pub struct MacPrefix {
    /// Uppercase hex nibbles, no separators, no trailing `*`.
    pub nibbles: &'static str,
    /// HA integration domain.
    pub domain: &'static str,
}

/// Longest MAC prefix in the table, in nibbles.
pub const MAX_MAC_PREFIX_NIBBLES: usize = 7;

/// Nibbles in a 24-bit OUI.
pub const OUI_NIBBLES: usize = 6;

/// A hit in [`DHCP_MAC_PREFIXES`]: the domains registering the longest prefix
/// that matched, and that prefix's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPrefixMatch {
    /// Length in nibbles of the prefix that matched.
    pub nibbles: usize,
    /// Every HA integration domain registering that prefix.
    pub domains: Vec<&'static str>,
}

impl MacPrefixMatch {
    /// The prefix is finer than the 24-bit OUI an IEEE vendor lookup already uses.
    ///
    /// Only 1 of the 103 carried prefixes are. A
    /// prefix that is not names the registrant, whose catalogue usually spans
    /// several device classes, so no `DeviceType` may be read out of it.
    #[must_use]
    pub const fn finer_than_oui(&self) -> bool {
        self.nibbles > OUI_NIBBLES
    }
}

/// Match `value` against an fnmatch-style `pattern` supporting `*` and `?`.
///
/// Both are compared bytewise; callers lowercase first.
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi) = (0usize, 0usize);
    // Position of the last `*` and the input position it was matched at.
    let mut star: Option<(usize, usize)> = None;

    while vi < v.len() {
        match p.get(pi) {
            Some(b'*') => {
                star = Some((pi, vi));
                pi += 1;
            }
            Some(b'?') => {
                pi += 1;
                vi += 1;
            }
            Some(&c) if c == v[vi] => {
                pi += 1;
                vi += 1;
            }
            _ => {
                let Some((sp, sv)) = star else { return false };
                pi = sp + 1;
                vi = sv + 1;
                star = Some((sp, vi));
            }
        }
    }

    p[pi..].iter().all(|&c| c == b'*')
}

/// HA integration domains whose zeroconf matchers all hold for this service.
///
/// `full_name` is the complete lowercase instance name with its trailing dot
/// (`shellyplus1-aabbcc._http._tcp.local.`); `txt` is the raw TXT record list.
#[must_use]
pub fn zeroconf_domains(service_type: &str, full_name: &str, txt: &[String]) -> Vec<&'static str> {
    let st = service_type.trim_end_matches('.').to_ascii_lowercase();
    let name = full_name.to_ascii_lowercase();
    let start = ZEROCONF_MATCHERS.partition_point(|m| m.service_type < st.as_str());

    let mut domains: Vec<&'static str> = Vec::new();
    for matcher in &ZEROCONF_MATCHERS[start..] {
        if matcher.service_type != st {
            break;
        }
        if matcher.name.is_some_and(|glob| !glob_match(glob, &name)) {
            continue;
        }
        let props_hold = matcher.properties.iter().all(|&(key, glob)| {
            rikitikitavi_network::mdns::txt_get(txt, key)
                .is_some_and(|value| glob_match(glob, &value.to_ascii_lowercase()))
        });
        if props_hold && !domains.contains(&matcher.domain) {
            domains.push(matcher.domain);
        }
    }
    domains
}

/// HA integration domain for a `HomeKit` accessory model (the `md` TXT key).
///
/// Upstream matches the model exactly, or as a prefix followed by a space or a
/// hyphen; keys themselves contain spaces (`"LIFX Indoor Neon"`), so this is a
/// scan for the longest matching key rather than a binary search.
#[must_use]
pub fn homekit_domain(model: &str) -> Option<&'static str> {
    let model = model.trim();
    let mut best: Option<(usize, &'static str)> = None;
    for &(key, domain) in HOMEKIT_MODELS {
        let matches = model.eq_ignore_ascii_case(key)
            || model
                .get(..key.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(key))
                && matches!(model.as_bytes().get(key.len()), Some(b' ' | b'-'));
        if matches && best.is_none_or(|(len, _)| key.len() > len) {
            best = Some((key.len(), domain));
        }
    }
    best.map(|(_, domain)| domain)
}

/// One hit in [`SSDP_MATCHERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsdpHit {
    /// HA integration domain.
    pub domain: &'static str,
    /// The matcher named something beyond the vendor — `st`, `nt`, `deviceType`,
    /// `modelName` or `modelDescription`.
    ///
    /// A matcher constrained by `manufacturer` alone (`wemo` on "Belkin
    /// International Inc.", `axis` on "AXIS") covers the vendor's whole
    /// catalogue, so it identifies the integration but not the device class.
    pub specific: bool,
}

/// HA integration domains whose SSDP matchers hold for the observed fields.
///
/// A matcher holds when every field it names is present and equal (case-
/// insensitive). Fields not yet fetched are passed as `None` and any matcher
/// naming them is skipped.
#[must_use]
pub fn ssdp_hits(observed: &SsdpFields<'_>) -> Vec<SsdpHit> {
    let mut hits: Vec<SsdpHit> = Vec::new();
    for matcher in SSDP_MATCHERS {
        let pairs = [
            (matcher.st, observed.st),
            (matcher.nt, observed.nt),
            (matcher.device_type, observed.device_type),
            (matcher.manufacturer, observed.manufacturer),
            (matcher.manufacturer_url, observed.manufacturer_url),
            (matcher.model_name, observed.model_name),
            (matcher.model_description, observed.model_description),
        ];
        let constrained = pairs.iter().any(|(want, _)| want.is_some());
        let holds = pairs.iter().all(|&(want, got)| {
            want.is_none_or(|want| got.is_some_and(|got| got.eq_ignore_ascii_case(want)))
        });
        if !constrained || !holds {
            continue;
        }
        let specific = matcher.st.is_some()
            || matcher.nt.is_some()
            || matcher.device_type.is_some()
            || matcher.model_name.is_some()
            || matcher.model_description.is_some();
        if let Some(hit) = hits.iter_mut().find(|h| h.domain == matcher.domain) {
            hit.specific |= specific;
        } else {
            hits.push(SsdpHit {
                domain: matcher.domain,
                specific,
            });
        }
    }
    hits
}

/// Domains of [`ssdp_hits`], in table order.
#[must_use]
pub fn ssdp_domains(observed: &SsdpFields<'_>) -> Vec<&'static str> {
    ssdp_hits(observed).into_iter().map(|h| h.domain).collect()
}

/// Observed SSDP / `UPnP` description fields, for [`ssdp_domains`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SsdpFields<'a> {
    /// `ST` header of the M-SEARCH response.
    pub st: Option<&'a str>,
    /// `NT` header of an SSDP NOTIFY.
    pub nt: Option<&'a str>,
    /// `<deviceType>` of the device description.
    pub device_type: Option<&'a str>,
    /// `<manufacturer>` of the device description.
    pub manufacturer: Option<&'a str>,
    /// `<manufacturerURL>` of the device description.
    pub manufacturer_url: Option<&'a str>,
    /// `<modelName>` of the device description.
    pub model_name: Option<&'a str>,
    /// `<modelDescription>` of the device description.
    pub model_description: Option<&'a str>,
}

/// Longest MAC-prefix hit for a MAC address.
///
/// `mac` may be in any common format; only hex digits are considered. A prefix
/// can be shared by two integrations, so every domain at the longest matching
/// length is returned and none from shorter ones.
#[must_use]
pub fn mac_prefix_match(mac: &str) -> Option<MacPrefixMatch> {
    let nibbles: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .take(MAX_MAC_PREFIX_NIBBLES)
        .collect();

    for len in (1..=nibbles.len()).rev() {
        let want = &nibbles[..len];
        let start = DHCP_MAC_PREFIXES.partition_point(|p| p.nibbles < want);
        let domains: Vec<&'static str> = DHCP_MAC_PREFIXES[start..]
            .iter()
            .take_while(|p| p.nibbles == want)
            .map(|p| p.domain)
            .collect();
        if !domains.is_empty() {
            return Some(MacPrefixMatch {
                nibbles: len,
                domains,
            });
        }
    }
    None
}

/// Our `DeviceType` for an HA integration domain, or `Unknown`.
#[must_use]
pub fn domain_device_type(domain: &str) -> DeviceType {
    DOMAIN_DEVICE_TYPES
        .binary_search_by_key(&domain, |&(d, _)| d)
        .map_or(DeviceType::Unknown, |i| DOMAIN_DEVICE_TYPES[i].1)
}

/// The `DeviceType` all `domains` agree on, else `Unknown`.
#[must_use]
pub fn consensus_device_type(domains: &[&str]) -> DeviceType {
    let mut agreed = DeviceType::Unknown;
    for domain in domains {
        let t = domain_device_type(domain);
        if t == DeviceType::Unknown {
            continue;
        }
        if agreed == DeviceType::Unknown {
            agreed = t;
        } else if agreed != t {
            return DeviceType::Unknown;
        }
    }
    agreed
}

/// Zeroconf matchers, sorted by service type.
#[rustfmt::skip]
static ZEROCONF_MATCHERS: &[ZeroconfMatcher] = &[
    ZeroconfMatcher { service_type: "_aicu-http._tcp.local", domain: "romy", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_airgradient._tcp.local", domain: "airgradient", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_airplay._tcp.local", domain: "apple_tv", name: None, properties: &[("am", "airport*")] },
    ZeroconfMatcher { service_type: "_airplay._tcp.local", domain: "apple_tv", name: None, properties: &[("model", "appletv*")] },
    ZeroconfMatcher { service_type: "_airplay._tcp.local", domain: "apple_tv", name: None, properties: &[("model", "audioaccessory*")] },
    ZeroconfMatcher { service_type: "_airplay._tcp.local", domain: "samsungtv", name: None, properties: &[("manufacturer", "samsung*")] },
    ZeroconfMatcher { service_type: "_airport._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_altruist._tcp.local", domain: "altruist", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_amzn-alexa._tcp.local", domain: "roomba", name: Some("irobot-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_amzn-alexa._tcp.local", domain: "roomba", name: Some("roomba-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_androidtvremote2._tcp.local", domain: "androidtv_remote", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_api._tcp.local", domain: "baf", name: None, properties: &[("model", "haiku*")] },
    ZeroconfMatcher { service_type: "_api._tcp.local", domain: "baf", name: None, properties: &[("model", "i6*")] },
    ZeroconfMatcher { service_type: "_api._udp.local", domain: "guardian", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_appletv-v2._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_axis-video._tcp.local", domain: "axis", name: None, properties: &[("macaddress", "00408c*")] },
    ZeroconfMatcher { service_type: "_axis-video._tcp.local", domain: "axis", name: None, properties: &[("macaddress", "accc8e*")] },
    ZeroconfMatcher { service_type: "_axis-video._tcp.local", domain: "axis", name: None, properties: &[("macaddress", "b8a44f*")] },
    ZeroconfMatcher { service_type: "_axis-video._tcp.local", domain: "axis", name: None, properties: &[("macaddress", "e82725*")] },
    ZeroconfMatcher { service_type: "_axis-video._tcp.local", domain: "doorbird", name: None, properties: &[("macaddress", "1ccae3*")] },
    ZeroconfMatcher { service_type: "_bangolufsen._tcp.local", domain: "bang_olufsen", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_bbxsrv._tcp.local", domain: "blebox", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_bond._tcp.local", domain: "bond", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_companion-link._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_czc._tcp.local", domain: "zha", name: Some("czc*"), properties: &[] },
    ZeroconfMatcher { service_type: "_daap._tcp.local", domain: "forked_daapd", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_deako._tcp.local", domain: "deako", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_devialet-http._tcp.local", domain: "devialet", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_dkapi._tcp.local", domain: "daikin", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_droplet._tcp.local", domain: "droplet", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_dvl-deviceapi._tcp.local", domain: "devolo_home_control", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_dvl-deviceapi._tcp.local", domain: "devolo_home_network", name: None, properties: &[("mt", "*")] },
    ZeroconfMatcher { service_type: "_easylink._tcp.local", domain: "modern_forms", name: Some("wac*"), properties: &[] },
    ZeroconfMatcher { service_type: "_ecobee._tcp.local", domain: "ecobee", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_elg._tcp.local", domain: "elgato", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_elmax-ssl._tcp.local", domain: "elmax", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_enphase-envoy._tcp.local", domain: "enphase_envoy", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_esphomelib._tcp.local", domain: "esphome", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_esphomelib._tcp.local", domain: "zha", name: Some("tube*"), properties: &[] },
    ZeroconfMatcher { service_type: "_fbx-api._tcp.local", domain: "freebox", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_gasleser._tcp.local", domain: "energieleser", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_gaspulse._tcp.local", domain: "energieleser", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_googlecast._tcp.local", domain: "cast", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_hap._tcp.local", domain: "homekit_controller", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_hap._tcp.local", domain: "zwave_me", name: Some("*z.wave-me*"), properties: &[] },
    ZeroconfMatcher { service_type: "_hap._udp.local", domain: "homekit_controller", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_heos-audio._tcp.local", domain: "heos", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_homeconnect._tcp.local", domain: "home_connect", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_homekit._tcp.local", domain: "homekit", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_homewizard._tcp.local", domain: "homewizard", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_hscp._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "airq", name: None, properties: &[("device", "air-q")] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "awair", name: Some("awair*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "bosch_shc", name: Some("bosch shc*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "bsblan", name: Some("bsb-lan*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "eheimdigital", name: Some("eheimdigital._http._tcp.local."), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "hdfury", name: Some("diva-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "hdfury", name: Some("vertex2-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "hdfury", name: Some("vrroom-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "homevolt", name: Some("homevolt*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "indevolt", name: Some("igen_fw*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "lektrico", name: Some("lektrico*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "liebherr", name: Some("liebherr*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "loqed", name: Some("loqed*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "lunatone", name: None, properties: &[("manufacturer", "lunatone industrielle elektronik gmbh"), ("type", "dali-2-*"), ("uid", "*")] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "nam", name: None, properties: &[("manufacturer", "nettigo")] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "nam", name: Some("nam-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "peblar", name: Some("pblr-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "powerfox", name: Some("powerfox*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "powerfox_local", name: Some("powerfox*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "pure_energie", name: Some("smartbridge*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "rachio", name: Some("rachio*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "rainmachine", name: Some("rainmachine*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "shelly", name: Some("shelly*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "slide_local", name: Some("slide*"), properties: &[] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "synology_dsm", name: None, properties: &[("vendor", "synology*")] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "tailwind", name: None, properties: &[("vendor", "tailwind")] },
    ZeroconfMatcher { service_type: "_http._tcp.local", domain: "velux", name: Some("velux_klf_lan_*"), properties: &[] },
    ZeroconfMatcher { service_type: "_hue._tcp.local", domain: "hue", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_hwenergy._tcp.local", domain: "homewizard", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_iometer._tcp.local", domain: "iometer", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_ipp._tcp.local", domain: "ipp", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_ipps._tcp.local", domain: "ipp", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_kiosker._tcp.local", domain: "kiosker", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_kizbox._tcp.local", domain: "overkiz", name: Some("gateway*"), properties: &[] },
    ZeroconfMatcher { service_type: "_kizboxdev._tcp.local", domain: "overkiz", name: Some("gateway*"), properties: &[] },
    ZeroconfMatcher { service_type: "_linkplay._tcp.local", domain: "linkplay", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_linkplay._tcp.local", domain: "wiim", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_lookin._tcp.local", domain: "lookin", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_lutron._tcp.local", domain: "lutron_caseta", name: None, properties: &[("systype", "hwqs*")] },
    ZeroconfMatcher { service_type: "_lutron._tcp.local", domain: "lutron_caseta", name: None, properties: &[("systype", "ra2select*")] },
    ZeroconfMatcher { service_type: "_lutron._tcp.local", domain: "lutron_caseta", name: None, properties: &[("systype", "radiora3*")] },
    ZeroconfMatcher { service_type: "_lutron._tcp.local", domain: "lutron_caseta", name: None, properties: &[("systype", "smartbridge*")] },
    ZeroconfMatcher { service_type: "_mass._tcp.local", domain: "music_assistant", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_matter._tcp.local", domain: "matter", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_matterc._udp.local", domain: "matter", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_mediaremotetv._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_meshcop._udp.local", domain: "thread", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_mieleathome._tcp.local", domain: "miele", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_miio._udp.local", domain: "xiaomi_aqara", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_miio._udp.local", domain: "xiaomi_miio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_miio._udp.local", domain: "yeelight", name: Some("yeelink-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_musc._tcp.local", domain: "bluesound", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_mypv._tcp.local", domain: "my_pv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_nanoleafapi._tcp.local", domain: "nanoleaf", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_nanoleafms._tcp.local", domain: "nanoleaf", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_nrgkick._tcp.local", domain: "nrgkick", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_nut._tcp.local", domain: "nut", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_octoprint._tcp.local", domain: "octoprint", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_openevse._tcp.local", domain: "openevse", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_owserver._tcp.local", domain: "onewire", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_philipstv_rpc._tcp.local", domain: "philips_js", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_philipstv_s_rpc._tcp.local", domain: "philips_js", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_plexmediasvr._tcp.local", domain: "plex", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_plugwise._tcp.local", domain: "plugwise", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_powerhub._udp.local", domain: "bitvis", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_powerview-g3._tcp.local", domain: "hunterdouglas_powerview", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_powerview._tcp.local", domain: "hunterdouglas_powerview", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_prana._tcp.local", domain: "prana", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_printer._tcp.local", domain: "brother", name: Some("brother*"), properties: &[] },
    ZeroconfMatcher { service_type: "_rabbitair._udp.local", domain: "rabbitair", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_raop._tcp.local", domain: "apple_tv", name: None, properties: &[("am", "airport*")] },
    ZeroconfMatcher { service_type: "_raop._tcp.local", domain: "apple_tv", name: None, properties: &[("am", "appletv*")] },
    ZeroconfMatcher { service_type: "_raop._tcp.local", domain: "apple_tv", name: None, properties: &[("am", "audioaccessory*")] },
    ZeroconfMatcher { service_type: "_rio._tcp.local", domain: "russound_rio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_shelly._tcp.local", domain: "shelly", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_sideplay._tcp.local", domain: "ecobee", name: None, properties: &[("mdl", "eb-*")] },
    ZeroconfMatcher { service_type: "_sideplay._tcp.local", domain: "ecobee", name: None, properties: &[("mdl", "ecobee*")] },
    ZeroconfMatcher { service_type: "_sleep-proxy._udp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_slzb-06._tcp.local", domain: "smlight", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_slzb-06._tcp.local", domain: "zha", name: Some("slzb-06*"), properties: &[] },
    ZeroconfMatcher { service_type: "_smoip._tcp.local", domain: "cambridge_audio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_solaredge-modbus._tcp.local", domain: "solaredge_modbus", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_solarman._tcp.local", domain: "solarman", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_sonos._tcp.local", domain: "sonos", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_soundtouch._tcp.local", domain: "soundtouch", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_ssh._tcp.local", domain: "homee", name: Some("homee-*"), properties: &[] },
    ZeroconfMatcher { service_type: "_ssh._tcp.local", domain: "smappee", name: Some("smappee1*"), properties: &[] },
    ZeroconfMatcher { service_type: "_ssh._tcp.local", domain: "smappee", name: Some("smappee2*"), properties: &[] },
    ZeroconfMatcher { service_type: "_ssh._tcp.local", domain: "smappee", name: Some("smappee50*"), properties: &[] },
    ZeroconfMatcher { service_type: "_stream-magic._tcp.local", domain: "cambridge_audio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_stromleser._tcp.local", domain: "energieleser", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_system-bridge._tcp.local", domain: "system_bridge", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_systemnexa2._tcp.local", domain: "systemnexa2", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_tbk_vmc._tcp.local", domain: "flow_it", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_technove-stations._tcp.local", domain: "technove", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_touch-able._tcp.local", domain: "apple_tv", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_tvm._tcp.local", domain: "motionmount", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_uzg-01._tcp.local", domain: "zha", name: Some("uzg-01*"), properties: &[] },
    ZeroconfMatcher { service_type: "_vege._tcp.local", domain: "vegehub", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_viziocast._tcp.local", domain: "vizio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_volumio._tcp.local", domain: "volumio", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_waermeleser._tcp.local", domain: "energieleser", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_wasserleser._tcp.local", domain: "energieleser", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_wattwaechter._tcp.local", domain: "wattwaechter", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_wled._tcp.local", domain: "wled", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_ws._tcp.local", domain: "hotspring", name: Some("watkins_spa*"), properties: &[] },
    ZeroconfMatcher { service_type: "_wyoming._tcp.local", domain: "wyoming", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_xbmc-jsonrpc-h._tcp.local", domain: "kodi", name: None, properties: &[] },
    ZeroconfMatcher { service_type: "_xzg._tcp.local", domain: "zha", name: Some("xzg*"), properties: &[] },
    ZeroconfMatcher { service_type: "_zigate-zigbee-gateway._tcp.local", domain: "zha", name: Some("*zigate*"), properties: &[] },
    ZeroconfMatcher { service_type: "_zigbee-coordinator._tcp.local", domain: "zha", name: Some("*"), properties: &[] },
    ZeroconfMatcher { service_type: "_zigstar_gw._tcp.local", domain: "zha", name: Some("*zigstar*"), properties: &[] },
    ZeroconfMatcher { service_type: "_zwave-js-server._tcp.local", domain: "zwave_js", name: None, properties: &[] },
];

/// `HomeKit` `md` model -> HA integration domain, sorted by model.
#[rustfmt::skip]
static HOMEKIT_MODELS: &[(&str, &str)] = &[
    ("3810X", "roku"),
    ("3820X", "roku"),
    ("4660X", "roku"),
    ("7820X", "roku"),
    ("AC02", "tado"),
    ("Abode", "abode"),
    ("BSB002", "hue"),
    ("C105X", "roku"),
    ("C135X", "roku"),
    ("EB", "ecobee"),
    ("Escea", "escea"),
    ("HHKBridge*", "hive"),
    ("Healthy Home Coach", "netatmo"),
    ("Iota", "abode"),
    ("LIFX A19", "lifx"),
    ("LIFX A21", "lifx"),
    ("LIFX BR30", "lifx"),
    ("LIFX Beam", "lifx"),
    ("LIFX Candle", "lifx"),
    ("LIFX Ceiling", "lifx"),
    ("LIFX Clean", "lifx"),
    ("LIFX Color", "lifx"),
    ("LIFX Colour", "lifx"),
    ("LIFX DLCOL", "lifx"),
    ("LIFX DLWW", "lifx"),
    ("LIFX Dlight", "lifx"),
    ("LIFX Downlight", "lifx"),
    ("LIFX Filament", "lifx"),
    ("LIFX GU10", "lifx"),
    ("LIFX Indoor Neon", "lifx"),
    ("LIFX Lightstrip", "lifx"),
    ("LIFX Luna", "lifx"),
    ("LIFX Mini", "lifx"),
    ("LIFX Neon", "lifx"),
    ("LIFX Nightvision", "lifx"),
    ("LIFX PAR38", "lifx"),
    ("LIFX Permanent Outdoor", "lifx"),
    ("LIFX Pls", "lifx"),
    ("LIFX Plus", "lifx"),
    ("LIFX Round", "lifx"),
    ("LIFX Square", "lifx"),
    ("LIFX String", "lifx"),
    ("LIFX Tile", "lifx"),
    ("LIFX Tube", "lifx"),
    ("LIFX White", "lifx"),
    ("LIFX Z", "lifx"),
    ("NL29", "nanoleaf"),
    ("NL42", "nanoleaf"),
    ("NL47", "nanoleaf"),
    ("NL48", "nanoleaf"),
    ("NL52", "nanoleaf"),
    ("NL59", "nanoleaf"),
    ("NL69", "nanoleaf"),
    ("NL81", "nanoleaf"),
    ("Netatmo Relay", "netatmo"),
    ("PowerView", "hunterdouglas_powerview"),
    ("Presence", "netatmo"),
    ("Rachio", "rachio"),
    ("SPK5", "rainmachine"),
    ("Sensibo", "sensibo"),
    ("Smart Bridge", "lutron_caseta"),
    ("Socket", "wemo"),
    ("TRADFRI", "tradfri"),
    ("Touch HD", "rainmachine"),
    ("Welcome", "netatmo"),
    ("Wemo", "wemo"),
    ("YL*", "yeelight"),
    ("ecobee*", "ecobee"),
    ("iSmartGate", "gogogate2"),
    ("iZone", "izone"),
    ("tado", "tado"),
];

/// SSDP matchers, sorted by domain.
#[rustfmt::skip]
static SSDP_MATCHERS: &[SsdpMatcher] = &[
    SsdpMatcher { domain: "arcam_fmj", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("arcam"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "axis", st: None, nt: None, device_type: None, manufacturer: Some("axis"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "braviatv", st: Some("urn:schemas-sony-com:service:scalarwebapi:1"), nt: None, device_type: None, manufacturer: Some("sony corporation"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "control4", st: Some("c4:director"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "deconz", st: None, nt: None, device_type: None, manufacturer: Some("royal philips electronics"), manufacturer_url: Some("http://www.dresden-elektronik.de"), model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-denon-com:device:aiosdevice:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-denon-com:device:aiosdevice:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-denon-com:device:aiosdevice:1"), manufacturer: Some("denon professional"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-denon-com:device:aiosdevice:1"), manufacturer: Some("marantz"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("denon professional"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("marantz"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: Some("denon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: Some("denon professional"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "denonavr", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: Some("marantz"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "directv", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: Some("directv"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dmr", st: Some("urn:schemas-upnp-org:device:mediarenderer:1"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dmr", st: Some("urn:schemas-upnp-org:device:mediarenderer:2"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dmr", st: Some("urn:schemas-upnp-org:device:mediarenderer:3"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:3"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dms", st: Some("urn:schemas-upnp-org:device:mediaserver:1"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:1"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dms", st: Some("urn:schemas-upnp-org:device:mediaserver:2"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:2"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dms", st: Some("urn:schemas-upnp-org:device:mediaserver:3"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:3"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "dlna_dms", st: Some("urn:schemas-upnp-org:device:mediaserver:4"), nt: None, device_type: Some("urn:schemas-upnp-org:device:mediaserver:4"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "fritz", st: Some("urn:schemas-upnp-org:device:fritzbox:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "fritzbox", st: Some("urn:schemas-upnp-org:device:fritzbox:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "frontier_silicon", st: Some("urn:schemas-frontier-silicon-com:undok:fsapi:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "harman_luxury", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("harman luxury audio"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "harman_luxury", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("harman luxury audio"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "harmony", st: None, nt: None, device_type: Some("urn:myharmony-com:device:harmony:1"), manufacturer: Some("logitech"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "hegel", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("hegel"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "heos", st: Some("urn:schemas-denon-com:device:act-denon:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "huawei_lte", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("huawei"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "huawei_lte", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("huawei technologies co., ltd."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "huawei_lte", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("soyea technology co., ltd."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "hyperion", st: Some("urn:hyperion-project.org:device:basic:1"), nt: None, device_type: None, manufacturer: Some("hyperion open source ambient lighting"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "imeon_inverter", st: Some("upnp:rootdevice"), nt: None, device_type: Some("urn:schemas-upnp-org:device:basic:1"), manufacturer: Some("imeon"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "isy994", st: None, nt: None, device_type: Some("urn:udi-com:device:x_insteon_lighting_device:1"), manufacturer: Some("universal devices inc."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "kaleidescape", st: None, nt: None, device_type: Some("schemas-upnp-org:device:basic:1"), manufacturer: Some("kaleidescape, inc."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "keenetic_ndms2", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("keenetic ltd."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "keenetic_ndms2", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("zyxel communications corp."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "lametric", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:lametric:1"), manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "lyngdorf", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("lyngdorf"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "lyngdorf", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("steinway lyngdorf"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("inanoleaf:nl81"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("nanoleaf:nl29"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("nanoleaf:nl42"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("nanoleaf:nl52"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("nanoleaf:nl69"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "nanoleaf", st: Some("nanoleaf_aurora:light"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "netgear", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), manufacturer: Some("netgear, inc."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "octoprint", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:basic:1"), manufacturer: Some("the octoprint project"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("onkyo"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("onkyo & pioneer corporation"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:1"), manufacturer: Some("pioneer"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("onkyo"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("onkyo & pioneer corporation"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:2"), manufacturer: Some("pioneer"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:3"), manufacturer: Some("onkyo"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:3"), manufacturer: Some("onkyo & pioneer corporation"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "onkyo", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:mediarenderer:3"), manufacturer: Some("pioneer"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "openhome", st: Some("urn:av-openhome-org:service:product:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "openhome", st: Some("urn:av-openhome-org:service:product:2"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "openhome", st: Some("urn:av-openhome-org:service:product:3"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "openhome", st: Some("urn:av-openhome-org:service:product:4"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "roku", st: Some("roku:ecp"), nt: None, device_type: Some("urn:roku-com:device:player:1-0"), manufacturer: Some("roku"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "samsungtv", st: Some("urn:schemas-upnp-org:service:renderingcontrol:1"), nt: None, device_type: None, manufacturer: Some("samsung"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "samsungtv", st: Some("urn:schemas-upnp-org:service:renderingcontrol:1"), nt: None, device_type: None, manufacturer: Some("samsung electronics"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "samsungtv", st: Some("urn:samsung.com:device:remotecontrolreceiver:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "samsungtv", st: Some("urn:samsung.com:service:maintvagent2:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "songpal", st: Some("urn:schemas-sony-com:service:scalarwebapi:1"), nt: None, device_type: None, manufacturer: Some("sony corporation"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "sonos", st: Some("urn:schemas-upnp-org:device:zoneplayer:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "syncthru", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:printer:1"), manufacturer: Some("samsung electronics"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "synology_dsm", st: None, nt: None, device_type: Some("urn:schemas-upnp-org:device:basic:1"), manufacturer: Some("synology"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "unifi_discovery", st: None, nt: None, device_type: None, manufacturer: Some("ubiquiti networks"), manufacturer_url: None, model_name: None, model_description: Some("unifi dream machine") },
    SsdpMatcher { domain: "unifi_discovery", st: None, nt: None, device_type: None, manufacturer: Some("ubiquiti networks"), manufacturer_url: None, model_name: None, model_description: Some("unifi dream machine pro") },
    SsdpMatcher { domain: "unifi_discovery", st: None, nt: None, device_type: None, manufacturer: Some("ubiquiti networks"), manufacturer_url: None, model_name: None, model_description: Some("unifi dream machine pro max") },
    SsdpMatcher { domain: "unifi_discovery", st: None, nt: None, device_type: None, manufacturer: Some("ubiquiti networks"), manufacturer_url: None, model_name: None, model_description: Some("unifi dream machine se") },
    SsdpMatcher { domain: "upnp", st: None, nt: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "upnp", st: None, nt: Some("urn:schemas-upnp-org:device:internetgatewaydevice:2"), device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "upnp", st: Some("urn:schemas-upnp-org:device:internetgatewaydevice:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "upnp", st: Some("urn:schemas-upnp-org:device:internetgatewaydevice:2"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "webostv", st: Some("urn:lge-com:service:webos-second-screen:1"), nt: None, device_type: None, manufacturer: None, manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "wemo", st: None, nt: None, device_type: None, manufacturer: Some("belkin international inc."), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "wilight", st: None, nt: None, device_type: None, manufacturer: Some("all automacao ltda"), manufacturer_url: None, model_name: None, model_description: None },
    SsdpMatcher { domain: "xbox", st: None, nt: None, device_type: None, manufacturer: Some("microsoft corporation"), manufacturer_url: None, model_name: Some("xbox 360"), model_description: None },
    SsdpMatcher { domain: "xbox", st: None, nt: None, device_type: None, manufacturer: Some("microsoft corporation"), manufacturer_url: None, model_name: Some("xbox one"), model_description: None },
    SsdpMatcher { domain: "yamaha_musiccast", st: None, nt: None, device_type: None, manufacturer: Some("yamaha corporation"), manufacturer_url: None, model_name: None, model_description: None },
];

/// DHCP MAC prefixes, sorted by nibble string.
#[rustfmt::skip]
static DHCP_MAC_PREFIXES: &[MacPrefix] = &[
    MacPrefix { nibbles: "0003AC", domain: "fronius" },
    MacPrefix { nibbles: "000463", domain: "bosch_alarm" },
    MacPrefix { nibbles: "000EF3", domain: "insteon" },
    MacPrefix { nibbles: "001527", domain: "balboa" },
    MacPrefix { nibbles: "0016D0", domain: "fumis" },
    MacPrefix { nibbles: "001E42", domain: "teltonika" },
    MacPrefix { nibbles: "0023C1", domain: "verisure" },
    MacPrefix { nibbles: "0023D5", domain: "wmspro" },
    MacPrefix { nibbles: "0024E4", domain: "withings" },
    MacPrefix { nibbles: "00409D", domain: "elkm1" },
    MacPrefix { nibbles: "00D9D1", domain: "playstation_network" },
    MacPrefix { nibbles: "00E421", domain: "playstation_network" },
    MacPrefix { nibbles: "09E29", domain: "playstation_network" },
    MacPrefix { nibbles: "0CFE45", domain: "playstation_network" },
    MacPrefix { nibbles: "105A17", domain: "tuya" },
    MacPrefix { nibbles: "109C70", domain: "prusalink" },
    MacPrefix { nibbles: "10D561", domain: "tuya" },
    MacPrefix { nibbles: "1869D8", domain: "tuya" },
    MacPrefix { nibbles: "18B430", domain: "nest" },
    MacPrefix { nibbles: "18E829", domain: "unifi_discovery" },
    MacPrefix { nibbles: "1C4D89", domain: "imou" },
    MacPrefix { nibbles: "1C98C1", domain: "playstation_network" },
    MacPrefix { nibbles: "209727", domain: "teltonika" },
    MacPrefix { nibbles: "245A4C", domain: "unifi_discovery" },
    MacPrefix { nibbles: "245EBE", domain: "qnap_qsw" },
    MacPrefix { nibbles: "249E7D", domain: "roborock" },
    MacPrefix { nibbles: "24DFA7", domain: "broadlink" },
    MacPrefix { nibbles: "265A4C", domain: "unifi_discovery" },
    MacPrefix { nibbles: "280DFC", domain: "playstation_network" },
    MacPrefix { nibbles: "2CCC44", domain: "playstation_network" },
    MacPrefix { nibbles: "302450", domain: "imou" },
    MacPrefix { nibbles: "34E6E6", domain: "lg_thinq" },
    MacPrefix { nibbles: "34EA34", domain: "broadlink" },
    MacPrefix { nibbles: "381F8D", domain: "tuya" },
    MacPrefix { nibbles: "38AF29", domain: "imou" },
    MacPrefix { nibbles: "3CE36B", domain: "imou" },
    MacPrefix { nibbles: "3CEF8C", domain: "imou" },
    MacPrefix { nibbles: "444F8E", domain: "wiz" },
    MacPrefix { nibbles: "4844F7", domain: "samsungtv" },
    MacPrefix { nibbles: "508A06", domain: "tuya" },
    MacPrefix { nibbles: "5C843C", domain: "playstation_network" },
    MacPrefix { nibbles: "605BB4", domain: "playstation_network" },
    MacPrefix { nibbles: "606BBD", domain: "samsungtv" },
    MacPrefix { nibbles: "641666", domain: "nest" },
    MacPrefix { nibbles: "641CB0", domain: "samsungtv" },
    MacPrefix { nibbles: "64DBA0", domain: "sleepiq" },
    MacPrefix { nibbles: "68572D", domain: "tuya" },
    MacPrefix { nibbles: "68D79A", domain: "unifi_discovery" },
    MacPrefix { nibbles: "6C2990", domain: "wiz" },
    MacPrefix { nibbles: "70662A", domain: "playstation_network" },
    MacPrefix { nibbles: "708976", domain: "tuya" },
    MacPrefix { nibbles: "74ACB9", domain: "unifi_discovery" },
    MacPrefix { nibbles: "780F77", domain: "broadlink" },
    MacPrefix { nibbles: "784558", domain: "unifi_discovery" },
    MacPrefix { nibbles: "78C881", domain: "playstation_network" },
    MacPrefix { nibbles: "7CF666", domain: "tuya" },
    MacPrefix { nibbles: "802AA8", domain: "unifi_discovery" },
    MacPrefix { nibbles: "8060B7", domain: "playstation_network" },
    MacPrefix { nibbles: "84E342", domain: "tuya" },
    MacPrefix { nibbles: "84E657", domain: "playstation_network" },
    MacPrefix { nibbles: "8CC8CD", domain: "samsungtv" },
    MacPrefix { nibbles: "8CEA48", domain: "samsungtv" },
    MacPrefix { nibbles: "906A94", domain: "imou" },
    MacPrefix { nibbles: "986D35C", domain: "my_pv" },
    MacPrefix { nibbles: "9C37CB", domain: "playstation_network" },
    MacPrefix { nibbles: "9CADEF", domain: "obihai" },
    MacPrefix { nibbles: "A043B0", domain: "broadlink" },
    MacPrefix { nibbles: "A0BD1D", domain: "imou" },
    MacPrefix { nibbles: "A47EFA", domain: "withings" },
    MacPrefix { nibbles: "A83162", domain: "imou" },
    MacPrefix { nibbles: "A8474A", domain: "playstation_network" },
    MacPrefix { nibbles: "A8BB50", domain: "wiz" },
    MacPrefix { nibbles: "AC3DFA", domain: "imou" },
    MacPrefix { nibbles: "AC8995", domain: "playstation_network" },
    MacPrefix { nibbles: "B04A39", domain: "roborock" },
    MacPrefix { nibbles: "B40AD8", domain: "playstation_network" },
    MacPrefix { nibbles: "B4430D", domain: "broadlink" },
    MacPrefix { nibbles: "B44C3B", domain: "imou" },
    MacPrefix { nibbles: "B4FBE4", domain: "unifi_discovery" },
    MacPrefix { nibbles: "B87424", domain: "vicare" },
    MacPrefix { nibbles: "BC60A7", domain: "playstation_network" },
    MacPrefix { nibbles: "C863F1", domain: "playstation_network" },
    MacPrefix { nibbles: "C8F742", domain: "broadlink" },
    MacPrefix { nibbles: "D073D5", domain: "lifx" },
    MacPrefix { nibbles: "D44B5E", domain: "playstation_network" },
    MacPrefix { nibbles: "D4A651", domain: "tuya" },
    MacPrefix { nibbles: "D81F12", domain: "tuya" },
    MacPrefix { nibbles: "D8A011", domain: "wiz" },
    MacPrefix { nibbles: "D8D5B9", domain: "rainforest_eagle" },
    MacPrefix { nibbles: "D8EB46", domain: "nest" },
    MacPrefix { nibbles: "E063DA", domain: "unifi_discovery" },
    MacPrefix { nibbles: "E81656", domain: "broadlink" },
    MacPrefix { nibbles: "E84F25", domain: "airzone" },
    MacPrefix { nibbles: "E86E3A", domain: "playstation_network" },
    MacPrefix { nibbles: "E87072", domain: "broadlink" },
    MacPrefix { nibbles: "EC0BAE", domain: "broadlink" },
    MacPrefix { nibbles: "EC71DB", domain: "reolink" },
    MacPrefix { nibbles: "F09FC2", domain: "unifi_discovery" },
    MacPrefix { nibbles: "F47B5E", domain: "samsungtv" },
    MacPrefix { nibbles: "F8461C", domain: "playstation_network" },
    MacPrefix { nibbles: "F8D0AC", domain: "playstation_network" },
    MacPrefix { nibbles: "FC0FE6", domain: "playstation_network" },
    MacPrefix { nibbles: "FCB69D", domain: "imou" },
];

/// HA integration domain -> `DeviceType`, sorted by domain. Ours, not upstream's.
#[rustfmt::skip]
static DOMAIN_DEVICE_TYPES: &[(&str, DeviceType)] = &[
    ("abode", DeviceType::Hub),
    ("airgradient", DeviceType::Sensor),
    ("airq", DeviceType::Sensor),
    ("airzone", DeviceType::Thermostat),
    ("altruist", DeviceType::Sensor),
    ("androidtv_remote", DeviceType::MediaPlayer),
    ("apple_tv", DeviceType::MediaPlayer),
    ("arcam_fmj", DeviceType::MediaPlayer),
    ("awair", DeviceType::Sensor),
    ("axis", DeviceType::Camera),
    ("baf", DeviceType::IoT),
    ("balboa", DeviceType::Appliance),
    ("bang_olufsen", DeviceType::Speaker),
    ("blebox", DeviceType::IoT),
    ("bluesound", DeviceType::Speaker),
    ("bond", DeviceType::Hub),
    ("bosch_alarm", DeviceType::Hub),
    ("bosch_shc", DeviceType::Hub),
    ("braviatv", DeviceType::SmartTv),
    ("broadlink", DeviceType::Hub),
    ("brother", DeviceType::Printer),
    ("bsblan", DeviceType::Thermostat),
    ("cambridge_audio", DeviceType::Speaker),
    ("cast", DeviceType::MediaPlayer),
    ("control4", DeviceType::Hub),
    ("daikin", DeviceType::Thermostat),
    ("deako", DeviceType::IoT),
    ("deconz", DeviceType::Hub),
    ("denonavr", DeviceType::MediaPlayer),
    ("devialet", DeviceType::Speaker),
    ("devolo_home_control", DeviceType::Hub),
    ("directv", DeviceType::MediaPlayer),
    ("dlna_dmr", DeviceType::MediaPlayer),
    ("dlna_dms", DeviceType::MediaPlayer),
    ("doorbird", DeviceType::Doorbell),
    ("droplet", DeviceType::Sensor),
    ("ecobee", DeviceType::Thermostat),
    ("eheimdigital", DeviceType::Appliance),
    ("elgato", DeviceType::IoT),
    ("elkm1", DeviceType::Hub),
    ("energieleser", DeviceType::Sensor),
    ("enphase_envoy", DeviceType::Inverter),
    ("escea", DeviceType::Appliance),
    ("esphome", DeviceType::IoT),
    ("forked_daapd", DeviceType::MediaPlayer),
    ("freebox", DeviceType::Router),
    ("fritz", DeviceType::Router),
    ("fritzbox", DeviceType::Router),
    ("fronius", DeviceType::Inverter),
    ("frontier_silicon", DeviceType::MediaPlayer),
    ("fumis", DeviceType::Appliance),
    ("gogogate2", DeviceType::SmartLock),
    ("harman_luxury", DeviceType::Speaker),
    ("harmony", DeviceType::Hub),
    ("hdfury", DeviceType::MediaPlayer),
    ("hegel", DeviceType::MediaPlayer),
    ("heos", DeviceType::Speaker),
    ("hive", DeviceType::Hub),
    ("home_connect", DeviceType::Appliance),
    ("homee", DeviceType::Hub),
    ("homekit", DeviceType::Hub),
    ("homekit_controller", DeviceType::Hub),
    ("homevolt", DeviceType::Inverter),
    ("hotspring", DeviceType::Appliance),
    ("huawei_lte", DeviceType::Router),
    ("hue", DeviceType::Hub),
    ("hunterdouglas_powerview", DeviceType::IoT),
    ("hyperion", DeviceType::MediaPlayer),
    ("imeon_inverter", DeviceType::Inverter),
    ("imou", DeviceType::Camera),
    ("indevolt", DeviceType::Inverter),
    ("insteon", DeviceType::Hub),
    ("iometer", DeviceType::Sensor),
    ("ipp", DeviceType::Printer),
    ("isy994", DeviceType::Hub),
    ("izone", DeviceType::Thermostat),
    ("kaleidescape", DeviceType::MediaPlayer),
    ("keenetic_ndms2", DeviceType::Router),
    ("kodi", DeviceType::MediaPlayer),
    ("lametric", DeviceType::IoT),
    ("lektrico", DeviceType::EvCharger),
    ("lg_thinq", DeviceType::Appliance),
    ("liebherr", DeviceType::Appliance),
    ("lifx", DeviceType::IoT),
    ("linkplay", DeviceType::Speaker),
    ("lookin", DeviceType::IoT),
    ("loqed", DeviceType::SmartLock),
    ("lunatone", DeviceType::IoT),
    ("lutron_caseta", DeviceType::Hub),
    ("lyngdorf", DeviceType::MediaPlayer),
    ("miele", DeviceType::Appliance),
    ("modern_forms", DeviceType::IoT),
    ("music_assistant", DeviceType::MediaPlayer),
    ("my_pv", DeviceType::Inverter),
    ("nam", DeviceType::Sensor),
    ("nanoleaf", DeviceType::IoT),
    ("netgear", DeviceType::Router),
    ("nrgkick", DeviceType::EvCharger),
    ("octoprint", DeviceType::Printer3d),
    ("onewire", DeviceType::Sensor),
    ("onkyo", DeviceType::MediaPlayer),
    ("openevse", DeviceType::EvCharger),
    ("openhome", DeviceType::MediaPlayer),
    ("overkiz", DeviceType::Hub),
    ("peblar", DeviceType::EvCharger),
    ("philips_js", DeviceType::SmartTv),
    ("playstation_network", DeviceType::GameConsole),
    ("plex", DeviceType::MediaPlayer),
    ("plugwise", DeviceType::Thermostat),
    ("powerfox", DeviceType::Sensor),
    ("powerfox_local", DeviceType::Sensor),
    ("prana", DeviceType::Appliance),
    ("prusalink", DeviceType::Printer3d),
    ("pure_energie", DeviceType::Sensor),
    ("qnap_qsw", DeviceType::Switch),
    ("rabbitair", DeviceType::Appliance),
    ("rachio", DeviceType::IoT),
    ("rainforest_eagle", DeviceType::Sensor),
    ("rainmachine", DeviceType::IoT),
    ("reolink", DeviceType::Camera),
    ("roborock", DeviceType::Vacuum),
    ("roku", DeviceType::MediaPlayer),
    ("romy", DeviceType::Vacuum),
    ("roomba", DeviceType::Vacuum),
    ("russound_rio", DeviceType::Speaker),
    ("samsungtv", DeviceType::SmartTv),
    ("sensibo", DeviceType::Thermostat),
    ("shelly", DeviceType::SmartPlug),
    ("sleepiq", DeviceType::Sensor),
    ("slide_local", DeviceType::IoT),
    ("smappee", DeviceType::Sensor),
    ("smlight", DeviceType::Hub),
    ("solaredge_modbus", DeviceType::Inverter),
    ("solarman", DeviceType::Inverter),
    ("songpal", DeviceType::Speaker),
    ("sonos", DeviceType::Speaker),
    ("soundtouch", DeviceType::Speaker),
    ("syncthru", DeviceType::Printer),
    ("synology_dsm", DeviceType::Nas),
    ("system_bridge", DeviceType::Desktop),
    ("tado", DeviceType::Thermostat),
    ("tailwind", DeviceType::SmartLock),
    ("technove", DeviceType::EvCharger),
    ("teltonika", DeviceType::Router),
    ("tradfri", DeviceType::Hub),
    ("tuya", DeviceType::IoT),
    ("vegehub", DeviceType::Sensor),
    ("velux", DeviceType::IoT),
    ("verisure", DeviceType::Hub),
    ("vicare", DeviceType::Thermostat),
    ("vizio", DeviceType::SmartTv),
    ("volumio", DeviceType::MediaPlayer),
    ("wattwaechter", DeviceType::Sensor),
    ("webostv", DeviceType::SmartTv),
    ("wemo", DeviceType::SmartPlug),
    ("wiim", DeviceType::Speaker),
    ("wilight", DeviceType::IoT),
    ("withings", DeviceType::Sensor),
    ("wiz", DeviceType::IoT),
    ("wled", DeviceType::IoT),
    ("wmspro", DeviceType::Hub),
    ("xbox", DeviceType::GameConsole),
    ("xiaomi_aqara", DeviceType::IoT),
    ("xiaomi_miio", DeviceType::IoT),
    ("yamaha_musiccast", DeviceType::MediaPlayer),
    ("yeelight", DeviceType::IoT),
    ("zha", DeviceType::Hub),
    ("zwave_js", DeviceType::Hub),
    ("zwave_me", DeviceType::Hub),
];

#[cfg(test)]
mod tests;
