#!/usr/bin/env python3
"""Generate `ha_discovery_db.rs` from Home Assistant's generated discovery tables.

Home Assistant's `homeassistant/generated/{zeroconf,ssdp,dhcp}.py` are machine-
generated indexes of every integration's discovery matchers. They are the largest
Apache-2.0 corpus that maps an observable network artefact (mDNS service type,
SSDP header set, MAC prefix) onto a concrete product family — finer than an OUI
vendor name, which is all `oui_db.rs` can give.

Upstream is Apache-2.0 (`LICENSE.md` at the repository root, no NOTICE file).
Extracted fields only; integration domains are kept verbatim as `device_subtype`.
The domain -> `DeviceType` map below is ours, not upstream's.

Deliberate omissions:
  * Every DHCP entry carrying a `hostname` — we observe no DHCP traffic and have
    no reverse DNS, so the hostname conjunct cannot be evaluated. This drops the
    hostname-only matchers AND the `macaddress`+`hostname` ones: keeping the MAC
    half of a two-condition matcher would widen it into a false identification
    (HA's `august` rows pair `connect`/`august*` with WNC and AMPAK module OUIs).
  * DHCP `registered_devices: True` entries — no matcher at all, would encode as
    match-everything.
  * SSDP matchers keyed on `X_*` vendor extensions — we do not parse those fields.
  * Zeroconf globs using fnmatch character classes (`[...]`) — the glob matcher
    here implements `*` and `?` only.

Usage:
    uv run python scripts/gen_ha_discovery_db.py [--ref <sha>] \
        > crates/rikitikitavi-scanners/src/ha_discovery_db.rs
"""

from __future__ import annotations

import argparse
import ast
import datetime
import sys
import textwrap
import urllib.request

# The snapshot recorded in THIRD-PARTY-NOTICES.md. `dev` is a moving branch, so
# regeneration pins this by default and `--ref` selects another commit.
DEFAULT_REF = "8e2c2c3cf5c533fa8bc38d2a5432831c7e244ad8"
BASE = "https://raw.githubusercontent.com/home-assistant/core"
SOURCE_FILES = ("zeroconf", "ssdp", "dhcp")
LICENCE_URL = "https://github.com/home-assistant/core/blob/dev/LICENSE.md"

# Nibbles in a 24-bit OUI. A DHCP prefix this short names a registrant, not a
# product, so the Rust side refuses to derive a `DeviceType` from it.
OUI_NIBBLES = 6

# SSDP matcher keys we can evaluate: five come from the M-SEARCH response or the
# fetched device description, `nt` is the notify-type twin of `st`.
SSDP_KEYS = [
    ("st", "st"),
    ("nt", "nt"),
    ("deviceType", "device_type"),
    ("manufacturer", "manufacturer"),
    ("manufacturerURL", "manufacturer_url"),
    ("modelName", "model_name"),
    ("modelDescription", "model_description"),
]

# Our mapping from HA integration domain to `DeviceType`. Only domains we are
# confident about appear; everything else stays `Unknown` and is reported through
# `device_subtype` (the domain string) alone.
DOMAIN_TYPES: dict[str, str] = {
    # Routers / network gear
    "freebox": "Router",
    "fritz": "Router",
    "fritzbox": "Router",
    "huawei_lte": "Router",
    "keenetic_ndms2": "Router",
    "netgear": "Router",
    "teltonika": "Router",
    "qnap_qsw": "Switch",
    # No `unifi_discovery`: its DHCP prefixes are company-wide Ubiquiti OUIs and
    # its SSDP matchers name Dream Machine gateways, not access points.
    # Storage
    "synology_dsm": "Nas",
    # Printers
    "brother": "Printer",
    "ipp": "Printer",
    "syncthru": "Printer",
    "octoprint": "Printer3d",
    "prusalink": "Printer3d",
    # Cameras / doorbells
    "axis": "Camera",
    "blink": "Camera",
    "imou": "Camera",
    "reolink": "Camera",
    "doorbird": "Doorbell",
    # Televisions
    "braviatv": "SmartTv",
    "philips_js": "SmartTv",
    "samsungtv": "SmartTv",
    "vizio": "SmartTv",
    "webostv": "SmartTv",
    # Media players / receivers
    "androidtv_remote": "MediaPlayer",
    "apple_tv": "MediaPlayer",
    "arcam_fmj": "MediaPlayer",
    "cast": "MediaPlayer",
    "denonavr": "MediaPlayer",
    "directv": "MediaPlayer",
    "dlna_dmr": "MediaPlayer",
    "dlna_dms": "MediaPlayer",
    "forked_daapd": "MediaPlayer",
    "frontier_silicon": "MediaPlayer",
    "hdfury": "MediaPlayer",
    "hegel": "MediaPlayer",
    "hyperion": "MediaPlayer",
    "kaleidescape": "MediaPlayer",
    "kodi": "MediaPlayer",
    "lyngdorf": "MediaPlayer",
    "music_assistant": "MediaPlayer",
    "onkyo": "MediaPlayer",
    "openhome": "MediaPlayer",
    "plex": "MediaPlayer",
    "roku": "MediaPlayer",
    "squeezebox": "MediaPlayer",
    "volumio": "MediaPlayer",
    "yamaha_musiccast": "MediaPlayer",
    # Speakers
    "bang_olufsen": "Speaker",
    "bluesound": "Speaker",
    "cambridge_audio": "Speaker",
    "devialet": "Speaker",
    "harman_luxury": "Speaker",
    "heos": "Speaker",
    "linkplay": "Speaker",
    "russound_rio": "Speaker",
    "songpal": "Speaker",
    "sonos": "Speaker",
    "soundtouch": "Speaker",
    "wiim": "Speaker",
    # Consoles
    "playstation_network": "GameConsole",
    "xbox": "GameConsole",
    # Hubs, bridges and alarm panels: aggregation points holding other
    # devices' credentials.
    "abode": "Hub",
    "bond": "Hub",
    "bosch_alarm": "Hub",
    "bosch_shc": "Hub",
    "broadlink": "Hub",
    "control4": "Hub",
    "deconz": "Hub",
    "devolo_home_control": "Hub",
    "elkm1": "Hub",
    "harmony": "Hub",
    "hive": "Hub",
    "homee": "Hub",
    "homekit": "Hub",
    "homekit_controller": "Hub",
    "hue": "Hub",
    "insteon": "Hub",
    "isy994": "Hub",
    "lutron_caseta": "Hub",
    "overkiz": "Hub",
    "simplisafe": "Hub",
    "smartthings": "Hub",
    "smlight": "Hub",
    "somfy_mylink": "Hub",
    "tradfri": "Hub",
    "verisure": "Hub",
    "wmspro": "Hub",
    "zha": "Hub",
    "zwave_js": "Hub",
    "zwave_me": "Hub",
    # Locks and openers
    "august": "SmartLock",
    "gogogate2": "SmartLock",
    "loqed": "SmartLock",
    "tailwind": "SmartLock",
    "yale": "SmartLock",
    # Climate control
    "actron_air": "Thermostat",
    "airzone": "Thermostat",
    "bsblan": "Thermostat",
    "daikin": "Thermostat",
    "ecobee": "Thermostat",
    "incomfort": "Thermostat",
    "izone": "Thermostat",
    "lyric": "Thermostat",
    "nexia": "Thermostat",
    "nobo_hub": "Thermostat",
    "nuheat": "Thermostat",
    "plugwise": "Thermostat",
    "radiotherm": "Thermostat",
    "sensibo": "Thermostat",
    "tado": "Thermostat",
    "toon": "Thermostat",
    "vicare": "Thermostat",
    # EV charging
    "lektrico": "EvCharger",
    "nrgkick": "EvCharger",
    "openevse": "EvCharger",
    "peblar": "EvCharger",
    "technove": "EvCharger",
    "tesla_wall_connector": "EvCharger",
    # Solar / battery / energy gateways
    "enphase_envoy": "Inverter",
    "fronius": "Inverter",
    "homevolt": "Inverter",
    "imeon_inverter": "Inverter",
    "indevolt": "Inverter",
    "my_pv": "Inverter",
    "sma": "Inverter",
    "solaredge": "Inverter",
    "solaredge_modbus": "Inverter",
    "solarman": "Inverter",
    # Vacuums
    "roborock": "Vacuum",
    "roomba": "Vacuum",
    "romy": "Vacuum",
    # Plugs and relays
    "shelly": "SmartPlug",
    "wemo": "SmartPlug",
    # Sensors and meters
    "airgradient": "Sensor",
    "airq": "Sensor",
    "airthings": "Sensor",
    "altruist": "Sensor",
    "awair": "Sensor",
    "droplet": "Sensor",
    "emonitor": "Sensor",
    "energieleser": "Sensor",
    "iometer": "Sensor",
    "nam": "Sensor",
    "onewire": "Sensor",
    "powerfox": "Sensor",
    "powerfox_local": "Sensor",
    "pure_energie": "Sensor",
    "rainforest_eagle": "Sensor",
    "sense": "Sensor",
    "sleepiq": "Sensor",
    "smappee": "Sensor",
    "vegehub": "Sensor",
    "wattwaechter": "Sensor",
    "withings": "Sensor",
    # White goods and other mains appliances
    "balboa": "Appliance",
    "eheimdigital": "Appliance",
    "escea": "Appliance",
    "fumis": "Appliance",
    "guntamatic": "Appliance",
    "home_connect": "Appliance",
    "hotspring": "Appliance",
    "lg_thinq": "Appliance",
    "liebherr": "Appliance",
    "miele": "Appliance",
    "palazzetti": "Appliance",
    "prana": "Appliance",
    "rabbitair": "Appliance",
    "screenlogic": "Appliance",
    "steamist": "Appliance",
    # Lighting, blinds, small IoT
    "baf": "IoT",
    "blebox": "IoT",
    "deako": "IoT",
    "elgato": "IoT",
    "esphome": "IoT",
    "flux_led": "IoT",
    "hunterdouglas_powerview": "IoT",
    "lametric": "IoT",
    "lifx": "IoT",
    "lookin": "IoT",
    "lunatone": "IoT",
    "modern_forms": "IoT",
    "nanoleaf": "IoT",
    "rachio": "IoT",
    "rainmachine": "IoT",
    "slide_local": "IoT",
    "tuya": "IoT",
    "velux": "IoT",
    "wilight": "IoT",
    "wiz": "IoT",
    "wled": "IoT",
    "xiaomi_aqara": "IoT",
    "xiaomi_miio": "IoT",
    "yeelight": "IoT",
    # Hosts
    "system_bridge": "Desktop",
    # Matter/Thread are protocol roles, not device classes; see `mdns.rs`.
}


def fetch(ref: str, name: str) -> str:
    url = f"{BASE}/{ref}/homeassistant/generated/{name}.py"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read().decode("utf-8")


def top_level_assigns(src: str) -> dict[str, object]:
    """Walk top-level assignments; a whole-file `literal_eval` trips on the docstring."""
    out: dict[str, object] = {}
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            out[node.targets[0].id] = ast.literal_eval(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out[node.target.id] = ast.literal_eval(node.value)
    return out


def rs_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def rs_opt(value: str | None) -> str:
    return f"Some({rs_str(value)})" if value is not None else "None"


def doc_para(text: str) -> str:
    """Wrap `text` as `//!` doc-comment lines."""
    return "\n".join(textwrap.wrap(text, width=84, initial_indent="//! ", subsequent_indent="//! "))


def supported_glob(pattern: str) -> bool:
    return "[" not in pattern and "]" not in pattern


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help="home-assistant/core commit or branch to read (default: the "
        "snapshot recorded in THIRD-PARTY-NOTICES.md)",
    )
    ref = parser.parse_args().ref

    sources = {name: fetch(ref, name) for name in SOURCE_FILES}
    zeroconf_mod = top_level_assigns(sources["zeroconf"])
    ssdp_table = top_level_assigns(sources["ssdp"])["SSDP"]
    dhcp_table = top_level_assigns(sources["dhcp"])["DHCP"]

    # ── zeroconf ────────────────────────────────────────────────────
    zeroconf: list[tuple[str, str, str | None, list[tuple[str, str]]]] = []
    dropped_globs = 0
    for service_type, matchers in zeroconf_mod["ZEROCONF"].items():
        st = service_type.rstrip(".").lower()
        for matcher in matchers:
            name = matcher.get("name")
            props = sorted(matcher.get("properties", {}).items())
            if (name is not None and not supported_glob(name)) or any(
                not supported_glob(v) for _, v in props
            ):
                dropped_globs += 1
                continue
            zeroconf.append(
                (
                    st,
                    matcher["domain"],
                    name.lower() if name is not None else None,
                    [(k.lower(), str(v).lower()) for k, v in props],
                )
            )
    zeroconf.sort(key=lambda e: (e[0], e[1], e[2] or "", e[3]))

    homekit = sorted(
        (model, entry["domain"]) for model, entry in zeroconf_mod["HOMEKIT"].items()
    )

    # ── ssdp ────────────────────────────────────────────────────────
    ssdp: list[tuple[str, dict[str, str]]] = []
    dropped_ssdp = 0
    for domain, matchers in ssdp_table.items():
        for matcher in matchers:
            known = {k for k, _ in SSDP_KEYS}
            if not set(matcher) <= known:
                dropped_ssdp += 1
                continue
            ssdp.append((domain, {k: str(v).lower() for k, v in matcher.items()}))
    ssdp.sort(key=lambda e: (e[0], sorted(e[1].items())))

    # ── dhcp MAC prefixes ───────────────────────────────────────────
    # Only entries whose sole condition is the MAC. HA ANDs `hostname` with
    # `macaddress` in 154 of its 257 MAC entries; we cannot evaluate a hostname,
    # and keeping the MAC half alone turns a two-condition matcher into a false
    # identification of every device built on that OUI.
    mac_prefixes = sorted(
        {
            (entry["macaddress"].rstrip("*").upper(), entry["domain"])
            for entry in dhcp_table
            if "macaddress" in entry and "hostname" not in entry
        }
    )
    dhcp_conjunctive = sum(1 for e in dhcp_table if "macaddress" in e and "hostname" in e)
    dhcp_hostname_only = sum(
        1 for e in dhcp_table if "macaddress" not in e and "hostname" in e
    )
    dhcp_registered = sum(1 for e in dhcp_table if e.get("registered_devices"))
    finer_than_oui = sum(1 for p, _ in mac_prefixes if len(p) > OUI_NIBBLES)

    # A domain we map but no carried table can produce would never fire.
    carried = (
        {e[1] for e in zeroconf}
        | {d for _, d in homekit}
        | {d for d, _ in ssdp}
        | {d for _, d in mac_prefixes}
    )
    unreachable = sorted(set(DOMAIN_TYPES) - carried)
    if unreachable:
        print(
            f"note: {len(unreachable)} mapped domains occur in no carried table "
            f"and are omitted: {', '.join(unreachable)}",
            file=sys.stderr,
        )
    domain_types = sorted((d, t) for d, t in DOMAIN_TYPES.items() if d in carried)

    out = sys.stdout
    today = datetime.date.today().isoformat()
    entries_note = doc_para(
        f"Entries: {len(zeroconf)} zeroconf matchers over "
        f"{len({e[0] for e in zeroconf})} service types, {len(homekit)} `HomeKit` "
        f"models, {len(ssdp)} SSDP matchers, {len(mac_prefixes)} DHCP MAC prefixes, "
        f"{len(domain_types)} domain -> `DeviceType` mappings."
    )
    not_extracted_note = doc_para(
        f"Not extracted, every DHCP entry naming a `hostname`: {dhcp_conjunctive} AND "
        f"it with a `macaddress`, {dhcp_hostname_only} use it alone. This tool sees no "
        "DHCP traffic and has no reverse DNS, and keeping the MAC half of a "
        "two-condition matcher would widen it into a false identification. Also "
        f"dropped: {dhcp_registered} `registered_devices` entries (no matcher), "
        f"{dropped_ssdp} SSDP matcher{'s' if dropped_ssdp != 1 else ''} keyed on `X_*` "
        f"vendor extensions, {dropped_globs} zeroconf "
        f"matcher{'s' if dropped_globs != 1 else ''} using fnmatch character classes."
    )
    verb = "is" if finer_than_oui == 1 else "are"
    oui_note = doc_para(
        f"{finer_than_oui} of the {len(mac_prefixes)} MAC prefixes {verb} longer than a "
        "24-bit OUI; the rest name a registrant, whose catalogue usually spans several "
        "device classes, so no product class may be read out of them (see "
        "[`MacPrefixMatch::finer_than_oui`])."
    )
    out.write(f"""//! Home Assistant discovery tables — auto-generated.
//!
//! Source: <https://github.com/home-assistant/core> `homeassistant/generated/`
//! Files: `zeroconf.py`, `ssdp.py`, `dhcp.py` | Commit: `{ref}` | Retrieved: {today}
//! Licence: Apache-2.0 (<{LICENCE_URL}>), no upstream NOTICE file.
//!
{entries_note}
//!
{not_extracted_note}
//!
{oui_note}
//!
//! The domain -> `DeviceType` map is ours, not upstream's; HA integration domains
//! are carried verbatim as `device_subtype`. Mapped domains that no carried table
//! can produce are omitted.
//!
//! Regenerate with `uv run python scripts/gen_ha_discovery_db.py --ref {ref}`.

use rikitikitavi_models::DeviceType;

/// A TXT-property predicate: key, and a `*`/`?` glob over the value.
pub type TxtPredicate = (&'static str, &'static str);

/// One matcher from HA's `generated/zeroconf.py`.
#[derive(Debug, Clone, Copy)]
pub struct ZeroconfMatcher {{
    /// Service type, lowercase, no trailing dot (`_hap._tcp.local`).
    pub service_type: &'static str,
    /// HA integration domain.
    pub domain: &'static str,
    /// Glob over the full lowercase instance name, trailing dot included.
    pub name: Option<&'static str>,
    /// TXT predicates that must all hold.
    pub properties: &'static [TxtPredicate],
}}

/// One matcher from HA's `generated/ssdp.py`. All present fields must match.
#[derive(Debug, Clone, Copy)]
pub struct SsdpMatcher {{
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
}}

/// A MAC prefix glob from HA's `generated/dhcp.py`, in uppercase hex nibbles.
///
/// Nibble-granular: most are 6 nibbles (a 3-byte OUI) but some are longer and
/// not byte-aligned, so truncating to `[u8; 3]` would widen them. Only entries
/// whose sole upstream condition is the MAC are carried.
#[derive(Debug, Clone, Copy)]
pub struct MacPrefix {{
    /// Uppercase hex nibbles, no separators, no trailing `*`.
    pub nibbles: &'static str,
    /// HA integration domain.
    pub domain: &'static str,
}}

/// Longest MAC prefix in the table, in nibbles.
pub const MAX_MAC_PREFIX_NIBBLES: usize = {max(len(p) for p, _ in mac_prefixes)};

/// Nibbles in a 24-bit OUI.
pub const OUI_NIBBLES: usize = {OUI_NIBBLES};

/// A hit in [`DHCP_MAC_PREFIXES`]: the domains registering the longest prefix
/// that matched, and that prefix's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacPrefixMatch {{
    /// Length in nibbles of the prefix that matched.
    pub nibbles: usize,
    /// Every HA integration domain registering that prefix.
    pub domains: Vec<&'static str>,
}}

impl MacPrefixMatch {{
    /// The prefix is finer than the 24-bit OUI an IEEE vendor lookup already uses.
    ///
    /// Only {finer_than_oui} of the {len(mac_prefixes)} carried prefixes are. A
    /// prefix that is not names the registrant, whose catalogue usually spans
    /// several device classes, so no `DeviceType` may be read out of it.
    #[must_use]
    pub const fn finer_than_oui(&self) -> bool {{
        self.nibbles > OUI_NIBBLES
    }}
}}

/// Match `value` against an fnmatch-style `pattern` supporting `*` and `?`.
///
/// Both are compared bytewise; callers lowercase first.
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {{
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi) = (0usize, 0usize);
    // Position of the last `*` and the input position it was matched at.
    let mut star: Option<(usize, usize)> = None;

    while vi < v.len() {{
        match p.get(pi) {{
            Some(b'*') => {{
                star = Some((pi, vi));
                pi += 1;
            }}
            Some(b'?') => {{
                pi += 1;
                vi += 1;
            }}
            Some(&c) if c == v[vi] => {{
                pi += 1;
                vi += 1;
            }}
            _ => {{
                let Some((sp, sv)) = star else {{ return false }};
                pi = sp + 1;
                vi = sv + 1;
                star = Some((sp, vi));
            }}
        }}
    }}

    p[pi..].iter().all(|&c| c == b'*')
}}

/// HA integration domains whose zeroconf matchers all hold for this service.
///
/// `full_name` is the complete lowercase instance name with its trailing dot
/// (`shellyplus1-aabbcc._http._tcp.local.`); `txt` is the raw TXT record list.
#[must_use]
pub fn zeroconf_domains(service_type: &str, full_name: &str, txt: &[String]) -> Vec<&'static str> {{
    let st = service_type.trim_end_matches('.').to_ascii_lowercase();
    let name = full_name.to_ascii_lowercase();
    let start = ZEROCONF_MATCHERS.partition_point(|m| m.service_type < st.as_str());

    let mut domains: Vec<&'static str> = Vec::new();
    for matcher in &ZEROCONF_MATCHERS[start..] {{
        if matcher.service_type != st {{
            break;
        }}
        if matcher.name.is_some_and(|glob| !glob_match(glob, &name)) {{
            continue;
        }}
        let props_hold = matcher.properties.iter().all(|&(key, glob)| {{
            rikitikitavi_network::mdns::txt_get(txt, key)
                .is_some_and(|value| glob_match(glob, &value.to_ascii_lowercase()))
        }});
        if props_hold && !domains.contains(&matcher.domain) {{
            domains.push(matcher.domain);
        }}
    }}
    domains
}}

/// HA integration domain for a `HomeKit` accessory model (the `md` TXT key).
///
/// Upstream matches the model exactly, or as a prefix followed by a space or a
/// hyphen; keys themselves contain spaces (`"LIFX Indoor Neon"`), so this is a
/// scan for the longest matching key rather than a binary search.
#[must_use]
pub fn homekit_domain(model: &str) -> Option<&'static str> {{
    let model = model.trim();
    let mut best: Option<(usize, &'static str)> = None;
    for &(key, domain) in HOMEKIT_MODELS {{
        let matches = model.eq_ignore_ascii_case(key)
            || model
                .get(..key.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(key))
                && matches!(model.as_bytes().get(key.len()), Some(b' ' | b'-'));
        if matches && best.is_none_or(|(len, _)| key.len() > len) {{
            best = Some((key.len(), domain));
        }}
    }}
    best.map(|(_, domain)| domain)
}}

/// One hit in [`SSDP_MATCHERS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsdpHit {{
    /// HA integration domain.
    pub domain: &'static str,
    /// The matcher named something beyond the vendor — `st`, `nt`, `deviceType`,
    /// `modelName` or `modelDescription`.
    ///
    /// A matcher constrained by `manufacturer` alone (`wemo` on "Belkin
    /// International Inc.", `axis` on "AXIS") covers the vendor's whole
    /// catalogue, so it identifies the integration but not the device class.
    pub specific: bool,
}}

/// HA integration domains whose SSDP matchers hold for the observed fields.
///
/// A matcher holds when every field it names is present and equal (case-
/// insensitive). Fields not yet fetched are passed as `None` and any matcher
/// naming them is skipped.
#[must_use]
pub fn ssdp_hits(observed: &SsdpFields<'_>) -> Vec<SsdpHit> {{
    let mut hits: Vec<SsdpHit> = Vec::new();
    for matcher in SSDP_MATCHERS {{
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
        let holds = pairs.iter().all(|&(want, got)| {{
            want.is_none_or(|want| got.is_some_and(|got| got.eq_ignore_ascii_case(want)))
        }});
        if !constrained || !holds {{
            continue;
        }}
        let specific = matcher.st.is_some()
            || matcher.nt.is_some()
            || matcher.device_type.is_some()
            || matcher.model_name.is_some()
            || matcher.model_description.is_some();
        if let Some(hit) = hits.iter_mut().find(|h| h.domain == matcher.domain) {{
            hit.specific |= specific;
        }} else {{
            hits.push(SsdpHit {{
                domain: matcher.domain,
                specific,
            }});
        }}
    }}
    hits
}}

/// Domains of [`ssdp_hits`], in table order.
#[must_use]
pub fn ssdp_domains(observed: &SsdpFields<'_>) -> Vec<&'static str> {{
    ssdp_hits(observed).into_iter().map(|h| h.domain).collect()
}}

/// Observed SSDP / `UPnP` description fields, for [`ssdp_domains`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SsdpFields<'a> {{
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
}}

/// Longest MAC-prefix hit for a MAC address.
///
/// `mac` may be in any common format; only hex digits are considered. A prefix
/// can be shared by two integrations, so every domain at the longest matching
/// length is returned and none from shorter ones.
#[must_use]
pub fn mac_prefix_match(mac: &str) -> Option<MacPrefixMatch> {{
    let nibbles: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .take(MAX_MAC_PREFIX_NIBBLES)
        .collect();

    for len in (1..=nibbles.len()).rev() {{
        let want = &nibbles[..len];
        let start = DHCP_MAC_PREFIXES.partition_point(|p| p.nibbles < want);
        let domains: Vec<&'static str> = DHCP_MAC_PREFIXES[start..]
            .iter()
            .take_while(|p| p.nibbles == want)
            .map(|p| p.domain)
            .collect();
        if !domains.is_empty() {{
            return Some(MacPrefixMatch {{
                nibbles: len,
                domains,
            }});
        }}
    }}
    None
}}

/// Our `DeviceType` for an HA integration domain, or `Unknown`.
#[must_use]
pub fn domain_device_type(domain: &str) -> DeviceType {{
    DOMAIN_DEVICE_TYPES
        .binary_search_by_key(&domain, |&(d, _)| d)
        .map_or(DeviceType::Unknown, |i| DOMAIN_DEVICE_TYPES[i].1)
}}

/// The `DeviceType` all `domains` agree on, else `Unknown`.
#[must_use]
pub fn consensus_device_type(domains: &[&str]) -> DeviceType {{
    let mut agreed = DeviceType::Unknown;
    for domain in domains {{
        let t = domain_device_type(domain);
        if t == DeviceType::Unknown {{
            continue;
        }}
        if agreed == DeviceType::Unknown {{
            agreed = t;
        }} else if agreed != t {{
            return DeviceType::Unknown;
        }}
    }}
    agreed
}}

""")

    out.write("/// Zeroconf matchers, sorted by service type.\n")
    out.write("#[rustfmt::skip]\n")
    out.write("static ZEROCONF_MATCHERS: &[ZeroconfMatcher] = &[\n")
    for st, domain, name, props in zeroconf:
        prop_lits = ", ".join(f"({rs_str(k)}, {rs_str(v)})" for k, v in props)
        out.write(
            f"    ZeroconfMatcher {{ service_type: {rs_str(st)}, domain: {rs_str(domain)}, "
            f"name: {rs_opt(name)}, properties: &[{prop_lits}] }},\n"
        )
    out.write("];\n\n")

    out.write("/// `HomeKit` `md` model -> HA integration domain, sorted by model.\n")
    out.write("#[rustfmt::skip]\n")
    out.write("static HOMEKIT_MODELS: &[(&str, &str)] = &[\n")
    for model, domain in homekit:
        out.write(f"    ({rs_str(model)}, {rs_str(domain)}),\n")
    out.write("];\n\n")

    out.write("/// SSDP matchers, sorted by domain.\n")
    out.write("#[rustfmt::skip]\n")
    out.write("static SSDP_MATCHERS: &[SsdpMatcher] = &[\n")
    for domain, fields in ssdp:
        parts = ", ".join(
            f"{rust_key}: {rs_opt(fields.get(ha_key))}" for ha_key, rust_key in SSDP_KEYS
        )
        out.write(f"    SsdpMatcher {{ domain: {rs_str(domain)}, {parts} }},\n")
    out.write("];\n\n")

    out.write("/// DHCP MAC prefixes, sorted by nibble string.\n")
    out.write("#[rustfmt::skip]\n")
    out.write("static DHCP_MAC_PREFIXES: &[MacPrefix] = &[\n")
    for nibbles, domain in mac_prefixes:
        out.write(
            f"    MacPrefix {{ nibbles: {rs_str(nibbles)}, domain: {rs_str(domain)} }},\n"
        )
    out.write("];\n\n")

    out.write("/// HA integration domain -> `DeviceType`, sorted by domain. Ours, not upstream's.\n")
    out.write("#[rustfmt::skip]\n")
    out.write("static DOMAIN_DEVICE_TYPES: &[(&str, DeviceType)] = &[\n")
    for domain, variant in domain_types:
        out.write(f"    ({rs_str(domain)}, DeviceType::{variant}),\n")
    out.write("];\n\n")

    out.write("#[cfg(test)]\nmod tests;\n")


if __name__ == "__main__":
    main()
