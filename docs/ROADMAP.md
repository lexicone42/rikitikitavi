# Detection Roadmap

Derived from a 2026-09 research sweep across four dimensions (emerging threats,
embeddable resources, home hardware, comparable projects). Every item below was
fact-checked against primary sources and against this repository; refuted items
are listed in [Rejected or unusable](#rejected-or-unusable) with the reason.

Scope constraint for everything here: unprivileged, read-only, from an ordinary
LAN host. Licence constraint: Apache-2.0-compatible only (MIT/BSD/ISC/CC0/
Apache/public domain). GPL/LGPL/AGPL, NPSL, FoxIO and CC-BY-NC are excluded.

Baseline at time of writing: 26 `Scanner` impls (25 in `rikitikitavi-scanners`,
1 in `rikitikitavi-unifi`), 40,157 OUI entries, KEV catalog 2026.09.16
(1,713 entries), EPSS at runtime.

## Executive summary

1. The largest coverage gap is not threat intelligence — it is **device
   identification**. mDNS asks about 8 service types; the consumer surface is 113.
2. Two Apache-2.0/BSD corpora close most of that gap mechanically: Rapid7 Recog
   (4,676 banner regexes, BSD-2-Clause) and Home Assistant's generated discovery
   tables (346 DHCP matchers, 113 zeroconf types, 91 SSDP matchers, Apache-2.0).
3. One 2026 KEV threat is worth a same-day check: the ASUS *AyySSHush* NVRAM SSH
   backdoor on TCP/53282, which survives firmware updates and whose only
   network-visible artefact is that port.
4. The scanner's port lists miss the entire consumer control plane — Kasa 9999,
   Tuya 6668, Modbus 502, Cast 8443/8009, Sonos 1400, Moonraker 7125, Plex 32400.
   Each is a self-identifying, unauthenticated read.
5. `DeviceType` has 16 variants and no way to express hub, lock, EV charger,
   inverter, NVR or vacuum — so the highest-risk classes collapse into `IoT`.
   Only JSON and HTML emit the field, so widening it is cheaper than assumed.
6. Firmware/software EOL is hand-coded and already wrong (`services.rs` still
   calls nginx 1.26.x "current stable"). endoflife.date (MIT) covers the server
   stack but **not** pfSense, UniFi, Synology DSM or OpenSSH.
7. CISA Vulnrichment (CC0) adds the one exploitation tier KEV and EPSS cannot
   express: `poc` — public exploit exists, not yet observed in the wild.
8. Several 2026 campaign reports did not survive fact-checking. UniFi, MikroTik,
   D-Link/HNAP, NETGEAR TelnetEnable and TP-Link TDDP were all rejected on
   misattributed CVEs, wrong fix-version tables, or unreachable probes.
9. Both embedded datasets are current: KEV catalog 2026.09.16 and the IEEE OUI
   table regenerated 2026-09-16 (40,157 entries). Refresh both with the
   generator scripts before each release.
10. A real bug surfaced during verification: `epss.rs` sends every CVE in one
    unpaginated request and silently drops everything past the API's 100-item
    default. See [Observations](#observations).

## Top 15 by (value x prevalence) / effort

| # | Item | Why now (year, source) | Detection sketch | Maps to | Effort |
|---|------|------------------------|------------------|---------|--------|
| 1 | mDNS service-type expansion (8 -> 113) | 2026 — HA `generated/zeroconf.py` enumerates 113 consumer service types; we query 8 | Add targeted PTR queries; interpret TXT (`md`, `fn`, `gen`, `VP`, `CM`) instead of only joining it to a string | `rikitikitavi-network/src/mdns.rs:373` `SERVICE_QUERIES`; `scanners/src/mdns.rs` classifier | M |
| 2 | ASUS AyySSHush SSH backdoor, TCP/53282 | 2025-06-02 KEV, CVE-2023-39780 — [GreyNoise](https://www.greynoise.io/blog/stealthy-backdoor-campaign-affecting-asus-routers) | SSH banner on 53282 = Critical/Confirmed; SSH banner on any non-22 port on the gateway = Probable | `ports.rs` `common_ports()`; `services.rs:501` `BANNER_PORTS` + `deep_probe` SSH arm | S |
| 3 | Rapid7 Recog fingerprint DB | 2026-08 HEAD, BSD-2-Clause — [rapid7/recog](https://github.com/rapid7/recog) | 4,676 regexes over banners already collected; `RegexSet` per match-key; 7,550 upstream examples become tests | `services.rs`, `http_audit.rs`, `snmp.rs`, `ssl.rs`, `smb.rs`, `printers.rs`, `device.rs` | L |
| 4 | HA discovery tables (OUI globs, zeroconf, SSDP) | 2026, Apache-2.0 — [home-assistant/core](https://github.com/home-assistant/core) `homeassistant/generated/` | 257 MAC prefixes (nibble-granular) + 165 zeroconf matchers + 91 SSDP matchers -> `DeviceHint` above the OUI tier | `device.rs` `DeviceHint`, `mdns.rs`, `upnp_igd.rs`, `arp.rs` | M |
| 5 | `DeviceType` widening + `device_subtype` | 2026 — hub/lock/EVSE/inverter/NVR/vacuum have no variant | Data-model change; only JSON (serde) and HTML (Debug) emit the field, CSV and OCSF do not | `models/src/device.rs:41`; `export/{json,html}.rs`; 2 exhaustive TUI matches | M |
| 6 | TP-Link Kasa, TCP/9999 | 2026 — [softScheck analysis](https://github.com/softScheck/tplink-smartplug): XOR autokey, "no authentication mechanism" | Length-prefixed XOR-autokey `get_sysinfo`; decode to JSON = Confirmed. Read-only allowlist (same socket accepts `reset`) | new probe in `services.rs`; `ports.rs` | S |
| 7 | endoflife.date EOL correlation | 2026, MIT — [endoflife.date](https://endoflife.date/api/v1/products/), 475 products, daily | Build-time table keyed on (product, cycle-prefix); join to versions `http_audit.rs` already parses | `services.rs`, `http_audit.rs`, new EOL enrichment in `rikitikitavi-analysis` | M |
| 8 | Tuya local protocol, UDP 6666/6667 + TCP 6668 | 2026 — [tinytuya](https://github.com/jasonacox/tinytuya) documents the firewall requirement | Passive: bind 6666/6667, decode both `0x000055AA` (AES-ECB) and `0x00006699` (AES-GCM) magics -> gwId/ip/productKey in clear | new `tuya` module; `ports.rs` | M |
| 9 | Hikvision SADP, UDP/37020 | 2025-2026 — CVE-2025-66177 (AV:A) + CVE-2017-7921 KEV 2026-03-05 | Single well-formed `<Types>inquiry</Types>` datagram; parse `SoftwareVersion` build date vs floor 250807 | new `sadp.rs`; `rtsp.rs` `CameraVendor`; `device.rs` | M |
| 10 | Modbus/TCP 502 (solar, battery, EVSE) | 2026 — IANA `mbap 502`; HA advertises `_solaredge-modbus._tcp`, `_enphase-envoy._tcp` | FC 0x03 SunSpec scan at bases 40000/0/50000 for `SunS` magic; FC 0x2B/0x0E as opportunistic extra. Never write | new `modbus` module; `ports.rs`; new `DeviceType` | M |
| 11 | CISA Vulnrichment SSVC | 2026, CC0-1.0 — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) (branch `develop`) | Extract `(cve, exploitation, automatable, technical_impact, cwe)`; the value is the `poc` tier, not `active` (all 13 active CVEs are already in KEV) | `analysis/src/exploit_intel.rs`, `risk_score.rs`; CWE backfill for OCSF | M |
| 12 | Google Cast 8443/8009 | 2026 — [pychromecast](https://github.com/home-assistant-libs/pychromecast) `dial.py` tries HTTPS/8443 first, 8008 as fallback | `GET /setup/eureka_info?params=...` (self-signed, verify off) -> `wifi.ssid`, `device_info.mac_address`; TLS handshake on 8009 | `ssl.rs` handshake path; `mdns.rs`; `ports.rs` | S |
| 13 | PaperCut NG/MF, TCP 9191 | 2026-08-31 KEV, CVE-2026-81578 -> CVE-2026-82078 — [vendor bulletin](https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/) | `GET /` on 9191; regex `\?(\d{4,6})papercut-(mf\|ng)` in asset paths gives build **and** edition | `printers.rs`; `ports.rs`; `http_audit.rs` | S |
| 14 | nuclei `network/detection` templates | 2026, MIT — [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Convert 73 send-bytes/expect-words YAMLs into a static table; second identification pass on ports that yielded no banner | `services.rs` | M |
| 15 | Matter / Thread border-router mDNS | 2026 — [ot-br-posix](https://github.com/openthread/ot-br-posix) border agent, BSD-3-Clause | `_matter._tcp`, `_matterc._udp` (`CM != 0`), `_meshcop._udp` (`sb` state bitmap, `nn`, `xp`, `omr`) | `rikitikitavi-network/src/mdns.rs` (needs an IPv6 socket) | M |

## Threats

Six of eighteen threat claims survived verification. The rest are in
[Rejected](#rejected-or-unusable).

### ET-03 — ASUS AyySSHush NVRAM SSH backdoor, TCP/53282
CVE-2023-39780 (CVSS 8.8, CWE-78, KEV 2025-06-02, due 2025-06-23) chained with
two login-bypass techniques that **are patched but were never assigned CVEs**.
The attacker enables SSH on 53282 and writes a key into `sshd_authkeys` in NVRAM;
it survives reboot and firmware upgrade, logging is disabled, no malware drops.
~9,000 compromised as of 2025-05-27. Affected: RT-AX55 (NVD CPE), plus RT-AC3100
and RT-AC3200 per GreyNoise. Remediation must say a firmware update does **not**
evict the key — GreyNoise's own advice is factory reset and manual reconfigure.
Implementation: 53282 must go in `BANNER_PORTS` (`services.rs:501`) as well as
the sweep lists, or no banner is ever grabbed. `ports.rs:171 grab_banner` is
port-agnostic and works today. Optional Authenticated-perspective escalation:
RFC 4252 §7 publickey probe with `have signature = FALSE` confirms the attacker
key without credentials — zero false positives, but it is an auth attempt and
must be opt-in.
Sources: https://www.greynoise.io/blog/stealthy-backdoor-campaign-affecting-asus-routers ,
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-39780

### ET-04 — DD-WRT UPnP M-SEARCH overflow, CVE-2021-27137 (KEV 2026-07-21)
`strcpy` in `router/upnp/src/ssdp.c`; weaponised by the c0xmo/Gafgyt variant on
UDP/1900. The vulnerable daemon is the Broadcom-derived `upnpd`, **not**
MiniUPnPd — `ssdp.c` emits `Server: DD-WRT/<os_version> UPnP/1.0 upnpd/0.9.0`,
and `os_name` is hardcoded `"DD-WRT"` even on Buffalo OEM builds. Match
`/DD-WRT/i` **together with** `upnpd/0.9.0`; a MiniUPnPd banner is a negative
indicator. No build number is reachable (`os_version` is a CFE board variable,
`modelNumber` is hardcoded `V30`), so the ceiling is High/Probable, not
Confirmed. Never send the oversized-uuid M-SEARCH — the public PoC crashes the
service. Passive `SERVER:` banner match only.
Sources: https://ssd-disclosure.com/ssd-advisory-dd-wrt-upnp-buffer-overflow/ ,
https://www.fortinet.com/blog/threat-research/inside-cross-platform-propagation-of-new-gafgyt-variant-c0xmo

### ET-05 — Hikvision SADP discovery, UDP/37020
CVE-2025-66177 (NVR/DVR/CVR/IPC) and CVE-2025-66176 (access control), both
CVSS 8.8 **AV:A** — adjacent-network, exactly this tool's vantage. Separately,
CVE-2017-7921 was added to KEV **2026-03-05**; this was a first-time addition,
not a re-addition (verified against the cisagov/kev-data commit diff; absent from
the 2023-06, 2024-06 and 2025-05 snapshots). A clean version floor exists: 89 of
104 affected families share `Build date before 250807`, and SADP's
`<SoftwareVersion>` carries exactly that YYMMDD form. Use the active
`<Types>inquiry</Types>` datagram as the primary path (documented, no crash
risk — the CVE needs a malformed packet); passive listening is a best-effort
supplement only, since unsolicited announcements are uncorroborated and IGMP
snooping blocks group traffic without a join. Use the XML-over-UDP flavour, not
the raw-Ethernet one, which needs `CAP_NET_RAW`. OEM rebrands (Annke, LaView)
answer SADP too.
Sources: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-66177 ,
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

### ET-11 — Sonos Era 300 SMB client OOB, CVE-2026-4149
CWE-119, NVD CVSS 3.1 9.8 (S:U); ZDI's own rating is 10.0 CVSS 3.0 (S:C).
ZDI advisory 2026-03-16, NVD published 2026-04-11. The bug is in the speaker as
an SMB **client**, so the attack comes from a hostile SMB server on the LAN —
it breaks the implicit assumption that LAN risk flows inbound to listening ports.
A fix floor **is** published (83.1-61240) but is unusable: Sonos dates that build
to 2025-02-04, below the affected build 91.0-70070, so a version comparison
would clear vulnerable speakers. Emit presence-plus-relationship at Inferred,
justified as "published floor is inconsistent with the affected build". The real
deliverable is a general **client-side LAN exposure** finding category; the CVE
is the worked example. Note `mdns.rs::parse_upnp_device_xml` reads
`firmwareVersion`, but Sonos emits `softwareVersion` — add the tag or it returns
`None`.
Sources: https://www.zerodayinitiative.com/advisories/ZDI-26-192/ ,
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-4149

### ET-12 — PaperCut NG/MF, CVE-2026-81578 -> CVE-2026-82078 (KEV 2026-08-31)
Missing authentication chained with unsafe reflection = unauthenticated RCE.
Vendor CVSS 9.4 and 8.8; KEV due 2026-09-14 under BOD 26-04. The advisory applies
to **all versions** of NG and MF, so an unparseable version defaults to "assume
vulnerable, verify build". Version comes from the cache-buster query string on
the unauthenticated login page (`/css/style.css?76602papercut-mf`), not the
footer, which carries edition and licensee only. Known fixed builds: MF 26.0.5 =
76602, NG 26.0.5 = 76603, MF 25.0.13 = 76604, NG 25.0.13 = 76605, MF 24.1.10 =
76610, NG 24.1.10 = 76611. Two traps: builds are **not monotonic across
branches** (76610 > 76604 > 76602), and Emergency Patches 1-3 carry earlier build
ids while being fixed — so anything in the ambiguous window is Medium "version
unverified", not Critical. `/api/health` returns 401 with distinctive JSON:
useful as a secondary fingerprint, useless for version. Gate on `relevant_ports()
= [9191, 9192]` so a pure-home scan pays nothing.
Sources: https://www.papercut.com/kb/Main/security-bulletin-27-aug-2026-urgent-security-advisory/ ,
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### ET-13 — KNXnet/IP building automation, UDP/3671 (CVE-2023-4346, KEV 2026-07-15)
CWE-645, CVSS 7.5, added to KEV two years after publication. An attacker on the
KNX installation can purge devices and set a BCU key, irreversibly locking any
device that does not already have one. Affected scope is narrower than it looks:
devices using Connection Authorization Option 1 **in which no BCU key is
currently set**. That state is a bus-level property and is **not carried in any
KNXnet/IP datagram** — so the "gateway does not advertise KNX Secure" inference
is two steps removed from anything measurable and must be downgraded to Info/Low
attack-surface framing, not a vulnerability verdict. The remediation in
ICSA-23-236-01 is "set the BCU Key in every KNX project", not "enable KNX
Secure". Probe: `SEARCH_REQUEST` (0x0201) to 224.0.23.12:3671 with a real
route-back HPAI, unicast fallback; optionally `SEARCH_REQUEST_EXTENDED` (0x020B)
for the Secured Service Families DIB, which plain 0x0202 does not carry. Never
send `CONNECT_REQUEST` or `DEVICE_CONFIGURATION_REQUEST`. CVE-2023-4346 is
already in `kev_db.rs`, so risk scoring picks it up for free.
Sources: https://www.cisa.gov/news-events/ics-advisories/icsa-23-236-01 ,
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4346

## Embeddable resources

### PL-01 — Rapid7 Recog (BSD-2-Clause)
4,676 live fingerprints across 51 XML files (a `grep` count of 4,685 includes 9
commented-out entries). Zero lookahead, lookbehind or backreferences, so every
pattern is `regex`-crate compatible. Flag mapping, corrected: `REG_ICASE` -> `(?i)`
(319 fingerprints, not 248); **both** `REG_DOT_NEWLINE` and `REG_MULTILINE` ->
`(?s)`, because Recog's Ruby reference maps both to Ruby's MULTILINE, which means
dot-matches-newline; and `(?m)` must be applied to **every** pattern, since Ruby
`^`/`$` are always line anchors while Rust's default to haystack anchors. With
that mapping all 7,549 usable upstream examples match; with the naive mapping, 19
fail. Two patterns exceed the default 10 MB compiled-size limit, and per-file
`RegexSet`s fail for `ftp_banners`, `html_title`, `smtp_banners` and
`snmp_sysdescr` — use `RegexSetBuilder::size_limit(256 MiB)` and
`RegexBuilder::size_limit(64 MiB)`. `os.device` gives a ready-made device-type
vocabulary (Printer 146, Switch 105, Router 87, WAP 42, Firewall 42, NAS 18,
IP Camera 13, DVR 10, ...) that feeds `DeviceHint`. Vendor `COPYING` verbatim and
retain "Copyright (c) 2014-2015, Rapid7".
Sources: https://github.com/rapid7/recog , https://raw.githubusercontent.com/rapid7/recog/master/LICENSE

### PL-03 — nuclei-templates (MIT)
Two separate imports. (a) `network/detection`: 73 top-level YAMLs (plus `ftp/`
and `ics/` subdirs) that are literally send-bytes/expect-words pairs — mechanical
conversion to a static table consumed by `services.rs` as a second identification
pass. Note the protocol key is `tcp:` (`tcp[].inputs[].data`), not `network:`,
and matchers may carry `encoding: hex`. (b) `http/default-logins`: do **not** bulk
import 246 vendors; of the home-relevant vendor list only asus, d-link, tplink,
dahua and grandstream actually have templates. `cves.json` is a
CVE -> template-path -> severity -> CVSS index (no tags field).
Source: https://github.com/projectdiscovery/nuclei-templates

### PL-04 — SecLists default credentials (MIT)
`Passwords/Default-Credentials/default-passwords.csv`, 2,875 rows,
`Vendor,Username,Password,Comments`. The vendor column is the point: join to the
OUI vendor already on `Device` and try 3-10 plausible pairs instead of a blind
list. Per-protocol better-lists exist for telnet, ssh, ftp, mysql, postgres,
mssql, oracle, db2, vnc, tomcat, windows (there is **no** mongodb list). Handle
the `<BLANK>` sentinel. Vendor strings need normalisation before the join
("3COM", "2Wire, Inc." vs IEEE registrant names). This is an active
authentication attempt: keep it behind the existing `--aggressive` gate, cap
attempts per host, and treat "low-noise" as relative — logins still trigger
account lockout and IDS logging.
Source: https://github.com/danielmiessler/SecLists

### PL-05 — DefaultCreds-cheat-sheet (MIT)
3,766 rows keyed on product rather than vendor. Merge into PL-04's generator, do
not ship a second table. Corrected numbers: DefaultCreds alone normalises to
3,685 unique triples vs SecLists' 2,850; the union is **~4,000-4,150**, not
5,000-5,500, because 88% of SecLists is already contained in DefaultCreds. Two
merge traps: the blank sentinel differs in case (`<blank>` here, `<BLANK>` in
SecLists — normalise case-insensitively or ~1,200 rows become literal passwords),
and 278 `productvendor` values carry a parenthesised protocol suffix
(`Cisco (ssh)`) that must be stripped before dedup and can supply a tighter proto
mask. Pin a commit SHA; the CSV moves.
Source: https://github.com/ihebski/DefaultCreds-cheat-sheet

### PL-06 — routersploit wordlists (BSD-3-Clause)
Creds value is low (heavy overlap with PL-04/05). The distinct asset is
`snmp.txt`: **120** curated community strings (the claim said "well under 100"),
against `snmp.rs`'s current `["public", "private"]`. Try each with a v2c
`sysDescr.0` GetRequest under a strict per-host cap; a reply on anything but
`public` is High/Confirmed CWE-798. BSD-3 forbids using the RouterSploit name to
endorse — attribution goes in `THIRD-PARTY-NOTICES.md`, not README copy. Do not
import the exploit modules.
Source: https://github.com/threat9/routersploit

### PL-07 — endoflife.date (MIT)
v1 API live, schema 1.2.1, 475 products. Present and useful: nginx,
apache-http-server, tomcat, jetty, php, nodejs, mysql, mariadb, postgresql,
mongodb, redis, debian, ubuntu, freebsd, openwrt, opnsense, routeros, truenas,
esxi. **Absent** (checked, 404): pfsense, unifi, synology-dsm, openssh, samba,
dropbear, busybox — i.e. the home-network-specific half, including the tool's
best banner. Corrections: use `ETag` + `If-None-Match` for conditional refresh
(there is no `Last-Modified`, and `If-Modified-Since` returns 200); cycle names
are heterogeneous (`2.4`, `13`, `11-26h1-e`) so a universal major.minor prefix
rule fails — generate per-product longest-dotted-prefix matching and exclude
Windows-shaped products; `isEol: true` with `eolFrom: null` is common, so map it
to Medium/Inferred rather than crashing the date arithmetic; `identifiers[]`
coverage is uneven — routeros and opnsense carry only CPEs, which is arguably
better since it joins to NVD/KEV. The v1 JSON carries no description field, so
the Wikipedia CC-BY-SA prose problem is structurally avoided. API is self-declared
Beta: pin `schema_version` and fail the build loudly on drift. Also note the real
constraint: for routeros/openwrt/opnsense an unauthenticated scan usually yields
no version at all, so ship server-software EOL first.
Sources: https://endoflife.date/api/v1/products/ , https://github.com/endoflife-date/endoflife.date

### PL-08 — CISA Vulnrichment (CC0-1.0)
Per-CVE SSVC decision points (Exploitation none/poc/active, Automatable,
Technical Impact) plus CWE backfill. The premise in the original claim that KEV is
stale is false. Two sizing corrections: the project's scanners reference **45**
distinct CVE ids, not ~600, so the generated table is a few KB; and the default
branch is **`develop`**, with paths `<year>/<n>xxx/CVE-<year>-<n>.json`.
Coverage is 72% and the gaps cluster on 2016-2022 nginx/Apache/lighttpd/Webmin
rows. The critical design point: mapping `active` to a KEV-equivalent adds
**zero** information — all 13 CVEs marked active are already in `kev_db.rs`, and
all 9 marked `poc` are not (regreSSHion, Terrapin, the CUPS chain, the Brother
printer pair). The value is the `poc` band, the `Automatable` wormability flag,
and the CWE backfill for OCSF `analytic.uid`. CISA has backfilled well before the
2024 program start (Heartbleed is enriched), so walk the project's own CVE list
rather than a 3-year window.
Source: https://github.com/cisagov/vulnrichment

### PL-12 — NIST IR 8425 (US Government work, public domain in the US)
The technical capability areas — Asset Identification, Product Configuration,
Data Protection, Interface Access Control, Software Update, Cybersecurity State
Awareness — give a citable consumer-IoT rubric where ETSI EN 303 645 text is
ETSI-copyright. Add `capability_area` to `Finding` and tag existing detections;
`Finding::fingerprint()` hashes only scanner/title/ip/port, so stored suppression
baselines are unaffected. Three hard constraints on the rendering: (a) label it
"findings mapped to NIST IR 8425 capability areas", never conformance and never
Cyber Trust Mark readiness — the FCC expressly declined to rely solely on the NIST
criteria; (b) Cybersecurity State Awareness is an internal logging property and
Asset Identification is about the product's own component inventory — neither is
network-observable, so render them Unknown/Not-Assessable, not failing; (c)
mapping Asset Identification to "no resolvable vendor" measures our OUI coverage,
not the device. Also: the default-SSID input this needs does not exist in
`wifi.rs` yet, and WiFi findings carry no `affected_ip`, so they cannot populate a
per-device row without attribution to the AP.
Source: https://csrc.nist.gov/pubs/ir/8425/final

### PL-13 — Home Assistant generated discovery tables (Apache-2.0)
`generated/dhcp.py`, `zeroconf.py`, `ssdp.py`. Parse with `ast.parse()` + walk
top-level assigns (a whole-file `literal_eval` raises on the docstring/import).
Corrected shapes, all of which break the naive schema:
- DHCP: 388 entries but **346 usable** — 42 are `registered_devices: True` with
  no matcher and would encode as match-everything wildcards. MAC globs are
  **nibble-granular**: 250 are true 3-byte OUIs, 6 are longer (`70B3D52A0*`,
  `DC44271*` = Tesla Wall Connector), one is a 5-nibble non-byte-aligned entry.
  `Option<[u8;3]>` truncation of `70B3D52A0*` widens it to a whole MA-S block.
  Store hex prefix + nibble count.
- zeroconf: 113 keys expand to 165 matchers; 70 carry name globs or TXT property
  predicates. `_http._tcp.local.` maps to shelly — a flat pair table would claim
  every mDNS HTTP responder.
- SSDP: 43 domains, **91 matchers**, nine keys. Only 40 are (deviceType,
  manufacturer); 21 are `st`-only (including Sonos ZonePlayer) and 4 are
  (manufacturer, modelDescription) — the entire UniFi Dream Machine set.
Sequence the work zeroconf + HomeKit first (`_hap._tcp` is already queried and
TXT already parsed, so the 71-model map needs only `md=` extraction), OUI second,
SSDP third, DHCP-hostname last (we have no DHCP option-12 source; mDNS host
labels often coincide but not always). Apache-2.0 has no NOTICE file upstream, so
obligations are §4(a) licence copy, §4(b) attribution, §4(c) modification notice.
Source: https://github.com/home-assistant/core

### PL-14 — HA device client libraries as protocol references
Once PL-13 types a device, the per-device library documents a read-only
auth-posture probe. pychromecast is MIT. Four corrections to the naive design:
Cast eureka_info is HTTPS/8443 first with HTTP/8008 as fallback, self-signed, and
the selector is `?params=device_info,name` not `?options=detail`; Roku keypresses
are gated behind "Control by mobile apps" as of Roku OS 14.1 but `/launch` and
`/query/device-info` are not; Shelly exposes `auth_en` directly in `GET /shelly`,
so `Shelly.GetConfig` is corroboration only; ESPHome's `InvalidEncryptionKeyAPIError`
carries `received_name` and `received_mac`, so even an encrypted node leaks
identity to an unauthenticated peer. Licences differ per library — python-kasa is
GPL-3.0; check each, never assume.
Source: https://github.com/home-assistant-libs/pychromecast

## Hardware

### HW-02 — mDNS service-type expansion
`SERVICE_QUERIES` (`rikitikitavi-network/src/mdns.rs:373`) is the DNS-SD
meta-query plus eight types. HA's table has 113 covering solar
(`_enphase-envoy._tcp`, `_solaredge-modbus._tcp`), EV charging (`_openevse._tcp`,
`_nrgkick._tcp`), Matter/Thread, Zigbee/Z-Wave coordinators, 3D printers, TVs,
speakers, appliances, UPS (`_nut._tcp`), vacuums. TXT is already parsed — the gap
is interpreting it. Caveats: `_amzn-alexa._tcp` maps to **roomba** in HA (gated on
`irobot-*`/`roomba-*`), not Amazon Echo; several keys are one-to-many
(`_axis-video` -> axis + doorbird, `_miio._udp` -> 3 domains), so the table needs
an ambiguous/multi representation; the meta-query is best-effort and many embedded
responders ignore it, so targeted PTRs must carry the weight.
Source: https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/zeroconf.py

### HW-06 — Modbus/TCP 502: solar, battery, EV charging
No authentication, no encryption, no authorisation; FC 0x06/0x10 writes accepted
from any peer. Probe order corrected: SunSpec **FC 0x03** at base addresses
`[40000, 0, 50000]` reading **3** registers (magic `SunS` plus model id) is the
primary path; FC 0x2B/0x0E Read Device Identification is optional in the spec and
most residential gear does not implement it. MBAP length for the device-ID frame
is **5**, not 6 (`00 01 00 00 00 05 01 2B 0E 01 00`). Treat a Modbus exception
response (FC | 0x80) as positive identification — it proves an unauthenticated
Modbus server. Unit id 1 then 0xFF. Never write. Do **not** claim registers are
writable — say the protocol accepts writes from any peer; SMA and others ship
write access off. High only with SunSpec confirmed, Medium for bare 502.
Operational hazard: several inverters accept one or two concurrent connections, so
one connection, three reads, close, no retry. `DC4427*` is wrong for Tesla Wall
Connector — the MA-M assignment is `DC44271*` (28-bit); `DC:44:27` as a 3-byte
OUI belongs to the IEEE Registration Authority and spans sixteen companies. Only
solaredge_modbus and my-PV of the seven mDNS types actually speak 502.
Sources: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt ,
https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/enphase_envoy/manifest.json

### HW-10 — Google Cast: 8009 TLS and 8443/8008 eureka_info
8009 is **not** an IANA Cast port — IANA assigns it to `nvme-disc`, and nmap names
it `ajp13`. Never label it Cast on port number alone; the TLS handshake is the
discriminator (AJP and nvme-disc will not complete one). Reuse
`ssl.rs:690 probe_tls_handshake`, but treat "open, handshake failed" as Ambiguous
since it builds rustls with safe defaults only. For eureka_info use
`?params=name,build_info,device_info,net,wifi,detail,settings&options=detail` on
HTTPS/8443 first, HTTP/8008 as fallback, certificate verification off, and connect
by IP (Cast returns 403 for a hostname `Host` header). Flag `wifi.ssid`,
`wifi.bssid`, `device_info.mac_address`, `device_info.local_authorization_token_hash`,
`settings.timezone`. Unverified: that the 8009 certificate CN/SAN carries a
serial — pychromecast never inspects the cert. `ports.rs` has no 8008 arm despite
8008 being in `extended_ports()`, so it currently reports "Unknown".
Source: https://github.com/home-assistant-libs/pychromecast

### HW-13 — TP-Link Kasa, TCP/9999
softScheck: "trivial XOR autokey encryption that provides no security" and
"There is no authentication mechanism and commands are accepted independent of
device state". Send the 4-byte-length-prefixed XOR-autokey (initial key 171)
encoding of `{"system":{"get_sysinfo":{}}}`, read the header then exactly that
many bytes (a single 2 KB `recv` truncates on devices with many schedule rules).
Extract `model`, `sw_ver`, `hw_ver`, `deviceId`, `alias`, and both
`latitude`/`longitude` and `latitude_i`/`longitude_i` (integers scaled 1e4).
Three corrections: `get_sysinfo` returns **no** stored Wi-Fi credentials — the
read-only leak is `netif.get_scaninfo` (nearby APs); an open 9999 is a
**hardware-generation** signal, not a firmware-age one (python-kasa: the KLAP
migration tracks hardware revision), so "update firmware" is unachievable
remediation for most affected units — lead with VLAN segmentation; and the same
socket accepts `reset`, `reboot` and `set_stainfo`, so the probe needs a hard
command allowlist, not convention. Gate the finding on a successful decode to
`system.get_sysinfo` JSON, not on the port being open. Consider High rather than
Medium for switched-mains plugs.
Source: https://github.com/softScheck/tplink-smartplug

### HW-14 — Tuya local protocol, UDP 6666/6667/7000 + TCP 6668
The largest unbranded-IoT population on a typical home LAN. Passive half is the
headline: bind 6666/6667 and decode broadcasts — `gwId`, `ip`, `productKey`,
`version` in the clear, continuously, to anyone with a socket. Decode **both**
magics: `0x000055AA` (plaintext JSON or AES-ECB under the fixed
`md5('yGAdlopoPVldABfn')` key) and `0x00006699` (protocol 3.5, AES-GCM) — a
55AA-only matcher misses every v3.5 device. Two scope corrections: 7000 is the
*app* port and v3.5 devices do not self-announce (tinytuya broadcasts
`REQ_DEVINFO = 0x25` to elicit them), so "zero packets sent" holds for 3.1/3.3
only; and unauthenticated *control* is not available — only unauthenticated
*status readout* on protocol 3.1 / firmware below 1.0.5. For the active probe,
DP_QUERY on 3.1 needs the device's own `gwId`/`devId` echoed back, so the passive
listener is a prerequisite; 3.4/3.5 require session-key negotiation first, so
treat any 55AA/6699-framed response as positive identification and reserve High
for parseable plaintext status JSON. Note 6667/TCP is already in `common_ports()`
as IRC — keep the two distinct in reporting.
Source: https://github.com/jasonacox/tinytuya

### HW-16 — Plex 32400 and Jellyfin 8096/8920/7359
CVE-2025-34158 (CVSS 8.5, CWE-669) affects Plex 1.41.7.x-1.42.0.x before 1.42.1:
`/myplex/account` exposes server-owner credentials. Note the vector is **PR:L**,
not PR:N — word it as "authenticated low-privilege user harvests the owner's
credentials", not unauthenticated LAN takeover. Probe `GET /identity` on 32400
for `machineIdentifier` and `version` (never `/myplex/account`), falling back to
HTTPS on the same port since Plex multiplexes and may refuse plaintext under
"Secure connections: Required". Confidence should be **Probable**, matching the
Apache 2.4.49/50 precedent in `http_audit.rs`. Worth adding a second range check
for CVE-2020-5741 (PMS before 1.19.3), which **is** KEV-listed — same version
string, stronger signal; CVE-2025-34158 is not in KEV. Jellyfin version comes only
from `GET /System/Info/Public`; the UDP 7359 reply carries Address/Id/Name and no
version, and works unicast (no broadcast needed). Also: `devices.rs:200` already
maps 32400 to "Plex", a label no scanner can currently produce, and
`upnp_igd.rs:891` asserts 32400 is *not* a sensitive port — revisit that in the
same change.
Sources: https://cveawg.mitre.org/api/cve/CVE-2025-34158 , https://jellyfin.org/docs/general/post-install/networking/

### HW-19 — 3D printers: OctoPrint 5000, Moonraker 7125
A Klipper/Moonraker printer with the LAN in `trusted_clients` is unauthenticated
arbitrary G-code, file upload and host reboot/update. Correction: `cors_domains`
is **not** an authentication bypass — `check_cors()` only decides response
headers; `authenticate_request()` runs independently. Only `trusted_clients` (or
an absent `[authorization]` section) disables auth. The compound risk worth
describing is `cors_domains: *` together with a trusted LAN: any page a LAN
browser visits can then drive the printer. Better probe: `GET /access/info` is
registered `auth_required=False`, always returns 200, and reports
`{"trusted": true|false, "login_required": ...}` directly — an explicit answer
rather than a status-code inference. Identify OctoPrint by the
`X-Clacks-Overhead: GNU Terry Pratchett` response header, present on every
response including the 403; `/api/version` alone cannot distinguish it, because
Moonraker's `octoprint_compat` component registers the same path on 7125. Port
7130 will usually be closed (HTTPS starts only if cert and key are configured).
"Fire risk" overstates it — Klipper enforces `max_temp` and thermal-runaway
protection, and shell execution needs the third-party `gcode_shell_command`
extension. Port 5000 is currently mislabelled `UPnP/DLNA` in `ports.rs:57`.
Source: https://moonraker.readthedocs.io/en/latest/configuration/

### HW-22 — `DeviceType` is missing the high-risk classes
Missing, each with a distinct HA discovery signal: Hub/Bridge (arguably the most
important — hubs aggregate every other device's credentials), Lock/AccessControl,
Thermostat/HVAC, EvCharger, SolarInverter/Battery, SmartSpeaker, Vacuum, NVR,
Appliance, 3dPrinter, Sensor. The change surface is **smaller than assumed**:
only `export/json.rs` (serde, snake_case) and `export/html.rs:414`
(`format!("{:?}")`, PascalCase) emit the field — `csv.rs` is findings-only and
the OCSF export emits no Device object at all. There is no `Display` impl and no
TUI column keyed on type; the real compile-time breakage sites are two exhaustive
emoji matches (`widgets/network_map.rs:12`, `widgets/devices.rs:36`), which is
the desired behaviour. Pre-existing bug to fix in the same PR: JSON emits
`smart_tv` while HTML emits `SmartTv` for the same device. Recommended design:
add a small number of variants that change triage severity (Hub, Lock, EvCharger,
SolarInverter, Nvr) plus `device_subtype: Option<String>` for the long tail —
additive in serde, invisible to CSV/OCSF, no enum bump per new category. If OCSF
device mapping is ever added, OCSF already defines Hub=11, Router=12, Switch=10,
IOT=7, so do not blanket-map to Other(99). Corrections to the evidence: `frigate`
and `moonraker` have no HA core integration; `ruuvi` is `ruuvi_gateway`; 8123 and
8581 are de-facto conventions, not IANA registrations.
Source: https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/dhcp.py

## Comparable projects

### CP-02 — Matter and Thread border-router discovery
Add `_matter._tcp`, `_matterc._udp`, `_matterd._udp`, `_meshcop._udp`,
`_meshcop-e._udp`. Corrections that change the output: (a) the mDNS socket binds
`0.0.0.0:0` and sends to 224.0.0.251 — **IPv4 only** — while Matter mandates IPv6
and Thread-attached nodes have no IPv4 address, so the Matter half needs an IPv6
socket first; (b) `_meshcop-e._udp` carries **no** TXT data (`PublishEpskcService`
passes an empty TXT), so it is presence-plus-SRV only and vendor fields must come
from the sibling `_meshcop` record; (c) test `CM != 0`, not `CM in {1,2}` —
`kEnabledJointFabric = 3` now exists, and CM=1 (Basic, static factory passcode) is
arguably worse than CM=2 (Enhanced, dynamic, time-boxed); (d) an open window is an
exposed authentication surface (PASE/SPAKE2+ still needs the setup passcode), not
an unauthenticated join — word it accordingly; (e) the ephemeral-key window
defaults to 2 minutes (max 10) and auto-stops on first failed connect, so the
`_meshcop-e` finding is realistically Info/Low opportunistic for a scheduled scan.
The richest TXT target is `_meshcop`'s `sb` state bitmap (commissioning posture)
plus `nn`, `xp`, `omr`, which leak Thread network identity and the routable IPv6
prefix in the clear.
Source: https://github.com/openthread/ot-br-posix

### CP-07 — routersploit corpora (BSD-3-Clause)
`defaults.txt` (653 lines, `user:pass`), `passwords.txt`, `usernames.txt`,
`snmp.txt`. The `exploits/routers` tree is a de-facto vendor fingerprint index
(2wire, 3com, asmax, asus, belkin, bhu, billion, cisco, comtrend, dlink,
fortinet, huawei, ipfire, lg, linksys, mikrotik, movistar, netcore, netgear,
netsys, shuttle, technicolor, thomson, tplink, ubiquiti, zte, zyxel, plus
`multi/`). The missing third leg next to telnet and FTP is HTTP Basic/Digest,
aimed at panels `mgmt_plane.rs` has already classified Exposed or Ambiguous.
Gate behind `--aggressive`, one attempt per credential per service, Confirmed
only on successful auth. Do not port the exploit modules. LICENSE appends an
informal attribution request satisfied by a `THIRD-PARTY-NOTICES.md` line.
Source: https://github.com/threat9/routersploit

### CP-11 — Declarative, user-extensible checks (concept from Wazuh SCA; GPL-2.0, concept only)
Today every check needs a Rust change and a recompile. A policy schema with
`id, title, severity, confidence, cwe, standards, when, remediation`, scoped in
v1 to predicates over facts already collected, would let users add checks without
touching the workspace — and the compliance field is where PL-12's capability-area
IDs and any ETSI/PSTI IDs belong. Three implementation corrections: `regex` is
**not** a workspace dependency (it reaches Cargo.lock only through
`termwiz -> fancy-regex` and the non-default `pcap` feature), so it is a new
direct dep; `toml` is also absent while `serde_yaml_ng` is present, so the format
should be YAML; and the project is closer to this than it looks —
`scanners/src/remediation.rs` already parses a declarative multi-document YAML
schema (OVRS) with `id/version/summary/metadata/parameters/steps/preflight/
validation/rollback`, and already reserves the predicate slot
(`r#match: Option<Value>`, currently `#[allow(dead_code)]`). The real delta is
`include_str!` -> XDG filesystem loading, not imperative -> declarative. Extend
the OVRS schema rather than shipping a second YAML dialect. Two of the seven
desirable predicate facts (`tls.key_bits`, `http.header`) are gathered but
dropped into Findings and never retained, so a fact-store change is a
prerequisite. Borrow Wazuh's policy-level `requirements` gate; model `compliance`
as an open map of standard -> IDs, since Wazuh's own ruleset maps eleven
standards plus MITRE ATT&CK.
Source: https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

### CP-12 — Metrics export (concept from WatchYourLAN, MIT)
`ScanHistory` plus the scan-diff engine are already more sophisticated than the
comparable's history, but there is no metrics export, so a cron-driven user
cannot graph or alert without writing a JSON parser. Add `--format prometheus`
emitting **Prometheus text exposition format 0.0.4** — *not* OpenMetrics:
node_exporter's textfile collector parses with `expfmt.NewTextParser`, which
rejects `# EOF`, `_created` series and OpenMetrics-only types, and would publish
`node_textfile_scrape_error 1` and drop the file. The collector also does not
support timestamps, so never append one (a `_timestamp_seconds` gauge whose
*value* is the epoch second is fine). Write to `name.prom.$$` and rename
atomically. Metrics: `devices_total`, `devices_new` (from `ScanDiff`),
`findings{severity,confidence}`, `kev_findings_total`, `eol_services_total`,
`scan_duration_seconds`, `last_scan_timestamp_seconds`. Use the info-metric
pattern — `device_info{ip,mac,vendor,device_type} 1` alongside a single-label
gauge — rather than three labels on one series. KEV and EOL metrics are
available today; a per-device grade is not (`Device` has no score field).
Source: https://github.com/aceberg/WatchYourLAN

### CP-13 — OWASP IoT Security Testing Guide IDs as a finding taxonomy (CC-BY-SA-4.0)
The OWASP IoT Top 10 is still the 2018 edition; the live work is the ISTG
(pushed 2026-08). Exercisable categories from this vantage are **three**, not two:
ISTG-DES, ISTG-UI and ISTG-WRLS — the attacker-model table marks Wireless
Interface as the only fully testable component at PA-2 (LAN access), which
`wifi.rs` and `passive_wifi.rs` already cover (WRLS-CRYPT-001 for WEP/TKIP,
WRLS-AUTHZ-001 for open SSID and WPS). One mapping correction: default
credentials are an authorization failure -> **DES-AUTHZ-001 / UI-AUTHZ-001**, not
DES-SCRT-001, whose objective is "whether secrets can be accessed via the data
exchange service" — reserve that for SNMP community strings, WPA-PSK, and
unauthenticated config dumps. Record the ISTG access level (PA-1/AA-1) alongside
the ID, or a coverage matrix implies we tested the PA-2+ half of the same test
case. Licence line: store bare ID strings, author your own labels, do not vendor
`checklists/checklist.md` or any `src/03_test_cases/*.md`, and do not reproduce
the full ID+title table — individual IDs are uncopyrightable but the taxonomy's
selection and arrangement is the compilation interest CC-BY-SA protects.
Depends on a `standards` field, which `Finding` does not have today.
Source: https://github.com/OWASP/owasp-istg

## Rejected or unusable

### Threats
| ID | Item | Reason |
|----|------|--------|
| ET-01 | UniFi OS CVE-2026-34910 chain | Fix-version table wrong — 5.0.8 applies only to UniFi OS Server; hardware consoles need 5.1.10/5.1.11/5.1.12, so ">= 5.0.8 safe" marks vulnerable UDM-Pro/UCG/UDR as patched. The claimed existing LAN detection does not exist (`local.rs` is on-device only). |
| ET-02 | MikroTik "MikroTrick" SSH chain | Vuln intel sound, probe broken: MikroTik OUIs are registered as "Routerboard.com", not "MikroTik" (zero matches in `oui_db.rs`); 8291 and 2000 are in `extended_ports()` only, dark on a default scan; version recovery from the Winbox handshake is unverified and gates the whole finding. |
| ET-06 | TP-Link TDDP UDP/1040 | CVE-2020-24363 (the KEV entry justifying the sweep) is an HTTP POST on TCP/80, not the UDP datagram service. TDDP listens only ~15 min after reboot, and Talos's two reports disagree on the port (1040 vs 1024). |
| ET-07 | NETGEAR TelnetEnable + June 2026 cluster | Headline CVE-2026-24714 is AV:N, not AV:A; CVE-2026-0407/0408 are from the January 2026 advisory, not June; EX8000 is in no affected list; the only product ever tied to TelnetEnable is the PR2000 travel router, not mesh gear. |
| ET-08 | D-Link 393-CVE fleet "driven by HNAP" | Two CVE ids transposed (90693/90699), DI-8400 CVE is 91001 (uncited). Only 7 of 393 descriptions mention HNAP (1.8%); the volume is `/boafrm/`, `/goform/` and `.asp`, and the top affected models are DNS-series NAS boxes with no HNAP at all. |
| ET-09 | Synology/QNAP NAS pre-auth RCE | CVE inventory and counts exact, but `SYNO.API.Info` returns an API catalogue with no DSM version or build — the version floor the whole finding depends on is unobtainable. SA_25_12 is the BeeStation advisory, wrong for the DSM CVE; CVE-2024-45538 is UI:R CSRF, not pre-auth. |
| ET-10 | Home Assistant add-ons host-network mode | The vulnerable sockets bind the hassio bridge 172.30.32.1, not the LAN address — a LAN sweep cannot see them. Confirming requires adding a host route (CAP_NET_ADMIN). Supervisor version is not exposed unauthenticated. |
| ET-14 | TP-Link extenders + Tapo camera | ONVIF `GetDeviceInformation` is READ_SYSTEM, not anonymous, and TP-Link requires a camera account for ONVIF/RTSP. `rtsp.rs` has no SOAP client — the "/onvif1" entry is an RTSP stream path, not the ONVIF service. |
| ET-15 | Reolink Home Hub CVE-2026-57473 | Firmware version is not recoverable unauthenticated (Baichuan gates everything above cmd_id 2 behind login), so the version comparison is unavailable at any confidence. Impact is stated backwards — CVSS is VC:N/VI:N/VA:N, all impact is on connected cameras. |
| ET-16 | Lantronix EDS5000 CVE-2025-67038 | The "cleanest identifier", TCP 9999, does not exist on the affected product — the vendor manual lists 22/80/443/21, UDP 161/514/30718. 9999 is the XPort/UDS setup port, which this CVE does not cover. |
| ET-18 | Systematise KEV EoL signal | Vendor list wrong (NETGEAR and DD-WRT have no EoL-flagged entries; the largest vendor is Microsoft). The headline entry has a patch. `Device` has no model field and 19 of 25 EoL entries name no specific model, so the join degenerates to vendor-only — a HIGH-FP design telling every D-Link owner to replace their router. |

### Resources
| ID | Item | Reason |
|----|------|--------|
| PL-02 | ZGrab2 protocol probes | Licence and module list fine, but the proposed new work already ships: `database.rs` implements both the Redis (`PING` -> `+PONG`/`-NOAUTH`, `INFO server`, EOL check) and memcached (`version`) probes with CWE-306. The remaining gaps (socks5, IPP, RDP, MSRPC, AMQP, NTP) are real but were not the pitch. |
| PL-09 | "KEV catalog is stale" | False. `kev_db.rs` is at catalog 2026.09.16, released 2026-09-16, 1,713 entries, committed 2026-09-16 — byte-identical to the live feed. The 2026-07-01 date came from a session heading in MEMORY.md. Licence is CC0-1.0, not "public domain by government authorship". |
| PL-10 | "EPSS has no formal licence" | False and the error is in the unsafe direction. FIRST Services Terms of Use v1.0.0 covers "API (Public)" and grants a **nonexclusive, nontransferable, revocable, field-of-use-limited** licence with all rights reserved — incompatible with Apache-2.0 redistribution. The operational advice (never embed, runtime only) is right for a stronger reason than given. |
| PL-11 | IANA port registry as a table | Licence (CC0) fine, data shape wrong: 1,072 rows with a service name have **no port**, and they are precisely the DNS-SD registrations (airplay, homekit, googlecast, raop, smb) the mDNS half wanted. A port-keyed `&[(u16,u8,&str,&str)]` structurally excludes them. Row count is 14,535 records over 15,404 lines (869 embedded newlines). |
| PL-20 | Sigma (DRL 1.1), OWASP ISVS (CC-BY-SA), OpenWrt ToH (CC-BY-SA), ET Open, CVE List V5 | Flag item; four of five sub-claims verified. ET Open's "mixed GPLv2" is wrong — all 71,758 sids in the current tarball are in the BSD range 2000000-2799999, zero GPLv2, zero ETPRO. Sigma's DRL 1.1 requires per-match author attribution in emitted messages; ISVS/OpenWrt are share-alike; cvelistV5 has no LICENSE file. |
| — | enthec/webappanalyzer | GPL-3.0. |
| — | python-kasa; many-passwords | GPL-3.0 / GPL-2.0. |
| — | JA4+ fingerprints | FoxIO License 1.1, non-commercial. |
| — | Nmap service probes; p0f | NPSL / LGPL-2.1. |
| — | Nmap `http-qnap-nas-info.nse` | "Same as Nmap" (NPSL). Reimplement from observed XML field names; do not port. |
| — | Vendor EOL pages (TP-Link/Netgear/ASUS/Synology/QNAP/Ubiquiti) | Individual copyrighted pages, no licence grant. Dates are uncopyrightable facts but cannot be bulk-redistributed as a scraped corpus. Use runtime lookup or hand-curated tables. |

### Hardware
| ID | Item | Reason |
|----|------|--------|
| HW-01 | "No `ssdp:all` sweep" | False. `scanners/src/mdns.rs:294 discover_ssdp()` already sends `ST: ssdp:all`, collects 3s/256 responses, parses LOCATION/SERVER/ST and fetches description XML. The real gap is narrower: the ST/manufacturer -> `DeviceType` map covers only IGD/MediaRenderer/MediaServer/Printer/Camera, so Roku, Sonos, Samsung, LG, Xbox are discovered but typed Unknown. |
| HW-03 | HA DHCP corpus as finer-than-OUI | 97% of the 257 MAC prefixes are exactly 3-byte OUIs and 255/257 are already in our table; `dhcp.rs` observes no DHCP traffic ("Sends no DHCP traffic") and there is no reverse-DNS anywhere, so the hostname half has no source. Superseded by PL-13, which states the shape correctly. |
| HW-04 | Roku ECP 8060 "unauthenticated full remote control" | Roku OS 14.1+ gates keypress/keydown/keyup behind "Control by mobile apps". The cited docs contain no SSID field and no `/query/apps`. Remediation advises "Default", which is the permissive value. (The read-only `/query/device-info` probe survives — folded into PL-14.) |
| HW-05 | ADB 5555 "abused by BADBOX 2.0" | The FBI PSA never mentions ADB or any port; BADBOX 2.0's documented vectors are firmware preinstallation and backdoored apps. RSA-key authorization applies since Android 4.2.2, not Android 11; the TV/Wear pairing floor is Android 13. |
| HW-07 | LG webOS 3000/3001 | Port 3000 is a WebSocket endpoint, not an HTTP server — `GET /` returns no version banner. The firmware string the CVE mapping needs comes from a post-registration request, and a register handshake puts a pairing prompt on the user's television mid-scan. |
| HW-08 | AdGuard Home :3000 / Pi-hole v6 | `/control/status` is not in AdGuard's auth-exempt list (403 when configured, unrouted when not), and on a configured instance `/install.html` falls through to the SPA catch-all returning 200 — every correctly-configured install would be flagged Critical. |
| HW-09 | Camera/NVR HTTP management plane | Hikvision ISAPI, Dahua magicBox and Axis basicdeviceinfo all require auth (Axis is POST-only); the only credential-free route to Hikvision deviceInfo is sending the CVE-2017-7921 magic parameter, i.e. exploitation. The DHCP-hostname trigger needs privileged sniffing. (The Frigate 5000-vs-8971 mislabel is real and worth fixing separately.) |
| HW-11 | Samsung Tizen 8001/8002/8000/55000 | Port 8000 is already scanned. `TokenAuthSupport` is a JSON string and is absent entirely on the older sets the Medium tier targets, so that tier cannot fire. Tokens are attached only on the TLS port, so "tokens transit unencrypted on 8001" is wrong. |
| HW-12 | Matter/Thread via TCP 5540 | `extended_ports()` feeds a TCP connect scan; Matter operational transport is UDP/5540 and `INET_CONFIG_ENABLE_TCP_ENDPOINT` defaults to 0, so TCP/5540 is closed on typical devices. Superseded by CP-02 (mDNS). |
| HW-15 | Sonos 1400 SOAP | Sonos firmware now ships UPnP **disabled by default**; HA added a repair issue and a prerequisite doc section, and `http://<ip>:1400/DeviceProperties/Control` returns 403. The quoted HA line is about the HA host's event listener, not the speaker. |
| HW-17 | Roborock 58867 / `_miio._udp` | Roborock's HA manifest declares no zeroconf key at all; `_miio._udp` maps to xiaomi_aqara/xiaomi_miio/yeelight. UDP 58866 is the port the *HA host* binds to receive the beacon, not a port on the vacuum. |
| HW-18 | Smart locks / garage doors | Nuki's bridge HTTP API returns **401**, not 403 (pynuki raises `InvalidCredentialsException` on 401); the one endpoint that returns 403 is `/auth`, which physically opens a 30-second pairing window on the lock bridge. `_nuki` is not an mDNS service type; discovery is via the Nuki cloud. |
| HW-20 | Shelly / ESPHome / WLED | Gen1 devices do not advertise `_shelly._tcp` (they are `_http._tcp` + `shelly*` hostname), so the probe's first step misses the exact population the CWE-306 finding targets. Gen2+ factory stock ships HTTPS enabled. uhttpd emits no `Server` header at all. (The ESPHome 6053 plaintext-vs-Noise probe is sound — folded into PL-14.) |
| HW-21 | AdGuard / Pi-hole panels | Duplicate of HW-08; same 403/200 defect. Note AdGuard Home is GPL-3.0 and Pi-hole FTL is EUPL-1.2 — no fixtures or strings may be copied. |
| HW-23 | ISP CPE / mesh KEV cluster | CVE-2025-59374 is ASUS **Live Update**, a PC updater, not a router. Across all 1,713 KEV entries the only mesh product is ASUS Lyra Mini; there are zero entries for eero, Orbi, Deco, Nest Wifi or Velop. KEV carries no version field and `kev_db.rs` stores bare CVE ids, so "version-to-CVE anchors from KEV" has no data source on either end. |
| HW-24 | Apple TV / HomeKit / Echo | `_amzn-alexa._tcp` maps to **roomba** in HA's table — the Echo half has no evidence. `_companion-link._tcp` is advertised by every Apple device, so classifying it SmartSpeaker relabels every Mac and iPhone. "Will accept pairing from any LAN host" overstates SRP-authenticated HAP pair-setup. (The `_hap._tcp` `sf` bit-0 read is genuinely one TXT field away — keep it.) |
| HW-25 | Consumer control-plane port profile | The stated trigger cannot fire: `PHASE1_IDS = ["network", "ports", "device"]` runs `ports` **before** `device`, and enrichment happens after the whole Phase 1 loop — at sweep time every device is `DeviceType::Unknown`. 8000 is already present; 5683 is UDP and would be a silent no-op in a TCP list. The port additions themselves are real and ride with each individual item above. |

### Comparable projects
| ID | Item | Reason |
|----|------|--------|
| CP-01 | HA manifests as a fingerprint corpus | Only 244 of 1,521 manifests carry a LAN-observable matcher, and the ~673 usable matchers are two orders of magnitude narrower than our 40,157-entry OUI table — a complement, not a superset. The quoted airplay example cross-wires two different matchers. Superseded by PL-13. |
| CP-03 | ETSI EN 303 645 as the taxonomy spine | TS 103 701 has **131** test cases, not 246. Verdict vocabulary is PASS/FAIL/INCONCLUSIVE, not NOT-APPLICABLE. Two of nine mappings are wrong (debug interfaces are physical — UART/JTAG — not Docker/kubelet; 5.3-8/5.3-13 are manufacturer-process provisions). UK PSTI is frozen at V2.1.1, so v3.1.3 IDs diverge from it. |
| CP-04 | NIST IR 8425A router profile | "What the FCC adopted for Cyber Trust Mark" is false — the R&O cites IR 8425, was adopted six months before 8425A, and explicitly excludes routers from scope. `tcp_connect_probe` returns `bool`, so RST-vs-timeout is not available. The protocol-mismatch probe would false-positive on every RFC 4253-conforming SSH server, which greets before reading. |
| CP-05 | RFC 8520 MUD URLs from X.509 | The extension lives in an 802.1AR IDevID/LDevID — a *client* credential presented during EAP-TLS. `ssl.rs` reads the device's TLS *server* certificate. Home LANs run no 802.1X, so the trigger never fires. Shipping without CMS verification is a stated MUST violation. |
| CP-06 | endoflife.date as a device EOL check | Four of nine named products (pfSense, UniFi, Synology DSM, OpenSSH) are not in the dataset; 7 of the 20-product curated list 404. The regulatory framing is accurate. The surviving server-software half is kept as PL-07. |
| CP-08 | Per-device report-card grade | `risk_grade()` already exists in `analysis/src/risk_score.rs:29` with the A-F ladder, rendered in CLI, TUI and HTML — at scan scope. There is no TLS grading in `ssl.rs` (every "grade" hit is inside "Upgrade"). NetAlertX is GPL-3.0 and implements no per-device grading; Fing's score is network-scoped. The per-device gap is real; the evidence for it was not. |
| CP-09 | NetAlertX rogue-DHCP / NBSTAT / router import | Probe (a) cannot work: per RFC 2131 servers reply to port 68, never to the request's source port, so an ephemeral socket receives nothing; binding 68 needs root and races the host's own DHCP client. NetAlertX itself shells out to nmap's `broadcast-dhcp-discover`, which requires root + pcap. (b) NBSTAT and (c) router import survive and are worth doing. |
| CP-10 | CISA SOHO router alert as three verdicts | The alert makes two enumerated asks plus two more in following sentences, and is organised around three *principles*, not three asks — the numerical match is coincidental. The claim also drops the fourth ask and overstates the LAN-only requirement, which the alert itself qualifies. |
| CP-14 | OpenWrt firmware currency + banIP | No LuCI detection exists in the tree to "extend" (zero matches for `luci`). uhttpd emits no `Server` header, and the default `luci-theme-bootstrap` suppresses the release string on the login page (`blank_page: true`). banIP is GPL-3.0-or-later and dibdot/DoH-IP-blocklists is GPL-3.0 — the DoH list cannot be embedded. |
| CP-15 | IoT Inspector device-identity-by-destination | The "device-labelling logic" is a client that POSTs device metadata to a remote fine-tuned LLaMA endpoint on Modal; the only local corpus in the repo is an OUI CSV. Apache-2.0 covers the client, not the model. Its flow visibility comes from ARP spoofing + libpcap (root), not from monitor mode — 802.11 data frames are CCMP-encrypted, so no destination IP/port/hostname is derivable. |

## Data refresh

Both embedded snapshots were regenerated on 2026-09-16 and the generators
reproduce the committed files byte for byte.

| Dataset | Embedded? | Current snapshot | Staleness | Licence |
|---------|-----------|------------------|-----------|---------|
| CISA KEV | Yes, `crates/rikitikitavi-analysis/src/kev_db.rs` | 2026.09.16, 1,713 entries | current | CC0-1.0 |
| IEEE OUI (MA-L) | Yes, `crates/rikitikitavi-scanners/src/oui_db.rs` | generated 2026-09-16, 40,157 entries | current | IEEE public listing |
| EPSS | No — runtime API | n/a | n/a | FIRST ToU: revocable, non-transferable; **never embed** |

### Commands

```bash
# KEV — regenerate from the live CISA feed (weekly is sufficient; ~a few CVEs/week)
uv run python scripts/gen_kev_db.py > crates/rikitikitavi-analysis/src/kev_db.rs
git diff --stat crates/rikitikitavi-analysis/src/kev_db.rs

# OUI — the generator reads a hardcoded /tmp/oui.csv and takes no argument
curl -fsSL https://standards-oui.ieee.org/oui/oui.csv -o /tmp/oui.csv
curl -sSL -o /tmp/oui.csv https://standards-oui.ieee.org/oui/oui.csv && uv run python scripts/gen_oui_db.py > crates/rikitikitavi-scanners/src/oui_db.rs
# (only MA-L rows are kept; MA-M/MA-S 28- and 36-bit blocks are dropped — see PL-13)

# Verify both compile and that the generated tables stay sorted
cargo test -p rikitikitavi-analysis -p rikitikitavi-scanners
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check   # oui_db.rs carries #[rustfmt::skip] to stop table churn
```

Notes:
- Both generated files are `#[rustfmt::skip]`-annotated tables sorted for
  `binary_search`; regenerate rather than hand-editing.
- KEV's JSON Schema was revised 2026-09-02, additively (`forensicTriage` added
  per BOD 26-04). The generator reads only `catalogVersion`, `dateReleased` and
  `vulnerabilities[].cveID`, all still in the schema's `required` lists, and has
  already run cleanly against the post-revision feed.
- KEV's licence is CC0-1.0 with two conditions the "public domain" shorthand
  drops: third-party links inside records are bound by those sites' licences,
  and use does not authorise the CISA logo or DHS seal. Record this in
  `THIRD-PARTY-NOTICES.md` (which does not exist yet).
- EPSS must stay a runtime lookup. FIRST's Services Terms of Use grant a
  revocable, non-transferable, field-of-use-limited licence that is incompatible
  with Apache-2.0 redistribution. Add an attribution line naming both FIRST and
  Empirical Security (which now generates the scores) to README and to the
  JSON/OCSF/HTML exports that carry the `epss` field.
- If PL-07 or PL-08 land, add `gen_eol_db.py` and `gen_ssvc_db.py` to the same
  refresh job. Vulnrichment's default branch is `develop`, not `main`.

## Observations

Found while grounding the roadmap against the code; none are in scope for the
roadmap itself but all are actionable.

1. **`epss.rs` silently drops CVEs past the first 100.**
   `crates/rikitikitavi-network/src/epss.rs:41` joins every unique CVE into one
   `?cve=` URL and never sends `limit` or paginates. FIRST's API defaults to
   `limit=100`, so a scan with >100 distinct CVEs gets scores for only the first
   100 (sorted order, so the dropped set is deterministic but arbitrary). Past
   ~140 CVEs the URL exceeds request-line limits and the API returns
   `{"total":0}` — all enrichment lost. Both failures deserialise cleanly, so the
   `tracing::debug!` arms never fire. A live scan already yields 144 findings and
   OpenSSH banner correlation alone maps 5 CVEs per host. Fix: chunk into batches
   of ≤100, pass `limit`, check HTTP status before `.json()`, and warn when the
   returned count is less than requested.
2. **`device_type` renders two different ways** — `smart_tv` in JSON (serde
   `rename_all`), `SmartTv` in HTML (`format!("{:?}")` at `html.rs:414`). There is
   no `Display` impl. Same field, two spellings, depending on export format.
3. **`THIRD-PARTY-NOTICES.md` does not exist.** Several items above (Recog,
   nuclei, SecLists, DefaultCreds, routersploit, HA tables, KEV, EPSS) create
   attribution obligations that need somewhere to live.
