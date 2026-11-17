# Detection Roadmap 2026-09

> **This roadmap is closed.** Its top 15 shipped in 0.4.0. The current roadmap,
> with all open work, is [ROADMAP-2026-11.md](ROADMAP-2026-11.md). The few
> 2026-09 items that are still partly open are listed below and repeated there
> under "Carried over from 2026-09". This file is kept for the rejected items
> and their reasons, which still apply.

Derived from a 2026-09 research sweep across four dimensions (emerging threats,
embeddable resources, home hardware, comparable projects). Every item was
fact-checked against primary sources and against this repository; refuted items
are listed in [Rejected or unusable](#rejected-or-unusable) with the reason.

Scope constraint for everything here: unprivileged, read-only, from an ordinary
LAN host. Licence constraint: Apache-2.0-compatible only (MIT/BSD/ISC/CC0/
Apache/public domain). GPL/LGPL/AGPL, NPSL, FoxIO and CC-BY-NC are excluded.

Baseline at time of writing: 26 `Scanner` impls, 40,157 OUI entries, KEV catalog
2026.09.16 (1,713 entries), EPSS at runtime.

## Status (checked against the code 2026-11-17)

Paths are relative to `crates/`. "Done" means the detection exists in the code,
not only in the changelog.

### Done

| ID | Item | Code |
|----|------|------|
| ET-03 | ASUS AyySSHush, SSH on TCP/53282 (top 15 #2) | `rikitikitavi-scanners/src/ports.rs`, `services.rs` |
| ET-04 | DD-WRT `upnpd` CVE-2021-27137, passive `SERVER:` match | `rikitikitavi-scanners/src/ddwrt_upnp.rs` |
| ET-05 | Hikvision SADP, build-date floor 250807 (top 15 #9) | `rikitikitavi-scanners/src/sadp.rs` |
| ET-11 | Client-side LAN exposure, Sonos CVE-2026-4149 | `rikitikitavi-scanners/src/lan_client_exposure.rs` |
| ET-12 | PaperCut NG/MF build check (top 15 #13) | `rikitikitavi-scanners/src/papercut.rs` |
| ET-13 | KNXnet/IP `SEARCH_REQUEST` | `rikitikitavi-scanners/src/knx.rs` |
| PL-01 | Rapid7 Recog fingerprints (top 15 #3) | `rikitikitavi-scanners/src/recog.rs`, `recog_db.rs` |
| PL-03 | nuclei `network/detection` table, part (a) (top 15 #14) | `rikitikitavi-scanners/src/nuclei_detect.rs`, `nuclei_db.rs` |
| PL-06 | routersploit `snmp.txt` communities, capped at 8 per host | `rikitikitavi-scanners/src/default_creds_db.rs`, `snmp.rs` |
| PL-07 | endoflife.date cycles (top 15 #7) | `rikitikitavi-scanners/src/eol_db.rs` |
| PL-08 | CISA Vulnrichment SSVC and CWE backfill (top 15 #11) | `rikitikitavi-analysis/src/vulnrichment_db.rs` |
| PL-13 | Home Assistant discovery tables (top 15 #4) | `rikitikitavi-scanners/src/ha_discovery_db.rs` |
| HW-02 | mDNS service types 8 -> 113, TXT interpreted (top 15 #1) | `rikitikitavi-network/src/mdns.rs` |
| HW-06 | Modbus/SunSpec, read-only (top 15 #10) | `rikitikitavi-scanners/src/modbus.rs` |
| HW-10 | Google Cast eureka_info and 8009 TLS (top 15 #12) | `rikitikitavi-scanners/src/cast.rs` |
| HW-13 | TP-Link Kasa `get_sysinfo` (top 15 #6) | `rikitikitavi-scanners/src/kasa.rs` |
| HW-14 | Tuya 55AA/6699 broadcasts (top 15 #8) | `rikitikitavi-scanners/src/tuya.rs` |
| HW-16 | Plex `/identity`, Jellyfin `/System/Info/Public` | `rikitikitavi-scanners/src/media_server.rs` |
| HW-19 | Moonraker `/access/info`, OctoPrint `X-Clacks-Overhead` | `rikitikitavi-scanners/src/print3d.rs` |
| HW-22 | `DeviceType` +13 variants and `device_subtype` (top 15 #5) | `rikitikitavi-models/src/device.rs` |
| CP-07 | Default-credential corpus from routersploit, `--aggressive` only, incl. HTTP Basic | `rikitikitavi-scanners/src/credentials.rs`, `default_creds_db.rs` |
| CP-11 | `scan --rules` declarative YAML rules | `rikitikitavi-analysis/src/declarative.rs` |
| CP-12 | `--format prometheus` (exposition 0.0.4) | `rikitikitavi-export/src/prometheus.rs` |

Also shipped, though rejected as pitched (CP-08): per-device report cards,
`rikitikitavi-analysis/src/device_grade.rs`.

### Partly done or not started

| ID | State | What is missing |
|----|-------|-----------------|
| CP-02 | Partly done | `_matter`, `_matterc`, `_meshcop` are queried and parsed, but only over IPv4 (`UdpSocket::bind("0.0.0.0:0")` in `rikitikitavi-network/src/mdns.rs`). Thread-only Matter nodes need an IPv6 mDNS socket. |
| CP-13 | Partly done | Findings are tagged with OWASP IoT Top 10 (2018) categories (`rikitikitavi-analysis/src/standards.rs`). OWASP ISTG test-case IDs with access level are not. |
| PL-14 | Partly done | Cast is done (HW-10). The Roku `/query/device-info`, Shelly `auth_en` and ESPHome identity probes are not. |
| PL-12 | Not started | NIST IR 8425 `capability_area` on `Finding`. |
| PL-04, PL-05 | Not started | SecLists and DefaultCreds are not used; the corpus came from routersploit instead (CP-07). |
| PL-03 (b) | Not started, by design | Bulk import of `http/default-logins` was advised against. |

Small loose ends from shipped items, still true in the code:
- HW-19: port 5000 is still labelled `UPnP/DLNA` in `rikitikitavi-scanners/src/ports.rs`.
- HW-16: `upnp_igd.rs` still treats a forwarded 32400 (Plex) as not sensitive.
- ET-11: `parse_upnp_device_xml` reads `firmwareVersion` only, not Sonos's
  `softwareVersion`. The Sonos finding does not need a version, so this only
  matters if a version check is added.

The detail sections below keep only the text needed for the open work. A done
item has one line; its design notes are in git history (`git log -- docs/ROADMAP.md`)
and in the module docs.

## Threats

- ET-03 ASUS AyySSHush, TCP/53282: done.
- ET-04 DD-WRT UPnP M-SEARCH overflow, CVE-2021-27137: done.
- ET-05 Hikvision SADP, UDP/37020: done.
- ET-11 Sonos Era 300 SMB client OOB, CVE-2026-4149: done, as the client-side
  LAN exposure category.
- ET-12 PaperCut NG/MF, CVE-2026-81578 -> CVE-2026-82078: done.
- ET-13 KNXnet/IP, UDP/3671, CVE-2023-4346: done.

## Embeddable resources

- PL-01 Rapid7 Recog (BSD-2-Clause): done.
- PL-03 nuclei-templates (MIT): `network/detection` done. Do **not** bulk import
  `http/default-logins`; of the home-relevant vendors only asus, d-link, tplink,
  dahua and grandstream have templates.
- PL-06 routersploit `snmp.txt` (BSD-3-Clause): done.
- PL-07 endoflife.date (MIT): done.
- PL-08 CISA Vulnrichment (CC0-1.0): done.
- PL-13 Home Assistant generated discovery tables (Apache-2.0): done.

### PL-04 — SecLists default credentials (MIT) — not started
`Passwords/Default-Credentials/default-passwords.csv`, 2,875 rows,
`Vendor,Username,Password,Comments`. The vendor column is the point: join to the
OUI vendor already on `Device` and try 3-10 plausible pairs instead of a blind
list. Handle the `<BLANK>` sentinel. Vendor strings need normalisation before the
join ("3COM", "2Wire, Inc." vs IEEE registrant names). Same `--aggressive` gate
and per-host cap as the existing corpus.
Source: https://github.com/danielmiessler/SecLists

### PL-05 — DefaultCreds-cheat-sheet (MIT) — not started
3,766 rows keyed on product. Merge into PL-04's generator, do not ship a second
table. The union with SecLists is ~4,000-4,150 triples (88% of SecLists is
already in DefaultCreds). Merge traps: the blank sentinel differs in case
(`<blank>` here, `<BLANK>` in SecLists), and 278 `productvendor` values carry a
protocol suffix (`Cisco (ssh)`) to strip before dedup. Pin a commit SHA.
Source: https://github.com/ihebski/DefaultCreds-cheat-sheet

### PL-12 — NIST IR 8425 (US Government work, public domain in the US) — not started
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
not the device. WiFi findings carry no `affected_ip`, so they cannot populate a
per-device row without attribution to the AP. `Finding` now has a `standards`
field (CP-13), which is the natural place for these IDs.
Source: https://csrc.nist.gov/pubs/ir/8425/final

### PL-14 — HA device client libraries as protocol references — partly done
Cast is done (HW-10). Remaining read-only auth-posture probes: Roku
`/query/device-info` (keypresses are gated behind "Control by mobile apps" as of
Roku OS 14.1, but `/launch` and `/query/device-info` are not); Shelly exposes
`auth_en` directly in `GET /shelly`, so `Shelly.GetConfig` is corroboration only;
ESPHome's `InvalidEncryptionKeyAPIError` carries `received_name` and
`received_mac`, so even an encrypted node leaks identity to an unauthenticated
peer. Licences differ per library — python-kasa is GPL-3.0; check each, never
assume.
Source: https://github.com/home-assistant-libs/pychromecast

## Hardware

- HW-02 mDNS service-type expansion: done.
- HW-06 Modbus/TCP 502: done.
- HW-10 Google Cast 8009 TLS and 8443/8008 eureka_info: done.
- HW-13 TP-Link Kasa, TCP/9999: done. The 2026-11 roadmap added a fixed-firmware table (NT-02).
- HW-14 Tuya local protocol: done.
- HW-16 Plex 32400 and Jellyfin: done. Loose end: `upnp_igd.rs` 32400 sensitivity.
- HW-19 3D printers, OctoPrint and Moonraker: done. Loose end: port 5000 label.
- HW-22 `DeviceType` widening: done. JSON and HTML now share one snake_case spelling.

## Comparable projects

- CP-07 routersploit corpora: done (see PL-04/PL-05 for the corpora not used).
- CP-11 Declarative, user-extensible checks: done.
- CP-12 Metrics export: done.

### CP-02 — Matter and Thread border-router discovery — partly done
Queries and TXT parsing for `_matter._tcp`, `_matterc._udp`, `_matterd._udp`
and `_meshcop._udp` are done, including `CM != 0` and the `sb`/`nn`/`xp`/`omr`
fields. Open: the mDNS socket binds `0.0.0.0:0` and sends to 224.0.0.251 —
**IPv4 only** — while Matter mandates IPv6 and Thread-attached nodes have no IPv4
address, so the Matter half needs an IPv6 socket.
Source: https://github.com/openthread/ot-br-posix

### CP-13 — OWASP IoT Security Testing Guide IDs (CC-BY-SA-4.0) — partly done
Shipped instead: OWASP IoT Top 10 (2018) category tags (`I1`-`I10`) in a
`standards` field. Open: ISTG IDs. Exercisable categories from this vantage are
ISTG-DES, ISTG-UI and ISTG-WRLS (WRLS-CRYPT-001 for WEP/TKIP, WRLS-AUTHZ-001 for
open SSID and WPS). Default credentials map to **DES-AUTHZ-001 / UI-AUTHZ-001**,
not DES-SCRT-001; reserve that for SNMP community strings, WPA-PSK and
unauthenticated config dumps. Record the ISTG access level (PA-1/AA-1) alongside
the ID. Licence: store bare ID strings, author your own labels, do not vendor
`checklists/checklist.md` or any `src/03_test_cases/*.md`, and do not reproduce
the full ID+title table.
Source: https://github.com/OWASP/owasp-istg

## Rejected or unusable

Reasons are as of 2026-09. Some code facts quoted below have changed since (for
example, reverse DNS now exists: ID-01 in the 2026-11 roadmap), but the reasons
for rejecting each item still hold.

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

Embedded snapshots as of 2026-11-17. Each generator's docstring gives its exact
usage; regenerate rather than hand-editing (the tables are sorted for
`binary_search` and carry `#[rustfmt::skip]`).

| Dataset | File (under `crates/`) | Snapshot | Generator | Licence |
|---------|------------------------|----------|-----------|---------|
| CISA KEV | `rikitikitavi-analysis/src/kev_db.rs` | 2026.11.13, 1,781 entries | `scripts/gen_kev_db.py` | CC0-1.0 |
| IEEE MA-L / MA-M / MA-S | `rikitikitavi-scanners/src/oui_db.rs` | 2026-11-14; 40,055 / 6,688 / 7,280 | `scripts/gen_oui_db.py --fetch <empty-dir>` | IEEE public listing |
| Home Assistant discovery | `rikitikitavi-scanners/src/ha_discovery_db.rs` | commit fa47075 | `scripts/gen_ha_discovery_db.py` | Apache-2.0 |
| endoflife.date | `rikitikitavi-scanners/src/eol_db.rs` | see file header | `scripts/gen_eol_db.py` | MIT |
| Vulnrichment | `rikitikitavi-analysis/src/vulnrichment_db.rs` | see file header | `scripts/gen_vulnrichment_db.py` | CC0-1.0 |
| Recog | `rikitikitavi-scanners/src/recog_db.rs` | see file header | `scripts/gen_recog_db.py` | BSD-2-Clause |
| nuclei detection | `rikitikitavi-scanners/src/nuclei_db.rs` | see file header | `scripts/gen_nuclei_db.py` | MIT |
| routersploit wordlists | `rikitikitavi-scanners/src/default_creds_db.rs` | ref 723b574 | `scripts/gen_default_creds_db.py` | BSD-3-Clause |
| EPSS | not embedded, runtime API | n/a | n/a | FIRST ToU: revocable, non-transferable; **never embed** |

After a refresh:

```bash
cargo test -p rikitikitavi-analysis -p rikitikitavi-scanners
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Notes:
- Attribution for the embedded data is in `THIRD-PARTY-NOTICES.md`.
- KEV's licence is CC0-1.0 with two conditions: third-party links inside records
  are bound by those sites' licences, and use does not authorise the CISA logo
  or DHS seal.
- EPSS must stay a runtime lookup. FIRST's Services Terms of Use grant a
  revocable, non-transferable, field-of-use-limited licence that is incompatible
  with Apache-2.0 redistribution. Still open: the README names FIRST.org but not
  Empirical Security (which now generates the scores), and the JSON/OCSF/HTML
  exports that carry `epss` have no attribution line.
- Vulnrichment's default branch is `develop`, not `main`.

## Observations

Found while grounding this roadmap against the code in 2026-09. Status as of
2026-11-17:

1. `epss.rs` dropped CVEs past the first 100. Fixed 2026-09-17 (batches of 100).
2. `device_type` rendered as `smart_tv` in JSON and `SmartTv` in HTML. Fixed in
   0.4.0 (one snake_case spelling).
3. `THIRD-PARTY-NOTICES.md` did not exist. It does now.
