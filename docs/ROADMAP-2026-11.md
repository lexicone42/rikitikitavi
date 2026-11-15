# Roadmap 2026-11

From a 2026-11-14 research sweep across four dimensions: threats, identification, remediation and resources. Every item was checked against the sources linked here and against this repository. Two verifiers reviewed each claim, and their corrections are folded into the text. Refuted items are listed under [Rejected or unusable](#rejected-or-unusable). Everything shipped in `docs/ROADMAP.md` is done and is not proposed again here.

Constraints are unchanged. Probes run unprivileged and read-only from a LAN host. Embedded data must be Apache-2.0-compatible. The `Confidence` enum is `Inferred | Probable | Confirmed`. Any "Possible" tier in the research becomes `Inferred`, because `exploit_intel.rs` raises KEV-tagged findings to High unless they are `Inferred`.

Owner-LAN evidence comes from `scan-20260912-224815.json` (43 devices, 219 findings) and the 2026-11 `smoke.json` (27 devices, 71 findings). `v040.json` was not present. The Kasa findings come from the 0.4.0 scanner on the owner's six plugs, as described in the task.

## Status (2026-11-14)

Shipped: Top 12 items 1-12 (Plex2Shell, Kasa firmware table, reverse DNS, remediation gate, product-aware remediation, identity ports, Synology advisories and rsync correlation, Hue swversion, Spotify Connect, HA hostname matchers and house table, `verify`), plus NT-06 (PHP2Shell), RE-02 (HA tables), FIX-02 (`fix-plan`) and the FIX-08 accepted-risk ledger.

Also shipped: NT-09 (UniFi SAB-069 floors; Protect AI Key skipped, nothing identifies one), ID-08 (NBSTAT), ID-11 (MA-M/MA-S).

NT-08/RE-04 (tvOS floors and EOL) and FIX-14 (AirPlay posture) shipped too; HomePod and macOS currency did not.

Open: ID-12 (UniFi client import), FIX-06 (segmentation advisor), FIX-08 `fixPath` key and template `validation:`, FIX-10 to FIX-13, RE-06 (OSV). Dedup now drops only restatements (it used to keep one scanner's findings per port).

## Executive summary

1. **Dependencies:** reqwest is stuck at 0.13.1. The workspace asks for the `webpki-roots` feature, which 0.13.2+ removed, so `cargo update` cannot reach 0.13.5 and its redirect header-stripping fix. Nothing flags this.
2. **Threats on this LAN:** Plex2Shell (4 KEV CVEs, 2026-10-20) affects NAS-hosted Plex. Two TP-Link Kasa CVEs list fixed firmware per model and hardware version (six plugs here). Two Critical Synology DSM advisories cover the DS418play.
3. **Identification:** the biggest gain is reverse DNS. The tool runs none. One PTR query to the gateway named 20/27 smoke-scan devices and 11/13 September "unknowns", including two garage-door openers and a smart lock.
4. **Remediation quality:** advice is wrong for appliances. Dyson gets "configure the broker for TLS" and Denon gets "use SSH instead". 9 of 13 smoke findings at Low or above carry no fix at all. `dedup_rank` throws away the mqtt scanner's "auth enforced" verdict.
5. **Dead code:** `classify_by_ports` rules for 62078 (iPhone), 3689, NAS (5001) and UniFi controller (8880) can never fire at the default port range.
6. **Fix loop:** the fix loop has no closing step. Planned: a `verify` mode that reports resolved / still present / inconclusive, a `fix-plan` checklist, and an accepted-risk ledger with expiry.
7. **Refuted:** an OpenSSH "sshole" version floor (Alpine backports), MikroTik fix thresholds (mixed up with a non-KEV CVE), "proxy listener means compromise", and the endoflife.date Chromecast feed (stale for the 4K model).
8. **Embedded data:** KEV 2026.11.13 is current. The HA tables should be regenerated: upstream adds HP printer zeroconf and removes six Dahua OUIs that mislabel Lorex/Amcrest devices as `imou`.

## Top 12 by (value x relevance to this LAN) / effort

| # | Item | Why now (source) | Design sketch | Maps to | Effort |
|---|------|------------------|---------------|---------|--------|
| 1 | Unpin reqwest (drop dead `webpki-roots` feature) | 0.13.4 strips sensitive headers when a redirect changes scheme. [CHANGELOG](https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md) | Remove the feature and run `cargo update -p reqwest` to reach 0.13.5. Set `.redirect(Policy::none())` on the authenticated UniFi client, since custom CSRF headers are never stripped. CI check for held-back direct deps, with an allowlist. | `Cargo.toml:38`; `rikitikitavi-unifi/src/api.rs:117` `build()`; `ci.yml` | S |
| 2 | Plex2Shell verdict (<1.43.3.10861) | 4 CVEs added to KEV 2026-10-20; "actively and widely exploited". [Plex forum](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319) | New `PlexVerdict::Plex2Shell` with floor `[1,43,3,10861]`. One finding lists every applicable CVE (also CVE-2025-34158 on 1.41.7–<1.42.1, CVE-2020-5741 below 1.19.3). High, Confirmed. Describe the chain as a whole. Note that NAS package centres can lag. | `media_server.rs:60-64` `PLEX_*`, `:131` `PlexVerdict`, `:143` `classify_plex` | S |
| 3 | Kasa: per-model fixed-firmware table + honest remediation | CVE-2026-108473 (FAQ 5342, 2026-10-14) and CVE-2026-76784 (FAQ 5267, 2026-08-26), CVSS4 8.7. [FAQ 5342](https://www.omadanetworks.com/us/support/faq/5342/) | Key `(model, full hw_ver string)` to a fixed `(maj,min,patch,build)`. Match: High, Confirmed. Model-only 5267 row with no 5342 counterpart: Probable. Unknown model: today's generic finding. Rewrite `segmentation_remediation` as: update, then verify, then segment. | `kasa.rs:344-413` `KasaSysinfo`, `:466` `segmentation_remediation`, `:507` builder | S |
| 4 | Reverse DNS (PTR) via gateway resolver | 20/27 smoke devices resolved, including UniFi AP models now mistyped as `switch`, MyQ, Schlage and Litter-Robot. [aiodiscover](https://github.com/Bluetooth-Devices/aiodiscover) | hickory PTR to the gateway plus RFC1918 nameservers only. RD=0 first, RD=1 fallback, 16 in flight, 1 s timeout. Strip `.localdomain`. Reject synthetic names, bare IPs and bare 12-hex MACs. `DeviceHint` with source `dns_ptr`, below mDNS/UPnP. | new `rikitikitavi-network/src/rdns.rs` (add `hickory-resolver.workspace = true`); `runner.rs` enrichment | S |
| 5 | Remediation coverage gate + quick reuse | 9/13 Low+ findings in smoke.json have no fix, so `generate_priority_actions` drops them | Test: severity ≥ Low needs a remediation or an accept rationale, with a shrinking allowlist. Wire existing templates: `ssl.cert-self-signed` on the x509 path (`ssl.rs:609`), `http_audit.missing-hsts` (`ssl.rs:931`), `gateway_ssh_remediation` for `ports.rs:372`. Hue self-signed means old firmware: the fix is "update". | `ssl.rs`, `ports.rs`, `services.rs:1065`, `device.rs:229`, `credentials.rs:1266`, `mdns.rs:572`; new `tests/remediation_coverage.rs` | S |
| 6 | Product-aware remediation (Dyson MQTT, Denon telnet) + dedup fix | Dyson's MQTT fix is the #1 priority action in smoke.json but cannot be done; the Denon has no SSH. [Denon protocol PDF](https://assets.denon.com/documentmaster/uk/avr1713_avr1613_protocol_v860.pdf) | Type `OvrsTemplate.match` (vendor/product/device_type/port). `resolve(finding, device)` after Phase-2 enrichment, most specific first. A Confirmed mqtt auth-enforced verdict downgrades `ports.mqtt-unencrypted` in `dedup_rank`. On an identified Denon/Marantz AVR, skip the telnet probe and default-cred attempt (single control slot). | `remediation.rs:12-24`; `templates/ports.yaml`; `runner.rs:784` `dedup_rank`; `credentials.rs` telnet gating | M |
| 7 | Default ports omit identity ports: dead classifier branches | 62078 is Apple "device pairing, sync, and backup" and is in neither port list. [Apple 103229](https://support.apple.com/en-us/103229) | Add 62078, 7000, 4070, 55442, 55443, 3689, 5001 and 8880 to `common_ports()` (or drop those rules). Add Echo rule 55442&&55443. Guard test: every `classify_by_ports` port must be in `common_ports()`. Update the 58/140 count tests. | `ports.rs:98,108,651`; `runner.rs:825` `classify_by_ports` | S |
| 8 | Synology DSM SA-26:13 / SA-26:19 advisory + rsync correlation | SA-26:19 (2026-11-10): Auth API SQLi 9.8 unauthenticated, rsync auth bypass CVE-2026-85101. [SA-26:19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19) | Put the minimum builds (7.2.1-69057-13 / 7.2.2-72806-10 / 7.3.2-86009-5 / 7.4.1-90080-1) in the existing Synology finding text. Correlate a nuclei `rsyncd-service-detect` hit with a Synology host: Medium, conditional, citing CVE-2026-85101. Build-exact tier only after the SSDP `desc-DSM-eth0.xml` lead is checked on the owner's NAS. | `http_audit.rs:173` `classify_nas_ha`; `nuclei_db.rs:1520`; runner correlation | S |
| 9 | Hue Bridge swversion check (ZDI HomeKit batch) | Owner's bridge (192.168.1.169) has hk_hap TCP 8080 open. Fixed in 1975170000. [ZDI-26-155](https://www.zerodayinitiative.com/advisories/ZDI-26-155/) | Gate on `_hue._tcp`/BSB002 and GET `/api/config` (unauthenticated). Parse `swversion` as decimal, allowing leading zeros. Below 1975170000 with 8080 open and `modelid=="BSB002"`: High, Confirmed (CVE-2026-3557 8.0, CVE-2026-3562 6.3). With 8080 closed: Medium. | `mdns.rs` Hue classification or `http_audit.rs` device probe | S |
| 10 | Spotify Connect ZeroConf `getInfo` | 5 responders here: three Echo Shows, a PS5 missing from the inventory, and the Denon. [Spotify ZeroConf](https://developer.spotify.com/documentation/commercial-hardware/implementation/guides/zeroconf) | Add `_spotify-connect._tcp`. GET `{CPath}?action=getInfo` with a 2 s timeout and 16 KiB cap. Read only `deviceType`/`brandDisplayName`/`modelDisplayName`/`remoteName`. Match `deviceType` case-insensitively; unknown means no hint. Never log `deviceID`/`publicKey`. | `rikitikitavi-network/src/mdns.rs:612` `SERVICE_QUERIES`; new `scanners/src/spotify_zc.rs` | S |
| 11 | Hostname-driven typing: HA DHCP hostname matchers + house table | 245 upstream hostname matchers (154 MAC+hostname) need ID-01. MyQ/`DENALI-`/UniFi model names are not in HA. [HA dhcp.py](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/dhcp.py) | Generator emits `DhcpHostnameMatcher` with fnmatch `[...]` classes. Hostname-only hits rank below MAC+hostname. House regex table guarded by OUI vendor: UniFi AP/switch, MyQ to `SmartLock` (existing garage-door convention), Schlage to `SmartLock`, `DENALI-` to `Thermostat`, Dyson to `Appliance`. Probable. | `scripts/gen_ha_discovery_db.py`; `ha_discovery_db.rs`; `device.rs` | S |
| 12 | `verify` mode (resolved / still present / inconclusive) | `--compare-previous` calls an offline device "resolved" | Replay (scanner, ip, port, rule id) from `ScanHistory::load_latest()` on a narrowed `ScanContext`. Liveness from TCP or the ARP/neighbour table. Fill the unused template `validation:` field. Needs a `kind` field on `ScanResults` so verify runs neither count as full scans nor push real scans out of `prune()`. Exit 0/3/4. | `cli.rs` new `Verify`; `runner.rs`; analysis history; `remediation.rs` | M |

## Fixes for this network

Covers each device with a High or Medium finding in the September or November scan. Steps are verified against the source shown. "Generic" marks steps without a vendor source.

**UniFi gateway, 192.168.1.1.** High: "Vulnerable OpenSSH 8.4p1 Debian-5+deb11u7". High: EOL Debian 11. Medium: certificate expiring.
- Turn off console SSH if you don't use it: Settings > Control Plane > Console > SSH. It is off by default on consoles, so an open port 22 means someone enabled it. [help.ui.com 204909374](https://help.ui.com/hc/en-us/articles/204909374-Connecting-to-UniFi-with-Debug-Tools-SSH) (verifiers read this through search extracts; help.ui.com returned 403).
- Turn on auto-update and update UniFi OS: Settings > Control Plane > Updates. [help.ui.com 7605005245975](https://help.ui.com/hc/en-us/articles/7605005245975-UniFi-Updates).
- SAB-069 DoS cluster (CVE-2026-77555 and siblings, unauthenticated): needs UniFi OS ≥ 5.1.31 on UDM/UDR/UCG/EFG/UDW/UX7, ≥ 4.0.21 on UX, ≥ 5.1.26 on UXG. [CVE-2026-77555](https://cveawg.mitre.org/api/cve/CVE-2026-77555). For UDMPRO, the latest release is `unifi-dream` v6.0.17 (2026-11-10). [fw-update feed](https://fw-update.ui.com/api/firmware-latest?filter=eq~~channel~~release&filter=eq~~platform~~UDMPRO).
- Keep UPnP off unless a game needs it, and use WireGuard/Teleport for remote access. It is in the Internet section of the Network app. [help.ui.com 12648697125783](https://help.ui.com/hc/en-us/articles/12648697125783-UniFi-Gateway-UPnP).
- The OpenSSH finding is not CVE-2026-123158 "sshole", which affects musl and non-PAM builds only (NT-04).

**Synology DS418play, 192.168.1.220.** High: "Vulnerable OpenSSH 8.2". Medium: SMB 445 and NetBIOS 139 exposed.
- Install DSM 7.4.1-90080 Update 1 (2026-10-12, marked security). Synology warns the NAS "may not notify you of this DSM update", so install it manually. [DS418play release notes](https://www.synology.com/api/releaseNote/findChangeLog?identify=DSM&lang=en-global&model=DS418play). This build fixes SA-26:19. On the 7.2 line you need at least 7.2.2-72806-10 or 7.2.1-69057-13. [SA-26:19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19), [SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13).
- DSM 7.4 is this model's last upgradable major, so plan a replacement (Synology DSM 7.4-90075 release note, same URL).
- Turn on Auto Block. It "blocks an IP address after a specified number of login failures within a predefined period" and covers DSM, SSH, Telnet and SMB. [DSM 7.4 spec](https://www.synology.com/dsm/7.4/software_spec/signin_protection). Disable SSH when unused (generic; menu path not verified).
- If Plex is installed: update to ≥ 1.43.3.10861, manually if Package Center lags. [Plex forum](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319).
- If Web Station or PHP packages are installed: apply SA-26:14. PHP 7.3 will not be fixed. [SA-26:14](https://www.synology.com/en-global/security/advisory/Synology_SA_26_14).
- Disable rsync if unused, since CVE-2026-85101 requires it (inferred from SA-26:19).

**Six TP-Link Kasa plugs (TCP 9999).** Finding: unauthenticated local control (High once NT-02 lands).
- Check for a firmware update in the Kasa app (generic path). Fixed builds include HS103 V5 1.1.3 Build 250908, KP115 V1 1.1.1 Build 250908, EP10 V1 1.1.1 Build 250908, HS300 V2 1.1.2 Build 241220 and KP303 V2 1.1.2 Build 241220. Match on the full hw_ver. [FAQ 5342](https://www.omadanetworks.com/us/support/faq/5342/), [FAQ 5267](https://www.omadanetworks.com/us/support/faq/5267/).
- Leave Me > Settings > Third-Party Compatibility off unless Home Assistant or another local controller needs it. It is off by default and "may reduce the security protections". TP-Link does not say whether it affects 9999. [FAQ 4416](https://www.tp-link.com/support/faq/4416).
- Updates can add authentication on some revisions. Home Assistant advises older-device owners to disable auto-update if they want to keep local access. [HA tplink](https://www.home-assistant.io/integrations/tplink).
- If 9999 still answers after updating, put the plugs on an IoT VLAN and allow 9999 only from the controller (generic).

**Denon AVR, 192.168.1.34.** High: "Telnet with potential default credentials" (wrong advice). Medium: excessive certificate validity.
- Port 23 is Denon's documented control protocol, with no authentication described. There is no SSH, so "use SSH instead" cannot be done. [Denon protocol PDF](https://assets.denon.com/documentmaster/uk/avr1713_avr1613_protocol_v860.pdf).
- If you don't use HEOS or the app from standby: Setup > Network > Network Control > Off In Standby. The default is Always On, which web control and the HEOS/AVR Remote apps need. [AVR-X3800H manual](https://manuals.denon.com/AVRX3800H/NA/EN/HJWMSYmehwmguq.php).
- Otherwise put it on the IoT VLAN and allow TCP 23/8080/60006 only from the controller. The receiver accepts a single connection. [HA denonavr](https://www.home-assistant.io/integrations/denonavr/).

**Dyson, 192.168.2.133 and 192.168.3.242.** Medium: MQTT unencrypted on 1883.
- The device runs its own plaintext broker. The per-device credential comes from the Dyson cloud, and there is no documented TLS or disable option (community reverse-engineering, not Dyson docs: [Tasmota example](https://gemu2015.github.io/Sonoff-Tasmota/examples/dyson_tp02/)).
- Fix: keep firmware current through the Dyson app, put the device on an IoT VLAN, and allow 1883 only from your controller (generic).

**Philips Hue Bridge, 192.168.1.169.** Medium: excessive certificate validity. Medium: "web admin panel without auth" on :80. Port 8080 (hk_hap) is open.
- Turn on Hue app > Settings > Software update > Automatic update. Confirm the bridge is ≥ 1975170000 (ZDI fix for the HomeKit batch). The latest is 6.5.1978688000 (2026-11-12). [Hue release notes](https://www.philips-hue.com/en-us/support/release-notes/bridge), [ZDI-26-155](https://www.zerodayinitiative.com/advisories/ZDI-26-155/).
- Firmware 1971060010 (2025-05-22) replaced the self-signed certificates, so a self-signed or old-style certificate means the firmware is old (same release-notes URL).

**HP LaserJet M478f, 192.168.1.2.** Medium: raw 9100/PJL. Medium: SNMP `public`. Medium: CSP findings.
- Update firmware to ≥ 002_2539E. This fixes CVE-2025-12784/-12785 (HP CVSS4 6.9, PR:H), which leak credentials through scan-destination and LDAP changes. [CVE-2025-12784 (HP CNA)](https://cveawg.mitre.org/api/cve/CVE-2025-12784), [HPSBPI04074](https://support.hp.com/us-en/document/ish_13229161-13229183-16/hpsbpi04074).
- Set an EWS admin password, because the CVEs need admin access. Disable unused protocols (9100, SNMPv1/v2 `public`) in the EWS network settings (generic; HP menu path not verified).

**Mac behind a Cable Matters dongle, 192.168.2.31.** Medium: VNC 5900. No vendor source was verified in this sweep; the existing ports template applies.

**Other Medium findings outside this research** (existing templates only): "web admin panel without auth" on 192.168.0.39 (Espressif) and on 192.168.0.178/192.168.2.140 (Alpha Networks; PTR names them MyQ garage openers), UPnP on 192.168.2.88, DNSSEC not enforced, and 12 "possibly exposed admin page" findings on UniFi device 192.168.1.149 (see Observations).

**Apple TVs (advisory; no finding yet).** Set Settings > AirPlay and HomeKit > Allow Access > Only People Sharing This Home (or Require Password). [Apple tvOS guide](https://support.apple.com/en-kz/guide/tv/atvb0342111f/18/tvos). Keep tvOS current: CVE-2024-27834 was added to KEV 2026-11-04 and is fixed in tvOS 17.5. [Apple 120901](https://support.apple.com/en-us/120901).

## Threats

**NT-01: Plex2Shell (CVE-2026-96652/-96654/-96655/-96656), KEV 2026-10-20.** Chained, these give unauthenticated RCE, used for miners and proxyware. Fixed in 1.43.3.10861. Synology and QNAP published their own notices. Floor `[1,43,3,10861]`. List every applicable CVE in one finding, at High/Confirmed. CISA and Plex describe 96655 differently, so describe the chain as a whole. Effort S.
[Plex forum](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319) · [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) · [Synology advisories](https://www.synology.com/en-global/security/advisory)

**NT-02: Kasa CVE-2026-108473 (FAQ 5342) and CVE-2026-76784 (FAQ 5267).** Both CVSS4 8.7 AV:A/PR:N. 5342 is improper authentication plus credential exposure (map to CWE-287); 5267 is weak crypto. Neither is in KEV. Match on the full `hw_ver` string, because HS200 V5 (1.1.2 B241220) and V5.26 (1.0.3 B240723) are separate firmware lines. Normalise names such as `KS230 KIT`, `HS103P3/P4` and `KP125MP2/MP4`, and add EP40M/KS205/KS225/KS240. Never send `set_*`. Effort S.
[FAQ 5342](https://www.omadanetworks.com/us/support/faq/5342/) · [FAQ 5267](https://www.omadanetworks.com/us/support/faq/5267/)

**NT-03: Synology SA-26:13 (2026-09-18, 8 CVEs, 2 Critical) and SA-26:19 (2026-11-10).** No unauthenticated route to the DSM build is verified. Now: put the per-branch minimum builds in `classify_nas_ha` text, and correlate nuclei `rsyncd-service-detect` with Synology for CVE-2026-85101. Later: check SSDP `desc-DSM-eth0.xml` on the owner's NAS, then add a build table. Listing rsync modules needs a client `@RSYNCD:` greeting first; the server greeting alone is enough. Effort S/M.
[SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13) · [SA-26:19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19)

**NT-06: PHP2Shell CVE-2026-109618/-109619 (KEV 2026-10-26).** Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; ≤ 8.1 is unsupported. Add a floor table to `check_powered_by_eol` (`http_audit.rs:298`): Probable below the floor. Distro-suffixed versions get `Inferred`. On a Synology host, exact 7.4.33 / 8.0.30 / 8.1.34 get `Inferred` (Synology backports); PHP 7.3 stays Probable (never fixed). No header, no finding. Effort S.
[CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) · [SA-26:14](https://www.synology.com/en-global/security/advisory/Synology_SA_26_14)

**NT-07: Hue Bridge v2 HomeKit batch (ZDI-26-155/-160).** CVE-2026-3557 is 8.0 PR:L (auth bypassable, TCP 8080). CVE-2026-3562 is 6.3 PR:N. Only ZDI names the fix build, 1975170000; Philips' notes do not mention it. `/api/config` is unauthenticated (deCONZ wiki). Gate on `_hue._tcp`/BSB002, not the old Recog "light bulb" entries. Check each other ZDI-26-15x/16x record before adding it. Effort S.
[ZDI-26-155](https://www.zerodayinitiative.com/advisories/ZDI-26-155/) · [CVE-2026-3557](https://cveawg.mitre.org/api/cve/CVE-2026-3557) · [CVE-2026-3562](https://cveawg.mitre.org/api/cve/CVE-2026-3562) · [deCONZ](https://github.com/dresden-elektronik/deconz-rest-plugin/wiki/Bridge-Discovery) · [Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge)

**NT-08: tvOS currency from AirPlay `osvers` + KEV join** (merge with RE-04). 27 KEV entries match "tvOS" by text; check each one is really affected. The 2026 additions set the floor: CVE-2026-20700, CVE-2025-43510, CVE-2025-43520, CVE-2025-31277, CVE-2021-30952 and CVE-2024-27834 (tvOS 17.5). Look up each fix on its own Apple page. Confirmed only for `AppleTV*`. HomePod has no vendor fix table, so skip it or mark `Inferred`. Effort M.
[Apple 120901](https://support.apple.com/en-us/120901) · [pyatv protocols](https://pyatv.dev/documentation/protocols/) · [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

**NT-09: UniFi SAB-069 DoS cluster and SAB-070 Protect AI Key (CVE-2026-110459, fixed 2.2.8).** Thresholds per family, from the CVE-2026-77555 record. Correction: `env.unifi_os_version` comes only from on-device `local.rs`. The credentialed LAN path is `/api/s/{site}/stat/device`, using `model` + `firmware_version` (`models.rs` ~L58-66). Without credentials: an Info advisory on an identified UniFi gateway. AI Key: Info only. Effort S.
[CVE-2026-77555](https://cveawg.mitre.org/api/cve/CVE-2026-77555) · [CVE-2026-110459](https://cveawg.mitre.org/api/cve/CVE-2026-110459) · [vuln.today](https://vuln.today/tag/ubiquiti)

## Identification

**ID-01: Reverse DNS (PTR).** See Top 12 #4. 20/27 smoke devices resolved, including `00178826d932` (Hue, a bare MAC), MyQ-6C7/-0C9, Schlage, WhiskerRobots, DENALI-…, Ring×3 and WeatherStation. Re-test the hit rate with `dig +norecurse`, since the check used RD=1. Cross-check MAC/hostname pairs across scans to catch stale leases. Effort S.
[aiodiscover](https://github.com/Bluetooth-Devices/aiodiscover) · [HA dhcp](https://www.home-assistant.io/integrations/dhcp/) · [NetAlertX plugins](https://docs.netalertx.com/PLUGINS_OVERVIEW/)

**ID-02: HA DHCP hostname matchers.** Upstream dev has 245 (154 MAC+hostname, 91 hostname-only; the 243 count was at the pinned commit 8e2c2c3). Implement fnmatch `[...]` (e.g. tplink `e[sp]*`), or drop and count those entries. Keep conjunctions intact. Hostname-only hits such as `samsung-*` get lower confidence. Effort S.
[HA dhcp.py](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/dhcp.py)

**ID-03: House hostname table.** Anchored, case-insensitive regexes guarded by OUI vendor. `AccessPoint`, `SmartLock` and `Thermostat` exist. There is no `GarageDoor`: follow the gogogate2/tailwind convention (`SmartLock`) or add a variant deliberately. Dyson goes to `Appliance`. Prefer the UBNT discovery `model` field over the hostname when available. Do not reuse the loose `classify_board()` ("ap" matches "laptop"). Effort S.
[Rapid7 UBNT discovery](https://www.rapid7.com/blog/post/2019/02/01/ubiquiti-discovery-service-exposures/) · [HA dhcp.py](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/generated/dhcp.py)

**ID-05: Spotify Connect `getInfo`.** See Top 12 #10. The guide documents only "SPEAKER". Other `deviceType` values (GameConsole, TV, AVR, STB, CastAudio…) come from implementations, so treat any unknown value as no hint. Effort S.
[Spotify ZeroConf](https://developer.spotify.com/documentation/commercial-hardware/implementation/guides/zeroconf)

**ID-08: NetBIOS NBSTAT (UDP 137).** Got names from Synology RUDIGER, HP7BA8A8, MAC-04B06C and BRYANS-MBP. Bounds-check the RR header (compression pointer, RDLENGTH) before `NUM_NAMES`. Take the hostname from a `<00>` entry with GROUP clear. UNIT_ID becomes an `alt_macs` correlation hint only: skip all-zeros, and note locally administered addresses. Unicast, 800 ms. Effort S.
[RFC 1002](https://www.rfc-editor.org/rfc/rfc1002.html) · [NetAlertX](https://docs.netalertx.com/PLUGINS_OVERVIEW/) · [Fing SDK doc](https://get.fing.com/fing-business/devrecog/documentation/Fing_Desktop_Embedded_SDK.pdf)

**ID-09: Identity ports missing from defaults.** See Top 12 #7. The Echo signature 4070/55442/55443 is community-derived and was observed locally. Effort S.
[Apple 103229](https://support.apple.com/en-us/103229)

**ID-11: IEEE MA-M/MA-S registries.** 6,688 + 7,281 data rows. Longest prefix first, falling back only on a miss. Skip "IEEE Registration Authority" rows inside MA-M/MA-S too. The refresh curl needs a User-Agent and retry (IEEE returns HTTP 418 intermittently). Resolves 04:a1:6f:10:4a:d4 to iENSO Inc. Effort S.
[mam.csv](https://standards-oui.ieee.org/oui28/mam.csv) · [oui36.csv](https://standards-oui.ieee.org/oui36/oui36.csv)

**ID-12: UniFi controller client import (credentialed).** `get_clients()` exists at `api.rs:306` but nothing calls it. Merge `stat/sta` (connected) with `rest/user`/`stat/alluser` (historical, fewer fields, usually no IP). Precedence: alias, then hostname, then PTR. Add a `seen_by` field. Record `dev_cat`/`dev_family`/`os_name` codes raw. Effort M.
[aiounifi client.py](https://sources.debian.org/data/main/p/python-aiounifi/79-3/aiounifi/models/client.py) · [NetAlertX](https://docs.netalertx.com/PLUGINS_OVERVIEW/)

## Remediation

**FIX-01: Product-aware remediation.** See Top 12 #6. Cite the Dyson facts as community-sourced. CONNACK 0x04/0x05 detection already exists in `mqtt.rs`; the bug is in `dedup_rank`. 11 template files carry an untyped `match.resourceKinds`. Effort M.
[Dyson (community)](https://gemu2015.github.io/Sonoff-Tasmota/examples/dyson_tp02/) · [Denon PDF](https://assets.denon.com/documentmaster/uk/avr1713_avr1613_protocol_v860.pdf) · [AVR-X3800H](https://manuals.denon.com/AVRX3800H/NA/EN/HJWMSYmehwmguq.php)

**FIX-02: `fix-plan` Markdown checklist.** Sections: do now / this weekend / replace / accepted. Items grouped per device, each with a source and a `verify` line. Sort and key by `FindingFingerprint` + IP, not UUIDv4, so the golden file stays stable. Write with `write_private`. Depends on FIX-01, FIX-03 and FIX-08. Don't name DSM versions without an official per-model page. Effort M.
[UniFi SSH](https://help.ui.com/hc/en-us/articles/204909374-Connecting-to-UniFi-with-Debug-Tools-SSH) · [UniFi Updates](https://help.ui.com/hc/en-us/articles/7605005245975-UniFi-Updates) · [UniFi UPnP](https://help.ui.com/hc/en-us/articles/12648697125783-UniFi-Gateway-UPnP)

**FIX-03: `verify` mode.** See Top 12 #12. UniFi SSH is off by default on consoles only; it is on by default on APs and switches. AirPlay verification needs an mDNS re-browse, not a TCP replay. Effort M.
[UniFi SSH](https://help.ui.com/hc/en-us/articles/204909374-Connecting-to-UniFi-with-Debug-Tools-SSH) · [HA tplink](https://www.home-assistant.io/integrations/tplink)

**FIX-05: Kasa remediation rewrite.** Replace the blanket "a firmware update does not add one" (`kasa.rs:466`/`:490`). HS100 4.1 (UK) fw 1.1.0 is the clear case of an update adding authentication (python-kasa). EP25 2.6 and HS200 5.26 required authentication from first release. TP-Link staff confirmed only that 1.1 shipped to HS100/HS110 (UK) v4.1. python-kasa is GPL-3.0: link only, never embed. Effort S.
[FAQ 4416](https://www.tp-link.com/support/faq/4416) · [HA tplink](https://www.home-assistant.io/integrations/tplink) · [python-kasa SUPPORTED.md](https://github.com/python-kasa/python-kasa/blob/master/SUPPORTED.md) · [TP-Link forum](https://community.tp-link.com/en/home/forum/topic/237614?page=3)

**FIX-06: Segmentation advisor.** Proposes Trusted / IoT / Infra zones from the inventory, plus a cited rule table:
- Thread border routers and Wi-Fi Matter nodes stay with the controller.
- An mDNS proxy list of services "advertised by IoT devices".
- Controller-only allow rules.
- Printers reachable from Trusted.

Mention the UniFi per-model mDNS-proxy network caps (Express 2 … EFG 60). The Kasa/Hue/Dyson ports need their own primary sources. Text only, never pushes config. Effort L.
[HA Matter](https://www.home-assistant.io/integrations/matter/) · [UniFi mDNS](https://help.ui.com/hc/en-us/articles/12648701398807-UniFi-Gateway-Multicast-DNS-mDNS-Proxy) · [UniFi isolation](https://help.ui.com/hc/en-us/articles/18965560820247-Implementing-Network-and-Client-Isolation-in-UniFi) · [HA denonavr](https://www.home-assistant.io/integrations/denonavr/)

**FIX-07: Coverage gate.** See Top 12 #5. A Hue self-signed certificate means outdated firmware, so the fix is "update", not "accept". Effort S.
[Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge)

**FIX-08: `fix_path` taxonomy + accepted-risk ledger.** Add a new `fixPath` template key; do not reuse `changeType`, which holds ITIL values ("standard" ×51). `--accept-file` entries take `{fingerprint, reason, accepted_on, expires, compensating}`. Accepted findings stay visible and come back as active on `expires`. Give it a real byte cap. `load_rules` (`declarative.rs:175`) has none either. Effort M.
[AVR-X3800H](https://manuals.denon.com/AVRX3800H/NA/EN/HJWMSYmehwmguq.php) · [Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge)

**FIX-09: Denon/Marantz telnet template.** "IP Control" on older models, "Network Control" on newer. That port 23 stays open while the unit is on is inferred, not stated by Denon. Skip both the banner grab and the default-cred attempt on identified AVRs. Effort S.
[AVR-X3800H](https://manuals.denon.com/AVRX3800H/NA/EN/HJWMSYmehwmguq.php) · [Denon PDF](https://assets.denon.com/documentmaster/uk/avr1713_avr1613_protocol_v860.pdf) · [HA denonavr](https://www.home-assistant.io/integrations/denonavr/)

**FIX-10: Synology hardening template + hand-curated lifecycle table.** DS418play's last major is 7.4 (Synology 7.4-90075 note). The Value Series list gives about 15 rows (DS116…RS217). Synology ToS §2(d) bans robots, so no runtime fetch and no embedded release notes. Effort S.
[DS418play changelog](https://www.synology.com/api/releaseNote/findChangeLog?identify=DSM&lang=en-global&model=DS418play) · [Auto Block spec](https://www.synology.com/dsm/7.4/software_spec/signin_protection) · [Synology ToS](https://www.synology.com/en-global/company/legal/terms_conditions) · [blackvoid (secondary)](https://www.blackvoid.club/synology-dsm-7-4-90075.md)

**FIX-11: Matter commissioning-window remediation.** Apple: Settings > General > Matter Accessories > Edit > Remove From [Service] / All Services / Remove from Keychain. HA: Manage fabrics, and store the QR "in a safe place". Devices "should" support ≥ 5 fabrics. Do not advise a factory reset for a leaked CM=1 code; the printed code does not change. Window timing and the Google path are unsourced. Effort S.
[Apple 102135](https://support.apple.com/102135) · [HA Matter](https://www.home-assistant.io/integrations/matter/)

**FIX-12: IPP `printer-firmware-*` read + HP fix floor.** Read-only Get-Printer-Attributes on 631. New TLV parser, so add a fuzz target. Seed `printer_fix_floors` from the HP CNA records: 002_2539E for M478-M479 and the sibling families in HPSBPI04074. Treat "per-unit PIN on label" as unverified. Effort M.
[IANA IPP registry](https://www.iana.org/assignments/ipp-registrations/ipp-registrations.xml) · [CVE-2025-12784 (NVD)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-12784) · [CVE-2025-12785 (NVD)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-12785) · [CVE-2025-12784 (HP CNA)](https://cveawg.mitre.org/api/cve/CVE-2025-12784)

**FIX-13: Opt-in online UniFi firmware currency.** `fw-update.ui.com` returns several products per platform (`udm`, `unifi-firmware`, `unifi-dream`). Filter by product and compare versions; never take the first element. A missing product or schema change is reported as "unknown". Home is the stub `unifi firmware-check` (`main.rs:1295`). No Synology or TP-Link feeds. Hue gets a static "Automatic update" step. Effort M.
[fw-update](https://fw-update.ui.com/api/firmware-latest?filter=eq~~channel~~release&filter=eq~~platform~~UDMPRO) · [UI ToS](https://www.ui.com/legal/termsofservice/) · [Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge) · [endoflife.date](https://endoflife.date/api/v1/products/)

**FIX-14: AirPlay access posture from TXT `flags`/`pw`.** Bits 3, 7, 9 and 10 come from a reverse-engineered spec, so Probable at most. TXT cannot tell "Everyone" from "Anyone on the Same Network". Bit 10 alone is weak evidence. Apple menu path for `AppleTV*` only; generic wording for Denon and other third parties. Do not interpret `acl`. Effort S.
[openairplay discovery](https://openairplay.github.io/airplay-spec/service_discovery.html) · [status flags](https://openairplay.github.io/airplay-spec/status_flags.html) · [Apple tvOS guide](https://support.apple.com/en-kz/guide/tv/atvb0342111f/18/tvos)

## Resources

**RE-01: reqwest 0.13.1 held back.** See Top 12 #1. 0.13.3 stops hickory logging full URLs; 0.13.5 fixes proxy-auth with multiple proxies. Effort S.
[reqwest CHANGELOG](https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md) · [crates.io 0.13.5](https://crates.io/api/v1/crates/reqwest/0.13.5)

**RE-02: Regenerate HA discovery tables.** Pinned commit 8e2c2c3 dates from 2026-09-10. a0d43ca (2026-11-11) adds `hp_printer` (`hp*` on `_ipp`/`_ipps`); add it to `DOMAIN_TYPES` in the generator. PR #189876 removes six Dahua OUIs from `imou`. Update the `tests.rs:330` count (103). Add a regression test: 38:AF:29 is no longer imou, 1C:4D:89 still is. Effort S.
[a0d43ca](https://github.com/home-assistant/core/commit/a0d43caec1) · [PR #189876](https://github.com/home-assistant/core/pull/189876) · [6afa73a](https://github.com/home-assistant/core/commit/6afa73a969) · [b1e84d4](https://github.com/home-assistant/core/commit/b1e84d443a)

**RE-04: endoflife.date `tvos`/`macos` join on `osvers`.** tvOS 27 is current (27.2) and 26 has been EOL since 2026-09-14. tvOS 26.6.1 still shipped after that date, so word the remediation around hardware that cannot move up. For macOS, use each cycle's `isEol`. Merge with NT-08. Effort S.
[pyatv protocols.md](https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md) · [pyatv airplay](https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py) · [endoflife tvos](https://endoflife.date/api/v1/products/tvos/) · [airplay spec](https://openairplay.github.io/airplay-spec/print.html)

**RE-06: OSV.dev Debian as a runtime backport-aware oracle.** Debian:12 openssh 1:9.2p1-2+deb12u3 returns 42 records (about 32 after the urgency filter). Debian:11, the gateway's base, returns only DLA/DSA advisories (2 for +deb11u3). For deb11, report "N Debian LTS advisories" as weaker evidence. Runtime and opt-in only: Ubuntu data is CC-BY-SA, Debian is unlicensed. Responses are capped at 32 MiB. Effort M.
[OSV ecosystems](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt) · [OSV data](https://google.github.io/osv.dev/data/) · [OSV FAQ](https://google.github.io/osv.dev/faq/)

## Rejected or unusable

- **NT-04 OpenSSH 10.6p2 "sshole" floor (CVE-2026-123158):** Alpine backports the fix to older upstream versions and the banner hides `-rN`, so a version floor flags patched hosts. The Alpine advisory cites no CVE.
- **NT-05 MikroTik September cluster:** the 7.23.6 / 7.24.3 "complete fix" is for CVE-2026-67278, which is not in KEV. The KEV CVEs are fixed in 7.24.2 / 7.23.4 / 6.49.21. Ports 2000/8291 are not in the default port list.
- **NT-10 "proxy listener means compromise":** Pawns.app and ClingSTUN connect outbound and open no LAN listener. RouterOS SOCKS can be enabled legitimately. Via/Proxy-Agent on GET does not identify an open proxy.
- **ID-04 per-host unicast mDNS:** the probe is sound and new, but the claim misstated the counts (127 queries, not 113) and attributed an ESP-IDF version floor to the wrong issue. Resubmit; ID-06 shows it works over IPv4.
- **ID-06 IPv6 link-local discovery:** the SJIT/Samsung device answers unicast mDNS over IPv4, so the payoff belongs to ID-04. IPv6 neighbour discovery is still useful for the 4 IPv6-only MACs.
- **ID-07 Thread BR from RA routes:** the LAN facts were wrong (2 routes, not 4, and the two "Apple hosts" are one host). It depends on the dhcpcd/kernel RA config. The TCP/53 SRP explanation is undocumented.
- **ID-10 Apple model identifiers:** AppleTV/AudioAccessory are already typed via the HA tables. `osxvers` is the Darwin major, not the macOS version. `DeviceType::Computer` does not exist. Mac ids to `Laptop`/`Desktop` remains a small gap.
- **FIX-04 UniFi templates:** "device SSH ships with random credentials" is wrong. Factory or unadopted devices use documented defaults (ui/ui, ubnt/ubnt). Several facts were not visible in any source.
- **RE-03 endoflife.date Chromecast:** stale for the GTV 4K, which is at UTTA.260813.002 and not UTTC.250917.004. `latest.date` is null. Build numbers do not compare across models, and several models share `model_name`.
- **Deferred (low):** LG webOS sync-demo (no version without pairing). Zyxel GS1900 CVE-2026-7273. BIND `version.bind` CHAOS probe. ProFTPD mod_copy floor. UBNT discovery on UDP 10001. WS-Discovery on 3702. endoflife.date samba/bind-9 (no join yet). Matter DCL (members-only licence). Recog and nuclei deltas (enterprise only; WinBox mirrors NPSL). CSAF (no consumer vendor here publishes it). Cyber Trust Mark (no registry). EUVD (no reuse licence).

## Observations

- **Possible false positive on the NAS:** `Vulnerable OpenSSH 8.2` on the Synology (192.168.1.220) may be the same backport problem as NT-04/NT-06. Synology patches packages without changing upstream version strings, as it does for PHP in SA-26:14. Not verified for OpenSSH; check against the DSM 7.2/7.4 release notes before trusting it.
- **Likely soft-404 artefact:** the 12 Medium "possibly exposed admin page" findings on UniFi device 192.168.1.149 (/admin, /wp-admin, /phpmyadmin…) look like a catch-all page being counted once per path. Not verified. Fixing it would cut the September Medium count by a third.
- **Hue "web admin panel without auth":** this likely flags the bridge's documented unauthenticated `/api/config` and needs a vendor exception.
- **Confidence mapping:** the research used a "Possible" tier that the code does not have. Map it to `Inferred`, or `exploit_intel.rs` will raise KEV-tagged backport-uncertain findings to High.
- **Missing input:** `v040.json` was not in the scratchpad. The per-device section uses the 2026-09-12 history scan and the 2026-11 smoke scan, so Plex presence on the NAS is unconfirmed.
