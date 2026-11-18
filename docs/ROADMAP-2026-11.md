# Roadmap 2026-11

> **This is the current roadmap.** It lists all open work, including the few
> items carried over from the closed 2026-09 roadmap,
> [ROADMAP.md](ROADMAP.md). ROADMAP.md is kept for its rejected items and their
> reasons. Nothing done there is proposed again here.

From a 2026-11-14 research sweep across four dimensions: threats, identification, remediation and resources. Every item was checked against the sources linked here and against this repository. Two verifiers reviewed each claim, and their corrections are folded into the text. Refuted items are listed under [Rejected or unusable](#rejected-or-unusable).

Constraints are unchanged. Probes run unprivileged and read-only from a LAN host. Embedded data must be Apache-2.0-compatible. The `Confidence` enum is `Inferred | Probable | Confirmed`. Any "Possible" tier in the research becomes `Inferred`, because `exploit_intel.rs` raises KEV-tagged findings to High unless they are `Inferred`.

Field evidence comes from scans of the author's home network.

## Status (checked against the code 2026-11-17)

Paths are relative to `crates/`. "Done" means the feature exists in the code, not only in the changelog.

### Open, in suggested order

Ordered by the same rule as the original Top 12, (value x relevance to this LAN) / effort. Details are in the sections below.

1. **RE-01 remainder:** a CI check for held-back direct dependencies, with an allowlist. Nothing in `.github/workflows/` does this yet. Effort S.
2. **FIX-08 remainder:** the `fixPath` template key, and filling the template `validation:` field (still `#[allow(dead_code)]` in `rikitikitavi-scanners/src/remediation.rs`) so `verify` can use it. Effort M.
3. **FIX-10:** Synology hardening template and hand-curated lifecycle table. Effort S.
4. **FIX-12:** IPP `printer-firmware-*` read and HP fix floor. Effort M.
5. **NT-03 remainder:** exact DSM build tier, after the SSDP `desc-DSM-eth0.xml` lead is checked on the owner's NAS. Effort S/M.
6. **FIX-13:** opt-in online UniFi firmware currency. `unifi firmware-check` is still a stub in `rikitikitavi/src/main.rs`. Effort M.
7. **RE-06:** OSV.dev Debian as a runtime backport-aware oracle. Effort M.
8. **NT-08 remainder:** HomePod and macOS currency. HomePod has no vendor fix table; skip it or mark `Inferred`.
9. **Replace chrono:** RUSTSEC-2026-0543 marks it unmaintained (no vulnerability). It is ignored in `deny.toml`; move to `jiff` or `time` and drop the ignore. Effort M.
10. **Stub subcommands:** `report` (beyond `--latest`), `init`, `update-db`, `aws` and `unifi devices|firmware-check|audit-controller|deploy|tui|report` only print a message. Their help now says so; implement or remove them. The `minimal` feature is empty.

Not planned: the NT-09 Protect AI Key check (nothing on the LAN identifies one).

### Carried over from 2026-09

Lower priority. Details in [ROADMAP.md](ROADMAP.md#partly-done-or-not-started).

- CP-02: Matter/Thread mDNS over IPv6 (IPv4 is done).
- PL-14: Roku, Shelly and ESPHome identity probes (Cast is done).
- CP-13: OWASP ISTG IDs (OWASP IoT Top 10 2018 tags are done).
- PL-12: NIST IR 8425 capability areas.
- PL-04, PL-05: SecLists and DefaultCreds corpora.
- Loose ends: port 5000 label (HW-19), `upnp_igd.rs` 32400 sensitivity (HW-16), Sonos `softwareVersion` (ET-11).

### Done

| ID | Item | Code |
|----|------|------|
| RE-01 | reqwest 0.13.5 (`webpki-roots` feature dropped); authenticated UniFi client follows no redirects | `Cargo.toml`, `rikitikitavi-unifi/src/api.rs` |
| NT-01 | Plex2Shell verdict below 1.43.3.10861 | `rikitikitavi-scanners/src/media_server.rs` |
| NT-02, FIX-05 | Kasa fixed-firmware table per model and hw_ver; remediation is update, verify, segment | `rikitikitavi-scanners/src/kasa.rs` |
| ID-01 | Reverse DNS via RFC 1918 resolvers | `rikitikitavi-network/src/rdns.rs` |
| FIX-07 | Remediation coverage gate (allowlist now empty) | `rikitikitavi-scanners/tests/remediation_coverage.rs` |
| FIX-01, FIX-09 | Product-aware remediation (Dyson, Denon/Marantz, Hue, UniFi); MQTT dedup fix; no telnet probe on identified AVRs | `rikitikitavi-scanners/src/remediation.rs`, `credentials.rs`, `templates/` |
| ID-09 | Identity ports in the default list (58 -> 66); Echo rule | `rikitikitavi-scanners/src/ports.rs` |
| NT-03 (part) | SA-26:13 / SA-26:19 minimum builds in the Synology finding; rsync correlation for CVE-2026-85101 | `rikitikitavi-scanners/src/http_audit.rs` |
| NT-07 | Hue Bridge swversion check | `rikitikitavi-scanners/src/hue.rs` |
| ID-05 | Spotify Connect `getInfo` | `rikitikitavi-scanners/src/spotify_zc.rs` |
| ID-02, ID-03 | HA DHCP hostname matchers; house hostname table | `rikitikitavi-scanners/src/ha_discovery_db.rs`, `hostname_db.rs` |
| FIX-03 | `verify` subcommand; `ScanKind` keeps verify runs out of `prune()` | `rikitikitavi/src/verify.rs`, `rikitikitavi-analysis/src/history.rs` |
| NT-06 | PHP2Shell floors on `X-Powered-By` | `rikitikitavi-scanners/src/http_audit.rs` |
| RE-02 | HA tables regenerated at fa47075 | `scripts/gen_ha_discovery_db.py`, `ha_discovery_db.rs` |
| FIX-02 | `fix-plan` subcommand | `rikitikitavi-export/src/fix_plan.rs` |
| FIX-08 (part) | `--accept-file` ledger with expiry and byte cap; rules file also capped | `rikitikitavi/src/accept.rs`, `rikitikitavi-analysis/src/declarative.rs` |
| NT-09 (part) | UniFi SAB-069 floors (credentialed, on-device, and Info advisory without credentials) | `rikitikitavi-unifi/src/firmware.rs` |
| ID-08 | NetBIOS NBSTAT naming | `rikitikitavi-network/src/nbns.rs` |
| ID-11 | IEEE MA-M / MA-S registries | `rikitikitavi-scanners/src/oui_db.rs` |
| NT-08 (part), RE-04 | tvOS fix floors from AirPlay `osvers`; tvOS end-of-life | `rikitikitavi-scanners/src/mdns/airplay.rs` |
| FIX-14 | AirPlay access posture from `flags`/`pw` | `rikitikitavi-scanners/src/mdns/airplay.rs` |
| FIX-11 | Matter commissioning-window remediation | `rikitikitavi-scanners/templates/mdns.yaml` |
| ID-12 | UniFi controller client import; `seen_by` on devices; `dev_cat` kept raw | `rikitikitavi-unifi/src/clients.rs`, `rikitikitavi-models/src/device.rs` |
| FIX-06 | `segment-plan` subcommand | `rikitikitavi-export/src/segment_plan.rs` |

Related change not on this roadmap: dedup now drops only restatements (it used to keep one scanner's findings per port).

## Threats

- NT-01 Plex2Shell (CVE-2026-96652/-96654/-96655/-96656), KEV 2026-10-20: done.
- NT-02 Kasa CVE-2026-108473 (FAQ 5342) and CVE-2026-76784 (FAQ 5267): done.
- NT-06 PHP2Shell CVE-2026-109618/-109619: done.
- NT-07 Hue Bridge v2 HomeKit batch (ZDI-26-155/-160): done.

**NT-03: Synology SA-26:13 (2026-09-18, 8 CVEs, 2 Critical) and SA-26:19 (2026-11-10). Partly done.** Done: per-branch minimum builds in the finding text, and the rsync correlation for CVE-2026-85101. Open: no unauthenticated route to the DSM build is verified. Check SSDP `desc-DSM-eth0.xml` on the owner's NAS, then add a build table. Listing rsync modules needs a client `@RSYNCD:` greeting first; the server greeting alone is enough. Effort S/M.
[SA-26:13](https://www.synology.com/en-global/security/advisory/Synology_SA_26_13) · [SA-26:19](https://www.synology.com/en-global/security/advisory/Synology_SA_26_19)

**NT-08: tvOS currency from AirPlay `osvers` + KEV join (merged with RE-04). Partly done.** Done for `AppleTV*`: six KEV fix floors and the tvOS end-of-life table. Open: HomePod has no vendor fix table, so skip it or mark `Inferred`. macOS currency (RE-04 suggested each cycle's `isEol`) is not done.
[Apple 120901](https://support.apple.com/en-us/120901) · [pyatv protocols](https://pyatv.dev/documentation/protocols/)

**NT-09: UniFi SAB-069 DoS cluster and SAB-070 Protect AI Key (CVE-2026-110459, fixed 2.2.8). SAB-069 done; AI Key not planned** (nothing identifies one on the LAN).

## Identification

- ID-01 Reverse DNS (PTR): done.
- ID-02 HA DHCP hostname matchers: done.
- ID-03 House hostname table: done.
- ID-05 Spotify Connect `getInfo`: done.
- ID-08 NetBIOS NBSTAT: done.
- ID-09 Identity ports in the default list: done.
- ID-11 IEEE MA-M/MA-S registries: done.
- ID-12 UniFi controller client import (credentialed): done. `dev_cat`/`dev_family`/`os_name` codes are kept raw, since no source gives their meaning.

## Remediation

- FIX-01 Product-aware remediation: done.
- FIX-02 `fix-plan` Markdown checklist: done.
- FIX-03 `verify` mode: done, except that it does not use the template `validation:` field (see FIX-08).
- FIX-05 Kasa remediation rewrite: done.
- FIX-06 Segmentation advisor (`segment-plan`): done.
- FIX-07 Coverage gate: done.
- FIX-09 Denon/Marantz telnet template: done.
- FIX-11 Matter commissioning-window remediation: done.
- FIX-14 AirPlay access posture: done.

**FIX-08: `fix_path` taxonomy + accepted-risk ledger. Partly done.** Done: `--accept-file` with `{fingerprint, reason, accepted_on, expires, compensating}`, byte caps on the accept and rules files. Open: add a new `fixPath` template key; do not reuse `changeType`, which holds ITIL values ("standard" ×51). Also open: the OVRS template `validation:` field is parsed but unused; filling it would let `verify` run a template's own check. Effort M.
[AVR-X3800H](https://manuals.denon.com/AVRX3800H/NA/EN/HJWMSYmehwmguq.php) · [Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge)

**FIX-10: Synology hardening template + hand-curated lifecycle table. Not started.** DS418play's last major is 7.4 (Synology 7.4-90075 note). The Value Series list gives about 15 rows (DS116…RS217). Synology ToS §2(d) bans robots, so no runtime fetch and no embedded release notes. Effort S.
[DS418play changelog](https://www.synology.com/api/releaseNote/findChangeLog?identify=DSM&lang=en-global&model=DS418play) · [Auto Block spec](https://www.synology.com/dsm/7.4/software_spec/signin_protection) · [Synology ToS](https://www.synology.com/en-global/company/legal/terms_conditions) · [blackvoid (secondary)](https://www.blackvoid.club/synology-dsm-7-4-90075.md)

**FIX-12: IPP `printer-firmware-*` read + HP fix floor. Not started.** Read-only Get-Printer-Attributes on 631. New TLV parser, so add a fuzz target. Seed `printer_fix_floors` from the HP CNA records: 002_2539E for M478-M479 and the sibling families in HPSBPI04074. Treat "per-unit PIN on label" as unverified. Effort M.
[IANA IPP registry](https://www.iana.org/assignments/ipp-registrations/ipp-registrations.xml) · [CVE-2025-12784 (NVD)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-12784) · [CVE-2025-12785 (NVD)](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-12785) · [CVE-2025-12784 (HP CNA)](https://cveawg.mitre.org/api/cve/CVE-2025-12784)

**FIX-13: Opt-in online UniFi firmware currency. Not started.** `fw-update.ui.com` returns several products per platform (`udm`, `unifi-firmware`, `unifi-dream`). Filter by product and compare versions; never take the first element. A missing product or schema change is reported as "unknown". Home is the stub `unifi firmware-check` in `rikitikitavi/src/main.rs`. No Synology or TP-Link feeds. Hue gets a static "Automatic update" step. Effort M.
[fw-update](https://fw-update.ui.com/api/firmware-latest?filter=eq~~channel~~release&filter=eq~~platform~~UDMPRO) · [UI ToS](https://www.ui.com/legal/termsofservice/) · [Hue notes](https://www.philips-hue.com/en-us/support/release-notes/bridge) · [endoflife.date](https://endoflife.date/api/v1/products/)

## Resources

- RE-02 Regenerate HA discovery tables: done (fa47075).
- RE-04 endoflife.date `tvos` join: done with NT-08; `macos` is open (see NT-08).

**RE-01: reqwest 0.13.1 held back. Partly done.** reqwest is at 0.13.5 and the authenticated UniFi client sets `Policy::none()`. Open: a CI check for held-back direct dependencies, with an allowlist, so this cannot recur silently. Effort S.
[reqwest CHANGELOG](https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md)

**RE-06: OSV.dev Debian as a runtime backport-aware oracle. Not started.** Debian:12 openssh 1:9.2p1-2+deb12u3 returns 42 records (about 32 after the urgency filter). Debian:11, the gateway's base, returns only DLA/DSA advisories (2 for +deb11u3). For deb11, report "N Debian LTS advisories" as weaker evidence. Runtime and opt-in only: Ubuntu data is CC-BY-SA, Debian is unlicensed. Responses are capped at 32 MiB. Effort M.
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

- **Possible false positive on the NAS:** `Vulnerable OpenSSH 8.2` on a Synology NAS may be the same backport problem as NT-04/NT-06. Synology patches packages without changing upstream version strings, as it does for PHP in SA-26:14. Not verified for OpenSSH; check against the DSM 7.2/7.4 release notes before trusting it. RE-06 would not help here (DSM is not Debian).
- **Soft-404 artefact (fixed in 0.5.0):** the 12 "possibly exposed admin page" findings on a UniFi camera came from a catch-all page. `http_audit.rs` now probes a non-existent path first and skips admin paths that return the same page.
- **Hue "web admin panel without auth":** this likely flags the bridge's documented unauthenticated `/api/config` and needs a vendor exception. Not addressed.
- **Confidence mapping:** the research used a "Possible" tier that the code does not have. Map it to `Inferred`, or `exploit_intel.rs` will raise KEV-tagged backport-uncertain findings to High.
