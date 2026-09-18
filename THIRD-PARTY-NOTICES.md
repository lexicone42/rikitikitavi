# Third-party data embedded in rikitikitavi

Code is Apache-2.0 (see LICENSE). The generated tables below carry their own terms.

## CISA Known Exploited Vulnerabilities catalog

Embedded in `crates/rikitikitavi-analysis/src/kev_db.rs` (regenerate with `scripts/gen_kev_db.py`).

- Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Licence: CC0 1.0 Universal

## OWASP IoT Top 10 (2018) taxonomy

Referenced in `crates/rikitikitavi-analysis/src/standards.rs` for finding tags.

- Source: OWASP IoT Top 10, 2018 edition, https://owasp.org/www-project-internet-of-things/
- Licence of the OWASP material: CC-BY-SA 4.0 (share-alike, not Apache-2.0 compatible).
- What is used: only the ten bare category identifiers `I1`–`I10`, which are facts, not
  copyrightable expression. The one-line category labels in `standards.rs` are this project's
  own factual restatements; no OWASP descriptive prose, table, wording or arrangement was copied.

## IEEE MA-L (OUI) registry

Embedded in `crates/rikitikitavi-scanners/src/oui_db.rs` (regenerate with `scripts/gen_oui_db.py`).

- Source: https://standards-oui.ieee.org/oui/oui.csv
- Terms: IEEE public listing, used for vendor lookup only

## CISA Vulnrichment (SSVC decision points and CWE assignments)

Embedded in `crates/rikitikitavi-analysis/src/vulnrichment_db.rs` (26 records).

- Source: https://github.com/cisagov/vulnrichment (branch `develop`, commit 3d608e158)
- Snapshot taken: 2026-09-17
- Licence: CC0 1.0 Universal (public domain dedication), https://creativecommons.org/publicdomain/zero/1.0/
- Extracted fields: `cveId`, and from the `CISA-ADP` container only, the SSVC decision points (Exploitation, Automatable, Technical Impact) and the CWE id. No CNA-container content is embedded.
- As with the KEV catalog, "public domain" does not extend to third-party links inside the upstream records, and this use does not imply CISA endorsement nor authorise the CISA logo or DHS seal.
- Regenerate with `uv run python scripts/gen_vulnrichment_db.py --clone <path>`. Rows
  are selected by the CVE ids production crate source references, plus the explicit
  allowlist in `scripts/vulnrichment_extra_cves.txt`; test fixtures select nothing.

## Home Assistant generated discovery tables

Embedded in `crates/rikitikitavi-scanners/src/ha_discovery_db.rs` (regenerate with
`uv run python scripts/gen_ha_discovery_db.py`, which pins the commit below by default;
`--ref <sha>` selects another).

- Source: https://github.com/home-assistant/core — `homeassistant/generated/zeroconf.py`,
  `homeassistant/generated/ssdp.py` and `homeassistant/generated/dhcp.py`, all read at
  commit `8e2c2c3cf5c533fa8bc38d2a5432831c7e244ad8` (2026-09-10, branch `dev`).
- Snapshot taken: 2026-09-17
- Licence: Apache License 2.0, https://github.com/home-assistant/core/blob/dev/LICENSE.md
  (verified: the repository root `LICENSE.md` is the Apache-2.0 text). There is no
  upstream `NOTICE` file, so the obligations here are §4(a) licence copy — satisfied by
  this project's own `LICENSE`, the same licence — §4(b) attribution, satisfied by this
  section, and §4(c) a statement of modification, below.
- Extracted fields: from `zeroconf.py`, the `ZEROCONF` mapping's service type, integration
  `domain`, `name` glob and `properties` predicates (164 matchers over 113 service types),
  and the `HOMEKIT` mapping's model key and `domain` (71 models); from `ssdp.py`, the
  `SSDP` mapping's `domain` plus the `st`, `nt`, `deviceType`, `manufacturer`,
  `manufacturerURL`, `modelName` and `modelDescription` fields (89 matchers); from
  `dhcp.py`, the `macaddress` glob and `domain` of the entries whose only condition is
  that glob (103 unique prefixes). Home Assistant integration domains are carried verbatim
  as the `device_subtype` of a finding's device hint.
- Not extracted, and this is the modification that matters most: **every DHCP entry that
  names a `hostname`**. Upstream has 388 DHCP entries, 257 of them carrying a
  `macaddress`; 154 of those 257 AND the MAC glob with a `hostname` glob, and a further 89
  entries are hostname-only. This tool observes no DHCP traffic and has no reverse DNS, so
  it cannot evaluate the hostname conjunct — and keeping the MAC half alone would turn a
  two-condition matcher into a false identification of every device built on that OUI.
  (Upstream's `august` rows, for instance, pair the hostnames `connect` and `august*` with
  contract-manufacturer OUIs belonging to Wistron NeWeb and AMPAK, which appear in
  thousands of unrelated products.) Also not extracted: 42 `registered_devices` entries
  (no matcher at all), two SSDP matchers keyed on `X_*` vendor extensions, and one
  zeroconf matcher whose glob uses an fnmatch character class.
- Modifications (Apache-2.0 §4(c)): the Python literals are transformed into sorted Rust
  static tables; service types, name globs and property values are lowercased and trailing
  dots stripped; MAC globs are uppercased with the trailing `*` removed and stored as
  nibble strings; the DHCP table is reduced to its MAC-only entries as described above.
  The accompanying integration-domain-to-`DeviceType` map in the same file is this
  project's own work, not Home Assistant's, and is emitted only for domains some carried
  table can actually produce.
- Size: 103 MAC prefixes, 164 + 71 + 89 table rows; 65 KB of generated Rust source.

The same `zeroconf.py` service-type list also informs the mDNS query set in
`crates/rikitikitavi-network/src/mdns.rs` (`SERVICE_QUERIES`), under the same licence and
attribution. The Matter and Thread service types in that list (`_matter._tcp`,
`_matterc._udp`, `_matterd._udp`, `_meshcop._udp`, `_meshcop-e._udp`), the meanings of the
TXT keys interpreted for them, and the bit layout of the border agent's `sb` state bitmap
decoded in `ThreadStateBitmap` come from the Matter and Thread specifications and from
https://github.com/openthread/ot-br-posix (BSD-3-Clause); no code or data was copied from
either.

## endoflife.date release and support dates

Embedded in `crates/rikitikitavi-scanners/src/eol_db.rs` (149 release cycles across 8
products; 25,852 bytes of table source, 31 KB file).

- Source: https://endoflife.date/api/v1/products/ (v1 API, `schema_version` 1.2.1)
- Snapshot taken: 2026-09-17
- Licence: MIT — https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE.
  That licence requires its copyright notice and permission notice to travel with
  the data, so both are reproduced verbatim below.
- Extracted fields, per release cycle: product `name`, cycle `name`, `codename`,
  `eolFrom`, `eoasFrom`, `isEol`, `latest.name`, and per product one supported
  cycle with its `isLts` flag. Nothing else from the record is embedded — no
  `links`, `identifiers`, `labels`, `custom` or release policy text.
- Products embedded: nginx, apache-http-server, eclipse-jetty, openssl, python, php,
  debian, ubuntu. Each has a call site in this workspace that joins a probed version
  against the table; mysql, mariadb and redis are tracked upstream but not embedded,
  because nothing joins them yet.
- The API is self-declared Beta; the generator pins `schema_version` and fails the
  build on drift. Refresh uses `ETag` / `If-None-Match`.
- Regenerate with `uv run python scripts/gen_eol_db.py`. Set `SOURCE_DATE` to pin the
  snapshot date and make the output byte-reproducible across days.

### endoflife.date licence (verbatim)

```
Copyright 2020 endoflife.date contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## nuclei-templates (detection matchers)

Embedded in `crates/rikitikitavi-scanners/src/nuclei_db.rs` (93,495 bytes; 145
TCP templates with 144 probe payloads and 150 matchers, 23 HTTP templates with
29 word matchers and 16 status matchers).

- Source: https://github.com/projectdiscovery/nuclei-templates, commit `218254aaf674b452f6982996ca06f97546d778de` (2026-09-17)
- Licence: MIT, https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md, reproduced verbatim below.
- Imported directories: `network/detection/**` (all 155 files) and 26 hand-picked
  files from `http/technologies/` that identify home hardware (23 of which
  survived the refusal rules below). Nothing from
  `http/default-logins`, `network/default-login`, `*/vulnerabilities`, `*/cves`,
  `*/exposures` or `*/misconfig` is embedded.
- Extracted fields, per template: `id`, `info.name` (as the product label),
  `info.metadata.vendor` (kept only where the template's own name corroborates
  it), `tcp[].port`, `tcp[].inputs[]` (`data`, `type`, `name`, `read`),
  `tcp[].read-size`, `tcp[].matchers-condition` and `tcp[].matchers[]`
  (`type`, `part`, `words`/`binary`/`regex`, `condition`, `case-insensitive`,
  `negative`, `name`). For the HTTP subset: `http[].path`, `http[].method` and
  the same matcher fields plus `status`. No `extractors`, `reference`,
  `classification`, `digest` or author metadata is embedded.
- Refused at generation time, and re-checked by `nuclei_db/tests.rs`: 14
  templates and 7 individual matchers. By reason — 3 with no default port
  (`java-rmi-detect`, `perforce-detection`, `weblogic-iiop-detect`), 5 left with
  no usable matcher (`gopher-detect`, `mikrotik-ssh-detect`, `casaos-detection`,
  `intel-amt-detect`, `microfocus-iprint-detect`), **2 whose payload
  authenticates or mutates** (`pgsql-detect` sends a startup packet with a
  username and a SCRAM message; `rdp-detection` sends `Cookie: mstshash=`),
  **1 whose payload changes the peer's state** (`rtl-tcp-server-detect` sends
  rtl_tcp commands `0x01` and `0x02`, which retune an SDR receiver), 3 whose
  payload exceeds the 128-byte cap (`ibm-db2-database-server`, `msmq-detect`,
  `rtsp-detect`), 2 regexes with no usable literal and 5 `dsl` matchers (mmh3
  favicon hashes and `len(body)` expressions).
- Every embedded payload is at most 128 bytes and carries no credential. The
  automated inertness rule is an ASCII-substring check, so it cannot speak for a
  binary blob: the 21 distinct binary payloads were read by hand at import — all
  reads or handshakes (S7 COTP/SZL read, Modbus read-device-id, `EtherNet/IP`
  ListIdentity, ONC RPC portmap DUMP, NFS NULL, DSI GetStatus, JDWP
  VirtualMachine.Version, AMQP and Radmin headers, a STOMP HELP, Mongo's
  `admin.$cmd` query, a RouterOS API command answered "not logged in", a BGP
  OPEN, and NUL/CRLF pokes) — and `nuclei_db/tests.rs` pins that set by digest so
  a regeneration that changes one has to be read again. The probe bytes are the
  upstream template's own; the refusal rules and the byte cap are ours.
- The BGP OPEN (port 179) and the ICS probes (102 S7, 44818 `EtherNet/IP`, 502
  Modbus) open a protocol session rather than read a banner. They are read-only,
  and kept because homelab and building-automation gear does appear on a home
  LAN; drop them from the import if that trade is not wanted.
- Table ports 81 and 8728 are outside `ports.rs`'s Common and Extended ranges,
  so nothing selects them until those lists carry them.
- Regenerate with
  `uv run --with pyyaml python scripts/gen_nuclei_db.py --clone <path> > crates/rikitikitavi-scanners/src/nuclei_db.rs`,
  then `cargo fmt`.

Upstream `LICENSE.md`, verbatim:

```
MIT License

Copyright (c) 2025 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Rapid7 Recog fingerprint database

Embedded in `crates/rikitikitavi-scanners/src/recog_db.rs` (regenerate with
`uv run --with defusedxml python scripts/gen_recog_db.py --clone <path>`).

- Source: https://github.com/rapid7/recog — the `xml/` fingerprint files, read at commit
  `d3d20938da9f5f1e442c2419fe6c30cd651b6878` (2026-08-17, branch `main`).
- Snapshot taken: 2026-09-17
- Licence: BSD-2-Clause. The repository's `LICENSE` is a Debian copyright-format file
  naming `Files: *`, `Copyright: 2014, Rapid7, Inc.`, `License: BSD-2-clause`; the licence
  text itself is in `COPYING`, reproduced verbatim below, including its
  "Copyright (c) 2014-2015, Rapid7" notice.
- Extracted fields: from 13 of the 51 fingerprint files, each `<fingerprint>` element's
  `pattern`, `flags` and `<description>`, and the `<param>` elements whose `name` is one of
  `service.{vendor,product,version,family}`, `os.{vendor,product,version,family,device,arch}`,
  `hw.{vendor,product,model,family,device}` or `host.name`. The `<example>` elements of the
  imported fingerprints are embedded behind `#[cfg(test)]` only.
- Not extracted: every `*.cpe23` value, `*.certainty`, `system.time*`, `openssh.comment`,
  `host.mac`, `host.ip`, `dell.service_tag` and the other vendor-specific parameters —
  2,427 parameters in all, because nothing in this workspace joins them. A fingerprint
  left with no extracted parameter is dropped (34 of them, mostly `html_title`'s generic
  HTTP error pages), and 38 of the 51 upstream files are not imported at all because no
  probe here produces their input; `scripts/gen_recog_db.py` records the reason per file.
- Row counts: 2,430 fingerprints across 13 match keys — `ssh.banner` 152,
  `telnet.banner` 144, `ftp.banner` 149, `smtp.banner` 139, `imap4.banner` 18,
  `pop3.banner` 30, `http_header.server` 451, `http_header.wwwauth` 74, `html_title` 452,
  `snmp.sys_description` 591, `x509.subject` 166, `x509.issuer` 29, `hp.pjl.id` 35 —
  plus 4,529 test-only examples.
- Byte size: 1,172,967 bytes of embedded table and 811,591 bytes of `#[cfg(test)]`
  examples, 1,984,558 bytes of generated source in total.
- Modifications (§ none required by BSD-2-Clause, recorded for review): each pattern is
  rewritten from Recog's Ruby/POSIX flag conventions into Rust inline flags —
  `REG_ICASE` becomes `(?i)`, `REG_DOT_NEWLINE` and `REG_MULTILINE` both become `(?s)`,
  and `(?m)` is prefixed to every pattern because Ruby's `^`/`$` are always line anchors.
  Pattern text is otherwise byte-for-byte upstream. Match resolution keeps upstream file
  order (first match wins). No fingerprint was dropped for using an unsupported regex
  feature: at this commit none of the imported patterns uses lookaround or a
  backreference.

Upstream `COPYING`, verbatim:

```
Copyright (c) 2014-2015, Rapid7
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

Upstream `LICENSE`, verbatim:

```
Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Source: https://github.com/rapid7/recog

Files: *
Copyright: 2014, Rapid7, Inc.
License: BSD-2-clause
```

## TP-Link Kasa local protocol (softScheck/tplink-smartplug)

- Source: https://github.com/softScheck/tplink-smartplug
- Licence: Apache-2.0, https://github.com/softScheck/tplink-smartplug/blob/master/LICENSE
- Taken: the protocol description (4-byte big-endian length prefix, XOR autokey
  stream with initial key 171) reproduced in the module doc of
  `crates/rikitikitavi-scanners/src/kasa.rs`, and one published 29-byte
  `get_sysinfo` ciphertext used as a test vector
  (`GET_SYSINFO_CIPHERTEXT` in that file's test module). No source code was
  copied; the encoder, decoder and scanner are ours.

## RouterSploit default-credential and SNMP community wordlists

Embedded in `crates/rikitikitavi-scanners/src/default_creds_db.rs` (regenerate with
`uv run python scripts/gen_default_creds_db.py`).

- Source: https://github.com/threat9/routersploit — `routersploit/resources/wordlists/defaults.txt`
  (653 lines, 9596 bytes) and `routersploit/resources/wordlists/snmp.txt`
  (120 lines, 839 bytes), both read at commit
  `723b574c36ae202857e3f93e4f3c2ab9a1638ed4` (2026-05-05, branch `master`).
- Snapshot taken: 2026-09-18
- Licence: BSD 3-Clause. The upstream `LICENSE` names it "the BSD licensing";
  its three conditions and disclaimer are the BSD-3-Clause text, reproduced below.
- Extracted fields: from `defaults.txt`, the `user:pass` pairs relevant to home /
  SOHO devices (routers, access points, cameras, NVRs, printers, NAS) — 79 pairs,
  each tagged generic or with a curated lowercase vendor token for prioritisation
  (the tag is this project's curation, not upstream metadata; every pair is present
  verbatim upstream); from `snmp.txt`, all 119 community strings, verbatim. No
  exploit modules, framework code, or the `exploits/` tree were copied.
- Modification: pairs were selected for home-relevance and grouped by vendor; the
  Rust table, accessors and the scanner wiring are ours. The corpus only informs
  findings — a login is attempted solely at `ScanIntensity::Aggressive`, capped and
  stopping at the first success (see SECURITY.md).
- The BSD-3 non-endorsement clause is observed: the `RouterSploit` name is used
  here only to attribute the data, not to endorse or promote this project.

> Copyright 2018, The RouterSploit Framework (RSF) by Threat9. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
> (1) Redistributions of source code must retain the above copyright notice, this
> list of conditions and the following disclaimer. (2) Redistributions in binary
> form must reproduce the above copyright notice, this list of conditions and the
> following disclaimer in the documentation and/or other materials provided with
> the distribution. (3) Neither the name of RouterSploit Framework nor the names
> of its contributors may be used to endorse or promote products derived from this
> software without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
> ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
> WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
> DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
> ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
> (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
> LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
> ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
> (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
> SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Concepts referenced, with no code or data copied

These projects and specifications informed features in this repository. Nothing
was vendored from them: no source, no fixtures, no data tables, no wording.

- **Prometheus text exposition format 0.0.4** — the output shape of
  `--format prometheus` (`crates/rikitikitavi-export/src/prometheus.rs`). The
  format is a published specification; the Prometheus project itself is
  Apache-2.0. Metric names, help strings and the choice of series are ours.
  Source: https://prometheus.io/docs/instrumenting/exposition_formats/
- **WatchYourLAN** (MIT) — prior art for exporting LAN-scan state as metrics.
  No code or metric definitions were taken. Source:
  https://github.com/aceberg/WatchYourLAN
- **tinytuya** (MIT) — the Tuya local discovery protocol, including the fixed
  broadcast key `md5("yGAdlopoPVldABfn")` embedded as `UDP_KEY` in
  `crates/rikitikitavi-scanners/src/tuya.rs`. That key is a published protocol
  constant, identical in every device and every client library; no tinytuya
  source, fixture or wording was copied, and the frame parsers and AES calls are
  ours. Source: https://github.com/jasonacox/tinytuya
- **NetAlertX** (GPL-3.0) — prior art for presenting per-device new/known state
  alongside the device inventory. The idea only; no GPL code, strings or schema
  is present, and the implementation reuses this repository's own
  `--known-devices` file. Source: https://github.com/jokob-sk/NetAlertX
