# Fuzz targets

libFuzzer harnesses for the parsers that consume network-sourced bytes. Requires nightly and
`cargo install cargo-fuzz`. The repo pins stable in rust-toolchain.toml, so pass `+nightly`.

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run dns_packet -- -max_total_time=60
cargo +nightly fuzz build            # compile every target without running
```

Crashes land in `fuzz/artifacts/<target>/`; reproduce with `cargo +nightly fuzz run <target> <artifact>`.

## Targets

| Target | Input |
|---|---|
| `dns_packet` | mDNS / DNS wire format |
| `wifi_frame` | radiotap and 802.11 management frames |
| `ssh_kex`, `service_banners` | SSH KEXINIT, SMTP, FTP and HTTP `Server` banners |
| `http_headers` | CSP, `Set-Cookie`, default-page and directory-listing bodies |
| `ssdp_upnp` | SSDP responses and UPnP device XML |
| `x509_der` | certificates |
| `snmp_ber` | SNMP BER TLVs |
| `smb_nbns` | SMB negotiate replies, NetBIOS node status |
| `databases` | Redis RESP, MySQL greeting, MongoDB reply, MQTT CONNACK |
| `line_protocols` | RTSP, FTP, telnet, PJL, UPnP IGD, AirPlay TXT, admin-page classification |
| `smart_home`, `ot_protocols`, `web_apps` | Cast, Kasa, Tuya, Spotify; Modbus, KNX, SADP; Hue, Plex, Jellyfin, PaperCut, 3D printers |
| `recog`, `tables`, `identifiers` | fingerprint matching, embedded tables, MAC/fingerprint/SPF/DMARC text |
| `exports` | property test: device text cannot break out of HTML, Markdown, Prometheus or JSON output |

Private parsers are reached through a `fuzz` module in their file, compiled only with the
scanners crate's `fuzzing` feature.

Not fuzzed: reverse-DNS replies (parsed by hickory), UniFi controller JSON and local files
(config, accept file, rules, saved scans), which go through serde.
