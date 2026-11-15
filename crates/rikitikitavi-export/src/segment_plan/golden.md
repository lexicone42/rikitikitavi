# Segmentation plan

A proposal only: this tool does not contact or configure any device. Each device shows why it was placed where it is; move it if you disagree.

| Zone | Devices |
| --- | --- |
| Trusted | 1 |
| IoT | 5 |
| Infrastructure | 3 |
| Unassigned | 1 |

## Start here

These devices accept unauthenticated local control; anyone on their network can operate them.

- printer (`192.168.1.2`) (proposed Infrastructure)
- Denon AVR (`192.168.1.34`) (proposed IoT)
- plug\|1 (`192.168.1.50`) (proposed IoT)

## Trusted (1)

- **laptop (`192.168.1.10`)**, Apple: Laptop: personal device

## IoT (5)

- **Denon AVR (`192.168.1.34`)**, D\&M Holdings: Speaker: casting target; the mDNS proxy keeps discovery working from Trusted
  - Segmentation limits who can reach:
    - Denon/Marantz receiver control port open without authentication on 192.168.1.34:23 (MEDIUM)
- **plug\|1 (`192.168.1.50`)**, TP-Link: IoT: smart-home device controlled by an app, hub or cloud
  - Segmentation limits who can reach:
    - TP-Link Kasa device accepts unauthenticated local control on 192.168.1.50:9999 (HIGH)
- **cam (`192.168.1.77`)**, Ring: Camera: smart-home device controlled by an app, hub or cloud
- **`192.168.1.169`**, Signify: IoT: smart-home device controlled by an app, hub or cloud
  - Segmentation limits who can reach:
    - Web admin panel without auth on 192.168.1.169:80 (MEDIUM)
- **Apple TV (`192.168.3.26`)**, Apple: Media Player: casting target; the mDNS proxy keeps discovery working from Trusted; Thread border router: keep it on the same network as its Matter controller \(see Constraints\)

## Infrastructure (3)

- **printer (`192.168.1.2`)**, HP: Printer: shared by Trusted devices; print channels are unauthenticated, so not in Trusted
  - Segmentation limits who can reach:
    - Raw printing \(JetDirect/PJL\) port open — unauthenticated print/control channel on 192.168.1.2:9100 (MEDIUM)
- **unifi (`192.168.1.1`)**, Ubiquiti Inc: Router: routes between the zones
- **nas (`192.168.1.20`)**, Synology: NAS: shared storage reached from Trusted, kept out of IoT
  - Segmentation limits who can reach:
    - SMB/CIFS exposed on 192.168.1.20:445 (MEDIUM)

## Unassigned (1)

Place these yourself; what the scan knows is listed.

- **box\_\*x\* (`192.168.2.31`)**, Cable Matters: Unknown: type not identified; remote-login ports open: likely a computer \(Trusted or Infrastructure\)
  - Open ports: TCP 22 (SSH), TCP 5900 (VNC)

## Allow rules

Everything between zones is denied unless a row below allows it. Replies to an allowed connection are permitted. Each device row is a port observed open in this scan; delete the rows for services you do not use.

### Between zones

| From | To | Action |
| --- | --- | --- |
| Trusted | Internet | Allow |
| IoT | Internet | Allow |
| Infrastructure | Internet | Allow (firmware updates) |
| IoT | Trusted | Deny new connections |
| IoT | Infrastructure | Deny new connections, except DNS and DHCP from the gateway |
| Any other pair | Any | Deny |

### To devices

| From | To | Port | Service | Why |
| --- | --- | --- | --- | --- |
| Controller host(s) in Trusted | Denon AVR (`192.168.1.34`) | TCP 23 | Telnet | device control or app access; observed open in this scan; accepts unauthenticated control |
| Trusted | Denon AVR (`192.168.1.34`) | TCP 7000 | AirPlay | casting or streaming from phones and computers; observed open in this scan |
| Controller host(s) in Trusted | Denon AVR (`192.168.1.34`) | TCP 8080 | HTTP-Proxy | device control or app access; observed open in this scan |
| Controller host(s) in Trusted | plug\|1 (`192.168.1.50`) | TCP 9999 | Kasa | device control or app access; observed open in this scan; accepts unauthenticated control |
| Controller host(s) in Trusted | `192.168.1.169` | TCP 80 | HTTP | device control or app access; observed open in this scan |
| Controller host(s) in Trusted | `192.168.1.169` | TCP 443 | HTTPS | device control or app access; observed open in this scan |
| Trusted | Apple TV (`192.168.3.26`) | TCP 7000 | AirPlay | casting or streaming from phones and computers; observed open in this scan |
| Admin host(s) in Trusted | printer (`192.168.1.2`) | TCP 80 | HTTP | management; observed open in this scan |
| Trusted | printer (`192.168.1.2`) | TCP 631 | IPP | printing; observed open in this scan |
| Trusted | printer (`192.168.1.2`) | TCP 9100 | RAW-Printing | printing; observed open in this scan; accepts unauthenticated control |
| Admin host(s) in Trusted | unifi (`192.168.1.1`) | TCP 22 | SSH | management; observed open in this scan |
| All zones | unifi (`192.168.1.1`) | TCP 53 | DNS | DNS from the gateway; observed open in this scan |
| Admin host(s) in Trusted | unifi (`192.168.1.1`) | TCP 443 | HTTPS | management; observed open in this scan |
| Trusted | nas (`192.168.1.20`) | TCP 445 | SMB | file sharing; observed open in this scan |
| Admin host(s) in Trusted | nas (`192.168.1.20`) | TCP 5001 | DSM-HTTPS | management; observed open in this scan |

## mDNS proxy allow-list

Service types advertised by IoT and Infrastructure devices in this scan. Repeat only these into Trusted so casting, AirPlay and printer discovery keep working across zones.

| Service type | Advertised by |
| --- | --- |
| `_airplay._tcp` | Apple TV (`192.168.3.26`) (IoT) |
| `_hue._tcp` | `192.168.1.169` (IoT) |
| `_ipp._tcp` | printer (`192.168.1.2`) (Infrastructure) |
| `_meshcop._udp` | Apple TV (`192.168.3.26`) (IoT) |
| `_raop._tcp` | Denon AVR (`192.168.1.34`) (IoT) |

## Constraints

- **Matter and Thread.** Home Assistant: "Make sure that Matter devices that use Wi-Fi (including Thread border router) are on the same VLANs/VLAN as Home Assistant", and Matter "relies on (local) IPv6 and mDNS (multicast traffic) traveling freely in your network". Put your Matter controller in the same zone as these devices, or keep them with it. <https://www.home-assistant.io/integrations/matter/>
  - Apple TV (`192.168.3.26`) (Thread border router, proposed IoT)
- **mDNS proxy.** The gateway repeats discovery between networks. The number of networks that can use mDNS proxy depends on the gateway model; check the limit for yours before splitting into more networks. <https://help.ui.com/hc/en-us/articles/12648701398807-UniFi-Gateway-Multicast-DNS-mDNS-Proxy>
- **Cameras and recorders.** A camera recorded by an NVR or console in another zone needs an allow rule from the camera to that recorder. The scan cannot see which recorder each camera uses.
- **Denon/Marantz receivers** (Denon AVR (`192.168.1.34`)). Home Assistant: telnet control "is limited to a single connection", and across VLANs it needs TCP 23, 8080 and 60006 on the receiver. Allow these from one controller only. <https://www.home-assistant.io/integrations/denonavr/>
- **Vendor ports.** Device ports in the rule table are the ones observed open in this scan, not vendor requirements.

## On UniFi

The gateway looks like a UniFi device. Create one network per zone, turn on isolation for the IoT network, add the allow rules above, and enable mDNS proxy for the service types listed. Isolation: <https://help.ui.com/hc/en-us/articles/18965560820247-Implementing-Network-and-Client-Isolation-in-UniFi>. mDNS proxy: <https://help.ui.com/hc/en-us/articles/12648701398807-UniFi-Gateway-Multicast-DNS-mDNS-Proxy>.

## Limits

- Built from one scan; devices that were offline then are missing.
- Moving a device to another zone changes its IP address. Re-scan afterwards and run `rikitikitavi verify`.
