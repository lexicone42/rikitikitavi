# Fix plan

## Do now

### nas.local (192.168.1.20)

- [ ] **Telnet open** (`192.168.1.20:23`, CRITICAL): Disable Telnet
  1. Open the admin UI
  2. Turn off Telnet
  - References: <https://example.com/telnet>
  - Verify: `rikitikitavi verify --finding 734f6e3975d8f280`

### cam\_\*evil\* (192.168.1.30)

- [ ] **Admin panel \<b\>\[click\]\(http://evil\)\</b\> \*now\*** (`192.168.1.30:80`, HIGH): Set a password
  - Verify: `rikitikitavi verify --finding c1c5cd9c5fd087d4`

## This weekend

### nas.local (192.168.1.20)

- [ ] **Weak TLS** (`192.168.1.20:443`, MEDIUM): Disable TLS 1.0
  - Verify: `rikitikitavi verify --finding 5fd13261183fcc94`

### Network-wide

- [ ] **UPnP IGD enabled** (`network`, LOW): Turn off UPnP on the router
  - Verify: `rikitikitavi verify --finding 1f916cf844047485`

## Replace

### nas.local (192.168.1.20)

- [ ] **End-of-life Debian 9 on 192.168.1.20:22** (`192.168.1.20:22`, HIGH)
  - Verify: `rikitikitavi verify --finding a82f1e068cc1e11e`

## Accepted

### cam\_\*evil\* (192.168.1.30)

- **SNMP public community** (`192.168.1.30:161`, HIGH, `3f16bc0127c166f2`)
  - Reason: Camera VLAN blocks SNMP (accepted 2026-11-01, expires 2027-02-01)
  - Compensating: ACL on gateway

## No fix available

- RTSP stream open (`192.168.1.30:554`, MEDIUM, cam\_\*evil\* (192.168.1.30), `a9f78d5d237b653b`)

1 informational finding(s) not listed.
