//! nuclei-templates detection matchers — auto-generated.
//!
//! Source: <https://github.com/projectdiscovery/nuclei-templates> (MIT), commit 218254aaf674b452f6982996ca06f97546d778de (2026-09-17)
//! Imported: 145 `network/detection` TCP templates, 23 curated
//! `http/technologies` templates. 14 upstream templates and
//! 7 individual matchers were refused; `scripts/gen_nuclei_db.py`
//! prints the reason for each.
//!
//! Detection only: every probe payload is inert (no credentials, no mutating
//! command, at most 128 bytes) and every HTTP path is an unauthenticated GET.
//! The inertness check is an ASCII-substring rule; the non-ASCII handshake blobs
//! were read by hand at import and `nuclei_db/tests.rs` pins that reviewed set.
//! Regenerate with
//! `uv run --with pyyaml python scripts/gen_nuclei_db.py --clone <path>`,
//! then `cargo fmt`.

/// How a list of patterns, or a list of matchers, combines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Every element must match.
    And,
    /// Any element may match.
    Or,
}

/// One inert payload written to the socket before reading.
#[derive(Debug, Clone, Copy)]
pub struct Probe {
    /// Bytes written verbatim.
    pub data: &'static [u8],
    /// Name of the response part this probe's read is stored under.
    pub name: Option<&'static str>,
    /// Bytes to read after writing, when the template caps it.
    pub read: Option<usize>,
}

/// Byte-substring matcher over one part of a TCP response.
#[derive(Debug, Clone, Copy)]
pub struct ByteMatcher {
    /// `"body"` (everything read) or a [`Probe::name`].
    pub part: &'static str,
    /// Patterns, already lowercased when `case_insensitive`.
    pub patterns: &'static [&'static [u8]],
    /// How `patterns` combine.
    pub condition: Condition,
    /// Compare ASCII-case-insensitively.
    pub case_insensitive: bool,
    /// Match means "none of these patterns are present".
    pub negative: bool,
    /// Upstream matcher name, e.g. an OS version label.
    pub label: Option<&'static str>,
}

/// A `network/detection` template: probe, then match what came back.
#[derive(Debug, Clone, Copy)]
pub struct TcpTemplate {
    /// Upstream template id.
    pub id: &'static str,
    /// Product this identifies.
    pub product: &'static str,
    /// Ports the template declares.
    pub ports: &'static [u16],
    /// Payloads to send, in order.
    pub probes: &'static [Probe],
    /// Bytes to read per probe when the probe does not cap it.
    pub read_size: usize,
    /// How `matchers` combine.
    pub condition: Condition,
    /// Matchers over the response.
    pub matchers: &'static [ByteMatcher],
}

/// Part of an HTTP response a matcher reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPart {
    /// Response body.
    Body,
    /// Response headers, one `Name: value` line each.
    Header,
    /// Status line, headers and body.
    All,
}

/// Matcher over an HTTP response.
#[derive(Debug, Clone, Copy)]
pub enum HttpMatcher {
    /// Substring match over `part`.
    Words {
        /// Part to search.
        part: HttpPart,
        /// Patterns, already lowercased when `case_insensitive`.
        patterns: &'static [&'static str],
        /// How `patterns` combine.
        condition: Condition,
        /// Compare ASCII-case-insensitively.
        case_insensitive: bool,
        /// Match means "none of these patterns are present".
        negative: bool,
        /// Upstream matcher name.
        label: Option<&'static str>,
    },
    /// Status-code match.
    Status {
        /// Accepted status codes.
        codes: &'static [u16],
        /// Match means "not one of these codes".
        negative: bool,
    },
}

/// A curated `http/technologies` template: GET each path, then match.
#[derive(Debug, Clone, Copy)]
pub struct HttpTemplate {
    /// Upstream template id.
    pub id: &'static str,
    /// Product this identifies.
    pub product: &'static str,
    /// Paths to GET, relative to the base URL.
    pub paths: &'static [&'static str],
    /// How `matchers` combine.
    pub condition: Condition,
    /// Matchers over the response.
    pub matchers: &'static [HttpMatcher],
}

/// Upstream commit this snapshot was generated from.
pub const NUCLEI_TEMPLATES_COMMIT: &str = "218254aaf674b452f6982996ca06f97546d778de";

/// Longest probe payload, in bytes. Tests hold the table to it.
pub const MAX_PROBE_BYTES: usize = 128;

/// Look up a TCP template by upstream id. O(log n).
#[must_use]
pub fn tcp_template(id: &str) -> Option<&'static TcpTemplate> {
    TCP_TEMPLATES
        .binary_search_by(|t| t.id.cmp(id))
        .ok()
        .map(|i| &TCP_TEMPLATES[i])
}

/// Look up an HTTP template by upstream id. O(log n).
#[must_use]
pub fn http_template(id: &str) -> Option<&'static HttpTemplate> {
    HTTP_TEMPLATES
        .binary_search_by(|t| t.id.cmp(id))
        .ok()
        .map(|i| &HTTP_TEMPLATES[i])
}

/// TCP templates declaring `port`.
pub fn tcp_templates_for_port(port: u16) -> impl Iterator<Item = &'static TcpTemplate> {
    TCP_TEMPLATES
        .iter()
        .filter(move |t| t.ports.contains(&port))
}

/// Whether the HTTP pass has anything to say about `port`.
#[must_use]
pub fn is_http_port(port: u16) -> bool {
    HTTP_PORTS.contains(&port)
}

/// Ports the HTTP pass runs against.
#[rustfmt::skip]
pub static HTTP_PORTS: &[u16] = &[80, 81, 443, 631, 8000, 8008, 8080, 8081, 8123, 8443, 8888];

/// Every port either table can act on, sorted.
#[rustfmt::skip]
pub static NUCLEI_PORTS: &[u16] = &[21, 22, 23, 25, 79, 80, 81, 102, 110, 111, 143, 179, 443, 465, 502, 541, 548, 587, 631, 873, 902, 2002, 2049, 2525, 3200, 3299, 3306, 3310, 4899, 5001, 5005, 5222, 5672, 5900, 6379, 6380, 6835, 7001, 7002, 7676, 8000, 8008, 8080, 8081, 8087, 8123, 8443, 8728, 8888, 9042, 9090, 27017, 30005, 44818, 61613, 61616];

/// `network/detection` templates, sorted by id.
#[rustfmt::skip]
pub static TCP_TEMPLATES: &[TcpTemplate] = &[
    TcpTemplate {
        id: "3com-ftp-detect",
        product: "3Com 3CDaemon FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"3Com 3CDaemon FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "activemq-openwire-transport-detect",
        product: "ActiveMQ OpenWire Transport",
        ports: &[6835, 61616],
        probes: &[
            Probe { data: b"VERSION", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ActiveMQ"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "adi-galaxy-ftp-detect",
        product: "ADI Convergence Galaxy FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ADI Convergence Galaxy"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "adsb-ultrafeeder-detect",
        product: "ADSB Ultrafeeder Beast Mode",
        ports: &[30005],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"\x1a1", b"\x1a2", b"\x1a3"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "afp-server-detect",
        product: "AFP Server",
        ports: &[548],
        probes: &[
            Probe { data: b"\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x0f\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"AFP", b"DHCAST"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "aix-websm-detect",
        product: "AIX WebSM",
        ports: &[9090],
        probes: &[
            Probe { data: b"en_US\x0d\x0a", name: None, read: Some(1024) },
        ],
        read_size: 4096,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"/var/websm/", b"startNewWServer"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-compactlogix-detect",
        product: "Allen-Bradley CompactLogix Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"1769-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-guardplc-detect",
        product: "Allen-Bradley GuardPLC Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"1753-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            ByteMatcher { part: "info", patterns: &[b"1754-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            ByteMatcher { part: "info", patterns: &[b"1755-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-micro800-detect",
        product: "Allen-Bradley Micro800 Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"2080-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-micrologix-detect",
        product: "Allen-Bradley MicroLogix Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"1761-", b"1762-", b"1763-", b"1764-", b"1766-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-plc5-detect",
        product: "Allen-Bradley PLC-5 Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"1771-", b"1772-", b"1785-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "allen-bradley-slc-500-detect",
        product: "Allen-Bradley SLC-500 Series PLC",
        ports: &[44818],
        probes: &[
            Probe { data: b"c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: Some("info"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"1746-", b"1772-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "apache-activemq-detect",
        product: "Apache ActiveMQ",
        ports: &[61613],
        probes: &[
            Probe { data: b"HELP\x0a\x0a\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Unknown STOMP action", b"norg.apache.activemq.transport.stomp"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "argosoft-ftp-detect",
        product: "ArGoSoft FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ArGoSoft FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "avalaunch-ftp-detect",
        product: "Avalaunch FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"The Avalaunch FTP system"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "aws-sftp-detect",
        product: "AWS SFTP Service",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"aws_sftp"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "axigen-mail-server-detect",
        product: "Axigen Mail Server",
        ports: &[25],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Axigen ESMTP", b"AXIGEN"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "baby-ftp-detect",
        product: "Baby FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Baby FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "betaftpd-detect",
        product: "BetaFTPD Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"BetaFTPD"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "bgp-detect",
        product: "BGP",
        ports: &[179],
        probes: &[
            Probe { data: b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x1d\x01\x04\x00\xff\xff\x00\x00\xb4\xc0", name: None, read: None },
        ],
        read_size: 16,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "bitvise-detect",
        product: "SSH Bitvise Service",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"bitvise"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "blackjumbodog-ftp-detect",
        product: "BlackJumboDog FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP ( BlackJumboDog"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "blackmoon-chaos-ftp-detect",
        product: "BlackMoon FTP Chaos Edition Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"BlackMoon FTP Server Version"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "blackmoon-free-ftp-detect",
        product: "BlackMoon FTP Free Edition Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"BlackMoon FTP Server - Free Edition"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "bluecoat-telnet-proxy-detect",
        product: "BlueCoat Telnet Proxy",
        ports: &[23],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: Some(1024) },
        ],
        read_size: 4096,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Blue Coat telnet proxy"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "bsdi-ftp-detect",
        product: "BSDI FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (BSDI"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "cerberus-ftp-detect",
        product: "Cerberus FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Cerberus FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "checkpoint-ftp-detect",
        product: "Check Point FireWall-1 FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Check Point FireWall-1 Secure FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "cisco-finger-detect",
        product: "Cisco Finger Daemon",
        ports: &[79],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Interface", b"Mode", b"User"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "clamav-detect",
        product: "ClamAV Server",
        ports: &[3310],
        probes: &[
            Probe { data: b"VERSION", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ClamAV "], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "cleo-vlproxy-ftp-detect",
        product: "Cleo VLProxy FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Cleo VLProxy"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "code-crafters-ftp-detect",
        product: "Code-Crafters Ability FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Code Crafters Ability FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "communigate-ftp-detect",
        product: "CommuniGate Pro FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"CommuniGate Pro FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "cql-native-transport",
        product: "CQL Native Transport",
        ports: &[9042],
        probes: &[
            Probe { data: b"/n", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"valid or unsupported protocol"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "delegate-ftp-detect",
        product: "DeleGate PROXY-FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"PROXY-FTP server (DeleGate"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "detect-addpac-voip-gateway",
        product: "AddPac GSM VoIP Gateway Panel",
        ports: &[23],
        probes: &[
            Probe { data: b"\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome", b"APOS(tm)", b"User Access Verification"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "detect-jabber-xmpp",
        product: "Jabber XMPP Protocol",
        ports: &[5222],
        probes: &[
            Probe { data: b"a\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"stream:stream xmlns:stream", b"stream:error xmlns:stream"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "direct-connect-detect",
        product: "Direct Connect P2P",
        ports: &[548],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"$MyNick bb3096", b"$Lock EXTENDEDPROTOCOL"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "diskstation-ftp-detect",
        product: "DiskStation FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"DiskStation FTP server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "dotnet-remoting-service-detect",
        product: "Microsoft .NET Remoting httpd",
        ports: &[8080],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Server: MS .NET Remoting"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "dumb-ftp-detect",
        product: "Dumb FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Dumb FTP Server (dftpd)"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "easycoder-ftp-detect",
        product: "EasyCoder FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"EasyCoder FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "erlang-otp-ssh-detect",
        product: "Erlang/OTP SSH Server",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"SSH-2.0-Erlang"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "esmtp-detect",
        product: "ESMTP",
        ports: &[25, 465, 587, 2525],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ESMTP Postfix", b"220"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "exim-detect",
        product: "Exim",
        ports: &[465, 587],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ESMTP Exim"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "expn-mail-detect",
        product: "EXPN Mail Server",
        ports: &[25, 465, 587, 2525],
        probes: &[
            Probe { data: b"ehlo checktls\x0a", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"250-EXPN"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "famatech-radmin-detect",
        product: "Famatech Radmin",
        ports: &[4899],
        probes: &[
            Probe { data: b"\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"\x01\x00\x00\x00\x09"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "filezilla-ftp-detect",
        product: "FileZilla FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FileZilla Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "finger-detect",
        product: "Finger Daemon",
        ports: &[79],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"User", b"Action", b"Node"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "firstclass-ftp-detect",
        product: "FirstClass FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (FirstClass"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "fortinet-fgfm-detect",
        product: "Fortinet FGFM protocol",
        ports: &[541],
        probes: &[
            Probe { data: b".", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b".fortinet.com", b"Certificate Authority"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "freebox-ftp-detect",
        product: "Freebox FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Freebox FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "ftp-detect",
        product: "FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ftp"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "gene6-ftp-detect",
        product: "Gene6 FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Gene6 FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "globalscape-ftp-detect",
        product: "GlobalSCAPE Secure FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"GlobalSCAPE Secure FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "globalsite-selector-ftp-detect",
        product: "Global Site Selector FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Global Site Selector FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "gnu-inetutils-ftpd-detect",
        product: "GNU Inetutils FTPd",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"SmartGateway FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "golden-ftp-detect",
        product: "Golden FTP Server Pro Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Golden FTP Server Pro"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "hp-ftp-detect",
        product: "Hewlett-Packard FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Hewlett-Packard"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "hummingbird-ftp-detect",
        product: "Hummingbird HCLFTPD Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (Hummingbird Ltd. HCLFTPD)"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "ibm-ftp-detect",
        product: "IBM FTP CS Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTPD1 IBM FTP CS"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "imap-detect",
        product: "IMAP",
        ports: &[143],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"OK ", b"IMAP4rev1"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "iplanet-imap-detect",
        product: "iPlanet Messaging Server IMAP Protocol",
        ports: &[110],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"iPlanet Messaging Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "jana-ftp-detect",
        product: "Jana-Server FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Ftp service of Jana-Server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "java-ftp-proxy-detect",
        product: "Java FTP Proxy Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Java FTP Proxy Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "jd-ftp-detect",
        product: "JD FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"JD FTP Server Ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "jdwp-detect",
        product: "Java Debug Wire Protocol",
        ports: &[5005],
        probes: &[
            Probe { data: b"JDWP-Handshake", name: None, read: Some(14) },
            Probe { data: b"\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x01\x01", name: None, read: Some(1024) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"JVM version", b"VM"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "lanier-ftp-detect",
        product: "LANIER MP 2555 FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"LANIER MP 2555 FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "macosx-ftp-detect",
        product: "Mac OS X Server FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Mac OS X Server's FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "maverick-ssh-detect",
        product: "Maverick SSH Service",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"maverick"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "medusa-ftp-detect",
        product: "Medusa Async FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (Medusa Async"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "microsoft-ftp-detect",
        product: "Microsoft FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Microsoft FTP Service"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "microsoft-ftp-service",
        product: "Microsoft FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Microsoft FTP Service"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "mikrotik-ftp-detect",
        product: "MikroTik FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (MikroTik"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "mikrotik-ftp-server-detect",
        product: "MikroTik FTP server",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"MikroTik FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "mikrotik-routeros-api",
        product: "MikroTik RouterOS API",
        ports: &[8728],
        probes: &[
            Probe { data: b":\x00\x00\x00/\x00\x00\x00\x02\x00\x00@\x02\x0f\x00\x01\x00=\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"\x06!fatal\x0dnot logged in\x00"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "mongodb-detect",
        product: "MongoDB Service",
        ports: &[27017],
        probes: &[
            Probe { data: b":\x00\x00\x00\xa7A\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"logicalSessionTimeout", b"localTime"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "moveit-sftp-detect",
        product: "MOVEit Transfer SFTP",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"moveit"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "mysql-detect",
        product: "MySQL",
        ports: &[3306],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"mysql"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "ncftpd-detect",
        product: "NcFTPd Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"NcFTPd Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "netbsd-ftpd-detect",
        product: "NetBSD FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (NetBSD-ftpd"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "netdisk-ftp-detect",
        product: "NET Disk FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"NET Disk FTP Server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "networkcamera-ftp-detect",
        product: "Network Camera FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Network Camera FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "nfs-v3-exposed",
        product: "NFSv3 Exposed",
        ports: &[2049],
        probes: &[
            Probe { data: b"\x80\x00\x00(VER3\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 256,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"VER3\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"], condition: Condition::Or, case_insensitive: false, negative: false, label: Some("nfs-v3-success") },
            ByteMatcher { part: "body", patterns: &[b"HTTP/1.1"], condition: Condition::Or, case_insensitive: false, negative: true, label: None },
        ],
    },
    TcpTemplate {
        id: "nmc-ftp-detect",
        product: "Network Management Card FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Network Management Card AOS"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "nucleus-ftp-detect",
        product: "Nucleus FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Nucleus FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "opendreambox-ftp-detect",
        product: "OpenDreambox FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"OpenDreambox FTP service"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "openssh-detect",
        product: "OpenSSH Service",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"openssh"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "oracle-ifs-ftp-detect",
        product: "Oracle Internet File System FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Oracle Internet File System FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "oracle-xmldb-ftp-detect",
        product: "Oracle XML DB FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP Server (Oracle XML DB"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "pablo-ftp-detect",
        product: "Pablo's FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Pablo's FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "packetshaper-ftp-detect",
        product: "PacketShaper FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"PacketShaper FTP server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "personal-ftp-detect",
        product: "Personal FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Personal FTP Server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "pop3-detect",
        product: "POP3 Protocol",
        ports: &[110],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"+OK Dovecot ready", b"POP3"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "prnet-ftp-detect",
        product: "PrNET FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"PrNET FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "proftpd-server-detect",
        product: "ProFTPD Server",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ProFTPD Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "psosystem-ftp-detect",
        product: "pSOSystem FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"pSOSystem FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "pure-ftpd-detect",
        product: "Pure-FTPd Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Pure-FTPd"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "rabbitmq-detect",
        product: "RabbitMQ",
        ports: &[5672],
        probes: &[
            Probe { data: b"AMQP\x00\x00\x09\x01", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"publisher_confirmst", b"RabbitMQ"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "red-lion-enip-detect",
        product: "Red Lion ENIP",
        ports: &[502],
        probes: &[
            Probe { data: b"\x00\x04\x01+\x1b\x00", name: Some("info"), read: Some(200) },
            Probe { data: b"\x00\x04\x01*\x1a\x00", name: Some("note"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "info", patterns: &[b"Red Lion Controls"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "redis-detect",
        product: "Redis Service",
        ports: &[6379, 6380],
        probes: &[
            Probe { data: b"*1\x0d\x0a$4\x0d\x0ainfo\x0d\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"DENIED Redis", b"CONFIG REWRITE", b"NOAUTH Authentication"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "riak-detect",
        product: "Riak",
        ports: &[8087],
        probes: &[
            Probe { data: b"\x00\x00\x00\x01\x07", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"riak"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "riedel-ftp-detect",
        product: "RIEDEL Artist FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"RIEDEL Artist FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "rpcbind-portmapper-detect",
        product: "Rpcbind Portmapper",
        ports: &[111],
        probes: &[
            Probe { data: b"\x80\x00\x00(6\xeddm\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"/run/rpcbind.sock"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "rsyncd-service-detect",
        product: "Rsyncd Service",
        ports: &[873],
        probes: &[
            Probe { data: b"?\x0d\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"RSYNCD: ", b"ERROR: protocol startup error"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sambar-ftp-detect",
        product: "Sambar FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Sambar FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sap-dispatcher-detect",
        product: "SAP Dispatcher",
        ports: &[3200],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"DPTMMSG"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sap-router",
        product: "SAPRouter",
        ports: &[3299],
        probes: &[
            Probe { data: b"WHOAREYOU?\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"SAProuter"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sap-router-detect",
        product: "SAProuter",
        ports: &[3200],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"SAProuter", b"network interface"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "schneider-modicon-340-detect",
        product: "Schneider Electric Modicon 340 Series PLC",
        ports: &[502],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00\x00\x05\x00+\x0e\x02\x00", name: Some("info"), read: Some(200) },
            Probe { data: b"\x00\x01\x00\x00\x00\x04\x00Z\x00\x02", name: Some("note"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "note", patterns: &[b"BMX P34"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            ByteMatcher { part: "info", patterns: &[b"Schneider Electric"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "schneider-modicon-580-detect",
        product: "Schneider Electric Modicon 580 Series PLC",
        ports: &[502],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00\x00\x05\x00+\x0e\x02\x00", name: Some("info"), read: Some(200) },
            Probe { data: b"\x00\x01\x00\x00\x00\x04\x00Z\x00\x02", name: Some("note"), read: Some(200) },
        ],
        read_size: 1024,
        condition: Condition::And,
        matchers: &[
            ByteMatcher { part: "note", patterns: &[b"BME P58"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            ByteMatcher { part: "info", patterns: &[b"Schneider Electric"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "securegateway-ftp-detect",
        product: "Secure Gateway FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Secure Gateway FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "serv-u-ftp-detect",
        product: "Serv-U FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Serv-U FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sidewinder-ftp-detect",
        product: "Sidewinder FTP Proxy Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Sidewinder ftp proxy"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "siemens-s7-detect",
        product: "Siemens SIMATIC S7 Series PLC",
        ports: &[102],
        probes: &[
            Probe { data: b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x14\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a", name: Some("cotp"), read: Some(1024) },
            Probe { data: b"\x03\x00\x00\x19\x02\xf0\x802\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x01\xe0", name: Some("setup"), read: Some(1024) },
            Probe { data: b"\x03\x00\x00!\x02\xf0\x802\x07\x00\x00\x00\x00\x00\x08\x00\x08\x00\x01\x12\x04\x11D\x01\x00\xff\x09\x00\x04\x00\x11\x00\x01", name: Some("szl"), read: Some(1024) },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "szl", patterns: &[b"\x02\xf0\x802\x07\x00\x00", b"6ES7"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "smtp-detect",
        product: "SMTP",
        ports: &[25, 465, 587, 2525],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"SMTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sshd-dropbear-detect",
        product: "Dropbear sshd",
        ports: &[22],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"dropbear"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "starttls-mail-detect",
        product: "STARTTLS Mail Server",
        ports: &[25, 465, 587, 2525],
        probes: &[
            Probe { data: b"ehlo checktls\x0a", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"250-STARTTLS"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sunos56-ftp-detect",
        product: "SunOS 5.6 FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (SunOS 5.6)"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "sunos58-ftp-detect",
        product: "SunOS 5.8 FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (SunOS 5.8)"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "teamspeak3-detect",
        product: "TeamSpeak 3 ServerQuery",
        ports: &[2002],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"TS3", b"TeamSpeak 3 ServerQuery interface"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "telnet-detect",
        product: "Telnet",
        ports: &[23],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Telnet", b"Login authentication"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "titan-ftp-detect",
        product: "Titan FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Titan FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "tnftpd-detect",
        product: "TNFTPD Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP server (tnftpd"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "tornado-vxworks-ftp-detect",
        product: "Tornado-VxWorks FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Tornado-vxWorks (VxWorks"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "totemomail-smtp-detect",
        product: "Totemomail SMTP Server",
        ports: &[25, 465, 587],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: None },
        ],
        read_size: 2048,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"totemomail"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "tp-print-ftp-detect",
        product: "TP Print FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"TP print service:V-"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "treck-ftp-detect",
        product: "Treck FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Treck FTP server ready"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "typsoft-ftp-detect",
        product: "TYPSoft FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"TYPSoft FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "unauth-java-message-broker-detect",
        product: "Unauthenticated Java Message Broker",
        ports: &[7676],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"101 imqbroker", b"cluster_discovery"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "vmware-authentication-daemon",
        product: "VMware Authentication Daemon",
        ports: &[902],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ServerDaemonProtocol:SOAP", b"MKSDisplayProtocol:VNC"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "vnc-service-detect",
        product: "VNC Service",
        ports: &[5900],
        probes: &[
            Probe { data: b"\x0d\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"RFB"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "vsftpd-detect",
        product: "vsFTPd Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"vsFTPd"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "vtun-server",
        product: "VTUN Server",
        ports: &[5001],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"VTUN server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "weblogic-t3-detect",
        product: "Weblogic T3 Protocol",
        ports: &[7001],
        probes: &[
            Probe { data: b"t3 12.2.1\x0aAS:255\x0aHL:19\x0aMS:10000000\x0aPU:t3://us-l-breens:7001\x0a\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"HELO"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "weblogic-t3-detect-2",
        product: "Weblogic T3 Protocol",
        ports: &[7002],
        probes: &[
            Probe { data: b"t3s 12.2.1\x0aAS:255\x0aHL:19\x0aMS:10000000\x0aPU:t3://us-l-breens:7001\x0a\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"HELO"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "windriver-ftp-detect",
        product: "Wind River FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Wind River FTP server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "wing-ftp-detect",
        product: "Wing FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Wing FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "ws_ftp-ssh-detect",
        product: "WS_FTP-SSH Service",
        ports: &[22],
        probes: &[],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"ws_ftp-ssh"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "x2-wsftp-detect",
        product: "X2 WS_FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"X2 WS_FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "xerver-ftp-detect",
        product: "Xerver Free FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Welcome to Xerver Free FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "xlight-ftp-detect",
        product: "Xlight FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Xlight FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "xlight-ftp-service-detect",
        product: "Xlight FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x0a", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Xlight FTP Server"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "zftp-detect",
        product: "Z-FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"Z-FTP"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    TcpTemplate {
        id: "zywall-ftp-detect",
        product: "ZyWALL FTP Service",
        ports: &[21],
        probes: &[
            Probe { data: b"\x00\x00\x00\x00", name: None, read: None },
        ],
        read_size: 1024,
        condition: Condition::Or,
        matchers: &[
            ByteMatcher { part: "body", patterns: &[b"FTP Server (ZyWALL"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
];

/// Curated `http/technologies` templates, sorted by id.
#[rustfmt::skip]
pub static HTTP_TEMPLATES: &[HttpTemplate] = &[
    HttpTemplate {
        id: "airtame-device-detect",
        product: "Airtame Device",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["To access the settings of your Airtame", "https://airtame.com/download"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "boa-web-server",
        product: "Boa Web Server",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["server: Boa/"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "cups-detect",
        product: "CUPS",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["Web Interface is Disabled - CUPS", "Forbidden - CUPS", "Server: CUPS"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200, 404, 403], negative: false },
        ],
    },
    HttpTemplate {
        id: "dreambox-detect",
        product: "DreamBox",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Status { codes: &[200], negative: false },
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Dreambox WebControl</title>"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "fiberhome-router-detect",
        product: "Fiberhome Router",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Status { codes: &[200], negative: false },
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>fiberhome</title>"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["/faviconfh.ico", "ais_fibre"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "hikvision-detect",
        product: "Hikvision Panel",
        paths: &["/favicon.ico", "/doc/page/login.asp"],
        condition: Condition::Or,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["Hikvision Digital Technology"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["Hikvision-Webs"], condition: Condition::Or, case_insensitive: false, negative: false, label: Some("server") },
        ],
    },
    HttpTemplate {
        id: "hp-media-vault-detect",
        product: "HP Media Vault",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>HP Media Vault"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "hue-wireless-lighting",
        product: "Hue Personal Wireless Lighting",
        paths: &["/"],
        condition: Condition::Or,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["hue personal wireless lighting", "Welcome to hue"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "ilo-detect",
        product: "HP iLO",
        paths: &["/xmldata?item=all"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Status { codes: &[200], negative: false },
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["text/xml"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<RIMP>", "<HSI>"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "ispyconnect-detect",
        product: "iSpyConnect",
        paths: &["/"],
        condition: Condition::Or,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["iSpy is running"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["server: iSpy"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "jellyfin-detect",
        product: "Jellyfin detected",
        paths: &["/home.html", "/web/home.html", "/index.html"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["name=\"application-name\" content=\"Jellyfin\"", "class=\"page homePage libraryPage allLibraryPage backdropPage pageWithAbsoluteTabs withTabs\"", "The Free Software Media System"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "lexmark-detect",
        product: "Lexmark Device",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Lexmark "], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "meteobridge-detect",
        product: "MeteoBridge",
        paths: &["/cgi-bin/meteobridge.cgi"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["Basic realm=\"MeteoBridge\""], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[401], negative: false },
        ],
    },
    HttpTemplate {
        id: "mikrotik-httpproxy",
        product: "MikroTik httpproxy",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["server: mikrotik httpproxy"], condition: Condition::Or, case_insensitive: true, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "miniupnpd-detect",
        product: "MiniUPnPd",
        paths: &["/"],
        condition: Condition::Or,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["MiniUPnPd"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "nextcloud-detect",
        product: "Nextcloud",
        paths: &["/", "/login", "/nextcloud/login"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["var nc_lastLogin", "var nc_pageLoad"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "node-red-detect",
        product: "Node-RED Dashboard",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Node-RED</title>"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "opnhap-detect",
        product: "OpenHAP",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["openHAB"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "pi-hole-panel",
        product: "Pi-hole Login Panel",
        paths: &["/", "/admin/index.php", "/admin/login.php"],
        condition: Condition::Or,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["Pi-hole", "Web Interface", "FTL"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Pi-hole", "Pi-hole: Your black hole for Internet advertisements", "Pi-hole: A black hole for Internet advertisements", "<pre>sudo pihole -a -p</pre>"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
        ],
    },
    HttpTemplate {
        id: "samsung-smarttv-debug",
        product: "Samsung SmartTV Debug Config",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Debug Config</title>", "MultiScreen Service"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "synology-web-station",
        product: "Synology Web Station Page",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>Hello! Welcome to Synology Web Station!</title>"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "vivotex-web-console-detect",
        product: "VIVOTEK Web Console",
        paths: &["/"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["<title>VIVOTEK Web Console</title>"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Words { part: HttpPart::Header, patterns: &["text/html"], condition: Condition::Or, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
    HttpTemplate {
        id: "xerox-workcentre-detect",
        product: "Xerox Workcentre",
        paths: &["/index.dhtml"],
        condition: Condition::And,
        matchers: &[
            HttpMatcher::Words { part: HttpPart::Body, patterns: &["XEROX WORKCENTRE", "/header.php?tab=status"], condition: Condition::And, case_insensitive: false, negative: false, label: None },
            HttpMatcher::Status { codes: &[200], negative: false },
        ],
    },
];

#[cfg(test)]
mod tests;
