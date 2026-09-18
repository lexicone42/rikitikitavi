use super::*;
use proptest::prelude::*;

/// Substrings that would make a payload authenticate or mutate. The generator
/// refuses such templates; this holds the committed table to the same rule.
const FORBIDDEN: &[&[u8]] = &[
    b"user",
    b"pass",
    b"login",
    b"auth",
    b"scram",
    b"credential",
    b"mstshash",
    b"secret",
    b"token",
    b"set ",
    b"del",
    b"write",
    b"reset",
    b"reboot",
    b"create",
    b"drop ",
    b"insert",
    b"update",
    b"exec",
    b"shutdown",
];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Table shape ─────────────────────────────────────────────────────────

#[test]
fn tcp_table_is_strictly_sorted_by_id() {
    assert!(TCP_TEMPLATES.windows(2).all(|w| w[0].id < w[1].id));
}

#[test]
fn http_table_is_strictly_sorted_by_id() {
    assert!(HTTP_TEMPLATES.windows(2).all(|w| w[0].id < w[1].id));
}

#[test]
fn every_tcp_row_looks_up_by_id() {
    for template in TCP_TEMPLATES {
        let found = tcp_template(template.id).expect(template.id);
        assert_eq!(found.id, template.id);
        assert_eq!(found.product, template.product);
    }
}

#[test]
fn every_http_row_looks_up_by_id() {
    for template in HTTP_TEMPLATES {
        let found = http_template(template.id).expect(template.id);
        assert_eq!(found.id, template.id);
        assert_eq!(found.paths, template.paths);
    }
}

#[test]
fn ids_are_lowercase_slugs() {
    let ids = TCP_TEMPLATES
        .iter()
        .map(|t| t.id)
        .chain(HTTP_TEMPLATES.iter().map(|t| t.id));
    for id in ids {
        assert!(!id.is_empty());
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b)),
            "{id} is not a slug"
        );
    }
}

#[test]
fn every_template_names_a_product() {
    for template in TCP_TEMPLATES {
        assert!(!template.product.is_empty(), "{}", template.id);
    }
    for template in HTTP_TEMPLATES {
        assert!(!template.product.is_empty(), "{}", template.id);
    }
}

// ── Probe safety ────────────────────────────────────────────────────────

/// FNV-1a, so the reviewed-payload digest below does not depend on the
/// standard library's hasher staying put.
fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn is_binary(payload: &[u8]) -> bool {
    payload
        .iter()
        .any(|b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
}

/// Distinct payloads carrying non-ASCII bytes, sorted.
fn binary_payloads() -> Vec<&'static [u8]> {
    let mut out: Vec<&'static [u8]> = TCP_TEMPLATES
        .iter()
        .flat_map(|t| t.probes)
        .map(|p| p.data)
        .filter(|p| is_binary(p))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// [`every_probe_payload_is_inert`] is a substring rule, so it says nothing
/// about a binary blob. The distinct ones were read by hand at import, and are
/// all reads or handshakes: the S7 COTP connect and SZL read, Modbus and UMAS
/// read-device-id, `EtherNet/IP` `ListIdentity`, ONC RPC portmap DUMP and NFS
/// NULL, DSI `GetStatus`, JDWP `VirtualMachine.Version`, Riak server-info, the
/// AMQP and Radmin protocol headers, a STOMP `HELP`, Mongo's `admin.$cmd`
/// query, a `RouterOS` API command the peer answers "not logged in", a BGP
/// OPEN, and the NUL/CRLF pokes that make a banner arrive. This pins that
/// reviewed set: a regeneration that adds or changes one fails here and has to
/// be read again.
#[test]
fn binary_payloads_are_the_reviewed_set() {
    let payloads = binary_payloads();
    let mut joined = Vec::new();
    for payload in &payloads {
        joined.extend_from_slice(payload);
        joined.push(0xff);
    }
    assert_eq!(payloads.len(), 21, "the set of binary payloads changed");
    assert_eq!(
        fnv1a(&joined),
        0xa77f_9d8c_fbe2_99f4,
        "a binary payload changed; read it before updating this digest"
    );
}

#[test]
fn every_probe_payload_is_inert() {
    for template in TCP_TEMPLATES {
        for probe in template.probes {
            let lowered: Vec<u8> = probe.data.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(
                    !contains(&lowered, bad),
                    "{} sends {:?}",
                    template.id,
                    String::from_utf8_lossy(bad)
                );
            }
        }
    }
}

#[test]
fn probe_payloads_are_bounded() {
    for template in TCP_TEMPLATES {
        for probe in template.probes {
            assert!(
                !probe.data.is_empty() && probe.data.len() <= MAX_PROBE_BYTES,
                "{} payload is {} bytes",
                template.id,
                probe.data.len()
            );
        }
        assert!(template.probes.len() <= 8, "{}", template.id);
        assert!(
            template.read_size > 0 && template.read_size <= 8192,
            "{}",
            template.id
        );
    }
}

#[test]
fn http_paths_are_relative_gets() {
    for template in HTTP_TEMPLATES {
        assert!(!template.paths.is_empty(), "{}", template.id);
        for path in template.paths {
            assert!(path.starts_with('/'), "{} path {path}", template.id);
            assert!(!path.contains("{{"), "{} path {path}", template.id);
        }
    }
}

// ── Matcher invariants ──────────────────────────────────────────────────

#[test]
fn tcp_matchers_are_usable() {
    for template in TCP_TEMPLATES {
        assert!(!template.matchers.is_empty(), "{}", template.id);
        let named: Vec<&str> = template.probes.iter().filter_map(|p| p.name).collect();
        for matcher in template.matchers {
            assert!(!matcher.patterns.is_empty(), "{}", template.id);
            for pattern in matcher.patterns {
                assert!(!pattern.is_empty(), "{}", template.id);
                if matcher.case_insensitive {
                    assert_eq!(
                        *pattern,
                        pattern.to_ascii_lowercase().as_slice(),
                        "{} pattern is not pre-lowercased",
                        template.id
                    );
                }
            }
            assert!(
                matcher.part == "body" || named.contains(&matcher.part),
                "{} matches part {} that no probe names",
                template.id,
                matcher.part
            );
            assert!(
                matcher.label.is_none_or(|l| !l.is_empty()),
                "{}",
                template.id
            );
        }
    }
}

#[test]
fn http_matchers_are_usable() {
    for template in HTTP_TEMPLATES {
        let mut has_words = false;
        for matcher in template.matchers {
            match matcher {
                HttpMatcher::Words {
                    patterns,
                    case_insensitive,
                    ..
                } => {
                    has_words = true;
                    assert!(!patterns.is_empty(), "{}", template.id);
                    for pattern in *patterns {
                        assert!(!pattern.is_empty(), "{}", template.id);
                        if *case_insensitive {
                            assert_eq!(*pattern, pattern.to_lowercase(), "{}", template.id);
                        }
                    }
                }
                HttpMatcher::Status { codes, .. } => {
                    assert!(!codes.is_empty(), "{}", template.id);
                    assert!(
                        codes.iter().all(|c| (100..600).contains(c)),
                        "{}",
                        template.id
                    );
                }
            }
        }
        assert!(has_words, "{} has no word matcher", template.id);
    }
}

// ── Port index ──────────────────────────────────────────────────────────

#[test]
fn port_tables_are_sorted_and_deduplicated() {
    assert!(NUCLEI_PORTS.windows(2).all(|w| w[0] < w[1]));
    assert!(HTTP_PORTS.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn nuclei_ports_is_the_union_of_both_tables() {
    let mut expected: Vec<u16> = TCP_TEMPLATES
        .iter()
        .flat_map(|t| t.ports.iter().copied())
        .chain(HTTP_PORTS.iter().copied())
        .collect();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(NUCLEI_PORTS, expected.as_slice());
}

#[test]
fn every_template_port_selects_that_template() {
    for template in TCP_TEMPLATES {
        assert!(!template.ports.is_empty(), "{}", template.id);
        for &port in template.ports {
            assert!(
                tcp_templates_for_port(port).any(|t| t.id == template.id),
                "{} is not selected on port {port}",
                template.id
            );
        }
    }
}

#[test]
fn http_port_predicate_agrees_with_the_table() {
    for &port in HTTP_PORTS {
        assert!(is_http_port(port));
    }
    assert!(!is_http_port(9999));
}

// ── Properties ──────────────────────────────────────────────────────────

fn arb_id() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[a-z0-9-]{0,24}",
        (0..TCP_TEMPLATES.len()).prop_map(|i| TCP_TEMPLATES[i].id.to_owned()),
        (0..HTTP_TEMPLATES.len()).prop_map(|i| HTTP_TEMPLATES[i].id.to_owned()),
    ]
}

proptest! {
    /// Binary search agrees with a linear scan and never panics.
    #[test]
    fn prop_tcp_lookup_agrees_with_linear_scan(id in arb_id()) {
        let linear = TCP_TEMPLATES.iter().find(|t| t.id == id).map(|t| t.id);
        prop_assert_eq!(tcp_template(&id).map(|t| t.id), linear);
    }

    #[test]
    fn prop_http_lookup_agrees_with_linear_scan(id in arb_id()) {
        let linear = HTTP_TEMPLATES.iter().find(|t| t.id == id).map(|t| t.id);
        prop_assert_eq!(http_template(&id).map(|t| t.id), linear);
    }

    /// Selection by port is exactly "declares that port", for any port.
    #[test]
    fn prop_port_selection_is_total(port in any::<u16>()) {
        let selected: Vec<&str> = tcp_templates_for_port(port).map(|t| t.id).collect();
        let expected: Vec<&str> = TCP_TEMPLATES
            .iter()
            .filter(|t| t.ports.contains(&port))
            .map(|t| t.id)
            .collect();
        let empty = expected.is_empty();
        prop_assert_eq!(selected, expected);
        if !empty {
            prop_assert!(NUCLEI_PORTS.contains(&port));
        }
    }
}
