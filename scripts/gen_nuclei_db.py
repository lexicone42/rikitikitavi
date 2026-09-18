#!/usr/bin/env python3
"""Generate `nuclei_db.rs` from projectdiscovery/nuclei-templates (MIT).

Two imports, both detection-only:

* `network/detection/**.yaml` — send-bytes/expect-words TCP templates, converted
  to a static table of probes and byte-substring matchers.
* a curated allowlist of `http/technologies/*.yaml` that identify home hardware,
  converted to GET paths plus body/header/status matchers.

Everything that exploits, authenticates or mutates is refused: templates whose
payload contains a credential or a mutating command, templates whose binary
opcodes change the peer's state (`STATEFUL_TEMPLATES`), templates with no
default port, templates needing a regex/DSL engine, and payloads over 128
bytes. Each refusal is counted and printed to stderr.

Usage:
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/projectdiscovery/nuclei-templates.git /tmp/nuclei-templates
    git -C /tmp/nuclei-templates sparse-checkout set network http/technologies
    uv run --with pyyaml python scripts/gen_nuclei_db.py --clone /tmp/nuclei-templates \
        > crates/rikitikitavi-scanners/src/nuclei_db.rs
    cargo fmt        # the emitted tables are `#[rustfmt::skip]`, the rest is not
"""

# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///

from __future__ import annotations

import argparse
import binascii
import collections
import os
import re
import subprocess
import sys

import yaml

REPO_URL = "https://github.com/projectdiscovery/nuclei-templates"

# nuclei's default TCP read size.
DEFAULT_READ_SIZE = 1024
# Anything longer is a protocol-specific connection blob, not a banner poke.
MAX_PAYLOAD_BYTES = 128

# A payload containing any of these is treated as authenticating or mutating and
# refused outright, whatever the template claims to do.
FORBIDDEN_PAYLOAD = (
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
)

# Payloads whose bytes carry no forbidden word but whose opcodes change the
# peer's state. Refused by id, because a binary opcode is not a substring.
STATEFUL_TEMPLATES = {
    # rtl_tcp command 0x01 sets the dongle's centre frequency and 0x02 its
    # sample rate: probing would retune someone's SDR receiver.
    "rtl-tcp-server-detect": "retunes the SDR (rtl_tcp 0x01/0x02)",
}

# http/technologies templates that identify hardware found on a home LAN.
HTTP_ALLOWLIST = [
    "airtame-device-detect.yaml",
    "boa-web-server.yaml",
    "casaos-detection.yaml",
    "cups-detect.yaml",
    "dreambox-detect.yaml",
    "fiberhome-router-detect.yaml",
    "hikvision-detect.yaml",
    "hp-media-vault-detect.yaml",
    "hue-wireless-lighting.yaml",
    "ilo-detect.yaml",
    "intel-amt-detect.yaml",
    "ispyconnect-detect.yaml",
    "jellyfin-detect.yaml",
    "lexmark-detect.yaml",
    "meteobridge-detect.yaml",
    "microfocus-iprint-detect.yaml",
    "mikrotik-httpproxy.yaml",
    "miniupnpd-detect.yaml",
    "nextcloud-detect.yaml",
    "node-red-detect.yaml",
    "openhap-detect.yaml",
    "pi-hole-detect.yaml",
    "samsung-smarttv-debug.yaml",
    "synology-web-station.yaml",
    "vivotex-web-console-detect.yaml",
    "xerox-workcentre-detect.yaml",
]

# Ports the HTTP pass runs against.
HTTP_PORTS = [80, 81, 443, 631, 8000, 8008, 8080, 8081, 8123, 8443, 8888]

REGEX_META = set(r".^$*+?()[]{}|\\")

# `reqwest` hands us lowercase header names, so a pattern that carries a
# capitalised one ("Server: Boa/") could never match. Lowercase the name part;
# the value keeps its case.
HEADER_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*):")

drops: collections.Counter = collections.Counter()
dropped_ids: dict[str, list[str]] = collections.defaultdict(list)

# Reasons that discard a whole template; everything else discards one matcher.
TEMPLATE_LEVEL = (
    "no-default-port",
    "payload-changes-peer-state",
    "no-usable-matcher",
    "payload-authenticates-or-mutates",
    "payload-too-large",
    "undecodable-payload",
    "http-multi-block",
    "http-not-get",
    "http-carries-body-or-headers",
    "http-path-templated",
    "http-no-path",
    "http-missing-upstream",
)


def drop(reason: str, template_id: str) -> None:
    drops[reason] += 1
    dropped_ids[reason].append(template_id)


def drop_counts() -> tuple[int, int]:
    """(templates refused, matchers refused)."""
    templates = sum(n for reason, n in drops.items() if reason in TEMPLATE_LEVEL)
    return templates, sum(drops.values()) - templates


# ── YAML loading ────────────────────────────────────────────────────────────


def load(path: str) -> dict:
    """Load with `BaseLoader` so `data: 00000000` stays the string it is.

    `BaseLoader` constructs only str/list/dict — no Python object tags.
    """
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=yaml.BaseLoader) or {}


def truthy(value) -> bool:
    return str(value).lower() == "true"


# ── payload decoding ────────────────────────────────────────────────────────

HEX_DECODE = re.compile(r"^\{\{hex_decode\('([0-9a-fA-F]+)'\)\}\}$")


def decode_payload(data: str, kind: str) -> bytes | None:
    """Decode one `inputs[].data` to the bytes actually put on the wire."""
    if kind == "hex":
        try:
            return binascii.unhexlify(data.strip().replace(" ", ""))
        except binascii.Error:
            return None
    m = HEX_DECODE.match(data.strip())
    if m:
        return binascii.unhexlify(m.group(1))
    if "{{" in data:
        return None  # any other templating needs a nuclei runtime
    return data.encode("utf-8", "surrogateescape")


def inert(payload: bytes) -> bool:
    lowered = payload.lower()
    return not any(bad in lowered for bad in FORBIDDEN_PAYLOAD)


# ── matcher conversion ──────────────────────────────────────────────────────


def literal_prefix(pattern: str) -> str:
    """Longest leading run of a regex that is plain text."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch in REGEX_META:
            break
        # A literal followed by a quantifier is not part of the fixed prefix.
        if i + 1 < len(pattern) and pattern[i + 1] in "*?{":
            break
        out.append(ch)
        i += 1
    return "".join(out)


# A whole-literal regex is usable at this length; a truncated prefix needs more,
# so that e.g. `(?i)SSH-2.0-ROSSSH` does not degrade to every SSH server.
MIN_LITERAL = 5
MIN_TRUNCATED_PREFIX = 7


def regex_to_words(patterns: list[str]) -> tuple[list[str], bool] | None:
    """Convert a regex matcher to a literal word matcher, or give up."""
    case_insensitive = False
    words = []
    for pattern in patterns:
        body = pattern
        if body.startswith("(?i)"):
            case_insensitive = True
            body = body[4:]
        body = body.removeprefix("^")
        literal = literal_prefix(body)
        floor = MIN_LITERAL if literal == body else MIN_TRUNCATED_PREFIX
        if len(literal) < floor:
            return None
        words.append(literal)
    return words, case_insensitive


def normalise_header_pattern(pattern: str) -> str:
    """Lowercase a leading `Name:` in a header-part pattern; see [`HEADER_NAME`]."""
    m = HEADER_NAME.match(pattern)
    return m.group(1).lower() + pattern[m.end(1) :] if m else pattern


def matcher_words(matcher: dict) -> list[bytes] | None:
    """Patterns of a word/binary matcher as raw bytes."""
    kind = matcher.get("type")
    if kind == "binary":
        out = []
        for word in matcher.get("binary", []):
            try:
                out.append(binascii.unhexlify(word.strip()))
            except binascii.Error:
                return None
        return out
    if kind != "word":
        return None
    encoding = matcher.get("encoding")
    out = []
    for word in matcher.get("words", []):
        if encoding == "hex":
            try:
                out.append(binascii.unhexlify(word.strip()))
            except binascii.Error:
                # Upstream has odd-length "hex" words; take the literal instead.
                out.append(word.encode())
        else:
            out.append(word.encode())
    return out


def convert_byte_matchers(block: dict, template_id: str) -> tuple[list[dict], str] | None:
    """Convert one TCP block's matchers. Returns (matchers, condition)."""
    condition = block.get("matchers-condition", "or").lower()
    out = []
    for matcher in block.get("matchers") or []:
        kind = matcher.get("type")
        # nuclei spells the whole TCP response "body", "raw" or "data".
        part = matcher.get("part", "body")
        if part in ("raw", "data", "all", "response"):
            part = "body"
        negative = truthy(matcher.get("negative"))
        case_insensitive = truthy(matcher.get("case-insensitive"))
        inner = matcher.get("condition", "or").lower()
        label = matcher.get("name")

        if negative and condition == "or":
            # A negative matcher under OR fires on almost anything; dropping it
            # can only make the template stricter.
            drop("negative-matcher-under-or", template_id)
            continue

        if kind == "regex":
            converted = regex_to_words(matcher.get("regex", []))
            if converted is None:
                if condition == "and":
                    return None
                drop("regex-not-literal", template_id)
                continue
            words, ci = converted
            patterns = [w.encode() for w in words]
            case_insensitive = case_insensitive or ci
        elif kind in ("word", "binary"):
            patterns = matcher_words(matcher)
            if patterns is None:
                return None
        else:  # dsl, status, size, ...
            if condition == "and":
                return None
            drop(f"unsupported-matcher-{kind}", template_id)
            continue

        patterns = [p for p in patterns if p]
        if not patterns:
            continue
        if case_insensitive:
            patterns = [p.lower() for p in patterns]
        out.append(
            {
                "part": part,
                "patterns": patterns,
                "condition": inner,
                "case_insensitive": case_insensitive,
                "negative": negative,
                "label": label,
            }
        )
    if not out:
        return None
    return out, condition


# ── template conversion ─────────────────────────────────────────────────────


def vendor_of(info: dict, product: str) -> str | None:
    """Upstream `metadata.vendor`, kept only when the template name corroborates it.

    Several `network/detection` templates carry copy-pasted metadata (redis-detect
    claims vendor `apache`), so an uncorroborated vendor is dropped.
    """
    vendor = (info.get("metadata") or {}).get("vendor")
    if not vendor:
        return None
    squash = lambda text: re.sub(r"[^a-z0-9]", "", text.lower())  # noqa: E731
    return vendor if squash(vendor) in squash(product) else None


def product_name(info: dict) -> str:
    name = (info.get("name") or "").strip()
    for suffix in (" - Detect", " - Detection", " - detect", " Detection", " Detect"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name.strip()


def parse_ports(raw) -> list[int]:
    if raw is None:
        return []
    ports = []
    for part in str(raw).split(","):
        part = part.strip()
        if part.isdigit() and 0 < int(part) <= 65535:
            ports.append(int(part))
    return sorted(set(ports))


def convert_tcp(path: str) -> list[dict]:
    doc = load(path)
    template_id = doc.get("id") or os.path.basename(path)
    info = doc.get("info") or {}
    blocks = doc.get("tcp") or doc.get("network") or []
    product = product_name(info)
    out = []
    for index, block in enumerate(blocks):
        block_id = template_id if index == 0 else f"{template_id}-{index + 1}"
        if template_id in STATEFUL_TEMPLATES:
            drop("payload-changes-peer-state", f"{block_id} ({STATEFUL_TEMPLATES[template_id]})")
            continue
        ports = parse_ports(block.get("port"))
        if not ports:
            drop("no-default-port", block_id)
            continue

        probes = []
        refused = False
        for item in block.get("inputs") or []:
            payload = decode_payload(item.get("data", ""), item.get("type", "text"))
            if payload is None:
                drop("undecodable-payload", block_id)
                refused = True
                break
            if not inert(payload):
                drop("payload-authenticates-or-mutates", block_id)
                refused = True
                break
            if len(payload) > MAX_PAYLOAD_BYTES:
                drop("payload-too-large", block_id)
                refused = True
                break
            read = item.get("read")
            probe = {
                "data": payload,
                "name": item.get("name"),
                "read": int(read) if read else None,
            }
            # Upstream repeats the same unnamed poke up to 8 times; once is enough.
            if probes and probe["name"] is None and probes[-1] == probe:
                continue
            probes.append(probe)
        if refused:
            continue

        converted = convert_byte_matchers(block, block_id)
        if converted is None:
            drop("no-usable-matcher", block_id)
            continue
        matchers, condition = converted

        read_size = int(block.get("read-size") or DEFAULT_READ_SIZE)
        out.append(
            {
                "id": block_id,
                "product": product,
                "vendor": vendor_of(info, product),
                "ports": ports,
                "probes": probes,
                "read_size": min(read_size, 8192),
                "condition": condition,
                "matchers": matchers,
            }
        )
    return out


def convert_http(path: str) -> dict | None:
    doc = load(path)
    template_id = doc.get("id") or os.path.basename(path)
    info = doc.get("info") or {}
    blocks = doc.get("http") or doc.get("requests") or []
    if len(blocks) != 1:
        drop("http-multi-block", template_id)
        return None
    block = blocks[0]
    if (block.get("method") or "GET").upper() != "GET":
        drop("http-not-get", template_id)
        return None
    if block.get("body") or block.get("headers"):
        drop("http-carries-body-or-headers", template_id)
        return None

    paths = []
    for raw in block.get("path") or []:
        raw = raw.strip()
        if not raw.startswith("{{BaseURL}}"):
            drop("http-path-templated", template_id)
            return None
        rest = raw[len("{{BaseURL}}") :]
        if "{{" in rest:
            drop("http-path-templated", template_id)
            return None
        paths.append(rest or "/")
    paths = list(dict.fromkeys(paths))[:3]
    if not paths:
        drop("http-no-path", template_id)
        return None

    condition = block.get("matchers-condition", "or").lower()
    matchers = []
    for matcher in block.get("matchers") or []:
        kind = matcher.get("type")
        negative = truthy(matcher.get("negative"))
        inner = matcher.get("condition", "or").lower()
        part = matcher.get("part", "body").lower()
        if part not in ("body", "header", "all", "response"):
            if condition == "and":
                return None
            drop(f"http-unsupported-part-{part}", template_id)
            continue
        if part in ("all", "response"):
            part = "all"

        if kind == "status":
            codes = [int(c) for c in matcher.get("status", []) if str(c).isdigit()]
            if not codes:
                continue
            matchers.append({"kind": "status", "codes": codes, "negative": negative})
            continue
        if kind == "regex":
            converted = regex_to_words(matcher.get("regex", []))
            if converted is None:
                if condition == "and":
                    return None
                drop("regex-not-literal", template_id)
                continue
            words, ci = converted
        elif kind == "word":
            words = matcher.get("words", [])
            ci = truthy(matcher.get("case-insensitive"))
        else:
            if condition == "and":
                return None
            drop(f"unsupported-matcher-{kind}", template_id)
            continue

        words = [w for w in words if w]
        if not words:
            continue
        if part == "header":
            words = [normalise_header_pattern(w) for w in words]
        if ci:
            words = [w.lower() for w in words]
        matchers.append(
            {
                "kind": "words",
                "part": part,
                "patterns": words,
                "condition": inner,
                "case_insensitive": ci,
                "negative": negative,
                "label": matcher.get("name"),
            }
        )

    if not any(m["kind"] == "words" for m in matchers):
        drop("no-usable-matcher", template_id)
        return None

    product = product_name(info)
    return {
        "id": template_id,
        "product": product,
        "vendor": vendor_of(info, product),
        "paths": paths,
        "condition": condition,
        "matchers": matchers,
    }


# ── Rust emission ───────────────────────────────────────────────────────────


def rust_bytes(payload: bytes) -> str:
    out = []
    for byte in payload:
        ch = chr(byte)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\x{byte:02x}")
    return 'b"' + "".join(out) + '"'


def rust_str(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def rust_opt_str(text) -> str:
    return f"Some({rust_str(text)})" if text else "None"


def cond(name: str) -> str:
    return "Condition::And" if name == "and" else "Condition::Or"


def emit_tcp(template: dict, out) -> None:
    out.write("    TcpTemplate {\n")
    out.write(f"        id: {rust_str(template['id'])},\n")
    out.write(f"        product: {rust_str(template['product'])},\n")
    out.write(f"        vendor: {rust_opt_str(template['vendor'])},\n")
    ports = ", ".join(str(p) for p in template["ports"])
    out.write(f"        ports: &[{ports}],\n")
    if template["probes"]:
        out.write("        probes: &[\n")
        for probe in template["probes"]:
            read = f"Some({probe['read']})" if probe["read"] else "None"
            out.write(
                f"            Probe {{ data: {rust_bytes(probe['data'])}, "
                f"name: {rust_opt_str(probe['name'])}, read: {read} }},\n"
            )
        out.write("        ],\n")
    else:
        out.write("        probes: &[],\n")
    out.write(f"        read_size: {template['read_size']},\n")
    out.write(f"        condition: {cond(template['condition'])},\n")
    out.write("        matchers: &[\n")
    for matcher in template["matchers"]:
        patterns = ", ".join(rust_bytes(p) for p in matcher["patterns"])
        out.write(
            f"            ByteMatcher {{ part: {rust_str(matcher['part'])}, "
            f"patterns: &[{patterns}], condition: {cond(matcher['condition'])}, "
            f"case_insensitive: {str(matcher['case_insensitive']).lower()}, "
            f"negative: {str(matcher['negative']).lower()}, "
            f"label: {rust_opt_str(matcher['label'])} }},\n"
        )
    out.write("        ],\n")
    out.write("    },\n")


def emit_http(template: dict, out) -> None:
    out.write("    HttpTemplate {\n")
    out.write(f"        id: {rust_str(template['id'])},\n")
    out.write(f"        product: {rust_str(template['product'])},\n")
    out.write(f"        vendor: {rust_opt_str(template['vendor'])},\n")
    paths = ", ".join(rust_str(p) for p in template["paths"])
    out.write(f"        paths: &[{paths}],\n")
    out.write(f"        condition: {cond(template['condition'])},\n")
    out.write("        matchers: &[\n")
    for matcher in template["matchers"]:
        if matcher["kind"] == "status":
            codes = ", ".join(str(c) for c in matcher["codes"])
            out.write(
                f"            HttpMatcher::Status {{ codes: &[{codes}], "
                f"negative: {str(matcher['negative']).lower()} }},\n"
            )
            continue
        patterns = ", ".join(rust_str(p) for p in matcher["patterns"])
        part = {"body": "HttpPart::Body", "header": "HttpPart::Header", "all": "HttpPart::All"}[
            matcher["part"]
        ]
        out.write(
            f"            HttpMatcher::Words {{ part: {part}, "
            f"patterns: &[{patterns}], condition: {cond(matcher['condition'])}, "
            f"case_insensitive: {str(matcher['case_insensitive']).lower()}, "
            f"negative: {str(matcher['negative']).lower()}, "
            f"label: {rust_opt_str(matcher['label'])} }},\n"
        )
    out.write("        ],\n")
    out.write("    },\n")


HEADER = '''//! nuclei-templates detection matchers — auto-generated.
//!
//! Source: <{repo}> (MIT), commit {commit} ({date})
//! Imported: {tcp_count} `network/detection` TCP templates, {http_count} curated
//! `http/technologies` templates. {dropped_templates} upstream templates and
//! {dropped_matchers} individual matchers were refused; `scripts/gen_nuclei_db.py`
//! prints the reason for each.
//!
//! Detection only: every probe payload is inert (no credentials, no mutating
//! command, at most {max_payload} bytes) and every HTTP path is an unauthenticated GET.
//! The inertness check is an ASCII-substring rule; the non-ASCII handshake blobs
//! were read by hand at import and `nuclei_db/tests.rs` pins that reviewed set.
//! Regenerate with
//! `uv run --with pyyaml python scripts/gen_nuclei_db.py --clone <path>`,
//! then `cargo fmt`.

/// How a list of patterns, or a list of matchers, combines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {{
    /// Every element must match.
    And,
    /// Any element may match.
    Or,
}}

/// One inert payload written to the socket before reading.
#[derive(Debug, Clone, Copy)]
pub struct Probe {{
    /// Bytes written verbatim.
    pub data: &'static [u8],
    /// Name of the response part this probe's read is stored under.
    pub name: Option<&'static str>,
    /// Bytes to read after writing, when the template caps it.
    pub read: Option<usize>,
}}

/// Byte-substring matcher over one part of a TCP response.
#[derive(Debug, Clone, Copy)]
pub struct ByteMatcher {{
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
}}

/// A `network/detection` template: probe, then match what came back.
#[derive(Debug, Clone, Copy)]
pub struct TcpTemplate {{
    /// Upstream template id.
    pub id: &'static str,
    /// Product this identifies.
    pub product: &'static str,
    /// Vendor, when upstream metadata names one.
    pub vendor: Option<&'static str>,
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
}}

/// Part of an HTTP response a matcher reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPart {{
    /// Response body.
    Body,
    /// Response headers, one `Name: value` line each.
    Header,
    /// Status line, headers and body.
    All,
}}

/// Matcher over an HTTP response.
#[derive(Debug, Clone, Copy)]
pub enum HttpMatcher {{
    /// Substring match over `part`.
    Words {{
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
    }},
    /// Status-code match.
    Status {{
        /// Accepted status codes.
        codes: &'static [u16],
        /// Match means "not one of these codes".
        negative: bool,
    }},
}}

/// A curated `http/technologies` template: GET each path, then match.
#[derive(Debug, Clone, Copy)]
pub struct HttpTemplate {{
    /// Upstream template id.
    pub id: &'static str,
    /// Product this identifies.
    pub product: &'static str,
    /// Vendor, when upstream metadata names one.
    pub vendor: Option<&'static str>,
    /// Paths to GET, relative to the base URL.
    pub paths: &'static [&'static str],
    /// How `matchers` combine.
    pub condition: Condition,
    /// Matchers over the response.
    pub matchers: &'static [HttpMatcher],
}}

/// Upstream commit this snapshot was generated from.
pub const NUCLEI_TEMPLATES_COMMIT: &str = "{commit}";

/// Longest probe payload, in bytes. Tests hold the table to it.
pub const MAX_PROBE_BYTES: usize = {max_payload};

/// Look up a TCP template by upstream id. O(log n).
#[must_use]
pub fn tcp_template(id: &str) -> Option<&'static TcpTemplate> {{
    TCP_TEMPLATES
        .binary_search_by(|t| t.id.cmp(id))
        .ok()
        .map(|i| &TCP_TEMPLATES[i])
}}

/// Look up an HTTP template by upstream id. O(log n).
#[must_use]
pub fn http_template(id: &str) -> Option<&'static HttpTemplate> {{
    HTTP_TEMPLATES
        .binary_search_by(|t| t.id.cmp(id))
        .ok()
        .map(|i| &HTTP_TEMPLATES[i])
}}

/// TCP templates declaring `port`.
pub fn tcp_templates_for_port(port: u16) -> impl Iterator<Item = &'static TcpTemplate> {{
    TCP_TEMPLATES.iter().filter(move |t| t.ports.contains(&port))
}}

/// Whether the HTTP pass has anything to say about `port`.
#[must_use]
pub fn is_http_port(port: u16) -> bool {{
    HTTP_PORTS.contains(&port)
}}

/// Ports the HTTP pass runs against.
#[rustfmt::skip]
pub static HTTP_PORTS: &[u16] = &[{http_ports}];

/// Every port either table can act on, sorted.
#[rustfmt::skip]
pub static NUCLEI_PORTS: &[u16] = &[{all_ports}];

'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clone", required=True, help="path to a nuclei-templates checkout")
    args = parser.parse_args()
    root = os.path.abspath(args.clone)

    commit = subprocess.run(
        ["git", "-C", root, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    date = subprocess.run(
        ["git", "-C", root, "log", "-1", "--format=%cs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    tcp: list[dict] = []
    detection = os.path.join(root, "network", "detection")
    total_tcp_files = 0
    for dirpath, dirnames, filenames in os.walk(detection):
        dirnames.sort()  # deterministic drop report
        for filename in sorted(filenames):
            if not filename.endswith((".yaml", ".yml")):
                continue
            total_tcp_files += 1
            tcp.extend(convert_tcp(os.path.join(dirpath, filename)))
    tcp.sort(key=lambda t: t["id"])

    http: list[dict] = []
    for filename in HTTP_ALLOWLIST:
        path = os.path.join(root, "http", "technologies", filename)
        if not os.path.exists(path):
            drop("http-missing-upstream", filename)
            continue
        converted = convert_http(path)
        if converted:
            http.append(converted)
    http.sort(key=lambda t: t["id"])

    all_ports = sorted({p for t in tcp for p in t["ports"]} | set(HTTP_PORTS))

    dropped_templates, dropped_matchers = drop_counts()

    out = sys.stdout
    out.write(
        HEADER.format(
            repo=REPO_URL,
            commit=commit,
            date=date,
            tcp_count=len(tcp),
            http_count=len(http),
            dropped_templates=dropped_templates,
            dropped_matchers=dropped_matchers,
            max_payload=MAX_PAYLOAD_BYTES,
            http_ports=", ".join(str(p) for p in HTTP_PORTS),
            all_ports=", ".join(str(p) for p in all_ports),
        )
    )

    out.write("/// `network/detection` templates, sorted by id.\n#[rustfmt::skip]\n")
    out.write("pub static TCP_TEMPLATES: &[TcpTemplate] = &[\n")
    for template in tcp:
        emit_tcp(template, out)
    out.write("];\n\n")

    out.write("/// Curated `http/technologies` templates, sorted by id.\n#[rustfmt::skip]\n")
    out.write("pub static HTTP_TEMPLATES: &[HttpTemplate] = &[\n")
    for template in http:
        emit_http(template, out)
    out.write("];\n\n#[cfg(test)]\nmod tests;\n")

    print(
        f"{total_tcp_files} network/detection files -> {len(tcp)} templates; "
        f"{len(http)} http/technologies templates",
        file=sys.stderr,
    )
    for reason, count in sorted(drops.items()):
        print(f"  dropped {count:3d}  {reason}: {', '.join(dropped_ids[reason])}", file=sys.stderr)


if __name__ == "__main__":
    main()
