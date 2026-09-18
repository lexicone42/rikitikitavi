#!/usr/bin/env python3
"""Generate `recog_db.rs` from rapid7/recog (BSD-2-Clause).

Recog is a corpus of banner regexes with named capture parameters. This script
imports only the fingerprint files whose match key is something this workspace
already reads off the wire, and only the parameters something here consumes.

Selection
---------
`KEYS` lists the imported files and names the call site that feeds each one. A
file with no consumer is not imported; `NO_CONSUMER` records the ones that were
considered and rejected so the decision is not re-made by hand.

`KEPT_FIELDS` is the parameter allowlist. CPE strings, `*.certainty`,
`system.time*`, `openssh.comment` and the other bookkeeping parameters are
dropped: nothing joins them, and they are the bulk of the table. A fingerprint
left with no kept parameter is dropped entirely, which is what removes
`html_title`'s generic error pages.

Regex dialect
-------------
Recog patterns are Ruby regexes, compiled by callers with POSIX-ish flags. The
mapping to the Rust `regex` crate:

* `REG_ICASE`         -> `(?i)`
* `REG_DOT_NEWLINE`   -> `(?s)`
* `REG_MULTILINE`     -> `(?s)`, because Recog's Ruby reference maps it to
  Ruby's MULTILINE, which means dot-matches-newline, not Rust's `(?m)`.
* every pattern also gets `(?m)`, because Ruby `^`/`$` are always line anchors
  while Rust's default to haystack anchors.

Patterns using lookaround or backreferences cannot compile with the `regex`
crate; none exist at the imported HEAD, but the check stays and counts them.

Usage
-----
    git clone --depth 1 https://github.com/rapid7/recog /tmp/recog
    uv run --with defusedxml python scripts/gen_recog_db.py --clone /tmp/recog \\
        > crates/rikitikitavi-scanners/src/recog_db.rs
    cargo fmt   # the tables are `#[rustfmt::skip]`; the rest is not
"""

# /// script
# requires-python = ">=3.11"
# dependencies = ["defusedxml"]
# ///

from __future__ import annotations

import argparse
import base64
import collections
import re
import subprocess
import sys
from pathlib import Path

from defusedxml import ElementTree as ET

REPO_URL = "https://github.com/rapid7/recog"

# Imported fingerprint files: stem -> (Rust enum variant, static name, Recog
# match key, the call site that supplies the string).
KEYS = [
    ("ssh_banners", "SshBanner", "SSH_BANNER", "ssh.banner",
     "`services.rs`: the software-and-comment part of an RFC 4253 identification string"),
    ("telnet_banners", "TelnetBanner", "TELNET_BANNER", "telnet.banner",
     "`services.rs`: the TCP/23 banner"),
    ("ftp_banners", "FtpBanner", "FTP_BANNER", "ftp.banner",
     "`services.rs`: the TCP/21 greeting"),
    ("smtp_banners", "SmtpBanner", "SMTP_BANNER", "smtp.banner",
     "`services.rs`: the TCP/25 greeting"),
    ("imap_banners", "ImapBanner", "IMAP_BANNER", "imap4.banner",
     "`services.rs`: the TCP/143 greeting"),
    ("pop_banners", "PopBanner", "POP_BANNER", "pop3.banner",
     "`services.rs`: the TCP/110 greeting"),
    ("http_servers", "HttpServer", "HTTP_SERVER", "http_header.server",
     "services.rs and `http_audit.rs`: the `Server` response header"),
    ("http_wwwauth", "HttpWwwAuth", "HTTP_WWWAUTH", "http_header.wwwauth",
     "`http_audit.rs`: the `WWW-Authenticate` response header"),
    ("html_title", "HtmlTitle", "HTML_TITLE", "html_title",
     "`http_audit.rs`: the `<title>` of an unauthenticated GET"),
    ("snmp_sysdescr", "SnmpSysDescr", "SNMP_SYSDESCR", "snmp.sys_description",
     "`snmp.rs`: `sysDescr.0` from a v2c `GetRequest`"),
    ("x509_subjects", "X509Subject", "X509_SUBJECT", "x509.subject",
     "`ssl.rs`: the certificate subject, rendered as a Go-style RDN string"),
    ("x509_issuers", "X509Issuer", "X509_ISSUER", "x509.issuer",
     "`ssl.rs`: the certificate issuer, rendered as a Go-style RDN string"),
    ("hp_pjl_id", "HpPjlId", "HP_PJL_ID", "hp.pjl.id",
     "`printers.rs`: the `@PJL INFO ID` response from TCP/9100"),
]

# Considered and not imported, with the reason. Revisit a line only together
# with the probe that would feed it.
NO_CONSUMER = {
    "smb_native_os": "smb.rs negotiates and does an anonymous SMB2 session setup; "
                     "Native OS is an SMB1 session-setup field we never read",
    "smb_native_lm": "same as smb_native_os",
    "mdns_device-info_txt": "mdns.rs is not in this change's file set",
    "mdns_workstation_txt": "one fingerprint, and mdns.rs is not in this change's file set",
    "dns_versionbind": "no version.bind CH TXT query exists",
    "ntp_banners": "no NTP probe exists",
    "rtsp_servers": "rtsp.rs is not in this change's file set",
    "dhcp_vendor_class": "no DHCP option-60 source exists",
    "favicons": "matches an MD5 of the favicon; nothing fetches or hashes one",
    "mysql_banners": "database.rs is not in this change's file set",
    "mysql_error": "database.rs is not in this change's file set",
    "http_cookies": "no cookie is retained from the unauthenticated probes",
    "http_xpoweredby": "one fingerprint; http_audit.rs already has an X-Powered-By EOL check",
    "apache_modules": "matches the module list inside a Server header we do not split out",
    "apache_os": "same input as http_servers, which is imported",
    "operating_system": "a cross-file OS roll-up, not a wire string",
    "architecture": "a cross-file roll-up, not a wire string",
    "ldap_searchresult": "no LDAP probe exists",
    "sip_banners": "no SIP probe exists",
    "sip_user_agents": "no SIP probe exists",
    "h323_callresp": "no H.323 probe exists",
    "x11_banners": "no X11 probe exists",
    "nntp_banners": "no NNTP probe exists",
    "rsh_resp": "no rsh probe exists",
    "tls_jarm": "JARM hashing is not implemented",
    "snmp_sysobjid": "extract_sys_descr reads sysDescr.0 only",
    "smtp_ehlo": "services.rs sends EHLO but keeps the greeting, not the capability list",
    "smtp_debug": "the SMTP probe sends no DEBUG/VRFY/EXPN/HELP verbs",
    "smtp_expn": "see smtp_debug",
    "smtp_help": "see smtp_debug",
    "smtp_mailfrom": "see smtp_debug",
    "smtp_noop": "see smtp_debug",
    "smtp_quit": "see smtp_debug",
    "smtp_rcptto": "see smtp_debug",
    "smtp_rset": "see smtp_debug",
    "smtp_turn": "see smtp_debug",
    "smtp_vrfy": "see smtp_debug",
    "http_header.x-fortisandbox-version": "enterprise appliance header, one fingerprint",
}

# Parameter allowlist: Recog name -> (Rust variant, doc line).
KEPT_FIELDS = [
    ("service.vendor", "ServiceVendor", "Vendor of the listening software."),
    ("service.product", "ServiceProduct", "Name of the listening software."),
    ("service.version", "ServiceVersion", "Version of the listening software."),
    ("service.family", "ServiceFamily", "Product family of the listening software."),
    ("os.vendor", "OsVendor", "Vendor of the operating system or firmware."),
    ("os.product", "OsProduct", "Operating system or firmware name."),
    ("os.version", "OsVersion", "Operating system or firmware version."),
    ("os.family", "OsFamily", "Operating system family."),
    ("os.device", "OsDevice", "Upstream device-class vocabulary, e.g. `Printer`, `WAP`."),
    ("os.arch", "OsArch", "CPU architecture."),
    ("hw.vendor", "HwVendor", "Hardware vendor."),
    ("hw.product", "HwProduct", "Hardware model."),
    ("hw.model", "HwModel", "Hardware model number, where upstream separates it from `hw.product`."),
    ("hw.family", "HwFamily", "Hardware product family."),
    ("hw.device", "HwDevice", "Hardware device class, same vocabulary as `os.device`."),
    ("host.name", "HostName", "Hostname the service disclosed."),
]
FIELD_VARIANT = dict((n, v) for n, v, _ in KEPT_FIELDS)

# Ruby/POSIX flags to inline Rust regex flags. See the module docstring.
FLAG_MAP = {"REG_ICASE": "i", "REG_DOT_NEWLINE": "s", "REG_MULTILINE": "s"}

LOOKAROUND = re.compile(r"\(\?<?[=!]")
BACKREF = re.compile(r"\\[1-9]")
TEMPLATE = re.compile(r"\{([a-z0-9_.]+)\}")


def rust_str(s: str) -> str:
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + "".join(c if (c.isprintable() or c in " ") else f"\\u{{{ord(c):x}}}" for c in out) + '"'


def translate(pattern: str, flags: str) -> str:
    """Prefix the Rust inline flags Recog's Ruby semantics imply."""
    letters = "m"
    for flag in (flags or "").split(","):
        mapped = FLAG_MAP.get(flag.strip())
        if mapped and mapped not in letters:
            letters += mapped
    return f"(?{letters}){pattern}"


def example_text(node) -> str | None:
    raw = node.text or ""
    if node.get("_encoding") == "base64":
        try:
            return base64.b64decode(raw).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clone", required=True, type=Path, help="path to a rapid7/recog checkout")
    args = ap.parse_args()

    xml_dir = args.clone / "xml"
    if not xml_dir.is_dir():
        print(f"no xml/ under {args.clone}", file=sys.stderr)
        return 1
    commit = subprocess.run(
        ["git", "-C", str(args.clone), "log", "-1", "--format=%H %cs"],
        capture_output=True, text=True, check=True).stdout.strip()

    seen = {p.stem for p in xml_dir.glob("*.xml")} - {"fingerprints"}
    imported = {stem for stem, *_ in KEYS}
    unclassified = seen - imported - set(NO_CONSUMER)
    if unclassified:
        print(f"unclassified fingerprint files upstream: {sorted(unclassified)}", file=sys.stderr)
        return 1

    tables: list[tuple[str, str, str, str, list]] = []
    examples: list[tuple[str, int, str, list[tuple[str, str]]]] = []
    dropped_no_param = 0
    dropped_regex = collections.Counter()
    dropped_params = collections.Counter()
    dropped_examples = 0

    for stem, variant, static_name, match_key, consumer in KEYS:
        root = ET.parse(str(xml_dir / f"{stem}.xml")).getroot()
        rows = []
        for fp in root.findall("fingerprint"):
            pattern = fp.get("pattern")
            if LOOKAROUND.search(pattern):
                dropped_regex["lookaround"] += 1
                continue
            if BACKREF.search(pattern):
                dropped_regex["backreference"] += 1
                continue
            params = []
            for par in fp.findall("param"):
                name = par.get("name")
                if name not in FIELD_VARIANT:
                    dropped_params[name] += 1
                    continue
                params.append((FIELD_VARIANT[name], int(par.get("pos")), par.get("value") or ""))
            # A value may interpolate another parameter; drop it when the
            # reference did not survive the allowlist, and repeat, because
            # dropping one parameter can orphan another.
            while True:
                kept_names = {name for name, _, _ in params}
                survivors = [p for p in params
                             if all(FIELD_VARIANT.get(ref) in kept_names
                                    for ref in TEMPLATE.findall(p[2]))]
                if len(survivors) == len(params):
                    break
                params = survivors
            if not params:
                dropped_no_param += 1
                continue
            index = len(rows)
            rows.append((pattern, translate(pattern, fp.get("flags")),
                         (fp.find("description").text or "").strip() if fp.find("description") is not None else "",
                         params))
            for ex in fp.findall("example"):
                text = example_text(ex)
                if text is None:
                    dropped_examples += 1
                    continue
                expect = [(FIELD_VARIANT[a], v) for a, v in sorted(ex.attrib.items())
                          if a in FIELD_VARIANT]
                examples.append((variant, index, text, expect))
        tables.append((variant, static_name, match_key, consumer, rows))

    total = sum(len(rows) for *_, rows in tables)
    out: list[str] = []
    w = out.append

    w("//! Rapid7 Recog banner fingerprints — auto-generated.")
    w("//!")
    w(f"//! Source: <{REPO_URL}> commit {commit}")
    w("//! Licence: BSD-2-Clause, \"Copyright (c) 2014-2015, Rapid7\". The copyright")
    w("//! notice, the conditions and the disclaimer it requires are reproduced verbatim")
    w("//! in THIRD-PARTY-NOTICES.md at the repository root.")
    w("//!")
    w(f"//! Imported: {total} fingerprints across {len(tables)} match keys, "
      f"{len(examples)} upstream examples (test-only).")
    w("//!")
    w("//! Only fingerprint files whose input this workspace already reads off the wire")
    w("//! are imported, and only the parameters something here consumes; a fingerprint")
    w(f"//! left with no consumed parameter is dropped ({dropped_no_param} of them, mostly")
    w("//! `html_title`'s generic error pages). `scripts/gen_recog_db.py` names every")
    w("//! upstream file it refused and why.")
    w("//!")
    w("//! Row order is upstream file order and is load-bearing: Recog resolves a string")
    w("//! against the first pattern that matches, so the table must not be sorted.")
    w("//!")
    w("//! Regenerate with")
    w("//! `uv run --with defusedxml python scripts/gen_recog_db.py --clone <path>`,")
    w("//! then `cargo fmt`.")
    w("")
    w("/// A fingerprint parameter this workspace consumes.")
    w("///")
    w("/// Recog defines many more; the rest are dropped at import.")
    w("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]")
    w("pub enum RecogField {")
    for name, variant, doc in KEPT_FIELDS:
        w(f"    /// {doc} Recog `{name}`.")
        w(f"    {variant},")
    w("}")
    w("")
    w("impl RecogField {")
    w("    /// The Recog parameter name, e.g. `service.product`.")
    w("    #[must_use]")
    w("    pub const fn as_str(self) -> &'static str {")
    w("        match self {")
    for name, variant, _ in KEPT_FIELDS:
        w(f"            Self::{variant} => {rust_str(name)},")
    w("        }")
    w("    }")
    w("")
    w("    /// Every variant, in declaration order.")
    w(f"    pub const ALL: [Self; {len(KEPT_FIELDS)}] = [")
    for _, variant, _ in KEPT_FIELDS:
        w(f"        Self::{variant},")
    w("    ];")
    w("}")
    w("")
    w("/// One parameter of one fingerprint.")
    w("#[derive(Debug, Clone, Copy)]")
    w("pub struct RecogParam {")
    w("    /// Field this parameter sets.")
    w("    pub field: RecogField,")
    w("    /// Capture group to read, or 0 when [`Self::value`] is literal.")
    w("    pub pos: u8,")
    w("    /// Literal value when `pos == 0`; may interpolate `{field.name}`.")
    w("    pub value: &'static str,")
    w("}")
    w("")
    w("/// One Recog fingerprint: a pattern and what a match asserts.")
    w("#[derive(Debug, Clone, Copy)]")
    w("pub struct RecogFingerprint {")
    w("    /// Rust-dialect pattern, inline flags already applied.")
    w("    pub pattern: &'static str,")
    w("    /// Upstream description.")
    w("    pub description: &'static str,")
    w("    /// Parameters a match yields.")
    w("    pub params: &'static [RecogParam],")
    w("}")
    w("")
    w("/// A match key: one kind of string, one fingerprint table.")
    w("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]")
    w("pub enum RecogKey {")
    for variant, _static, match_key, consumer, _rows in tables:
        w(f"    /// Recog `{match_key}` — {consumer}.")
        w(f"    {variant},")
    w("}")
    w("")
    w("impl RecogKey {")
    w("    /// Every variant, in declaration order.")
    w(f"    pub const ALL: [Self; {len(tables)}] = [")
    for variant, *_ in tables:
        w(f"        Self::{variant},")
    w("    ];")
    w("")
    w("    /// The Recog match key, e.g. `ssh.banner`.")
    w("    #[must_use]")
    w("    pub const fn as_str(self) -> &'static str {")
    w("        match self {")
    for variant, _static, match_key, *_ in tables:
        w(f"            Self::{variant} => {rust_str(match_key)},")
    w("        }")
    w("    }")
    w("")
    w("    /// Position of this variant in [`Self::ALL`].")
    w("    #[must_use]")
    w("    pub const fn index(self) -> usize {")
    w("        match self {")
    for i, (variant, *_) in enumerate(tables):
        w(f"            Self::{variant} => {i},")
    w("        }")
    w("    }")
    w("")
    w("    /// Fingerprints for this key, in upstream order.")
    w("    #[must_use]")
    w("    pub const fn fingerprints(self) -> &'static [RecogFingerprint] {")
    w("        match self {")
    for variant, static_name, *_ in tables:
        w(f"            Self::{variant} => {static_name},")
    w("        }")
    w("    }")
    w("}")

    for variant, static_name, match_key, consumer, rows in tables:
        w("")
        w(f"/// Recog `{match_key}` ({len(rows)} fingerprints) — {consumer}.")
        w("#[rustfmt::skip]")
        w(f"pub static {static_name}: &[RecogFingerprint] = &[")
        for _orig, pattern, description, params in rows:
            plist = ", ".join(
                f"RecogParam {{ field: RecogField::{v}, pos: {pos}, value: {rust_str(val)} }}"
                for v, pos, val in params)
            w(f"    RecogFingerprint {{ pattern: {rust_str(pattern)}, "
              f"description: {rust_str(description)}, params: &[{plist}] }},")
        w("];")

    w("")
    w("/// An upstream `<example>`: an input and the parameters it must yield.")
    w("#[cfg(test)]")
    w("#[derive(Debug, Clone, Copy)]")
    w("pub struct RecogExample {")
    w("    /// Match key the example belongs to.")
    w("    pub key: RecogKey,")
    w("    /// Index into that key's table — the fingerprint that must claim it.")
    w("    pub index: usize,")
    w("    /// The example string.")
    w("    pub input: &'static str,")
    w("    /// Capture-derived values upstream asserts, for consumed fields only.")
    w("    pub expected: &'static [(RecogField, &'static str)],")
    w("}")
    w("")
    w(f"/// Every upstream example for an imported fingerprint ({len(examples)}).")
    w("#[cfg(test)]")
    w("#[rustfmt::skip]")
    w("pub static EXAMPLES: &[RecogExample] = &[")
    for variant, index, text, expect in examples:
        elist = ", ".join(f"(RecogField::{v}, {rust_str(val)})" for v, val in expect)
        w(f"    RecogExample {{ key: RecogKey::{variant}, index: {index}, "
          f"input: {rust_str(text)}, expected: &[{elist}] }},")
    w("];")
    w("")
    w("#[cfg(test)]")
    w("mod tests;")
    w("")

    body = "\n".join(out)
    sys.stdout.write(body)

    print(f"recog {commit}", file=sys.stderr)
    for variant, _s, _k, _c, rows in tables:
        print(f"  {variant}: {len(rows)} fingerprints", file=sys.stderr)
    print(f"  total {total} fingerprints, {len(examples)} examples", file=sys.stderr)
    print(f"  dropped: {dropped_no_param} fingerprints with no consumed parameter, "
          f"{dropped_examples} non-UTF-8 examples", file=sys.stderr)
    print(f"  dropped regex features: {dict(dropped_regex) or 'none'}", file=sys.stderr)
    print(f"  dropped parameters: {sum(dropped_params.values())} "
          f"({', '.join(f'{k}={v}' for k, v in dropped_params.most_common(8))})", file=sys.stderr)
    print(f"  emitted {len(body)} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
