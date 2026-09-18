#!/usr/bin/env python3
"""Generate `vulnrichment_db.rs` from the CISA Vulnrichment repository.

CISA Vulnrichment publishes SSVC decision points (Exploitation, Automatable,
Technical Impact) and CWE assignments per CVE, in the `CISA-ADP` container of
each CVE-5 record. The `poc` Exploitation tier is the part KEV and EPSS cannot
express: public exploit code exists, exploitation in the wild has not been
observed.

Licence: CC0-1.0 (public domain dedication). Default branch: `develop`, not
`main`. Record paths are `<year>/<seq//1000>xxx/CVE-<year>-<seq>.json`.

Data source
-----------
Clone the repository (~1.6 GB checked out; needed only for the repo-wide
`poc`/`active` sweep)::

    git clone --depth 1 --branch develop --single-branch \\
        https://github.com/cisagov/vulnrichment.git /tmp/vulnrichment

Without a clone, `--download` fetches just the records for the CVEs this
workspace references, one HTTPS request each.

Usage
-----
    # committed snapshot: clone sweep
    uv run python scripts/gen_vulnrichment_db.py --clone /tmp/vulnrichment \\
        > crates/rikitikitavi-analysis/src/vulnrichment_db.rs

    # no clone, workspace CVEs only
    uv run python scripts/gen_vulnrichment_db.py --download \\
        > crates/rikitikitavi-analysis/src/vulnrichment_db.rs

    # offline: does the committed table still match the selection rule?
    uv run python scripts/gen_vulnrichment_db.py \\
        --check crates/rikitikitavi-analysis/src/vulnrichment_db.rs

Row selection: every CVE this workspace references that CISA has enriched.
References are harvested from production crate source only — the generated
tables, `tests.rs` files, `#[cfg(test)]` items and comments are stripped by a
lexer that knows string, raw-string and char literals, so a fixture id cannot
select a row — plus the explicit allowlist in
`scripts/vulnrichment_extra_cves.txt` for ids the tests spot-check. Records with
neither an SSVC block nor a CISA-ADP CWE are dropped.

`--sweep-tiers` additionally embeds every `poc`/`active` record repo-wide. That
is 42,295 `poc` + 1,714 `active` as of 2026-09-17 — ~4.5 MB of Rust source, and
unreachable: findings only ever carry CVE ids this workspace hardcodes. It
exists for the day scanners learn CVEs at runtime.

Stdlib only; no third-party imports.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_URL = "https://github.com/cisagov/vulnrichment"
RAW_BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
CFG_TEST_RE = re.compile(r"#\[cfg\(test\)\]")
RAW_STR_RE = re.compile(r'b?r(#*)"')
SSVC_ROW_RE = re.compile(r'Ssvc \{ cve: "(CVE-[0-9]{4}-[0-9]{4,7})"')
# Generated tables: their CVE ids are data, not references this workspace makes.
# `tests.rs`: fixture ids, not references either.
SKIP_SOURCES = {"kev_db.rs", "vulnrichment_db.rs", "tests.rs"}
# Ids to embed regardless of what the sources reference; one per line, `#` comments.
EXTRA_CVES = Path(__file__).resolve().parent / "vulnrichment_extra_cves.txt"

EXPLOITATION = {"none": "None", "poc": "Poc", "active": "Active"}
AUTOMATABLE = {"no": "No", "yes": "Yes"}
IMPACT = {"partial": "Partial", "total": "Total"}


def char_literal_end(text: str, i: int) -> int | None:
    """End index of the char literal starting at `i`, or None for a lifetime."""
    n = len(text)
    if i + 1 >= n:
        return None
    if text[i + 1] == "\\":
        j = i + 2
        if j >= n:
            return None
        if text[j] == "u":
            j = text.find("}", j)
            if j < 0:
                return None
            j += 1
        elif text[j] == "x":
            j += 3
        else:
            j += 1
        return j + 1 if j < n and text[j] == "'" else None
    # `'a` is a lifetime or a loop label, not a literal.
    return i + 3 if i + 2 < n and text[i + 2] == "'" else None


def mask_source(text: str) -> tuple[str, str]:
    """`(no_comments, code_only)`, both the length of `text`.

    `no_comments` blanks comments. `code_only` blanks comments and the text of string,
    raw-string and char literals, so a brace or a quote inside one is not read as code.
    """
    no_comments = list(text)
    code_only = list(text)
    n = len(text)
    i = 0

    def blank(start: int, stop: int, comment: bool) -> None:
        for k in range(start, min(stop, n)):
            fill = "\n" if text[k] == "\n" else " "
            code_only[k] = fill
            if comment:
                no_comments[k] = fill

    while i < n:
        char = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end, comment=True)
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j, comment=True)
            i = j
        elif char == "'" and (end := char_literal_end(text, i)):
            blank(i, end, comment=False)
            i = end
        elif char in "br" and (match := raw_string_at(text, i)):
            hashes = match.group(1)
            close = text.find('"' + hashes, match.end())
            end = n if close < 0 else close + 1 + len(hashes)
            blank(i, end, comment=False)
            i = end
        elif char == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                elif text[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            blank(i, j, comment=False)
            i = j
        else:
            i += 1
    return "".join(no_comments), "".join(code_only)


def raw_string_at(text: str, i: int) -> re.Match | None:
    """Raw-string prefix (`r"`, `r#"`, `br#"`) starting at `i`, if it starts a token."""
    if i and (text[i - 1].isalnum() or text[i - 1] == "_"):
        return None
    return RAW_STR_RE.match(text, i)


def cfg_test_spans(code_only: str) -> list[tuple[int, int]]:
    """Half-open spans of every `#[cfg(test)]` item, by brace matching over code."""
    spans: list[tuple[int, int]] = []
    n = len(code_only)
    i = 0
    while match := CFG_TEST_RE.search(code_only, i):
        brace = code_only.find("{", match.end())
        semi = code_only.find(";", match.end())
        if brace < 0 or 0 <= semi < brace:
            # `#[cfg(test)] mod tests;` — the file itself is skipped by name.
            i = semi + 1 if semi >= 0 else match.end()
            continue
        depth, j = 0, brace
        while j < n:
            if code_only[j] == "{":
                depth += 1
            elif code_only[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        spans.append((match.start(), min(j + 1, n)))
        i = j + 1
    return spans


def production_source(text: str) -> str:
    """Rust source with comments and `#[cfg(test)]` items removed."""
    no_comments, code_only = mask_source(text)
    out: list[str] = []
    prev = 0
    for start, end in cfg_test_spans(code_only):
        out.append(no_comments[prev:start])
        prev = end
    out.append(no_comments[prev:])
    return "".join(out)


def extra_cves(path: Path = EXTRA_CVES) -> set[str]:
    """Allowlisted ids: embedded whether or not production source references them."""
    if not path.exists():
        return set()
    found: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().upper()
        if line:
            if not CVE_RE.fullmatch(line):
                raise SystemExit(f"{path}: not a CVE id: {line}")
            found.add(line)
    return found


def workspace_cves(crates: Path) -> set[str]:
    """CVE ids referenced by production crate source, plus the allowlist.

    Generated tables, `tests.rs` files, `#[cfg(test)]` items and comments are
    excluded: a fixture id must never select a row.
    """
    found: set[str] = set()
    for path in crates.rglob("*.rs"):
        if path.name in SKIP_SOURCES or "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        found.update(CVE_RE.findall(production_source(source)))
    return {c.upper() for c in found} | extra_cves()


def cisa_adp(record: dict) -> list[dict]:
    containers = record.get("containers") or {}
    return [
        c
        for c in (containers.get("adp") or [])
        if (c.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"
    ]


def parse_record(record: dict) -> tuple | None:
    """`(cve, exploitation, automatable, technical_impact, cwe)`, or None if unenriched.

    Only the CISA-ADP container is read; the CNA container is not CISA's work.
    """
    cve = ((record.get("cveMetadata") or {}).get("cveId") or "").strip().upper()
    if not CVE_RE.fullmatch(cve):
        return None

    exploitation = automatable = impact = cwe = None
    for container in cisa_adp(record):
        for metric in container.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            for option in (other.get("content") or {}).get("options") or []:
                for raw_key, raw_value in option.items():
                    key = str(raw_key).strip().lower()
                    value = str(raw_value).strip().lower()
                    if key == "exploitation":
                        exploitation = EXPLOITATION.get(value, exploitation)
                    elif key == "automatable":
                        automatable = AUTOMATABLE.get(value, automatable)
                    elif key == "technical impact":
                        impact = IMPACT.get(value, impact)
        for problem in container.get("problemTypes") or []:
            for desc in problem.get("descriptions") or []:
                candidate = (desc.get("cweId") or "").strip().upper()
                if cwe is None and re.fullmatch(r"CWE-[0-9]{1,6}", candidate):
                    cwe = candidate

    if exploitation is None and cwe is None:
        return None
    return (cve, exploitation or "None", automatable, impact, cwe)


def load_json(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def record_path(root: Path, cve: str) -> Path:
    """`<root>/<year>/<seq//1000>xxx/<cve>.json`."""
    _, year, seq = cve.split("-")
    return root / year / f"{int(seq) // 1000}xxx" / f"{cve}.json"


def read_wanted(clone: Path, wanted: set[str]) -> dict[str, tuple]:
    """Records for the workspace CVE set, read straight from their paths."""
    rows: dict[str, tuple] = {}
    for cve in sorted(wanted):
        record = load_json(record_path(clone, cve))
        parsed = parse_record(record) if record else None
        if parsed:
            rows[parsed[0]] = parsed
    return rows


def sweep_tiers(clone: Path) -> dict[str, tuple]:
    """Every `poc`/`active` record in the clone. Adds ~44k rows; see `--sweep-tiers`."""
    rows: dict[str, tuple] = {}
    scanned = 0
    for year_dir in sorted(clone.iterdir()):
        if not (year_dir.is_dir() and re.fullmatch(r"[0-9]{4}", year_dir.name)):
            continue
        for path in year_dir.rglob("CVE-*.json"):
            record = load_json(path)
            scanned += 1
            if record is None:
                continue
            parsed = parse_record(record)
            if parsed and parsed[1] in ("Poc", "Active"):
                rows[parsed[0]] = parsed
    print(f"swept {scanned:,} records in {clone}", file=sys.stderr)
    return rows


def fetch_record(cve: str) -> dict | None:
    """Fetch one record over HTTPS; absent records are the common case."""
    _, year, seq = cve.split("-")
    url = f"{RAW_BASE}/{year}/{int(seq) // 1000}xxx/{cve}.json"
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return json.load(resp)
    except Exception:  # noqa: BLE001
        return None


def clone_commit(clone: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def rust_option(value: str | None, kind: str) -> str:
    return "None" if value is None else f"Some({kind}::{value})"


def emit(rows: list[tuple], meta: dict, out) -> None:
    tiers = {t: sum(1 for r in rows if r[1] == t) for t in ("Active", "Poc", "None")}
    header = f'''//! CISA Vulnrichment SSVC decision points — auto-generated.
//!
//! Source: <{REPO_URL}> (branch `develop`, commit {meta["commit"]})
//! Licence: CC0-1.0 Universal (public domain dedication)
//! Snapshot: {meta["date"]} | Entries: {len(rows):,} (active {tiers["Active"]}, poc {tiers["Poc"]}, none {tiers["None"]})
//! Mode: {meta["mode"]}
//!
//! Regenerate with `uv run python scripts/gen_vulnrichment_db.py --clone <path>`;
//! `--check <this file>` re-runs the row selection offline.
//!
//! The `poc` tier — public exploit code, no observed exploitation — is the part KEV
//! and EPSS cannot express. `active` overlaps KEV almost exactly.

/// SSVC Exploitation: evidence that a vulnerability is being exploited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exploitation {{
    /// No public exploit code and no observed exploitation.
    None,
    /// Public proof-of-concept exploit code exists; no observed exploitation.
    Poc,
    /// Exploitation observed in the wild.
    Active,
}}

/// SSVC Automatable: whether reconnaissance through exploitation can be automated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Automatable {{
    /// Reliable automation of the first four kill-chain steps is not available.
    No,
    /// An attacker can automate the chain — the wormability signal.
    Yes,
}}

/// SSVC Technical Impact: control gained over the vulnerable component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TechnicalImpact {{
    /// Limited control, or information disclosure only.
    Partial,
    /// Total control of the vulnerable component.
    Total,
}}

/// One CISA Vulnrichment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssvc {{
    /// Normalised CVE id, e.g. `CVE-2024-6387`.
    pub cve: &'static str,
    /// Exploitation tier.
    pub exploitation: Exploitation,
    /// Automatable decision point; absent when the record carries no SSVC block.
    pub automatable: Option<Automatable>,
    /// Technical Impact decision point; absent when the record carries no SSVC block.
    pub technical_impact: Option<TechnicalImpact>,
    /// CISA-ADP CWE assignment; backfills findings that carry none.
    pub cwe: Option<&'static str>,
}}

/// The Vulnrichment snapshot date this table was generated from.
pub const VULNRICHMENT_SNAPSHOT: &str = "{meta["date"]}";

/// Vulnrichment record for `cve` (e.g. "CVE-2024-6387"), if CISA enriched it.
///
/// Case-insensitive; O(log n) binary search over the sorted table.
#[must_use]
pub fn lookup_ssvc(cve: &str) -> Option<&'static Ssvc> {{
    let needle = cve.trim().to_ascii_uppercase();
    SSVC_ENTRIES
        .binary_search_by(|entry| entry.cve.cmp(needle.as_str()))
        .ok()
        .map(|i| &SSVC_ENTRIES[i])
}}

/// Records sorted by CVE id.
#[rustfmt::skip]
static SSVC_ENTRIES: &[Ssvc] = &[
'''
    out.write(header)

    for cve, exploitation, automatable, impact, cwe in rows:
        cwe_lit = "None" if cwe is None else f'Some("{cwe}")'
        out.write(
            f'    Ssvc {{ cve: "{cve}", exploitation: Exploitation::{exploitation}, '
            f"automatable: {rust_option(automatable, 'Automatable')}, "
            f"technical_impact: {rust_option(impact, 'TechnicalImpact')}, "
            f"cwe: {cwe_lit} }},\n"
        )

    out.write("];\n\n#[cfg(test)]\nmod tests;\n")


def check_table(path: Path, wanted: set[str]) -> int:
    """Exit code: 1 if the table holds a row the current selection rule would not pick.

    Offline; checks which ids are embedded, not the SSVC values behind them.
    """
    table = set(SSVC_ROW_RE.findall(path.read_text(encoding="utf-8")))
    stale = sorted(table - wanted)
    print(
        f"{path}: {len(table)} rows; {len(stale)} not selected by the current rule: "
        f"{', '.join(stale) if stale else 'none'}",
        file=sys.stderr,
    )
    return 1 if stale else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate vulnrichment_db.rs")
    parser.add_argument(
        "--clone",
        type=Path,
        help=f"path to a clone of {REPO_URL} (branch develop); enables the poc/active sweep",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="fetch the workspace-referenced CVEs over HTTPS instead of from a clone",
    )
    parser.add_argument(
        "--sweep-tiers",
        action="store_true",
        help="also embed every poc/active record repo-wide (~44k rows, ~4.5 MB of Rust; "
        "needs --clone). Off by default: findings only ever carry CVEs this workspace "
        "hardcodes, so the extra rows are unreachable.",
    )
    parser.add_argument(
        "--crates",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "crates",
        help="workspace crate sources to harvest CVE references from",
    )
    parser.add_argument(
        "--check",
        type=Path,
        metavar="VULNRICHMENT_DB_RS",
        help="offline: report rows the current selection rule would no longer select, "
        "then exit non-zero if there are any",
    )
    args = parser.parse_args()

    if args.check:
        raise SystemExit(check_table(args.check, workspace_cves(args.crates)))
    if not args.clone and not args.download:
        parser.error("pass --clone <path> or --download")
    if args.sweep_tiers and not args.clone:
        parser.error("--sweep-tiers needs --clone")

    wanted = workspace_cves(args.crates)
    print(f"workspace references {len(wanted)} CVE ids", file=sys.stderr)

    selection = f"production CVE references + `{EXTRA_CVES.name}`"
    if args.clone:
        rows = read_wanted(args.clone, wanted)
        flags = "--clone"
        if args.sweep_tiers:
            rows = sweep_tiers(args.clone) | rows
            selection += " + repo-wide poc/active sweep"
            flags += " --sweep-tiers"
        meta = {"commit": clone_commit(args.clone), "mode": f"{selection} ({flags})"}
    else:
        rows = {}
        for cve in sorted(wanted):
            record = fetch_record(cve)
            parsed = parse_record(record) if record else None
            if parsed:
                rows[parsed[0]] = parsed
        meta = {"commit": "n/a (HTTPS fetch)", "mode": f"{selection} (--download)"}

    missing = sorted(wanted - rows.keys())
    print(
        f"{len(rows):,} rows; {len(missing)} workspace CVEs unenriched: "
        f"{', '.join(missing) if missing else 'none'}",
        file=sys.stderr,
    )

    meta["date"] = os.environ.get("SOURCE_DATE") or dt.date.today().isoformat()
    # Bytewise sort, matching `str::cmp` in the Rust binary search.
    ordered = sorted(rows.values(), key=lambda row: row[0].encode())
    emit(ordered, meta, sys.stdout)


if __name__ == "__main__":
    main()
