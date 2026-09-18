#!/usr/bin/env python3
"""Generate `eol_db.rs` from the endoflife.date v1 API.

endoflife.date tracks support and end-of-life dates per product release cycle.
The table this emits replaces hand-coded "current stable is X" claims in
`services.rs` — which had already gone stale — with dated facts.

Licence: MIT (https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE,
"Copyright 2020 endoflife.date contributors"). Data is fetched from the API, not
vendored from the repository.

Product selection
-----------------
`PRODUCTS` is deliberately small: a product is embedded only when this workspace
already recovers a version string for it from an unauthenticated probe. `ABSENT`
records products that were checked against the API and are not tracked there, so
the check is not repeated by hand.

Schema
------
Pinned to `schema_version` 1.2.1; the build fails loudly on drift because the v1
API is self-declared Beta. Cycle names are heterogeneous across products
(`2.4`, `13`, `11-26h1-e`), so only dotted-numeric cycles are embedded and
lookup does longest-dotted-prefix matching per product; Windows-shaped cycles
are dropped with a warning. `isEol: true` with `eolFrom: null` is common and is
kept as a flag with no date rather than crashing date arithmetic.

Conditional refresh uses `ETag`/`If-None-Match`; there is no `Last-Modified` and
`If-Modified-Since` returns 200.

Two support dates
-----------------
`eolFrom` and `eoasFrom` mean different things per product and the product's own
`labels` say which; both are embedded and the caller decides. For Debian
`labels.eol` is "Debian LTS" and `labels.eoas` is "Debian Security Support", so
`eoasFrom` is the day Debian's own security team stops and only LTS remains —
a real change in patch coverage. For Ubuntu `labels.eoas` is "Hardware &
Maintenance", the last point release, which says nothing about patching: 22.04
passed it on 2024-09-30 and is security-supported until 2027-06-01. So a caller
must read `labels` semantics per product rather than treating `eoasFrom`
uniformly. `labels` itself is not embedded; the meanings are recorded here and
locked by eol_db/tests.rs.

Usage
-----
    uv run python scripts/gen_eol_db.py \\
        > crates/rikitikitavi-scanners/src/eol_db.rs

    # with an on-disk ETag cache (skips unchanged products)
    uv run python scripts/gen_eol_db.py --cache-dir /tmp/eol-cache \\
        > crates/rikitikitavi-scanners/src/eol_db.rs

    # pin the snapshot date so output is byte-reproducible across days
    SOURCE_DATE=2026-09-17 uv run python scripts/gen_eol_db.py \\
        > crates/rikitikitavi-scanners/src/eol_db.rs

Stdlib only; no third-party imports.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://endoflife.date/api/v1/products"
SCHEMA_VERSION = "1.2.1"
CYCLE_RE = re.compile(r"[0-9]+(\.[0-9]+)*")

# Embedded products. A product is embedded only when a call site in this
# workspace actually joins its version against the table; the comment names that
# call site. "A probe recovers the version" is not sufficient — an unjoined row
# is dead weight in an MIT-attributed table.
PRODUCTS = [
    "nginx",  # services.rs check_header_components, `Server` token
    "apache-http-server",  # services.rs check_header_components
    "eclipse-jetty",  # services.rs check_header_components, `Jetty/12.0.x`
    "openssl",  # services.rs check_header_components, `... OpenSSL/1.0.2k`
    "python",  # services.rs check_header_components, `Python/3.9.2`
    "php",  # http_audit.rs check_powered_by_eol, `X-Powered-By: PHP/8.1.2`
    "debian",  # services.rs check_os_eol, SSH banner `+debNuM` suffix
    "ubuntu",  # services.rs check_os_eol, via the bundled OpenSSH version
]

# Tracked upstream and probed by this workspace, but NOT embedded: nothing joins
# them. `mysql`/`mariadb` versions arrive in the MySQL greeting packet and
# `redis` in the `INFO` reply, both parsed in scanners/src/database.rs, which
# carries its own hand-coded EOL checks and never calls `eol_db`. Add them back
# here in the same commit that routes database.rs through `eol_summary`.
UNJOINED = ["mysql", "mariadb", "redis"]

# Checked against the API and not tracked there, so no table row can exist.
# Re-check before adding a hand-coded EOL claim for any of these.
ABSENT = [
    "openssh",
    "lighttpd",
    "iis",
    "openresty",
    "webmin",
    "samba",
    "cups",
    "dropbear",
    "busybox",
    "synology-dsm",
    "qnap",
    "unifi",
    "pfsense",
    "plex",
    "home-assistant",
    "roku",
]


def fetch(url: str, etag: str | None = None) -> tuple[dict | None, str | None]:
    """`(payload, etag)`; payload is None when the server answers 304."""
    request = urllib.request.Request(url)
    if etag:
        request.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(request, timeout=60) as resp:
            return json.load(resp), resp.headers.get("ETag")
    except urllib.error.HTTPError as err:
        if err.code == 304:
            return None, etag
        raise


def load_product(name: str, cache: Path | None) -> dict:
    """Product record, using an ETag cache when one is configured."""
    body = cache / f"{name}.json" if cache else None
    tag = cache / f"{name}.etag" if cache else None
    etag = tag.read_text().strip() if tag and tag.exists() else None

    payload, new_etag = fetch(f"{API}/{name}", etag if body and body.exists() else None)
    if payload is None:
        return json.loads(body.read_text())

    if cache:
        cache.mkdir(parents=True, exist_ok=True)
        body.write_text(json.dumps(payload))
        if new_etag:
            tag.write_text(new_etag)
    return payload


def check_schema(payload: dict, what: str) -> None:
    got = payload.get("schema_version")
    if got != SCHEMA_VERSION:
        sys.exit(
            f"endoflife.date schema drift on {what}: expected {SCHEMA_VERSION}, got {got}. "
            "Re-read the v1 API docs before regenerating."
        )


def rows_for(product: dict) -> tuple[list[tuple], tuple | None, int]:
    """`(cycle rows, current row, skipped)` for one product record.

    The API lists releases newest-first. "Supported" here means not EOL and
    still maintained. The current row names the newest supported cycle that
    upstream marks `isLts`, falling back to the newest supported cycle when the
    product marks none — newest alone would point an OpenSSL user at 4.0 rather
    than the 3.5 LTS. Its last element records whether other supported cycles
    exist, so the remediation sentence can decline to recommend a track (nginx
    keeps mainline and stable supported at once, and neither is marked LTS).
    """
    name = product["name"]
    rows: list[tuple] = []
    supported: list[tuple] = []
    skipped = 0

    for release in product.get("releases") or []:
        cycle = str(release.get("name") or "").strip()
        if not CYCLE_RE.fullmatch(cycle):
            skipped += 1
            continue
        latest = (release.get("latest") or {}).get("name")
        is_eol = bool(release.get("isEol"))
        rows.append(
            (
                name,
                cycle,
                release.get("codename"),
                release.get("eolFrom"),
                release.get("eoasFrom"),
                is_eol,
                latest,
            )
        )
        if not is_eol and release.get("isMaintained"):
            supported.append((cycle, latest, bool(release.get("isLts"))))

    current = None
    if supported:
        pick = next((s for s in supported if s[2]), supported[0])
        current = (name, pick[0], pick[1], pick[2], len(supported) > 1)

    return rows, current, skipped


def rust_str(value: str | None) -> str:
    if value is None:
        return "None"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'Some("{escaped}")'


HEADER = '''//! Software end-of-life table from endoflife.date — auto-generated.
//!
//! Source: <https://endoflife.date/api/v1/products/> (schema {schema}, snapshot {date})
//! Licence: MIT — <https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE>.
//! The copyright and permission notices it requires are reproduced verbatim in
//! THIRD-PARTY-NOTICES.md at the repository root.
//! Products: {products} | Cycles: {cycles} | Table: {bytes} bytes of source
//!
//! Regenerate with `uv run python scripts/gen_eol_db.py`.
//!
//! Cycle names are heterogeneous across products (`2.4`, `13`, `1.30`), so
//! lookup matches the longest dotted-numeric prefix of an observed version
//! against the cycles of one product. `is_eol` with no `eol_from` date means
//! upstream declared the cycle dead without dating it.
//!
//! Not tracked upstream (checked {date}, no rows can exist): {absent}.
//!
//! Tracked upstream but deliberately not embedded, because nothing joins them:
//! {unjoined}. Their versions are parsed in `database.rs`, which keeps its own
//! EOL checks; embed them in the same commit that routes it through `eol_db`.

/// One release cycle of one product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EolCycle {{
    /// endoflife.date product name, e.g. `apache-http-server`.
    pub product: &'static str,
    /// Cycle name as upstream spells it, e.g. `2.4`.
    pub cycle: &'static str,
    /// Release codename where the product has one, e.g. `Bookworm`.
    pub codename: Option<&'static str>,
    /// Date support ended, `YYYY-MM-DD`; absent when upstream dated nothing.
    ///
    /// Upstream's `eolFrom`, whose meaning is per-product: Debian LTS end for
    /// `debian`, Maintenance & Security end for `ubuntu`, security support end
    /// for `nginx` and `php`.
    pub eol_from: Option<&'static str>,
    /// Date *active* support ended, `YYYY-MM-DD`; upstream's `eoasFrom`.
    ///
    /// Per-product, and NOT a security date everywhere. For `debian` it is the
    /// day Debian's own security team stops and only the community LTS project
    /// continues. For `ubuntu` it is the last point release ("Hardware &
    /// Maintenance") and says nothing about patching — 22.04 passed it in 2024
    /// and is security-supported to 2027. Check the product before keying a
    /// finding on it.
    pub eoas_from: Option<&'static str>,
    /// Upstream's end-of-life flag at snapshot time.
    pub is_eol: bool,
    /// Last release of this cycle, e.g. `1.18.0`.
    pub latest: Option<&'static str>,
}}

/// A supported cycle of a product at snapshot time — not necessarily the newest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentCycle {{
    /// endoflife.date product name.
    pub product: &'static str,
    /// Cycle name, e.g. `1.30`. The newest supported LTS cycle where upstream
    /// marks one, else the newest supported cycle.
    pub cycle: &'static str,
    /// Latest release of that cycle, e.g. `1.30.5`.
    pub latest: Option<&'static str>,
    /// Upstream marks this cycle long-term support.
    pub is_lts: bool,
    /// Upstream still supports other cycles too, so this one is not advice.
    pub other_supported: bool,
}}

/// Date the table was generated from the API, `YYYY-MM-DD`.
pub const EOL_SNAPSHOT: &str = "{date}";

/// endoflife.date API schema version this table was generated against.
pub const EOL_SCHEMA_VERSION: &str = "{schema}";

/// Cycles of one product, newest-cycle order not guaranteed.
#[must_use]
pub fn product_cycles(product: &str) -> &'static [EolCycle] {{
    let start = EOL_CYCLES.partition_point(|e| e.product < product);
    let end = EOL_CYCLES.partition_point(|e| e.product <= product);
    &EOL_CYCLES[start..end]
}}

/// Exact `(product, cycle)` row.
#[must_use]
pub fn cycle(product: &str, cycle: &str) -> Option<&'static EolCycle> {{
    EOL_CYCLES
        .binary_search_by(|e| (e.product, e.cycle).cmp(&(product, cycle)))
        .ok()
        .map(|i| &EOL_CYCLES[i])
}}

/// Row for an observed `version` of `product`, by longest dotted-numeric prefix.
///
/// `lookup("nginx", "1.18.0")` finds cycle `1.18`; `lookup("debian", "11")`
/// finds cycle `11`. Trailing non-numeric text (`1.0.2k-fips`) is ignored.
#[must_use]
pub fn lookup(product: &str, version: &str) -> Option<&'static EolCycle> {{
    let numeric = version
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.')
        .count();
    let mut head = &version[..numeric];
    loop {{
        head = head.trim_end_matches('.');
        if head.is_empty() {{
            return None;
        }}
        if let Some(found) = cycle(product, head) {{
            return Some(found);
        }}
        head = &head[..head.rfind('.')?];
    }}
}}

/// A supported cycle of `product` at snapshot time; see `CurrentCycle::cycle`.
#[must_use]
pub fn current(product: &str) -> Option<&'static CurrentCycle> {{
    CURRENT_CYCLES
        .binary_search_by(|e| e.product.cmp(product))
        .ok()
        .map(|i| &CURRENT_CYCLES[i])
}}

/// Whether `entry` was end-of-life on `today` (`YYYY-MM-DD`).
///
/// A dated cycle is compared by date, so a table snapshot does not go stale the
/// moment a cycle expires; an undated `is_eol` cycle is EOL immediately.
#[must_use]
pub fn is_eol_on(entry: &EolCycle, today: &str) -> bool {{
    entry.eol_from.map_or(entry.is_eol, |date| date <= today)
}}

/// Cycles sorted by `(product, cycle)` bytewise.
#[rustfmt::skip]
static EOL_CYCLES: &[EolCycle] = &[
'''


def emit(rows: list[tuple], currents: list[tuple], meta: dict, out) -> None:
    body = []
    for product, cycle_name, codename, eol_from, eoas_from, is_eol, latest in rows:
        body.append(
            f'    EolCycle {{ product: "{product}", cycle: "{cycle_name}", '
            f"codename: {rust_str(codename)}, eol_from: {rust_str(eol_from)}, "
            f"eoas_from: {rust_str(eoas_from)}, is_eol: {str(is_eol).lower()}, "
            f"latest: {rust_str(latest)} }},\n"
        )
    current_body = [
        f'    CurrentCycle {{ product: "{p}", cycle: "{c}", latest: {rust_str(l)}, '
        f"is_lts: {str(lts).lower()}, other_supported: {str(more).lower()} }},\n"
        for p, c, l, lts, more in currents
    ]
    table_bytes = sum(len(s) for s in body) + sum(len(s) for s in current_body)

    out.write(
        HEADER.format(
            schema=SCHEMA_VERSION,
            date=meta["date"],
            products=len({r[0] for r in rows}),
            cycles=len(rows),
            bytes=f"{table_bytes:,}",
            absent=", ".join(f"`{a}`" for a in ABSENT),
            unjoined=", ".join(f"`{u}`" for u in UNJOINED),
        )
    )
    out.writelines(body)
    out.write("];\n\n/// One supported cycle per product, sorted by product.\n")
    out.write("#[rustfmt::skip]\nstatic CURRENT_CYCLES: &[CurrentCycle] = &[\n")
    out.writelines(current_body)
    out.write("];\n\n#[cfg(test)]\nmod tests;\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate eol_db.rs")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="directory for the ETag cache; unchanged products are not re-downloaded",
    )
    args = parser.parse_args()

    index, _ = fetch(f"{API}/")
    check_schema(index, "product index")
    known = {p["name"] for p in index["result"]}
    known |= {a for p in index["result"] for a in p.get("aliases") or []}

    missing = [p for p in PRODUCTS if p not in known]
    if missing:
        sys.exit(f"products no longer tracked upstream: {', '.join(missing)}")
    resurfaced = [p for p in ABSENT if p in known]
    if resurfaced:
        print(
            f"note: now tracked upstream, consider embedding: {', '.join(resurfaced)}",
            file=sys.stderr,
        )

    rows: list[tuple] = []
    currents: list[tuple] = []
    for name in PRODUCTS:
        payload = load_product(name, args.cache_dir)
        check_schema(payload, name)
        product_rows, current, skipped = rows_for(payload["result"])
        if skipped:
            print(f"{name}: skipped {skipped} non-numeric cycles", file=sys.stderr)
        if not product_rows:
            sys.exit(f"{name}: no usable cycles")
        rows.extend(product_rows)
        if current:
            currents.append(current)
        else:
            print(f"note: {name} has no supported cycle upstream", file=sys.stderr)

    rows.sort(key=lambda r: (r[0].encode(), r[1].encode()))
    currents.sort(key=lambda r: r[0].encode())
    print(f"{len(rows)} cycles across {len(PRODUCTS)} products", file=sys.stderr)

    meta = {"date": os.environ.get("SOURCE_DATE") or dt.date.today().isoformat()}
    emit(rows, currents, meta, sys.stdout)


if __name__ == "__main__":
    main()
