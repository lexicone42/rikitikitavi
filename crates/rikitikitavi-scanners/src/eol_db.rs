//! Software end-of-life table from endoflife.date — auto-generated.
//!
//! Source: <https://endoflife.date/api/v1/products/> (schema 1.2.1, snapshot 2026-09-17)
//! Licence: MIT — <https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE>.
//! The copyright and permission notices it requires are reproduced verbatim in
//! THIRD-PARTY-NOTICES.md at the repository root.
//! Products: 8 | Cycles: 149 | Table: 25,852 bytes of source
//!
//! Regenerate with `uv run python scripts/gen_eol_db.py`.
//!
//! Cycle names are heterogeneous across products (`2.4`, `13`, `1.30`), so
//! lookup matches the longest dotted-numeric prefix of an observed version
//! against the cycles of one product. `is_eol` with no `eol_from` date means
//! upstream declared the cycle dead without dating it.
//!
//! Not tracked upstream (checked 2026-09-17, no rows can exist): `openssh`, `lighttpd`, `iis`, `openresty`, `webmin`, `samba`, `cups`, `dropbear`, `busybox`, `synology-dsm`, `qnap`, `unifi`, `pfsense`, `plex`, `home-assistant`, `roku`.
//!
//! Tracked upstream but deliberately not embedded, because nothing joins them:
//! `mysql`, `mariadb`, `redis`. Their versions are parsed in `database.rs`, which keeps its own
//! EOL checks; embed them in the same commit that routes it through `eol_db`.

/// One release cycle of one product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EolCycle {
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
}

/// A supported cycle of a product at snapshot time — not necessarily the newest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentCycle {
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
}

/// Date the table was generated from the API, `YYYY-MM-DD`.
pub const EOL_SNAPSHOT: &str = "2026-09-17";

/// endoflife.date API schema version this table was generated against.
pub const EOL_SCHEMA_VERSION: &str = "1.2.1";

/// Cycles of one product, newest-cycle order not guaranteed.
#[must_use]
pub fn product_cycles(product: &str) -> &'static [EolCycle] {
    let start = EOL_CYCLES.partition_point(|e| e.product < product);
    let end = EOL_CYCLES.partition_point(|e| e.product <= product);
    &EOL_CYCLES[start..end]
}

/// Exact `(product, cycle)` row.
#[must_use]
pub fn cycle(product: &str, cycle: &str) -> Option<&'static EolCycle> {
    EOL_CYCLES
        .binary_search_by(|e| (e.product, e.cycle).cmp(&(product, cycle)))
        .ok()
        .map(|i| &EOL_CYCLES[i])
}

/// Row for an observed `version` of `product`, by longest dotted-numeric prefix.
///
/// `lookup("nginx", "1.18.0")` finds cycle `1.18`; `lookup("debian", "11")`
/// finds cycle `11`. Trailing non-numeric text (`1.0.2k-fips`) is ignored.
#[must_use]
pub fn lookup(product: &str, version: &str) -> Option<&'static EolCycle> {
    let numeric = version
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.')
        .count();
    let mut head = &version[..numeric];
    loop {
        head = head.trim_end_matches('.');
        if head.is_empty() {
            return None;
        }
        if let Some(found) = cycle(product, head) {
            return Some(found);
        }
        head = &head[..head.rfind('.')?];
    }
}

/// A supported cycle of `product` at snapshot time; see `CurrentCycle::cycle`.
#[must_use]
pub fn current(product: &str) -> Option<&'static CurrentCycle> {
    CURRENT_CYCLES
        .binary_search_by(|e| e.product.cmp(product))
        .ok()
        .map(|i| &CURRENT_CYCLES[i])
}

/// Whether `entry` was end-of-life on `today` (`YYYY-MM-DD`).
///
/// A dated cycle is compared by date, so a table snapshot does not go stale the
/// moment a cycle expires; an undated `is_eol` cycle is EOL immediately.
#[must_use]
pub fn is_eol_on(entry: &EolCycle, today: &str) -> bool {
    entry.eol_from.map_or(entry.is_eol, |date| date <= today)
}

/// Cycles sorted by `(product, cycle)` bytewise.
#[rustfmt::skip]
static EOL_CYCLES: &[EolCycle] = &[
    EolCycle { product: "apache-http-server", cycle: "1.3", codename: None, eol_from: Some("2010-02-03"), eoas_from: None, is_eol: true, latest: Some("1.3.42") },
    EolCycle { product: "apache-http-server", cycle: "2.0", codename: None, eol_from: Some("2013-07-10"), eoas_from: None, is_eol: true, latest: Some("2.0.65") },
    EolCycle { product: "apache-http-server", cycle: "2.2", codename: None, eol_from: Some("2017-07-11"), eoas_from: None, is_eol: true, latest: Some("2.2.34") },
    EolCycle { product: "apache-http-server", cycle: "2.4", codename: None, eol_from: None, eoas_from: None, is_eol: false, latest: Some("2.4.68") },
    EolCycle { product: "debian", cycle: "1.1", codename: Some("Buzz"), eol_from: Some("1996-12-12"), eoas_from: Some("1996-12-12"), is_eol: true, latest: Some("1.1") },
    EolCycle { product: "debian", cycle: "1.2", codename: Some("Rex"), eol_from: Some("1997-10-23"), eoas_from: Some("1997-10-23"), is_eol: true, latest: Some("1.2") },
    EolCycle { product: "debian", cycle: "1.3", codename: Some("Bo"), eol_from: Some("1998-12-08"), eoas_from: Some("1998-12-08"), is_eol: true, latest: Some("1.3.1 r.6") },
    EolCycle { product: "debian", cycle: "10", codename: Some("Buster"), eol_from: Some("2024-06-30"), eoas_from: Some("2022-09-10"), is_eol: true, latest: Some("10.13") },
    EolCycle { product: "debian", cycle: "11", codename: Some("Bullseye"), eol_from: Some("2026-08-31"), eoas_from: Some("2024-08-14"), is_eol: true, latest: Some("11.11") },
    EolCycle { product: "debian", cycle: "12", codename: Some("Bookworm"), eol_from: Some("2028-06-30"), eoas_from: Some("2026-07-11"), is_eol: false, latest: Some("12.15") },
    EolCycle { product: "debian", cycle: "13", codename: Some("Trixie"), eol_from: Some("2030-06-30"), eoas_from: Some("2028-08-09"), is_eol: false, latest: Some("13.7") },
    EolCycle { product: "debian", cycle: "2.0", codename: Some("Hamm"), eol_from: Some("1999-02-15"), eoas_from: Some("1999-02-15"), is_eol: true, latest: Some("2.0r5") },
    EolCycle { product: "debian", cycle: "2.1", codename: Some("Slink"), eol_from: Some("2000-10-30"), eoas_from: Some("2000-09-30"), is_eol: true, latest: Some("2.1r5") },
    EolCycle { product: "debian", cycle: "2.2", codename: Some("Potato"), eol_from: Some("2003-06-30"), eoas_from: Some("2003-06-30"), is_eol: true, latest: Some("2.2r7") },
    EolCycle { product: "debian", cycle: "3.0", codename: Some("Woody"), eol_from: Some("2006-06-30"), eoas_from: Some("2006-06-30"), is_eol: true, latest: Some("3.0r6") },
    EolCycle { product: "debian", cycle: "3.1", codename: Some("Sarge"), eol_from: Some("2008-03-31"), eoas_from: Some("2008-03-31"), is_eol: true, latest: Some("3.1r8") },
    EolCycle { product: "debian", cycle: "4", codename: Some("Etch"), eol_from: Some("2010-02-15"), eoas_from: Some("2010-02-15"), is_eol: true, latest: Some("4.0r9") },
    EolCycle { product: "debian", cycle: "5", codename: Some("Lenny"), eol_from: Some("2012-02-06"), eoas_from: Some("2012-02-06"), is_eol: true, latest: Some("5.0.10") },
    EolCycle { product: "debian", cycle: "6", codename: Some("Squeeze"), eol_from: Some("2016-02-29"), eoas_from: Some("2014-05-31"), is_eol: true, latest: Some("6.0.10") },
    EolCycle { product: "debian", cycle: "7", codename: Some("Wheezy"), eol_from: Some("2018-05-31"), eoas_from: Some("2016-04-25"), is_eol: true, latest: Some("7.11") },
    EolCycle { product: "debian", cycle: "8", codename: Some("Jessie"), eol_from: Some("2020-06-30"), eoas_from: Some("2018-06-17"), is_eol: true, latest: Some("8.11") },
    EolCycle { product: "debian", cycle: "9", codename: Some("Stretch"), eol_from: Some("2022-07-01"), eoas_from: Some("2020-07-18"), is_eol: true, latest: Some("9.13") },
    EolCycle { product: "eclipse-jetty", cycle: "10", codename: None, eol_from: Some("2025-01-01"), eoas_from: Some("2024-01-01"), is_eol: true, latest: Some("10.0.26") },
    EolCycle { product: "eclipse-jetty", cycle: "11", codename: None, eol_from: Some("2025-01-01"), eoas_from: Some("2024-01-01"), is_eol: true, latest: Some("11.0.26") },
    EolCycle { product: "eclipse-jetty", cycle: "12.0", codename: None, eol_from: None, eoas_from: None, is_eol: false, latest: Some("12.0.39") },
    EolCycle { product: "eclipse-jetty", cycle: "12.1", codename: None, eol_from: None, eoas_from: None, is_eol: false, latest: Some("12.1.13") },
    EolCycle { product: "eclipse-jetty", cycle: "7", codename: None, eol_from: Some("2014-12-31"), eoas_from: Some("2014-12-31"), is_eol: true, latest: Some("7.6.21.v20160908") },
    EolCycle { product: "eclipse-jetty", cycle: "8", codename: None, eol_from: Some("2014-12-31"), eoas_from: Some("2014-12-31"), is_eol: true, latest: Some("8.2.0.v20160908") },
    EolCycle { product: "eclipse-jetty", cycle: "9.0", codename: None, eol_from: Some("2013-12-31"), eoas_from: Some("2013-12-31"), is_eol: true, latest: Some("9.0.7.v20131107") },
    EolCycle { product: "eclipse-jetty", cycle: "9.1", codename: None, eol_from: Some("2014-12-31"), eoas_from: Some("2014-12-31"), is_eol: true, latest: Some("9.1.6.v20160112") },
    EolCycle { product: "eclipse-jetty", cycle: "9.2", codename: None, eol_from: Some("2018-03-08"), eoas_from: Some("2018-03-08"), is_eol: true, latest: Some("9.2.30.v20200428") },
    EolCycle { product: "eclipse-jetty", cycle: "9.3", codename: None, eol_from: Some("2020-12-07"), eoas_from: Some("2020-12-07"), is_eol: true, latest: Some("9.3.30.v20211001") },
    EolCycle { product: "eclipse-jetty", cycle: "9.4", codename: None, eol_from: Some("2025-08-14"), eoas_from: Some("2022-06-01"), is_eol: true, latest: Some("9.4.58.v20250814") },
    EolCycle { product: "nginx", cycle: "1.0", codename: None, eol_from: Some("2012-04-23"), eoas_from: None, is_eol: true, latest: Some("1.0.15") },
    EolCycle { product: "nginx", cycle: "1.10", codename: None, eol_from: Some("2017-04-12"), eoas_from: None, is_eol: true, latest: Some("1.10.3") },
    EolCycle { product: "nginx", cycle: "1.12", codename: None, eol_from: Some("2018-04-17"), eoas_from: None, is_eol: true, latest: Some("1.12.2") },
    EolCycle { product: "nginx", cycle: "1.14", codename: None, eol_from: Some("2019-04-23"), eoas_from: None, is_eol: true, latest: Some("1.14.2") },
    EolCycle { product: "nginx", cycle: "1.16", codename: None, eol_from: Some("2020-04-20"), eoas_from: None, is_eol: true, latest: Some("1.16.1") },
    EolCycle { product: "nginx", cycle: "1.18", codename: None, eol_from: Some("2021-04-20"), eoas_from: None, is_eol: true, latest: Some("1.18.0") },
    EolCycle { product: "nginx", cycle: "1.19", codename: None, eol_from: Some("2021-05-25"), eoas_from: None, is_eol: true, latest: Some("1.19.10") },
    EolCycle { product: "nginx", cycle: "1.2", codename: None, eol_from: Some("2013-04-24"), eoas_from: None, is_eol: true, latest: Some("1.2.9") },
    EolCycle { product: "nginx", cycle: "1.20", codename: None, eol_from: Some("2022-05-24"), eoas_from: None, is_eol: true, latest: Some("1.20.2") },
    EolCycle { product: "nginx", cycle: "1.21", codename: None, eol_from: Some("2022-06-21"), eoas_from: None, is_eol: true, latest: Some("1.21.6") },
    EolCycle { product: "nginx", cycle: "1.22", codename: None, eol_from: Some("2023-04-11"), eoas_from: None, is_eol: true, latest: Some("1.22.1") },
    EolCycle { product: "nginx", cycle: "1.23", codename: None, eol_from: Some("2023-05-23"), eoas_from: None, is_eol: true, latest: Some("1.23.4") },
    EolCycle { product: "nginx", cycle: "1.24", codename: None, eol_from: Some("2024-04-23"), eoas_from: None, is_eol: true, latest: Some("1.24.0") },
    EolCycle { product: "nginx", cycle: "1.25", codename: None, eol_from: Some("2024-05-29"), eoas_from: None, is_eol: true, latest: Some("1.25.5") },
    EolCycle { product: "nginx", cycle: "1.26", codename: None, eol_from: Some("2025-04-23"), eoas_from: None, is_eol: true, latest: Some("1.26.3") },
    EolCycle { product: "nginx", cycle: "1.27", codename: None, eol_from: Some("2025-06-24"), eoas_from: None, is_eol: true, latest: Some("1.27.5") },
    EolCycle { product: "nginx", cycle: "1.28", codename: None, eol_from: Some("2026-04-14"), eoas_from: None, is_eol: true, latest: Some("1.28.3") },
    EolCycle { product: "nginx", cycle: "1.29", codename: None, eol_from: Some("2026-05-13"), eoas_from: None, is_eol: true, latest: Some("1.29.8") },
    EolCycle { product: "nginx", cycle: "1.30", codename: None, eol_from: None, eoas_from: None, is_eol: false, latest: Some("1.30.5") },
    EolCycle { product: "nginx", cycle: "1.31", codename: None, eol_from: None, eoas_from: None, is_eol: false, latest: Some("1.31.6") },
    EolCycle { product: "nginx", cycle: "1.4", codename: None, eol_from: Some("2014-04-24"), eoas_from: None, is_eol: true, latest: Some("1.4.7") },
    EolCycle { product: "nginx", cycle: "1.6", codename: None, eol_from: Some("2015-04-21"), eoas_from: None, is_eol: true, latest: Some("1.6.3") },
    EolCycle { product: "nginx", cycle: "1.8", codename: None, eol_from: Some("2016-04-26"), eoas_from: None, is_eol: true, latest: Some("1.8.1") },
    EolCycle { product: "openssl", cycle: "0.9.8", codename: None, eol_from: Some("2015-12-31"), eoas_from: None, is_eol: true, latest: Some("0.9.8zh") },
    EolCycle { product: "openssl", cycle: "1.0.0", codename: None, eol_from: Some("2015-12-31"), eoas_from: None, is_eol: true, latest: Some("1.0.0t") },
    EolCycle { product: "openssl", cycle: "1.0.1", codename: None, eol_from: Some("2016-12-31"), eoas_from: None, is_eol: true, latest: Some("1.0.1u") },
    EolCycle { product: "openssl", cycle: "1.0.2", codename: None, eol_from: Some("2019-12-31"), eoas_from: None, is_eol: true, latest: Some("1.0.2u") },
    EolCycle { product: "openssl", cycle: "1.1.0", codename: None, eol_from: Some("2019-09-11"), eoas_from: None, is_eol: true, latest: Some("1.1.0l") },
    EolCycle { product: "openssl", cycle: "1.1.1", codename: None, eol_from: Some("2023-09-11"), eoas_from: None, is_eol: true, latest: Some("1.1.1w") },
    EolCycle { product: "openssl", cycle: "3.0", codename: None, eol_from: Some("2026-09-07"), eoas_from: None, is_eol: true, latest: Some("3.0.22") },
    EolCycle { product: "openssl", cycle: "3.1", codename: None, eol_from: Some("2025-03-14"), eoas_from: None, is_eol: true, latest: Some("3.1.8") },
    EolCycle { product: "openssl", cycle: "3.2", codename: None, eol_from: Some("2025-11-23"), eoas_from: None, is_eol: true, latest: Some("3.2.6") },
    EolCycle { product: "openssl", cycle: "3.3", codename: None, eol_from: Some("2026-04-09"), eoas_from: None, is_eol: true, latest: Some("3.3.7") },
    EolCycle { product: "openssl", cycle: "3.4", codename: None, eol_from: Some("2026-10-22"), eoas_from: None, is_eol: false, latest: Some("3.4.7") },
    EolCycle { product: "openssl", cycle: "3.5", codename: None, eol_from: Some("2030-04-08"), eoas_from: None, is_eol: false, latest: Some("3.5.8") },
    EolCycle { product: "openssl", cycle: "3.6", codename: None, eol_from: Some("2026-11-01"), eoas_from: None, is_eol: false, latest: Some("3.6.4") },
    EolCycle { product: "openssl", cycle: "4.0", codename: None, eol_from: Some("2027-05-14"), eoas_from: None, is_eol: false, latest: Some("4.0.2") },
    EolCycle { product: "php", cycle: "5.0", codename: None, eol_from: Some("2005-09-05"), eoas_from: Some("2005-09-05"), is_eol: true, latest: Some("5.0.5") },
    EolCycle { product: "php", cycle: "5.1", codename: None, eol_from: Some("2006-08-24"), eoas_from: Some("2006-08-24"), is_eol: true, latest: Some("5.1.6") },
    EolCycle { product: "php", cycle: "5.2", codename: None, eol_from: Some("2011-01-06"), eoas_from: Some("2008-11-02"), is_eol: true, latest: Some("5.2.17") },
    EolCycle { product: "php", cycle: "5.3", codename: None, eol_from: Some("2014-08-14"), eoas_from: Some("2011-06-30"), is_eol: true, latest: Some("5.3.29") },
    EolCycle { product: "php", cycle: "5.4", codename: None, eol_from: Some("2015-09-14"), eoas_from: Some("2014-09-14"), is_eol: true, latest: Some("5.4.45") },
    EolCycle { product: "php", cycle: "5.5", codename: None, eol_from: Some("2016-07-21"), eoas_from: Some("2015-07-10"), is_eol: true, latest: Some("5.5.38") },
    EolCycle { product: "php", cycle: "5.6", codename: None, eol_from: Some("2018-12-31"), eoas_from: Some("2017-01-19"), is_eol: true, latest: Some("5.6.40") },
    EolCycle { product: "php", cycle: "7.0", codename: None, eol_from: Some("2019-01-10"), eoas_from: Some("2018-01-04"), is_eol: true, latest: Some("7.0.33") },
    EolCycle { product: "php", cycle: "7.1", codename: None, eol_from: Some("2019-12-01"), eoas_from: Some("2018-12-01"), is_eol: true, latest: Some("7.1.33") },
    EolCycle { product: "php", cycle: "7.2", codename: None, eol_from: Some("2020-11-30"), eoas_from: Some("2019-11-30"), is_eol: true, latest: Some("7.2.34") },
    EolCycle { product: "php", cycle: "7.3", codename: None, eol_from: Some("2021-12-06"), eoas_from: Some("2020-12-06"), is_eol: true, latest: Some("7.3.33") },
    EolCycle { product: "php", cycle: "7.4", codename: None, eol_from: Some("2022-11-28"), eoas_from: Some("2021-11-28"), is_eol: true, latest: Some("7.4.33") },
    EolCycle { product: "php", cycle: "8.0", codename: None, eol_from: Some("2023-11-26"), eoas_from: Some("2022-11-26"), is_eol: true, latest: Some("8.0.30") },
    EolCycle { product: "php", cycle: "8.1", codename: None, eol_from: Some("2025-12-31"), eoas_from: Some("2023-11-25"), is_eol: true, latest: Some("8.1.34") },
    EolCycle { product: "php", cycle: "8.2", codename: None, eol_from: Some("2026-12-31"), eoas_from: Some("2024-12-31"), is_eol: false, latest: Some("8.2.33") },
    EolCycle { product: "php", cycle: "8.3", codename: None, eol_from: Some("2027-12-31"), eoas_from: Some("2025-12-31"), is_eol: false, latest: Some("8.3.33") },
    EolCycle { product: "php", cycle: "8.4", codename: None, eol_from: Some("2028-12-31"), eoas_from: Some("2026-12-31"), is_eol: false, latest: Some("8.4.25") },
    EolCycle { product: "php", cycle: "8.5", codename: None, eol_from: Some("2029-12-31"), eoas_from: Some("2027-12-31"), is_eol: false, latest: Some("8.5.10") },
    EolCycle { product: "python", cycle: "2.6", codename: None, eol_from: Some("2013-10-29"), eoas_from: None, is_eol: true, latest: Some("2.6.9") },
    EolCycle { product: "python", cycle: "2.7", codename: None, eol_from: Some("2020-01-01"), eoas_from: None, is_eol: true, latest: Some("2.7.18") },
    EolCycle { product: "python", cycle: "3.0", codename: None, eol_from: Some("2009-06-27"), eoas_from: None, is_eol: true, latest: Some("3.0.1") },
    EolCycle { product: "python", cycle: "3.1", codename: None, eol_from: Some("2012-04-09"), eoas_from: None, is_eol: true, latest: Some("3.1.5") },
    EolCycle { product: "python", cycle: "3.10", codename: None, eol_from: Some("2026-10-31"), eoas_from: Some("2023-04-05"), is_eol: false, latest: Some("3.10.21") },
    EolCycle { product: "python", cycle: "3.11", codename: None, eol_from: Some("2027-10-31"), eoas_from: Some("2024-04-01"), is_eol: false, latest: Some("3.11.16") },
    EolCycle { product: "python", cycle: "3.12", codename: None, eol_from: Some("2028-10-31"), eoas_from: Some("2025-04-02"), is_eol: false, latest: Some("3.12.14") },
    EolCycle { product: "python", cycle: "3.13", codename: None, eol_from: Some("2029-10-31"), eoas_from: Some("2026-10-01"), is_eol: false, latest: Some("3.13.15") },
    EolCycle { product: "python", cycle: "3.14", codename: None, eol_from: Some("2030-10-31"), eoas_from: Some("2027-10-01"), is_eol: false, latest: Some("3.14.7") },
    EolCycle { product: "python", cycle: "3.2", codename: None, eol_from: Some("2016-02-20"), eoas_from: None, is_eol: true, latest: Some("3.2.6") },
    EolCycle { product: "python", cycle: "3.3", codename: None, eol_from: Some("2017-09-29"), eoas_from: None, is_eol: true, latest: Some("3.3.7") },
    EolCycle { product: "python", cycle: "3.4", codename: None, eol_from: Some("2019-03-18"), eoas_from: None, is_eol: true, latest: Some("3.4.10") },
    EolCycle { product: "python", cycle: "3.5", codename: None, eol_from: Some("2020-09-30"), eoas_from: None, is_eol: true, latest: Some("3.5.10") },
    EolCycle { product: "python", cycle: "3.6", codename: None, eol_from: Some("2021-12-23"), eoas_from: Some("2018-12-24"), is_eol: true, latest: Some("3.6.15") },
    EolCycle { product: "python", cycle: "3.7", codename: None, eol_from: Some("2023-06-27"), eoas_from: Some("2020-06-27"), is_eol: true, latest: Some("3.7.17") },
    EolCycle { product: "python", cycle: "3.8", codename: None, eol_from: Some("2024-10-07"), eoas_from: Some("2021-05-03"), is_eol: true, latest: Some("3.8.20") },
    EolCycle { product: "python", cycle: "3.9", codename: None, eol_from: Some("2025-10-31"), eoas_from: Some("2022-05-17"), is_eol: true, latest: Some("3.9.25") },
    EolCycle { product: "ubuntu", cycle: "10.04", codename: Some("Lucid Lynx"), eol_from: Some("2013-05-09"), eoas_from: Some("2013-05-09"), is_eol: true, latest: Some("10.04.4") },
    EolCycle { product: "ubuntu", cycle: "10.10", codename: Some("Maverick Meerkat"), eol_from: Some("2012-04-10"), eoas_from: Some("2012-04-10"), is_eol: true, latest: Some("10.10") },
    EolCycle { product: "ubuntu", cycle: "11.04", codename: Some("Natty Narwhal"), eol_from: Some("2012-10-28"), eoas_from: Some("2012-10-28"), is_eol: true, latest: Some("11.04") },
    EolCycle { product: "ubuntu", cycle: "11.10", codename: Some("Oneiric Ocelot"), eol_from: Some("2013-05-09"), eoas_from: Some("2013-05-09"), is_eol: true, latest: Some("11.10") },
    EolCycle { product: "ubuntu", cycle: "12.04", codename: Some("Precise Pangolin"), eol_from: Some("2017-04-28"), eoas_from: Some("2017-04-28"), is_eol: true, latest: Some("12.04.5") },
    EolCycle { product: "ubuntu", cycle: "12.10", codename: Some("Quantal Quetzal"), eol_from: Some("2014-05-16"), eoas_from: Some("2014-05-16"), is_eol: true, latest: Some("12.10") },
    EolCycle { product: "ubuntu", cycle: "13.04", codename: Some("Raring Ringtail"), eol_from: Some("2014-01-27"), eoas_from: Some("2014-01-27"), is_eol: true, latest: Some("13.04") },
    EolCycle { product: "ubuntu", cycle: "13.10", codename: Some("Saucy Salamander"), eol_from: Some("2014-07-17"), eoas_from: Some("2014-07-17"), is_eol: true, latest: Some("13.10") },
    EolCycle { product: "ubuntu", cycle: "14.04", codename: Some("Trusty Tahr"), eol_from: Some("2019-04-02"), eoas_from: Some("2019-04-02"), is_eol: true, latest: Some("14.04.6") },
    EolCycle { product: "ubuntu", cycle: "14.10", codename: Some("Utopic Unicorn"), eol_from: Some("2015-07-23"), eoas_from: Some("2015-07-23"), is_eol: true, latest: Some("14.10") },
    EolCycle { product: "ubuntu", cycle: "15.04", codename: Some("Vivid Vervet"), eol_from: Some("2016-02-04"), eoas_from: Some("2016-02-04"), is_eol: true, latest: Some("15.04") },
    EolCycle { product: "ubuntu", cycle: "15.10", codename: Some("Wily Werewolf"), eol_from: Some("2016-07-28"), eoas_from: Some("2016-07-28"), is_eol: true, latest: Some("15.10") },
    EolCycle { product: "ubuntu", cycle: "16.04", codename: Some("Xenial Xerus"), eol_from: Some("2021-04-02"), eoas_from: Some("2021-04-02"), is_eol: true, latest: Some("16.04.7") },
    EolCycle { product: "ubuntu", cycle: "16.10", codename: Some("Yakkety Yak"), eol_from: Some("2017-07-20"), eoas_from: Some("2017-07-20"), is_eol: true, latest: Some("16.10") },
    EolCycle { product: "ubuntu", cycle: "17.04", codename: Some("Zesty Zapus"), eol_from: Some("2018-01-13"), eoas_from: Some("2018-01-13"), is_eol: true, latest: Some("17.04") },
    EolCycle { product: "ubuntu", cycle: "17.10", codename: Some("Artful Aardvark"), eol_from: Some("2018-07-19"), eoas_from: Some("2018-07-19"), is_eol: true, latest: Some("17.10") },
    EolCycle { product: "ubuntu", cycle: "18.04", codename: Some("Bionic Beaver"), eol_from: Some("2023-05-31"), eoas_from: Some("2023-05-31"), is_eol: true, latest: Some("18.04.6") },
    EolCycle { product: "ubuntu", cycle: "18.10", codename: Some("Cosmic Cuttlefish"), eol_from: Some("2019-07-18"), eoas_from: Some("2019-07-18"), is_eol: true, latest: Some("18.10") },
    EolCycle { product: "ubuntu", cycle: "19.04", codename: Some("Disco Dingo"), eol_from: Some("2020-01-23"), eoas_from: Some("2020-01-23"), is_eol: true, latest: Some("19.04") },
    EolCycle { product: "ubuntu", cycle: "19.10", codename: Some("Eoan Ermine"), eol_from: Some("2020-07-06"), eoas_from: Some("2020-07-06"), is_eol: true, latest: Some("19.10") },
    EolCycle { product: "ubuntu", cycle: "20.04", codename: Some("Focal Fossa"), eol_from: Some("2025-05-31"), eoas_from: Some("2022-10-01"), is_eol: true, latest: Some("20.04.6") },
    EolCycle { product: "ubuntu", cycle: "20.10", codename: Some("Groovy Gorilla"), eol_from: Some("2021-07-22"), eoas_from: Some("2021-07-22"), is_eol: true, latest: Some("20.10") },
    EolCycle { product: "ubuntu", cycle: "21.04", codename: Some("Hirsute Hippo"), eol_from: Some("2022-01-20"), eoas_from: Some("2022-01-20"), is_eol: true, latest: Some("21.04") },
    EolCycle { product: "ubuntu", cycle: "21.10", codename: Some("Impish Indri"), eol_from: Some("2022-07-14"), eoas_from: Some("2022-07-14"), is_eol: true, latest: Some("21.10") },
    EolCycle { product: "ubuntu", cycle: "22.04", codename: Some("Jammy Jellyfish"), eol_from: Some("2027-06-01"), eoas_from: Some("2024-09-30"), is_eol: false, latest: Some("22.04.5") },
    EolCycle { product: "ubuntu", cycle: "22.10", codename: Some("Kinetic Kudu"), eol_from: Some("2023-07-20"), eoas_from: Some("2023-07-20"), is_eol: true, latest: Some("22.10") },
    EolCycle { product: "ubuntu", cycle: "23.04", codename: Some("Lunar Lobster"), eol_from: Some("2024-01-20"), eoas_from: Some("2024-01-20"), is_eol: true, latest: Some("23.04") },
    EolCycle { product: "ubuntu", cycle: "23.10", codename: Some("Mantic Minotaur"), eol_from: Some("2024-07-12"), eoas_from: Some("2024-07-12"), is_eol: true, latest: Some("23.10") },
    EolCycle { product: "ubuntu", cycle: "24.04", codename: Some("Noble Numbat"), eol_from: Some("2029-05-31"), eoas_from: Some("2029-05-31"), is_eol: false, latest: Some("24.04.4") },
    EolCycle { product: "ubuntu", cycle: "24.10", codename: Some("Oracular Oriole"), eol_from: Some("2025-07-10"), eoas_from: Some("2025-07-10"), is_eol: true, latest: Some("24.10") },
    EolCycle { product: "ubuntu", cycle: "25.04", codename: Some("Plucky Puffin"), eol_from: Some("2026-01-17"), eoas_from: Some("2026-01-17"), is_eol: true, latest: Some("25.04") },
    EolCycle { product: "ubuntu", cycle: "25.10", codename: Some("Questing Quokka"), eol_from: Some("2026-07-01"), eoas_from: Some("2026-07-01"), is_eol: true, latest: Some("25.10") },
    EolCycle { product: "ubuntu", cycle: "26.04", codename: Some("Resolute Raccoon"), eol_from: Some("2031-05-29"), eoas_from: Some("2031-05-29"), is_eol: false, latest: Some("26.04.1") },
    EolCycle { product: "ubuntu", cycle: "4.10", codename: Some("Warty Warthog"), eol_from: Some("2006-04-30"), eoas_from: Some("2004-10-26"), is_eol: true, latest: Some("4.10") },
    EolCycle { product: "ubuntu", cycle: "5.04", codename: Some("Hoary Hedgehog"), eol_from: Some("2006-10-31"), eoas_from: Some("2006-10-31"), is_eol: true, latest: Some("5.04") },
    EolCycle { product: "ubuntu", cycle: "5.10", codename: Some("Breezy Badger"), eol_from: Some("2007-04-13"), eoas_from: Some("2007-04-13"), is_eol: true, latest: Some("5.10") },
    EolCycle { product: "ubuntu", cycle: "6.06", codename: Some("Dapper Drake"), eol_from: Some("2011-06-01"), eoas_from: Some("2011-06-01"), is_eol: true, latest: Some("6.06.2") },
    EolCycle { product: "ubuntu", cycle: "6.10", codename: Some("Edgy Eft"), eol_from: Some("2008-04-26"), eoas_from: Some("2006-10-26"), is_eol: true, latest: Some("6.10") },
    EolCycle { product: "ubuntu", cycle: "7.04", codename: Some("Feisty Fawn"), eol_from: Some("2008-10-19"), eoas_from: Some("2008-10-19"), is_eol: true, latest: Some("7.04") },
    EolCycle { product: "ubuntu", cycle: "7.10", codename: Some("Gutsy Gibbon"), eol_from: Some("2009-04-18"), eoas_from: Some("2009-04-18"), is_eol: true, latest: Some("7.10") },
    EolCycle { product: "ubuntu", cycle: "8.04", codename: Some("Hardy Heron"), eol_from: Some("2013-05-09"), eoas_from: Some("2013-05-09"), is_eol: true, latest: Some("8.04.4") },
    EolCycle { product: "ubuntu", cycle: "8.10", codename: Some("Intrepid Ibex"), eol_from: Some("2010-04-30"), eoas_from: Some("2010-04-30"), is_eol: true, latest: Some("8.10") },
    EolCycle { product: "ubuntu", cycle: "9.04", codename: Some("Jaunty Jackalope"), eol_from: Some("2010-10-23"), eoas_from: Some("2010-10-23"), is_eol: true, latest: Some("9.04") },
    EolCycle { product: "ubuntu", cycle: "9.10", codename: Some("Karmic Koala"), eol_from: Some("2011-04-30"), eoas_from: Some("2011-04-30"), is_eol: true, latest: Some("9.10") },
];

/// One supported cycle per product, sorted by product.
#[rustfmt::skip]
static CURRENT_CYCLES: &[CurrentCycle] = &[
    CurrentCycle { product: "apache-http-server", cycle: "2.4", latest: Some("2.4.68"), is_lts: false, other_supported: false },
    CurrentCycle { product: "debian", cycle: "13", latest: Some("13.7"), is_lts: false, other_supported: true },
    CurrentCycle { product: "eclipse-jetty", cycle: "12.1", latest: Some("12.1.13"), is_lts: false, other_supported: true },
    CurrentCycle { product: "nginx", cycle: "1.31", latest: Some("1.31.6"), is_lts: false, other_supported: true },
    CurrentCycle { product: "openssl", cycle: "3.5", latest: Some("3.5.8"), is_lts: true, other_supported: true },
    CurrentCycle { product: "php", cycle: "8.5", latest: Some("8.5.10"), is_lts: false, other_supported: true },
    CurrentCycle { product: "python", cycle: "3.14", latest: Some("3.14.7"), is_lts: false, other_supported: true },
    CurrentCycle { product: "ubuntu", cycle: "26.04", latest: Some("26.04.1"), is_lts: true, other_supported: true },
];

#[cfg(test)]
mod tests;
