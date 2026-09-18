use super::*;
use proptest::prelude::*;

/// Strictly ascending on `(product, cycle)`: the binary-search precondition, no duplicates.
#[test]
fn table_is_strictly_sorted() {
    assert!(
        EOL_CYCLES
            .windows(2)
            .all(|w| (w[0].product, w[0].cycle) < (w[1].product, w[1].cycle))
    );
}

#[test]
fn current_table_is_strictly_sorted() {
    assert!(
        CURRENT_CYCLES
            .windows(2)
            .all(|w| w[0].product < w[1].product)
    );
}

/// Every row is reachable by exact lookup and by its own cycle string as a version.
#[test]
fn every_row_is_reachable() {
    for entry in EOL_CYCLES {
        assert_eq!(cycle(entry.product, entry.cycle), Some(entry));
        assert_eq!(lookup(entry.product, entry.cycle), Some(entry));
    }
}

/// `YYYY-MM-DD`, so bytewise `<=` is a date comparison.
fn assert_iso_date(date: &str) {
    assert_eq!(date.len(), 10, "{date}");
    let bytes = date.as_bytes();
    assert!(bytes[4] == b'-' && bytes[7] == b'-', "{date}");
    assert!(
        date.bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit()),
        "{date}"
    );
}

/// Cycles are dotted-numeric, dates are `YYYY-MM-DD`, strings are non-empty.
#[test]
fn rows_are_well_formed() {
    for entry in EOL_CYCLES {
        assert!(!entry.product.is_empty());
        assert!(
            !entry.cycle.is_empty()
                && entry
                    .cycle
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
            "cycle {}",
            entry.cycle
        );
        if let Some(date) = entry.eol_from {
            assert_iso_date(date);
        }
        if let Some(date) = entry.eoas_from {
            assert_iso_date(date);
            // Active support cannot outlast support; upstream sets them equal
            // where a product has only one phase.
            if let Some(eol) = entry.eol_from {
                assert!(
                    date <= eol,
                    "{} {}: {date} > {eol}",
                    entry.product,
                    entry.cycle
                );
            }
        }
        assert!(entry.codename.is_none_or(|c| !c.is_empty()));
        assert!(entry.latest.is_none_or(|l| !l.is_empty()));
    }
}

/// `eoas_from` means a different thing per product, and only Debian's is a
/// security event. Locking both halves here because a caller that treats the
/// field uniformly produces false positives.
#[test]
fn eoas_is_a_security_date_only_for_debian() {
    // Debian: `labels.eoas` is "Debian Security Support", so the gap between
    // the two dates is the window where only the community LTS project covers
    // the release.
    let split = product_cycles("debian")
        .iter()
        .filter(|e| matches!((e.eoas_from, e.eol_from), (Some(a), Some(b)) if a < b))
        .count();
    assert!(
        split >= 3,
        "debian should date security-team end before LTS end"
    );

    // Ubuntu: `labels.eoas` is "Hardware & Maintenance" — the last point
    // release, not a patching change. Jammy passed it on 2024-09-30 and still
    // gets security updates until 2027-06-01, so a Medium tier keyed on this
    // field would fire on a fully supported host.
    let jammy = cycle("ubuntu", "22.04").expect("ubuntu 22.04");
    assert_eq!(jammy.eoas_from, Some("2024-09-30"));
    assert_eq!(jammy.eol_from, Some("2027-06-01"));
    assert!(!jammy.is_eol);
}

/// Products whose versions nothing joins are not embedded.
#[test]
fn unjoined_products_are_absent() {
    for product in ["mysql", "mariadb", "redis"] {
        assert!(
            product_cycles(product).is_empty(),
            "{product} is embedded but database.rs does not call eol_db"
        );
    }
}

/// Every current row names a real, non-EOL cycle of the same product.
#[test]
fn current_rows_point_at_supported_cycles() {
    for entry in CURRENT_CYCLES {
        let row = cycle(entry.product, entry.cycle)
            .unwrap_or_else(|| panic!("{} {} missing", entry.product, entry.cycle));
        assert!(!row.is_eol, "{} {} is EOL", entry.product, entry.cycle);
        assert_eq!(row.latest, entry.latest);
        assert_eq!(current(entry.product), Some(entry));
        // `other_supported` claims a second non-EOL cycle exists; check it does.
        let live = product_cycles(entry.product)
            .iter()
            .filter(|e| !e.is_eol)
            .count();
        assert_eq!(entry.other_supported, live > 1, "{}", entry.product);
    }
}

/// The current row is the LTS branch where upstream marks one — OpenSSL 3.5,
/// not the newer 4.0, which is what a user on a stable track should hear.
#[test]
fn current_prefers_the_lts_branch() {
    let openssl = current("openssl").expect("openssl");
    assert_eq!(openssl.cycle, "3.5");
    assert!(openssl.is_lts);
    assert!(openssl.other_supported);
    assert!(!cycle("openssl", "4.0").expect("openssl 4.0").is_eol);

    // nginx marks no branch LTS and keeps two alive, so the caller is told so
    // rather than pointed at mainline.
    let nginx = current("nginx").expect("nginx");
    assert!(!nginx.is_lts);
    assert!(nginx.other_supported);
}

/// `product_cycles` returns exactly the rows of that product.
#[test]
fn product_cycles_partitions_the_table() {
    let mut seen = 0;
    for product in ["nginx", "debian", "php", "openssl", "ubuntu"] {
        let rows = product_cycles(product);
        assert!(!rows.is_empty(), "{product}");
        assert!(rows.iter().all(|r| r.product == product));
        seen += rows.len();
    }
    assert!(seen < EOL_CYCLES.len());
    assert!(product_cycles("not-a-product").is_empty());
}

/// Upstream values as of the snapshot. These are the claims the scanners repeat.
#[test]
fn known_cycles_match_upstream() {
    let nginx_118 = lookup("nginx", "1.18.0").expect("nginx 1.18");
    assert_eq!(nginx_118.cycle, "1.18");
    assert_eq!(nginx_118.eol_from, Some("2021-04-20"));
    assert!(nginx_118.is_eol);

    // The hand-coded claim this table replaced said "current stable is 1.26.x";
    // 1.26 went EOL 2025-04-23.
    assert!(cycle("nginx", "1.26").expect("nginx 1.26").is_eol);

    let debian_11 = lookup("debian", "11").expect("debian 11");
    assert_eq!(debian_11.codename, Some("Bullseye"));

    assert_eq!(
        lookup("php", "8.0.30").map(|e| e.eol_from),
        Some(Some("2023-11-26"))
    );
    assert!(
        !cycle("apache-http-server", "2.4")
            .expect("httpd 2.4")
            .is_eol
    );
    assert!(
        cycle("apache-http-server", "2.2")
            .expect("httpd 2.2")
            .is_eol
    );
}

/// Longest dotted prefix wins, and `1.2` never matches `1.20`.
#[test]
fn lookup_matches_longest_prefix() {
    assert_eq!(lookup("nginx", "1.2.9").map(|e| e.cycle), Some("1.2"));
    assert_eq!(lookup("nginx", "1.20.2").map(|e| e.cycle), Some("1.20"));
    assert_eq!(
        lookup("openssl", "1.0.2k-fips").map(|e| e.cycle),
        Some("1.0.2")
    );
    assert_eq!(lookup("openssl", "1.0.2").map(|e| e.cycle), Some("1.0.2"));
    // No cycle `1`, and no shorter prefix exists either.
    assert_eq!(lookup("php", "4"), None);
    assert_eq!(lookup("php", "8.9.1"), None);
}

#[test]
fn lookup_rejects_junk() {
    assert_eq!(lookup("nginx", ""), None);
    assert_eq!(lookup("nginx", "."), None);
    assert_eq!(lookup("nginx", "..."), None);
    assert_eq!(lookup("nginx", "abc"), None);
    assert_eq!(lookup("nginx", "-1.18"), None);
    assert_eq!(lookup("", "1.18"), None);
    assert_eq!(lookup("NGINX", "1.18"), None, "product names are lowercase");
}

#[test]
fn eol_is_evaluated_against_a_date() {
    let nginx_118 = cycle("nginx", "1.18").expect("nginx 1.18");
    assert!(is_eol_on(nginx_118, "2026-09-17"));
    assert!(!is_eol_on(nginx_118, "2020-01-01"));
    // Boundary: the eol_from date itself counts as EOL.
    assert!(is_eol_on(nginx_118, "2021-04-20"));

    let supported = cycle("php", "8.5").expect("php 8.5");
    assert!(!is_eol_on(supported, "2026-09-17"));

    // Undated cycles fall back to the upstream flag.
    let undated_live = EolCycle {
        product: "x",
        cycle: "1",
        codename: None,
        eol_from: None,
        eoas_from: None,
        is_eol: false,
        latest: None,
    };
    let undated_dead = EolCycle {
        is_eol: true,
        ..undated_live
    };
    assert!(!is_eol_on(&undated_live, "2099-01-01"));
    assert!(is_eol_on(&undated_dead, "1970-01-01"));
}

/// Longest-dotted-prefix lookup, written the slow obvious way.
fn linear_lookup(product: &str, version: &str) -> Option<&'static EolCycle> {
    let numeric: String = version
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut head = numeric.as_str();
    loop {
        head = head.trim_end_matches('.');
        if head.is_empty() {
            return None;
        }
        if let Some(found) = EOL_CYCLES
            .iter()
            .find(|e| e.product == product && e.cycle == head)
        {
            return Some(found);
        }
        head = &head[..head.rfind('.')?];
    }
}

fn arb_version() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[0-9]{1,3}(\\.[0-9]{1,3}){0,3}",
        "[0-9.]{0,12}",
        "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}[a-z-]{0,6}",
    ]
}

fn arb_product() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        (0..EOL_CYCLES.len()).prop_map(|i| EOL_CYCLES[i].product.to_owned()),
    ]
}

proptest! {
    /// Never panics, and agrees with the linear longest-prefix scan.
    #[test]
    fn prop_agrees_with_linear_scan(product in arb_product(), version in arb_version()) {
        prop_assert_eq!(lookup(&product, &version), linear_lookup(&product, &version));
    }

    /// Arbitrary bytes into every entry point: no panic, no slice on a char boundary.
    #[test]
    fn prop_no_panic_on_arbitrary_input(product in any::<String>(), version in any::<String>()) {
        let _ = lookup(&product, &version);
        let _ = cycle(&product, &version);
        let _ = current(&product);
        prop_assert!(product_cycles(&product).iter().all(|e| e.product == product));
    }

    /// The verdict is monotone in the clock: once EOL, always EOL.
    #[test]
    fn prop_is_eol_on_is_monotone(
        i in 0..EOL_CYCLES.len(),
        first in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
        second in "[0-9]{4}-[0-9]{2}-[0-9]{2}",
    ) {
        let (early, late) = if first <= second { (&first, &second) } else { (&second, &first) };
        let entry = &EOL_CYCLES[i];
        prop_assert!(is_eol_on(entry, late) || !is_eol_on(entry, early));
    }

    /// Any dated cycle is EOL by year 9999 and not yet EOL in year 0001.
    #[test]
    fn prop_is_eol_on_bounds(i in 0..EOL_CYCLES.len()) {
        let entry = &EOL_CYCLES[i];
        if entry.eol_from.is_some() {
            prop_assert!(is_eol_on(entry, "9999-12-31"));
            prop_assert!(!is_eol_on(entry, "0001-01-01"));
        } else {
            prop_assert_eq!(is_eol_on(entry, "9999-12-31"), entry.is_eol);
        }
    }

    /// Arbitrary `today` strings never panic.
    #[test]
    fn prop_is_eol_on_no_panic(i in 0..EOL_CYCLES.len(), today in ".*") {
        let _ = is_eol_on(&EOL_CYCLES[i], &today);
    }

    /// A row found for a version always belongs to the queried product and is a prefix of it.
    #[test]
    fn prop_result_is_a_prefix_of_the_query(product in arb_product(), version in arb_version()) {
        if let Some(found) = lookup(&product, &version) {
            prop_assert_eq!(found.product, product.as_str());
            prop_assert!(version.starts_with(found.cycle));
        }
    }
}
