use super::*;
use proptest::prelude::*;

/// Table is strictly ascending bytewise: binary-search precondition, no duplicates.
#[test]
fn table_is_strictly_sorted() {
    assert!(KEV_CVES.windows(2).all(|w| w[0] < w[1]));
}

/// Every entry equals its own normalisation and has the `CVE-YYYY-NNNN+` shape.
#[test]
fn table_entries_are_normalised_cve_ids() {
    for entry in KEV_CVES {
        assert_eq!(entry.trim().to_ascii_uppercase(), *entry);
        let Some((year, seq)) = entry
            .strip_prefix("CVE-")
            .and_then(|rest| rest.split_once('-'))
        else {
            panic!("malformed entry {entry}");
        };
        assert!(
            year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()),
            "{entry}"
        );
        assert!(
            seq.len() >= 4 && seq.bytes().all(|b| b.is_ascii_digit()),
            "{entry}"
        );
    }
}

/// A table entry with random per-byte lowercasing and ASCII whitespace padding.
fn arb_mangled_entry() -> impl Strategy<Value = String> {
    (0..KEV_CVES.len()).prop_flat_map(|i| {
        let entry = KEV_CVES[i];
        (
            proptest::collection::vec(any::<bool>(), entry.len()),
            "[ \t\r\n]{0,3}",
            "[ \t\r\n]{0,3}",
        )
            .prop_map(move |(flips, lead, trail)| {
                let body: String = entry
                    .bytes()
                    .zip(flips)
                    .map(|(b, flip)| char::from(if flip { b.to_ascii_lowercase() } else { b }))
                    .collect();
                format!("{lead}{body}{trail}")
            })
    })
}

fn arb_any_input() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "CVE-[0-9]{4}-[0-9]{4,7}",
        arb_mangled_entry(),
    ]
}

proptest! {
    /// Every table entry is reported as KEV.
    #[test]
    fn prop_table_entries_are_kev(i in 0..KEV_CVES.len()) {
        prop_assert!(is_kev(KEV_CVES[i]));
    }

    /// ASCII case and surrounding whitespace do not affect membership.
    #[test]
    fn prop_case_and_whitespace_invariant(mangled in arb_mangled_entry()) {
        prop_assert!(is_kev(&mangled));
    }

    /// Binary search agrees with a linear scan; never panics on arbitrary input.
    #[test]
    fn prop_agrees_with_linear_scan(s in arb_any_input()) {
        let needle = s.trim().to_ascii_uppercase();
        prop_assert_eq!(is_kev(&s), KEV_CVES.contains(&needle.as_str()));
    }
}
