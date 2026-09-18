use std::collections::BTreeSet;

use regex::{RegexBuilder, RegexSetBuilder};

use super::*;
use crate::recog::identify;

/// Same ceilings the matcher uses; two upstream patterns and four whole sets
/// exceed the crate's 10 MB default.
const SET_SIZE_LIMIT: usize = 256 << 20;
const REGEX_SIZE_LIMIT: usize = 64 << 20;

fn compile(pattern: &str) -> regex::Regex {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .unwrap_or_else(|e| panic!("{pattern}: {e}"))
}

/// The table is non-empty and every key has rows.
#[test]
fn every_key_has_fingerprints() {
    for key in RecogKey::ALL {
        assert!(
            !key.fingerprints().is_empty(),
            "{} has no fingerprints",
            key.as_str()
        );
    }
}

/// `index()` agrees with the position in `ALL` — the matcher indexes `SETS` by it.
#[test]
fn index_matches_declaration_order() {
    for (i, key) in RecogKey::ALL.into_iter().enumerate() {
        assert_eq!(key.index(), i, "{}", key.as_str());
    }
}

/// Match keys and field names are distinct; both are used as identifiers.
#[test]
fn names_are_unique() {
    let keys: BTreeSet<_> = RecogKey::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(keys.len(), RecogKey::ALL.len());
    let fields: BTreeSet<_> = RecogField::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(fields.len(), RecogField::ALL.len());
}

/// Every pattern compiles with the `regex` crate. Recog's Ruby dialect uses no
/// lookaround or backreferences, which is what makes this hold.
#[test]
fn every_pattern_compiles() {
    for key in RecogKey::ALL {
        for fp in key.fingerprints() {
            let _ = compile(fp.pattern);
        }
    }
}

/// Every whole-key set compiles at the matcher's size limit.
#[test]
fn every_set_compiles() {
    for key in RecogKey::ALL {
        let patterns = key.fingerprints().iter().map(|f| f.pattern);
        RegexSetBuilder::new(patterns)
            .size_limit(SET_SIZE_LIMIT)
            .build()
            .unwrap_or_else(|e| panic!("{}: {e}", key.as_str()));
    }
}

/// Format invariance: the generator rewrites Ruby flag semantics into inline
/// Rust flags on every pattern, so every pattern starts with `(?m`.
#[test]
fn every_pattern_carries_the_multiline_flag() {
    for key in RecogKey::ALL {
        for fp in key.fingerprints() {
            assert!(
                fp.pattern.starts_with("(?m"),
                "{}: {}",
                key.as_str(),
                fp.pattern
            );
        }
    }
}

/// A duplicate pattern in one key is dead weight: first match wins, so the
/// second row is unreachable.
#[test]
fn patterns_are_unique_within_a_key() {
    for key in RecogKey::ALL {
        let mut seen = BTreeSet::new();
        for fp in key.fingerprints() {
            assert!(
                seen.insert(fp.pattern),
                "{} repeats {}",
                key.as_str(),
                fp.pattern
            );
        }
    }
}

/// Every row yields at least one consumed parameter; rows that did not are
/// dropped at import.
#[test]
fn every_row_carries_a_consumed_parameter() {
    for key in RecogKey::ALL {
        for fp in key.fingerprints() {
            assert!(!fp.params.is_empty(), "{}: {}", key.as_str(), fp.pattern);
        }
    }
}

/// Every capture-group reference exists in its own pattern, and every literal
/// parameter is non-empty.
#[test]
fn every_parameter_is_resolvable() {
    for key in RecogKey::ALL {
        for fp in key.fingerprints() {
            let groups = compile(fp.pattern).captures_len();
            for param in fp.params {
                if param.pos == 0 {
                    assert!(
                        !param.value.is_empty(),
                        "{}: empty literal for {}",
                        fp.pattern,
                        param.field.as_str()
                    );
                } else {
                    assert!(
                        usize::from(param.pos) < groups,
                        "{}: pos {} but only {} groups",
                        fp.pattern,
                        param.pos,
                        groups - 1
                    );
                    assert!(
                        param.value.is_empty(),
                        "{}: capture param carries a literal",
                        fp.pattern
                    );
                }
            }
        }
    }
}

/// Every `{field}` interpolation names a field that the same fingerprint sets.
#[test]
fn every_interpolation_is_satisfiable() {
    for key in RecogKey::ALL {
        for fp in key.fingerprints() {
            let set: BTreeSet<_> = fp.params.iter().map(|p| p.field).collect();
            for param in fp.params {
                let mut rest = param.value;
                while let Some(open) = rest.find('{') {
                    let close = rest[open..]
                        .find('}')
                        .unwrap_or_else(|| panic!("{}: unclosed brace", fp.pattern))
                        + open;
                    let name = &rest[open + 1..close];
                    let field = RecogField::ALL
                        .into_iter()
                        .find(|f| f.as_str() == name)
                        .unwrap_or_else(|| panic!("{}: unknown field {name}", fp.pattern));
                    assert!(set.contains(&field), "{}: {name} is never set", fp.pattern);
                    rest = &rest[close + 1..];
                }
            }
        }
    }
}

/// Round trip every field name through `as_str`.
#[test]
fn field_names_round_trip() {
    for field in RecogField::ALL {
        let found = RecogField::ALL
            .into_iter()
            .find(|f| f.as_str() == field.as_str());
        assert_eq!(found, Some(field));
    }
}

/// Every upstream `<example>` matches the fingerprint it is attached to.
///
/// This is the import's correctness proof: it exercises the Ruby-to-Rust flag
/// mapping against 4,529 strings Rapid7 curated.
#[test]
fn every_example_matches_its_own_fingerprint() {
    for example in EXAMPLES {
        let fp = &example.key.fingerprints()[example.index];
        assert!(
            compile(fp.pattern).is_match(example.input),
            "{} [{}] {} does not match {:?}",
            example.key.as_str(),
            example.index,
            fp.pattern,
            example.input
        );
    }
}

/// Every capture value upstream asserts is the value this crate resolves.
#[test]
fn every_example_yields_its_expected_parameters() {
    for example in EXAMPLES {
        let fp = &example.key.fingerprints()[example.index];
        let captures = compile(fp.pattern)
            .captures(example.input)
            .unwrap_or_else(|| panic!("{}: {:?}", fp.pattern, example.input));
        for (field, expected) in example.expected {
            let Some(param) = fp.params.iter().find(|p| p.field == *field) else {
                panic!("{}: no param for {}", fp.pattern, field.as_str());
            };
            if param.pos == 0 {
                // A literal or an interpolation; the literal case is checkable.
                if !param.value.contains('{') {
                    assert_eq!(param.value, *expected, "{}", fp.pattern);
                }
                continue;
            }
            let got = captures
                .get(usize::from(param.pos))
                .map(|m| m.as_str().trim())
                .unwrap_or_default();
            // The matcher trims captures; a handful of upstream examples record
            // the untrimmed group (Sendmail's AIX version carries a leading space).
            assert_eq!(got, expected.trim(), "{} group {}", fp.pattern, param.pos);
        }
    }
}

/// How often an earlier pattern in the same key claims a later fingerprint's
/// example. Recog resolves first-match-wins, so a shadow is a precedence fact,
/// not an import bug — but at this HEAD exactly one of 4,529 examples is
/// shadowed, so the tables are effectively unambiguous. Pinned so a
/// regeneration that makes them ambiguous is noticed.
#[test]
fn example_shadowing_is_bounded() {
    let mut shadowed = 0usize;
    for example in EXAMPLES {
        let m = identify(example.key, example.input);
        if m.is_none_or(|m| m.index != example.index) {
            shadowed += 1;
        }
    }
    assert!(
        shadowed <= 1,
        "{shadowed} of {} examples are claimed by an earlier pattern",
        EXAMPLES.len()
    );
}

/// The device vocabulary is a closed upstream enumeration, which is what makes
/// it safe to map to `DeviceType`. Guard against it turning into free text.
#[test]
fn device_classes_are_a_small_vocabulary() {
    let classes: BTreeSet<&str> = RecogKey::ALL
        .into_iter()
        .flat_map(RecogKey::fingerprints)
        .flat_map(|f| f.params)
        .filter(|p| matches!(p.field, RecogField::OsDevice | RecogField::HwDevice) && p.pos == 0)
        .map(|p| p.value)
        .collect();
    assert!(
        classes.len() < 120,
        "{} distinct device classes upstream",
        classes.len()
    );
    assert!(classes.contains("Printer"));
    assert!(classes.contains("IP Camera"));
}
