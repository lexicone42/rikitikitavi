use super::*;
use rikitikitavi_models::DeviceType;

/// A row's sort key mirrors the generator's: (vendor, service, user, password).
fn key(c: &DefaultCred) -> (&str, u8, &str, &str) {
    let svc = match c.service {
        CredService::Any => 0,
        CredService::Telnet => 1,
        CredService::Ftp => 2,
        CredService::HttpAdmin => 3,
    };
    (c.vendor.unwrap_or(""), svc, c.username, c.password)
}

#[test]
fn corpus_is_non_empty_and_counts_match() {
    assert_eq!(DEFAULT_CREDS.len(), DEFAULT_CRED_COUNT);
    assert_eq!(SNMP_COMMUNITIES.len(), SNMP_COMMUNITY_COUNT);
    assert!(!DEFAULT_CREDS.is_empty());
    assert!(!SNMP_COMMUNITIES.is_empty());
}

#[test]
fn creds_are_sorted() {
    for pair in DEFAULT_CREDS.windows(2) {
        assert!(
            key(&pair[0]) <= key(&pair[1]),
            "unsorted: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn creds_have_no_duplicate_rows() {
    let mut seen = std::collections::BTreeSet::new();
    for c in DEFAULT_CREDS {
        assert!(
            seen.insert((c.vendor, c.service, c.username, c.password)),
            "duplicate row: {c:?}"
        );
    }
}

#[test]
fn usernames_are_never_empty() {
    // A blank password is valid; a blank username is a corpus error.
    for c in DEFAULT_CREDS {
        assert!(!c.username.is_empty(), "empty username: {c:?}");
        assert!(!c.source.is_empty(), "empty source: {c:?}");
    }
}

#[test]
fn vendor_tokens_are_lowercase_and_trimmed() {
    for c in DEFAULT_CREDS {
        if let Some(v) = c.vendor {
            assert_eq!(v, v.to_ascii_lowercase(), "vendor not lowercase: {v}");
            assert_eq!(v, v.trim(), "vendor not trimmed: {v}");
            assert!(!v.is_empty(), "empty vendor token");
        }
    }
}

#[test]
fn corpus_carries_both_generic_and_vendor_rows() {
    assert!(DEFAULT_CREDS.iter().any(|c| c.vendor.is_none()));
    assert!(DEFAULT_CREDS.iter().any(|c| c.vendor.is_some()));
}

#[test]
fn snmp_communities_are_sorted_and_unique() {
    for w in SNMP_COMMUNITIES.windows(2) {
        assert!(w[0] < w[1], "snmp not sorted/unique: {} {}", w[0], w[1]);
    }
    // The two canonical defaults must be present.
    assert!(SNMP_COMMUNITIES.contains(&"public"));
    assert!(SNMP_COMMUNITIES.contains(&"private"));
}

#[test]
fn covers_is_reflexive_and_any_covers_all() {
    for svc in [
        CredService::Any,
        CredService::Telnet,
        CredService::Ftp,
        CredService::HttpAdmin,
    ] {
        assert!(svc.covers(svc), "not reflexive: {svc:?}");
        assert!(CredService::Any.covers(svc), "Any must cover {svc:?}");
    }
    // A specific service does not cover a different specific service.
    assert!(!CredService::Telnet.covers(CredService::Ftp));
    assert!(!CredService::Ftp.covers(CredService::HttpAdmin));
    // A specific service never covers Any.
    assert!(!CredService::Telnet.covers(CredService::Any));
}

#[test]
fn every_class_note_resolves_and_no_class_repeats() {
    let mut seen: Vec<DeviceType> = Vec::new();
    for (dt, note) in DEFAULT_CRED_CLASSES {
        assert!(!note.is_empty());
        assert!(!seen.contains(dt), "class repeated: {dt:?}");
        seen.push(*dt);
        assert_eq!(class_default_note(*dt), Some(*note));
    }
    // A class that does not ship defaults resolves to None.
    assert_eq!(class_default_note(DeviceType::Desktop), None);
}

#[test]
fn every_vendor_token_is_resolvable_from_a_realistic_vendor_string() {
    // A device vendor string is matched by case-insensitive substring, so each
    // token must survive lowercasing the way the scanner performs the match.
    for c in DEFAULT_CREDS {
        if let Some(token) = c.vendor {
            let realistic = format!("{} Systems, Inc.", token.to_ascii_uppercase());
            assert!(
                realistic.to_ascii_lowercase().contains(token),
                "token {token} would not match {realistic}"
            );
        }
    }
}
