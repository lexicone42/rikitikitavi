#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{eol_db, ha_discovery_db};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mid = text.len() / 2;
    let mid = (0..=mid).rev().find(|&i| text.is_char_boundary(i)).unwrap_or(0);
    let (a, b) = text.split_at(mid);
    let _ = ha_discovery_db::glob_match(a, b);
    let _ = ha_discovery_db::glob_match(b, a);
    let txt = vec![a.to_owned(), b.to_owned()];
    let _ = ha_discovery_db::zeroconf_domains(a, b, &txt);
    let _ = ha_discovery_db::homekit_domain(a);
    let _ = ha_discovery_db::mac_prefix_match(a);
    let _ = eol_db::lookup(a, b);
    let _ = eol_db::cycle(a, b);
    let _ = eol_db::current(a);
});
