#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::http_audit::{
    is_default_page, is_directory_listing, parse_csp, parse_set_cookie,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_csp(&text);
    let _ = parse_set_cookie(&text);
    let _ = is_default_page(&text);
    let _ = is_directory_listing(&text);
});
