#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::http_audit::{
    analyze_cookies, analyze_cors, analyze_csp, classify_http_methods, classify_nas_ha,
    classify_server_header, detect_framework, is_default_page, is_directory_listing, parse_csp,
    parse_set_cookie,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let ip = std::net::IpAddr::from([10, 0, 0, 7]);
    let _ = parse_csp(&text);
    let _ = analyze_csp(ip, 443, &text, data.len() % 2 == 0);
    let cookies: Vec<_> = text.lines().map(parse_set_cookie).collect();
    let _ = analyze_cookies(ip, 443, data.len() % 2 == 0, &cookies);
    let _ = analyze_cors(ip, 443, Some(&text), data.len() % 2 == 0);
    let _ = classify_http_methods(ip, 80, &text);
    let _ = classify_server_header(ip, 80, &text);
    let _ = classify_nas_ha(ip, 80, Some(&text), &text);
    let _ = detect_framework(ip, 80, Some(&text), &text);
    let _ = is_default_page(&text);
    let _ = is_directory_listing(&text);
});
