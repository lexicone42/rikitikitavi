#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_network::wifi_frames::{parse_frame, parse_radiotap};

fuzz_target!(|data: &[u8]| {
    let _ = parse_radiotap(data);
    let _ = parse_frame(data);
});
