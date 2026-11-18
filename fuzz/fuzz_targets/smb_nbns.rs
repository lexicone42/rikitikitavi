#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rikitikitavi_scanners::smb::fuzz::response(data);
    // First two bytes double as the transaction id the reply must echo.
    let id = data.get(..2).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let _ = rikitikitavi_network::nbns::parse_node_status(data, id);
});
