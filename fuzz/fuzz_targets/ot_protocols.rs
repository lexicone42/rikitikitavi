#![no_main]
use libfuzzer_sys::fuzz_target;
use rikitikitavi_scanners::{knx, modbus, sadp};

fuzz_target!(|data: &[u8]| {
    modbus::fuzz::response(data);
    let _ = modbus::fuzz::registers(data);
    let _ = modbus::fuzz::device_id(data);
    let regs: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let _ = modbus::fuzz::common_model(&regs);
    let _ = knx::fuzz::search_response(data);
    let text = String::from_utf8_lossy(data);
    let _ = sadp::fuzz::probe_match(&text);
    let _ = sadp::fuzz::firmware(&text);
});
