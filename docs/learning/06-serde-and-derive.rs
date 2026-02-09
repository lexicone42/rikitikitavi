// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #6: Serde & Derive Macros
// ============================================================================
//
// `serde` is Rust's serialization/deserialization framework. It lets you
// convert Rust structs to/from JSON, YAML, TOML, and more. Combined with
// derive macros, it's incredibly ergonomic.

use serde::{Deserialize, Serialize};

// ── DERIVE MACROS ─────────────────────────────────────────────────────────
//
// `#[derive(...)]` auto-generates trait implementations. Instead of writing
// hundreds of lines of boilerplate, the compiler generates it for you.

/// A network device discovered during scanning.
#[derive(Debug,                  // Enables println!("{:?}", device)
         Clone,                  // Enables device.clone()
         Serialize,              // Enables serde_json::to_string(&device)
         Deserialize)]           // Enables serde_json::from_str::<Device>(json)
pub struct Device {
    pub ip: String,
    pub mac: Option<String>,       // Option = nullable field
    pub hostname: Option<String>,
    pub device_type: DeviceType,
    pub open_ports: Vec<u16>,      // Dynamic array of port numbers
}

/// Device classification with serde rename.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
//      ↑ This means variants serialize as "smart_tv" not "SmartTv"
pub enum DeviceType {
    Router,
    Desktop,
    Laptop,
    Phone,
    SmartTv,    // Serializes as "smart_tv" due to rename_all
    IoT,        // Serializes as "io_t" (hmm, not perfect!)
    Printer,
    Unknown,
}

// ── SERDE IN ACTION ───────────────────────────────────────────────────────

fn serialization_demo() {
    let device = Device {
        ip: "192.168.1.100".to_string(),
        mac: Some("AA:BB:CC:DD:EE:FF".to_string()),
        hostname: Some("my-laptop".to_string()),
        device_type: DeviceType::Laptop,
        open_ports: vec![22, 80, 443],
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&device).unwrap();
    println!("JSON:\n{json}");
    // Output:
    // {
    //   "ip": "192.168.1.100",
    //   "mac": "AA:BB:CC:DD:EE:FF",
    //   "hostname": "my-laptop",
    //   "device_type": "laptop",
    //   "open_ports": [22, 80, 443]
    // }

    // Deserialize from JSON
    let json_str = r#"{"ip":"10.0.0.1","mac":null,"hostname":null,"device_type":"router","open_ports":[]}"#;
    let router: Device = serde_json::from_str(json_str).unwrap();
    println!("\nDeserialized: {:?}", router);
}

// ── SERDE ATTRIBUTES ──────────────────────────────────────────────────────
//
// Serde has many attributes to control serialization:

/// App config showing common serde patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]  // Use Default::default() for missing fields
pub struct AppConfig {
    /// Name of the organization.
    pub name: String,

    /// Scan timeout — renamed in serialized form.
    #[serde(rename = "timeout_seconds")]
    pub timeout: u64,

    /// API key — skipped during serialization (don't leak secrets!).
    #[serde(skip_serializing)]
    pub api_key: Option<String>,

    /// Log level with a default value.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            timeout: 300,
            api_key: None,
            log_level: "info".to_string(),
        }
    }
}

// ── TAGGED ENUMS ──────────────────────────────────────────────────────────
//
// Serde can serialize enums in different ways. We use "internally tagged"
// for NetworkMode so the JSON looks natural:

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
//      ↑ The "type" field determines which variant to deserialize
pub enum NetworkMode {
    Auto,
    Wifi { ssid: String },
    Ethernet { interface: Option<String> },
}

fn tagged_enum_demo() {
    let wifi = NetworkMode::Wifi { ssid: "HomeNet".to_string() };
    let json = serde_json::to_string_pretty(&wifi).unwrap();
    println!("Tagged enum:\n{json}");
    // Output:
    // {
    //   "type": "wifi",        ← tag field
    //   "ssid": "HomeNet"      ← variant data
    // }

    // Deserialize back:
    let from_json = r#"{"type": "ethernet", "interface": "eth0"}"#;
    let mode: NetworkMode = serde_json::from_str(from_json).unwrap();
    println!("Deserialized: {:?}", mode);
}

fn main() {
    serialization_demo();
    println!();
    tagged_enum_demo();
}
