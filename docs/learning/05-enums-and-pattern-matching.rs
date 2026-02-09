// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #5: Enums & Pattern Matching
// ============================================================================
//
// Rust enums are way more powerful than enums in C/Java. Each variant
// can hold different data. Combined with `match`, they're one of Rust's
// most powerful features.

use serde::{Deserialize, Serialize};

// ── BASIC ENUM (like C enums) ─────────────────────────────────────────────

/// Our severity levels — simple variants with no data attached.
/// The derive macros auto-generate useful trait implementations.
#[derive(Debug,          // Enables {:?} formatting
         Clone, Copy,    // Can be duplicated (cheap for small types)
         PartialEq, Eq,  // Can be compared with ==
         PartialOrd, Ord, // Can be compared with <, >, sorted
         Serialize, Deserialize)] // Can be serialized to/from JSON/YAML
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// ── ENUM WITH DATA (algebraic data types / tagged unions) ─────────────────

/// Network mode — each variant holds different data.
/// This is much more powerful than a C enum!
#[derive(Debug, Clone)]
pub enum NetworkMode {
    Auto,                                          // No data
    Wifi { ssid: String, password: Option<String> }, // Named fields
    Ethernet { interface: Option<String> },         // Named fields
    External { proxy: Option<String> },             // Named fields
}

// Compare this to how you'd do it in C:
//   enum NetworkMode { AUTO, WIFI, ETHERNET, EXTERNAL };
//   struct NetworkConfig {
//       enum NetworkMode mode;
//       char* ssid;          // Only valid if mode == WIFI
//       char* password;      // Only valid if mode == WIFI
//       char* interface;     // Only valid if mode == ETHERNET
//       char* proxy;         // Only valid if mode == EXTERNAL
//   };
// In C, you can accidentally access ssid when mode is ETHERNET.
// In Rust, the compiler makes this impossible!

// ── PATTERN MATCHING WITH match ───────────────────────────────────────────

fn describe_severity(sev: Severity) -> &'static str {
    // `match` is like switch but WAY more powerful:
    // 1. It's exhaustive — you MUST handle every variant (or use _)
    // 2. It can destructure data from variants
    // 3. It's an expression (returns a value)
    match sev {
        Severity::Info => "Informational",
        Severity::Low => "Low risk",
        Severity::Medium => "Moderate risk",
        Severity::High => "High risk — action needed",
        Severity::Critical => "CRITICAL — immediate action required",
    }
    // If you add a new variant to Severity, the compiler will ERROR
    // here until you handle it. This prevents bugs when extending enums!
}

fn describe_network(mode: &NetworkMode) {
    match mode {
        // Destructure the data inside each variant:
        NetworkMode::Auto => println!("Auto-detecting network"),

        NetworkMode::Wifi { ssid, password } => {
            println!("WiFi mode: SSID={ssid}");
            // `password` is an Option<String>, so we can match on it too:
            match password {
                Some(p) => println!("  Password: {}", "*".repeat(p.len())),
                None => println!("  No password (open network)"),
            }
        }

        NetworkMode::Ethernet { interface: Some(iface) } => {
            //                             ^^^^^^^^^^^ nested pattern!
            println!("Ethernet on interface: {iface}");
        }
        NetworkMode::Ethernet { interface: None } => {
            println!("Ethernet (auto-detect interface)");
        }

        NetworkMode::External { proxy } => {
            if let Some(p) = proxy {
                //  ↑ `if let` is shorthand for a match with one pattern
                println!("External via proxy: {p}");
            } else {
                println!("External (direct)");
            }
        }
    }
}

// ── Option<T> — Rust's null replacement ───────────────────────────────────
//
// Rust has no null/nil. Instead, it uses Option<T>:
//   - Some(value) — a value is present
//   - None — no value
//
// This forces you to handle the "no value" case at compile time.

fn find_device_hostname(mac: &str) -> Option<String> {
    // Simulating a lookup
    match mac {
        "aa:bb:cc:dd:ee:ff" => Some("my-laptop".to_string()),
        _ => None,  // Unknown device — no hostname
    }
}

fn demo_option() {
    let hostname = find_device_hostname("aa:bb:cc:dd:ee:ff");

    // You can't just use hostname directly — it might be None!
    // println!("{hostname}");  // ERROR: Option doesn't implement Display

    // Method 1: match
    match &hostname {
        Some(name) => println!("Device: {name}"),
        None => println!("Unknown device"),
    }

    // Method 2: if let (when you only care about one case)
    if let Some(name) = &hostname {
        println!("Found: {name}");
    }

    // Method 3: unwrap_or (provide a default)
    let name = hostname.as_deref().unwrap_or("unknown");
    println!("Name: {name}");

    // Method 4: map (transform the inner value if present)
    let upper = find_device_hostname("aa:bb:cc:dd:ee:ff")
        .map(|n| n.to_uppercase());
    println!("Upper: {upper:?}");  // Some("MY-LAPTOP")
}

fn main() {
    println!("Severity: {}", describe_severity(Severity::Critical));

    let wifi = NetworkMode::Wifi {
        ssid: "HomeNetwork".to_string(),
        password: Some("secret123".to_string()),
    };
    describe_network(&wifi);

    let auto = NetworkMode::Auto;
    describe_network(&auto);

    demo_option();
}
