pub mod arp;
pub mod external;
pub mod interfaces;
pub mod mdns;
pub mod wifi;

pub use interfaces::{detect_gateway, list_interfaces, NetworkInterface};
