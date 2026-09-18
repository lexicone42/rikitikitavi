/// Build a `Vec<String>` of reference URLs from string literals.
macro_rules! refs {
    ($($url:expr),+ $(,)?) => {
        vec![$($url.to_owned()),+]
    };
}

pub mod remediation;
pub mod traits;

pub mod arp;
pub mod cast;
pub mod credentials;
pub mod database;
pub mod device;
pub mod dhcp;
pub mod dns;
pub mod exposure;
pub mod http_audit;
pub mod http_util;
pub mod isolation;
pub mod kasa;
pub mod mdns;
pub mod mgmt_plane;
pub mod modbus;
pub mod mqtt;
pub mod neighbor;
pub mod network;
pub mod oui_db;
pub mod papercut;
#[cfg(feature = "monitor")]
pub mod passive_wifi;
pub mod ports;
pub mod printers;
pub mod router;
pub mod rtsp;
pub mod sadp;
pub mod services;
pub mod smb;
pub mod snmp;
pub mod ssl;
pub mod tr069;
pub mod tuya;
pub mod upnp_igd;
pub mod wifi;

pub use traits::{Scanner, ScannerRegistry};
