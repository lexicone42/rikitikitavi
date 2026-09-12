//! Canonical MAC-address newtype.
//! Parses colon, hyphen, dotted and bare-hex forms (any case) into six octets,
//! so equal addresses compare, hash and serialize identically.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 48-bit hardware (MAC) address, stored as canonical octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Construct from raw octets.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The six octets.
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// The 3-byte OUI prefix (manufacturer identifier).
    #[must_use]
    pub const fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// The all-ones broadcast address `ff:ff:ff:ff:ff:ff`.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        matches!(self.0, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// The all-zero address `00:00:00:00:00:00` (unset / incomplete ARP entry).
    #[must_use]
    pub const fn is_unspecified(&self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }

    /// Group bit (LSB of octet 0) set: multicast address.
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Locally-administered bit (0x02 of octet 0) set: randomized MAC, no OUI vendor.
    #[must_use]
    pub const fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

/// Error returned when a string cannot be parsed as a MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMacError;

impl fmt::Display for ParseMacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address")
    }
}

impl std::error::Error for ParseMacError {}

impl FromStr for MacAddr {
    type Err = ParseMacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strip separators; require exactly 12 hex nibbles.
        let hex: String = s
            .chars()
            .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
            .collect();
        if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseMacError);
        }
        let mut octets = [0u8; 6];
        for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|_| ParseMacError)?;
            octets[i] = u8::from_str_radix(pair, 16).map_err(|_| ParseMacError)?;
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let o = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            o[0], o[1], o[2], o[3], o[4], o[5]
        )
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Canonical `aa:bb:cc:dd:ee:ff` string.
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_form() {
        let m: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(m.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn normalizes_across_formats_and_case() {
        // All forms of one address.
        let forms = [
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabb.ccdd.eeff",
            "AABBCCDDEEFF",
            "aa:bb:cc:dd:ee:ff",
        ];
        let parsed: Vec<MacAddr> = forms.iter().map(|s| s.parse().unwrap()).collect();
        for m in &parsed {
            assert_eq!(*m, parsed[0], "all textual forms must parse equal");
        }
        // Canonical lowercase rendering.
        assert_eq!(parsed[0].to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn display_roundtrips_through_parse() {
        let m: MacAddr = "01:23:45:67:89:ab".parse().unwrap();
        assert_eq!(m.to_string().parse::<MacAddr>().unwrap(), m);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "gg:bb:cc:dd:ee:ff",
            "aabbccddeeff00",
            "xyz",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn classifies_special_addresses() {
        assert!(
            "ff:ff:ff:ff:ff:ff"
                .parse::<MacAddr>()
                .unwrap()
                .is_broadcast()
        );
        assert!(
            "00:00:00:00:00:00"
                .parse::<MacAddr>()
                .unwrap()
                .is_unspecified()
        );
        assert!(
            "01:00:5e:00:00:01"
                .parse::<MacAddr>()
                .unwrap()
                .is_multicast()
        );
        assert!(
            !"aa:bb:cc:dd:ee:ff"
                .parse::<MacAddr>()
                .unwrap()
                .is_broadcast()
        );
    }

    #[test]
    fn detects_locally_administered_randomized_macs() {
        // Vendor OUIs: bit clear.
        assert!(
            !"a4:83:e7:1a:2b:3c"
                .parse::<MacAddr>()
                .unwrap()
                .is_locally_administered()
        ); // Apple
        assert!(
            !"68:d7:9a:00:00:01"
                .parse::<MacAddr>()
                .unwrap()
                .is_locally_administered()
        ); // Ubiquiti
        // Randomized MACs: bit set.
        assert!(
            "aa:bb:cc:dd:ee:ff"
                .parse::<MacAddr>()
                .unwrap()
                .is_locally_administered()
        );
        assert!(
            "06:00:00:00:00:01"
                .parse::<MacAddr>()
                .unwrap()
                .is_locally_administered()
        );
    }

    #[test]
    fn oui_is_first_three_octets() {
        let m: MacAddr = "3c:22:fb:11:22:33".parse().unwrap();
        assert_eq!(m.oui(), [0x3c, 0x22, 0xfb]);
    }

    #[test]
    fn serializes_as_canonical_string() {
        let m: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"aa:bb:cc:dd:ee:ff\"");
        let back: MacAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }
}
