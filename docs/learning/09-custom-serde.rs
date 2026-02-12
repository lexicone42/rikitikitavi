// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #9: Custom Serde Serialization (OCSF Export)
// ============================================================================
//
// This file explains how rikitikitavi uses custom serde serializers to
// produce OCSF-compliant JSON for AWS Security Lake. The key Rust concepts:
// serde attributes, custom serialize/deserialize functions, and the From trait.
//
// ── THE PROBLEM ─────────────────────────────────────────────────────────────
//
// OCSF (Open Cybersecurity Schema Framework) requires timestamps as epoch
// milliseconds (i64), not RFC 3339 strings. Chrono's `DateTime<Utc>` defaults
// to serializing as "2026-02-12T10:30:00Z". We need 1739353800000.
//
// We also need to map our internal types (Finding, Severity) to OCSF's
// specific field names and numeric codes.
//
// ── CUSTOM SERIALIZE FUNCTIONS ──────────────────────────────────────────────
//
// Serde lets you override serialization for individual fields:
//
//   use chrono::{DateTime, Utc};
//   use serde::{Serialize, Serializer, Deserialize, Deserializer};
//
//   fn serialize_epoch_ms<S: Serializer>(
//       dt: &DateTime<Utc>,
//       serializer: S,
//   ) -> Result<S::Ok, S::Error> {
//       serializer.serialize_i64(dt.timestamp_millis())
//   }
//
//   fn deserialize_epoch_ms<'de, D: Deserializer<'de>>(
//       deserializer: D,
//   ) -> Result<DateTime<Utc>, D::Error> {
//       let ms = i64::deserialize(deserializer)?;
//       DateTime::from_timestamp_millis(ms)
//           .ok_or_else(|| serde::de::Error::custom("invalid epoch ms"))
//   }
//
// The `S: Serializer` generic means this works with ANY output format —
// JSON, MessagePack, CBOR, etc. Serde's architecture is format-agnostic.
//
// ── APPLYING CUSTOM SERIALIZATION ───────────────────────────────────────────
//
// Use the `#[serde(serialize_with = "...")]` attribute on fields:
//
//   #[derive(Serialize, Deserialize)]
//   pub struct OcsfFinding {
//       /// Epoch milliseconds, not RFC 3339 string
//       #[serde(serialize_with = "serialize_epoch_ms")]
//       #[serde(deserialize_with = "deserialize_epoch_ms")]
//       pub time: DateTime<Utc>,
//
//       /// Same for metadata.modified_time
//       #[serde(serialize_with = "serialize_epoch_ms")]
//       #[serde(deserialize_with = "deserialize_epoch_ms")]
//       pub modified_time: DateTime<Utc>,
//   }
//
// Now `serde_json::to_string(&ocsf)` produces:
//   { "time": 1739353800000, "modified_time": 1739353800000, ... }
//
// Instead of:
//   { "time": "2026-02-12T10:30:00Z", ... }
//
// ── THE FROM TRAIT ──────────────────────────────────────────────────────────
//
// Rust's `From` trait expresses type conversions. We implement
// `From<&Finding> for OcsfFinding`:
//
//   impl From<&Finding> for OcsfFinding {
//       fn from(f: &Finding) -> Self {
//           // Build resources from finding's IP/port
//           let mut resources = Vec::new();
//           if let Some(ip) = &f.affected_ip {
//               resources.push(OcsfResource {
//                   uid: ip.to_string(),
//                   r#type: "IP Address".to_owned(),
//                   // ...
//               });
//           }
//
//           Self {
//               class_uid: 2002,
//               severity_id: f.severity.ocsf_id(),
//               time: f.discovered_at,
//               // ...
//           }
//       }
//   }
//
// Key points:
// - `From<&Finding>` takes a REFERENCE (no ownership transfer)
// - This also gives you `Into<OcsfFinding>` for free (Rust's blanket impl)
// - The conversion is explicit and documented — not a lossy cast
//
// ── SERDE RENAME AND SKIP ───────────────────────────────────────────────────
//
// OCSF field names don't always match Rust conventions:
//
//   #[derive(Serialize)]
//   pub struct OcsfFinding {
//       pub class_uid: u32,           // Already snake_case, matches OCSF
//
//       #[serde(skip_serializing_if = "Option::is_none")]
//       pub risk_score: Option<f64>,  // Omit from JSON if None
//
//       #[serde(skip_serializing_if = "Vec::is_empty")]
//       pub vulnerabilities: Vec<OcsfVulnerability>,  // Omit if empty
//   }
//
// `skip_serializing_if` keeps the JSON clean — OCSF consumers shouldn't
// see `"risk_score": null` or `"vulnerabilities": []` for every record.
//
// ── r#type: RAW IDENTIFIERS ─────────────────────────────────────────────────
//
// OCSF has a field called "type", which is a Rust keyword. Solution:
//
//   pub struct OcsfResource {
//       pub r#type: String,    // "type" as a field name
//   }
//
// The `r#` prefix is a "raw identifier" — it tells the compiler to treat
// a keyword as a regular identifier. In the JSON output, serde correctly
// serializes it as "type" (without the r# prefix).
//
// ── NDJSON FORMAT ───────────────────────────────────────────────────────────
//
// NDJSON (Newline-Delimited JSON) is one JSON object per line:
//
//   {"class_uid":2002,"severity_id":4,"time":1739353800000,...}
//   {"class_uid":2002,"severity_id":2,"time":1739353800000,...}
//   {"class_uid":2002,"severity_id":3,"time":1739353800000,...}
//
// Each line is a complete, valid JSON object. This format is preferred by
// AWS Glue, Athena, and Spark because it's:
// - Splittable: each line can be processed independently
// - Streamable: no need to buffer the entire array in memory
// - Appendable: just add more lines
//
// In Rust:
//
//   pub fn to_ocsf_ndjson(results: &ScanResults) -> Result<String> {
//       let mut buf = String::new();
//       for finding in &results.findings {
//           let ocsf = OcsfFinding::from(finding);
//           let line = serde_json::to_string(&ocsf)?;
//           buf.push_str(&line);
//           buf.push('\n');
//       }
//       Ok(buf)
//   }
//
// Note: `serde_json::to_string` (not `to_string_pretty`) gives compact
// single-line JSON. Each finding becomes exactly one line.
//
// ── TESTING SERIALIZATION ───────────────────────────────────────────────────
//
// We can test the epoch-ms roundtrip with proptest:
//
//   proptest! {
//       #[test]
//       fn prop_epoch_ms_roundtrip(ms in 0_i64..4_000_000_000_000) {
//           let dt = DateTime::from_timestamp_millis(ms).unwrap();
//           let ocsf = OcsfFinding { time: dt, ... };
//           let json = serde_json::to_string(&ocsf).unwrap();
//           let back: OcsfFinding = serde_json::from_str(&json).unwrap();
//           assert_eq!(ocsf.time, back.time);
//       }
//   }
//
// This generates thousands of random timestamps and verifies they survive
// serialize → deserialize without drift.
//
// ── KEY TAKEAWAYS ───────────────────────────────────────────────────────────
//
// 1. Custom serde functions let you control exactly how fields serialize
//    without changing the Rust type (DateTime stays DateTime, but JSON gets i64)
// 2. The From trait is the idiomatic way to express type conversions
// 3. skip_serializing_if keeps output clean for optional/empty fields
// 4. r#keyword lets you use reserved words as identifiers
// 5. NDJSON is just "one serde_json::to_string per line" — trivial in Rust
// 6. Property tests catch serialization edge cases (negative timestamps,
//    year 2038 overflow, etc.)

fn main() {
    println!("Read the comments above to learn about custom serde and OCSF export.");
}
