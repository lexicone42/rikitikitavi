pub mod attack_paths;
pub mod comparison;
pub mod exploit_intel;
pub mod history;
pub mod kev_db;
pub mod priority_actions;
pub mod risk_score;

pub use attack_paths::generate_attack_paths;
pub use comparison::{ScanDiff, SeverityChange, diff_scan_results};
pub use exploit_intel::enrich_exploit_intelligence;
pub use history::ScanHistory;
pub use kev_db::is_kev;
pub use priority_actions::generate_priority_actions;
pub use risk_score::{calculate_risk_score, risk_grade};
