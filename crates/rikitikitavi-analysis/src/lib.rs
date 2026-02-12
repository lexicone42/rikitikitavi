pub mod attack_paths;
pub mod comparison;
pub mod history;
pub mod priority_actions;
pub mod risk_score;

pub use attack_paths::generate_attack_paths;
pub use comparison::{diff_scan_results, ScanDiff, SeverityChange};
pub use history::ScanHistory;
pub use priority_actions::generate_priority_actions;
pub use risk_score::{calculate_risk_score, risk_grade};
