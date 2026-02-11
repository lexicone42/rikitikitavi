pub mod attack_paths;
pub mod comparison;
pub mod priority_actions;
pub mod risk_score;

pub use attack_paths::generate_attack_paths;
pub use comparison::diff_scan_results;
pub use priority_actions::generate_priority_actions;
pub use risk_score::{calculate_risk_score, risk_grade};
