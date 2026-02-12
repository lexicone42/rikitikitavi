use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use rikitikitavi_core::Severity;
use rikitikitavi_models::{Device, Finding, ScanResults};

/// Which screen the TUI is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    NetworkMap,
    Findings,
    AttackPaths,
    TopActions,
    DeviceDetail,
}

/// Clickable regions recorded during the last render pass.
/// Used by the mouse handler to map click coordinates to actions.
#[derive(Debug, Default)]
pub struct HitRegions {
    /// Footer tab buttons: (area, screen to switch to).
    pub footer_tabs: Vec<(Rect, Screen)>,
    /// The main scrollable list/table area (for row selection).
    pub list_area: Option<Rect>,
    /// Number of header rows before the first data row in the list.
    pub list_header_offset: u16,
}

/// TUI launch configuration.
#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub theme: Theme,
    pub watch_mode: bool,
    pub watch_interval_secs: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            watch_mode: false,
            watch_interval_secs: 300,
        }
    }
}

/// Color theme for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Hacker,
    Accessible,
}

/// Controls which severity levels are shown in the findings list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityFilter {
    /// Show only Critical, High, and Medium findings (default).
    #[default]
    ActionableOnly,
    /// Show all findings including Low and Info.
    All,
}

/// Central application state for the TUI.
pub struct App {
    pub screen: Screen,
    pub config: TuiConfig,
    pub results: Option<ScanResults>,
    pub selected_finding_index: usize,
    pub selected_device_index: usize,
    pub selected_device: Option<Device>,
    pub scanning: bool,
    pub scan_progress: f64,
    pub scan_status: String,
    pub should_quit: bool,
    pub status_message: Option<String>,
    /// Clickable regions from the last render — used by `handle_mouse`.
    pub hit_regions: HitRegions,
    /// Severity filter for findings display.
    pub severity_filter: SeverityFilter,
    /// Stateful table state for findings list (tracks scroll offset + selection).
    pub findings_table_state: TableState,
    /// Stateful table state for device lists (dashboard / network map).
    pub devices_table_state: TableState,
    /// Animation tick counter — incremented each event loop iteration (~100ms).
    pub tick: u64,
}

impl App {
    pub fn new(config: TuiConfig) -> Self {
        let mut findings_table_state = TableState::default();
        findings_table_state.select(Some(0));
        let mut devices_table_state = TableState::default();
        devices_table_state.select(Some(0));
        Self {
            screen: Screen::Dashboard,
            config,
            results: None,
            selected_finding_index: 0,
            selected_device_index: 0,
            selected_device: None,
            scanning: false,
            scan_progress: 0.0,
            scan_status: String::new(),
            should_quit: false,
            status_message: None,
            hit_regions: HitRegions::default(),
            severity_filter: SeverityFilter::default(),
            findings_table_state,
            devices_table_state,
            tick: 0,
        }
    }

    /// Handle keyboard input and update state.
    /// Returns true if a re-scan was requested.
    pub fn handle_key(&mut self, key: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('n') => self.screen = Screen::NetworkMap,
            KeyCode::Char('f') => self.screen = Screen::Findings,
            KeyCode::Char('a') => self.screen = Screen::AttackPaths,
            KeyCode::Char('t') => self.screen = Screen::TopActions,
            KeyCode::Char('s') if !self.scanning => {
                self.scanning = true;
                "Scanning...".clone_into(&mut self.scan_status);
                self.status_message = Some("Re-scan triggered".to_owned());
                return true;
            }
            KeyCode::Char('l') => {
                self.severity_filter = match self.severity_filter {
                    SeverityFilter::ActionableOnly => SeverityFilter::All,
                    SeverityFilter::All => SeverityFilter::ActionableOnly,
                };
                // Reset selection when filter changes
                self.selected_finding_index = 0;
                self.findings_table_state.select(Some(0));
                *self.findings_table_state.offset_mut() = 0;
            }
            KeyCode::Char('e') => {
                self.export_results();
            }
            KeyCode::Enter => {
                self.enter_detail();
            }
            KeyCode::Esc => {
                if self.screen == Screen::DeviceDetail {
                    self.screen = Screen::Dashboard;
                    self.selected_device = None;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-20),
            KeyCode::PageDown => self.move_selection(20),
            KeyCode::Home => self.move_selection_to(0),
            KeyCode::End => self.move_selection_to(usize::MAX),
            KeyCode::Left | KeyCode::BackTab => self.prev_screen(),
            KeyCode::Right | KeyCode::Tab => self.next_screen(),
            _ => {}
        }
        false
    }

    /// Handle mouse input and update state.
    /// Returns true if a re-scan was requested (e.g. clicking a "Scan" button).
    pub fn handle_mouse(&mut self, event: crossterm::event::MouseEvent) -> bool {
        use crossterm::event::{MouseButton, MouseEventKind};

        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let col = event.column;
                let row = event.row;

                // Check footer tab clicks
                for &(area, screen) in &self.hit_regions.footer_tabs {
                    if area.contains((col, row).into()) {
                        self.screen = screen;
                        return false;
                    }
                }

                // Check list area clicks (select row)
                if let Some(list_area) = self.hit_regions.list_area {
                    if list_area.contains((col, row).into()) {
                        let clicked_row = row.saturating_sub(list_area.y)
                            .saturating_sub(self.hit_regions.list_header_offset);
                        let visual_row = clicked_row as usize;

                        match self.screen {
                            Screen::Findings => {
                                // Account for scroll offset — visible row 0 = offset
                                let offset = self.findings_table_state.offset();
                                let idx = offset + visual_row;
                                let max = self.filtered_findings().len().saturating_sub(1);
                                self.selected_finding_index = idx.min(max);
                                self.findings_table_state
                                    .select(Some(self.selected_finding_index));
                            }
                            Screen::Dashboard | Screen::NetworkMap => {
                                let offset = self.devices_table_state.offset();
                                let idx = offset + visual_row;
                                let max = self
                                    .results
                                    .as_ref()
                                    .map_or(0, |r| r.devices.len().saturating_sub(1));
                                self.selected_device_index = idx.min(max);
                                self.devices_table_state
                                    .select(Some(self.selected_device_index));
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Double-click enters detail
            MouseEventKind::Down(MouseButton::Right) => {
                self.enter_detail();
            }

            // Scroll wheel = move selection
            MouseEventKind::ScrollUp => self.move_selection(-1),
            MouseEventKind::ScrollDown => self.move_selection(1),

            _ => {}
        }
        false
    }

    /// Cycle to the next screen tab (Left arrow / Shift+Tab).
    fn prev_screen(&mut self) {
        self.screen = match self.screen {
            Screen::Dashboard => Screen::TopActions,
            Screen::NetworkMap => Screen::Dashboard,
            Screen::Findings => Screen::NetworkMap,
            Screen::AttackPaths => Screen::Findings,
            Screen::TopActions => Screen::AttackPaths,
            Screen::DeviceDetail => Screen::DeviceDetail, // Don't cycle out of detail
        };
    }

    /// Cycle to the next screen tab (Right arrow / Tab).
    fn next_screen(&mut self) {
        self.screen = match self.screen {
            Screen::Dashboard => Screen::NetworkMap,
            Screen::NetworkMap => Screen::Findings,
            Screen::Findings => Screen::AttackPaths,
            Screen::AttackPaths => Screen::TopActions,
            Screen::TopActions => Screen::Dashboard,
            Screen::DeviceDetail => Screen::DeviceDetail, // Don't cycle out of detail
        };
    }

    fn enter_detail(&mut self) {
        match self.screen {
            Screen::Dashboard | Screen::NetworkMap => {
                let devices = self.devices();
                if self.selected_device_index < devices.len() {
                    self.selected_device = Some(devices[self.selected_device_index].clone());
                    self.screen = Screen::DeviceDetail;
                }
            }
            _ => {}
        }
    }

    fn export_results(&mut self) {
        if let Some(results) = &self.results {
            let path = std::path::PathBuf::from("rikitikitavi-results.json");
            match rikitikitavi_export::export_json(results, &path) {
                Ok(()) => {
                    self.status_message = Some(format!("Exported to {}", path.display()));
                }
                Err(e) => {
                    self.status_message = Some(format!("Export failed: {e}"));
                }
            }
        } else {
            self.status_message = Some("No results to export".to_owned());
        }
    }

    fn move_selection(&mut self, delta: i32) {
        match self.screen {
            Screen::Findings => {
                let max = self.filtered_findings().len().saturating_sub(1);
                if delta < 0 {
                    self.selected_finding_index = self
                        .selected_finding_index
                        .saturating_sub(delta.unsigned_abs() as usize);
                } else {
                    self.selected_finding_index =
                        (self.selected_finding_index + usize::try_from(delta).unwrap_or(0)).min(max);
                }
                self.findings_table_state
                    .select(Some(self.selected_finding_index));
            }
            Screen::Dashboard | Screen::NetworkMap => {
                let max = self
                    .results
                    .as_ref()
                    .map_or(0, |r| r.devices.len().saturating_sub(1));
                if delta < 0 {
                    self.selected_device_index = self
                        .selected_device_index
                        .saturating_sub(delta.unsigned_abs() as usize);
                } else {
                    self.selected_device_index =
                        (self.selected_device_index + usize::try_from(delta).unwrap_or(0)).min(max);
                }
                self.devices_table_state
                    .select(Some(self.selected_device_index));
            }
            _ => {}
        }
    }

    /// Jump selection to an absolute index (clamped to list bounds).
    fn move_selection_to(&mut self, target: usize) {
        match self.screen {
            Screen::Findings => {
                let max = self.filtered_findings().len().saturating_sub(1);
                self.selected_finding_index = target.min(max);
                self.findings_table_state
                    .select(Some(self.selected_finding_index));
            }
            Screen::Dashboard | Screen::NetworkMap => {
                let max = self
                    .results
                    .as_ref()
                    .map_or(0, |r| r.devices.len().saturating_sub(1));
                self.selected_device_index = target.min(max);
                self.devices_table_state
                    .select(Some(self.selected_device_index));
            }
            _ => {}
        }
    }

    /// Get current findings (convenience accessor).
    pub fn findings(&self) -> &[Finding] {
        self.results.as_ref().map_or(&[], |r| r.findings.as_slice())
    }

    /// Get findings filtered and sorted by severity (Critical first).
    /// In `ActionableOnly` mode, excludes Low and Info findings.
    pub fn filtered_findings(&self) -> Vec<&Finding> {
        let mut filtered: Vec<&Finding> = self.findings().iter()
            .filter(|f| match self.severity_filter {
                SeverityFilter::ActionableOnly => {
                    matches!(f.severity, Severity::Critical | Severity::High | Severity::Medium)
                }
                SeverityFilter::All => true,
            })
            .collect();
        // Sort by severity descending (Critical first since Ord is Info < ... < Critical)
        filtered.sort_by(|a, b| b.severity.cmp(&a.severity));
        filtered
    }

    /// Get current devices (convenience accessor).
    pub fn devices(&self) -> &[Device] {
        self.results.as_ref().map_or(&[], |r| r.devices.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    fn test_app() -> App {
        App::new(TuiConfig::default())
    }

    #[test]
    fn test_screen_navigation() {
        let mut app = test_app();
        assert_eq!(app.screen, Screen::Dashboard);

        app.handle_key(KeyCode::Char('f'));
        assert_eq!(app.screen, Screen::Findings);

        app.handle_key(KeyCode::Char('n'));
        assert_eq!(app.screen, Screen::NetworkMap);

        app.handle_key(KeyCode::Char('a'));
        assert_eq!(app.screen, Screen::AttackPaths);

        app.handle_key(KeyCode::Char('d'));
        assert_eq!(app.screen, Screen::Dashboard);
    }

    #[test]
    fn test_quit() {
        let mut app = test_app();
        assert!(!app.should_quit);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit);
    }

    #[test]
    fn test_rescan_request() {
        let mut app = test_app();
        let rescan = app.handle_key(KeyCode::Char('s'));
        assert!(rescan);
        assert!(app.scanning);
    }

    #[test]
    fn test_rescan_blocked_while_scanning() {
        let mut app = test_app();
        app.scanning = true;
        let rescan = app.handle_key(KeyCode::Char('s'));
        assert!(!rescan);
    }

    #[test]
    fn test_selection_bounds_no_results() {
        let mut app = test_app();
        app.screen = Screen::Findings;
        // Should not panic even with no results
        app.handle_key(KeyCode::Down);
        assert_eq!(app.selected_finding_index, 0);
        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_finding_index, 0);
    }

    #[test]
    fn test_esc_from_device_detail() {
        let mut app = test_app();
        app.screen = Screen::DeviceDetail;
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.screen, Screen::Dashboard);
    }

    #[test]
    fn test_arrow_tab_navigation() {
        let mut app = test_app();
        assert_eq!(app.screen, Screen::Dashboard);

        app.handle_key(KeyCode::Right);
        assert_eq!(app.screen, Screen::NetworkMap);

        app.handle_key(KeyCode::Right);
        assert_eq!(app.screen, Screen::Findings);

        app.handle_key(KeyCode::Left);
        assert_eq!(app.screen, Screen::NetworkMap);

        // Tab wraps around: Dashboard → Network → Findings → Attacks → TopActions → Dashboard
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.screen, Screen::Findings);

        app.handle_key(KeyCode::Tab);
        assert_eq!(app.screen, Screen::AttackPaths);

        app.handle_key(KeyCode::Tab);
        assert_eq!(app.screen, Screen::TopActions);

        app.handle_key(KeyCode::Tab);
        assert_eq!(app.screen, Screen::Dashboard);

        // BackTab goes backwards
        app.handle_key(KeyCode::BackTab);
        assert_eq!(app.screen, Screen::TopActions);

        app.handle_key(KeyCode::BackTab);
        assert_eq!(app.screen, Screen::AttackPaths);
    }

    #[test]
    fn test_top_actions_shortcut() {
        let mut app = test_app();
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.screen, Screen::TopActions);
    }

    #[test]
    fn test_vim_keys_selection() {
        let mut app = test_app();
        app.screen = Screen::Findings;
        // j/k should work like Down/Up
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.selected_finding_index, 0); // no results, stays at 0
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.selected_finding_index, 0);
    }

    #[test]
    fn test_severity_filter_default() {
        let app = test_app();
        assert_eq!(app.severity_filter, SeverityFilter::ActionableOnly);
    }

    #[test]
    fn test_severity_filter_toggle() {
        let mut app = test_app();
        assert_eq!(app.severity_filter, SeverityFilter::ActionableOnly);
        app.handle_key(KeyCode::Char('l'));
        assert_eq!(app.severity_filter, SeverityFilter::All);
        app.handle_key(KeyCode::Char('l'));
        assert_eq!(app.severity_filter, SeverityFilter::ActionableOnly);
    }

    #[test]
    fn test_filtered_findings_excludes_low_info() {
        use rikitikitavi_core::Severity;
        use rikitikitavi_models::Finding;

        let mut app = test_app();
        app.results = Some(ScanResults {
            findings: vec![
                Finding::new("test", "Critical", "desc", Severity::Critical),
                Finding::new("test", "High", "desc", Severity::High),
                Finding::new("test", "Medium", "desc", Severity::Medium),
                Finding::new("test", "Low", "desc", Severity::Low),
                Finding::new("test", "Info", "desc", Severity::Info),
            ],
            risk_score: 50.0,
            ..Default::default()
        });

        // Default filter: ActionableOnly
        let filtered = app.filtered_findings();
        assert_eq!(filtered.len(), 3);
        assert_eq!(filtered[0].severity, Severity::Critical);
        assert_eq!(filtered[1].severity, Severity::High);
        assert_eq!(filtered[2].severity, Severity::Medium);

        // Toggle to All
        app.severity_filter = SeverityFilter::All;
        let all = app.filtered_findings();
        assert_eq!(all.len(), 5);
        // Should still be sorted by severity descending
        assert_eq!(all[0].severity, Severity::Critical);
        assert_eq!(all[4].severity, Severity::Info);
    }
}
