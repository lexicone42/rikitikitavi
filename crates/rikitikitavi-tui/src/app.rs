use rikitikitavi_models::{Device, Finding, ScanResults};

/// Which screen the TUI is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    NetworkMap,
    Findings,
    AttackPaths,
    DeviceDetail,
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
}

impl App {
    pub const fn new(config: TuiConfig) -> Self {
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
            KeyCode::Char('s') if !self.scanning => {
                self.scanning = true;
                "Scanning...".clone_into(&mut self.scan_status);
                self.status_message = Some("Re-scan triggered".to_owned());
                return true;
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
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            _ => {}
        }
        false
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
                let max = self
                    .results
                    .as_ref()
                    .map_or(0, |r| r.findings.len().saturating_sub(1));
                if delta < 0 {
                    self.selected_finding_index = self
                        .selected_finding_index
                        .saturating_sub(delta.unsigned_abs() as usize);
                } else {
                    self.selected_finding_index =
                        (self.selected_finding_index + usize::try_from(delta).unwrap_or(0)).min(max);
                }
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
            }
            _ => {}
        }
    }

    /// Get current findings (convenience accessor).
    pub fn findings(&self) -> &[Finding] {
        self.results.as_ref().map_or(&[], |r| r.findings.as_slice())
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
}
