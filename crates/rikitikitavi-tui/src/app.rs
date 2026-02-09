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
        }
    }

    /// Handle keyboard input and update state.
    pub fn handle_key(&mut self, key: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode;

        match key {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('n') => self.screen = Screen::NetworkMap,
            KeyCode::Char('f') => self.screen = Screen::Findings,
            KeyCode::Char('a') => self.screen = Screen::AttackPaths,
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            _ => {}
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
                        (self.selected_finding_index + delta as usize).min(max);
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
                        (self.selected_device_index + delta as usize).min(max);
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
