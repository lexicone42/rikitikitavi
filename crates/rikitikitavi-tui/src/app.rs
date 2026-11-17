use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::widgets::TableState;
use rikitikitavi_analysis::ScanDiff;
use rikitikitavi_core::Severity;
use rikitikitavi_export::segment_plan::{Zone, zone_for};
use rikitikitavi_models::{
    Device, DeviceReportCard, Finding, FindingFingerprint, Grade, ScanResults,
};

use crate::text::short_title;
use crate::theme::Palette;

/// Top-level tabs, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Overview,
    Devices,
    Findings,
    Actions,
    AttackPaths,
}

impl Screen {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Devices,
        Self::Findings,
        Self::Actions,
        Self::AttackPaths,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Devices => "Devices",
            Self::Findings => "Findings",
            Self::Actions => "Top actions",
            Self::AttackPaths => "Attack paths",
        }
    }

    /// Tab label for narrow terminals.
    pub const fn short_title(self) -> &'static str {
        match self {
            Self::Actions => "Actions",
            Self::AttackPaths => "Paths",
            other => other.title(),
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    const fn has_list(self) -> bool {
        matches!(self, Self::Devices | Self::Findings)
    }
}

/// Full-screen view opened with Enter over the Devices or Findings tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    Device(IpAddr),
    /// Index into `ScanResults::findings`.
    Finding(usize),
}

/// Clickable regions recorded by the last render pass.
#[derive(Debug, Default)]
pub struct HitRegions {
    pub tabs: Vec<(Rect, Screen)>,
    /// Data rows of the visible table, header and borders excluded.
    pub rows: Option<Rect>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Hacker,
    Accessible,
}

/// A finding's status relative to the previous scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    New,
    Unchanged,
    SeverityChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityFilter {
    /// Critical, High and Medium.
    #[default]
    ActionableOnly,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceSort {
    /// Worst grade first.
    #[default]
    Grade,
    Address,
}

/// Ticks (~100 ms each) a status message stays visible.
const STATUS_TICKS: u64 = 80;

pub struct App {
    pub screen: Screen,
    pub detail: Option<Detail>,
    pub config: TuiConfig,
    pub palette: Palette,
    pub results: Option<ScanResults>,
    pub scan_started: Option<Instant>,
    pub should_quit: bool,
    pub show_help: bool,
    pub hit_regions: HitRegions,
    pub severity_filter: SeverityFilter,
    pub device_sort: DeviceSort,
    /// Case-insensitive substring filter on the Devices and Findings tables.
    pub search: String,
    pub search_editing: bool,
    /// Findings table limited to this device (`f` in a device's detail view).
    pub only_device: Option<IpAddr>,
    pub findings_state: TableState,
    pub devices_state: TableState,
    /// Scroll offset of the text view on screen (detail, top actions, attack paths).
    pub text_scroll: u16,
    /// Incremented each event-loop iteration (~100 ms).
    pub tick: u64,
    pub scan_diff: Option<ScanDiff>,
    status: Option<(String, u64)>,
    diff_status: HashMap<FindingFingerprint, DiffStatus>,
    /// Indices into `results.findings` after filter and sort.
    finding_rows: Vec<usize>,
    /// Indices into `results.devices` after filter and sort.
    device_rows: Vec<usize>,
    cards: HashMap<IpAddr, usize>,
    names: HashMap<IpAddr, String>,
    zones: HashMap<IpAddr, (Zone, String)>,
}

impl App {
    pub fn new(config: TuiConfig) -> Self {
        Self {
            screen: Screen::Overview,
            detail: None,
            palette: Palette::from_theme(config.theme),
            config,
            results: None,
            scan_started: None,
            should_quit: false,
            show_help: false,
            hit_regions: HitRegions::default(),
            severity_filter: SeverityFilter::default(),
            device_sort: DeviceSort::default(),
            search: String::new(),
            search_editing: false,
            only_device: None,
            findings_state: TableState::default(),
            devices_state: TableState::default(),
            text_scroll: 0,
            tick: 0,
            scan_diff: None,
            status: None,
            diff_status: HashMap::new(),
            finding_rows: Vec::new(),
            device_rows: Vec::new(),
            cards: HashMap::new(),
            names: HashMap::new(),
            zones: HashMap::new(),
        }
    }

    pub const fn scanning(&self) -> bool {
        self.scan_started.is_some()
    }

    /// Replace the results, keeping the selected device and finding where they still exist.
    pub fn set_results(&mut self, results: ScanResults) {
        let device = self.selected_device().map(|d| d.ip);
        let finding = self.selected_finding().map(Finding::fingerprint);
        let detail_finding = match self.detail {
            Some(Detail::Finding(i)) => self.findings().get(i).map(Finding::fingerprint),
            _ => None,
        };

        self.cards = index_by_ip(results.report_cards.iter().map(|c| c.ip));
        self.names = results
            .devices
            .iter()
            .filter_map(|d| Some((d.ip, d.hostname.clone()?)))
            .collect();
        let mut by_ip: HashMap<IpAddr, Vec<&Finding>> = HashMap::new();
        for f in &results.findings {
            if let Some(ip) = f.affected_ip {
                by_ip.entry(ip).or_default().push(f);
            }
        }
        self.zones = results
            .devices
            .iter()
            .map(|d| {
                let findings = by_ip.get(&d.ip).map_or(&[][..], Vec::as_slice);
                (d.ip, zone_for(d, findings))
            })
            .collect();
        self.results = Some(results);
        self.rebuild_rows();

        let device_row = device.and_then(|ip| {
            self.device_rows
                .iter()
                .position(|&i| self.devices()[i].ip == ip)
        });
        select(&mut self.devices_state, device_row, self.device_rows.len());
        let finding_row = finding.and_then(|fp| self.finding_row_of(fp));
        select(
            &mut self.findings_state,
            finding_row,
            self.finding_rows.len(),
        );
        self.detail = match self.detail {
            Some(Detail::Device(ip)) if self.names.contains_key(&ip) || self.has_device(ip) => {
                Some(Detail::Device(ip))
            }
            Some(Detail::Finding(_)) => detail_finding
                .and_then(|fp| self.findings().iter().position(|f| f.fingerprint() == fp))
                .map(Detail::Finding),
            _ => None,
        };
    }

    fn has_device(&self, ip: IpAddr) -> bool {
        self.devices().iter().any(|d| d.ip == ip)
    }

    fn finding_row_of(&self, fp: FindingFingerprint) -> Option<usize> {
        self.finding_rows
            .iter()
            .position(|&i| self.findings()[i].fingerprint() == fp)
    }

    /// Recompute the filtered, sorted row lists and clamp both selections.
    fn rebuild_rows(&mut self) {
        let needle = self.search.to_lowercase();
        let mut finding_rows: Vec<usize> = self
            .findings()
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                self.severity_filter == SeverityFilter::All || f.severity >= Severity::Medium
            })
            .filter(|(_, f)| self.only_device.is_none_or(|ip| f.affected_ip == Some(ip)))
            .filter(|(_, f)| needle.is_empty() || self.finding_matches(f, &needle))
            .map(|(i, _)| i)
            .collect();
        finding_rows.sort_by(|&a, &b| {
            let (a, b) = (&self.findings()[a], &self.findings()[b]);
            b.severity
                .cmp(&a.severity)
                .then(b.is_kev.cmp(&a.is_kev))
                .then_with(|| short_title(a).cmp(short_title(b)))
                .then(a.affected_ip.cmp(&b.affected_ip))
                .then(a.affected_port.cmp(&b.affected_port))
        });

        let mut device_rows: Vec<usize> = self
            .devices()
            .iter()
            .enumerate()
            .filter(|(_, d)| needle.is_empty() || self.device_matches(d, &needle))
            .map(|(i, _)| i)
            .collect();
        device_rows.sort_by(|&a, &b| {
            let (a, b) = (&self.devices()[a], &self.devices()[b]);
            match self.device_sort {
                DeviceSort::Address => a.ip.cmp(&b.ip),
                DeviceSort::Grade => self
                    .grade_key(a)
                    .cmp(&self.grade_key(b))
                    .then(a.ip.cmp(&b.ip)),
            }
        });

        self.finding_rows = finding_rows;
        self.device_rows = device_rows;
        let (f, d) = (
            self.findings_state.selected(),
            self.devices_state.selected(),
        );
        select(&mut self.findings_state, f, self.finding_rows.len());
        select(&mut self.devices_state, d, self.device_rows.len());
    }

    /// Sort key: F first, ungraded last; more Medium+ findings first within a grade.
    fn grade_key(&self, d: &Device) -> (u8, std::cmp::Reverse<usize>) {
        let card = self.report_card(d.ip);
        let rank = match card.map_or(Grade::NotAssessed, |c| c.grade) {
            Grade::F => 0,
            Grade::D => 1,
            Grade::C => 2,
            Grade::B => 3,
            Grade::A => 4,
            Grade::NotAssessed => 5,
        };
        (
            rank,
            std::cmp::Reverse(card.map_or(0, DeviceReportCard::actionable)),
        )
    }

    fn finding_matches(&self, f: &Finding, needle: &str) -> bool {
        let ip = f.affected_ip;
        f.title.to_lowercase().contains(needle)
            || f.scanner.to_lowercase().contains(needle)
            || f.cve_ids.iter().any(|c| c.to_lowercase().contains(needle))
            || ip.is_some_and(|ip| ip.to_string().contains(needle))
            || ip
                .and_then(|ip| self.names.get(&ip))
                .is_some_and(|n| n.to_lowercase().contains(needle))
    }

    fn device_matches(&self, d: &Device, needle: &str) -> bool {
        let has = |s: &Option<String>| {
            s.as_ref()
                .is_some_and(|s| s.to_lowercase().contains(needle))
        };
        d.ip.to_string().contains(needle)
            || has(&d.hostname)
            || has(&d.vendor)
            || has(&d.device_subtype)
            || d.device_type.label().to_lowercase().contains(needle)
            || d.mac.is_some_and(|m| m.to_string().contains(needle))
            || self
                .zone(d.ip)
                .is_some_and(|(z, _)| z.label().to_lowercase().contains(needle))
    }

    /// Handle a key; returns true if a re-scan was requested.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return false;
        }
        if self.search_editing {
            self.handle_search_key(key.code);
            return false;
        }
        if self.show_help {
            self.show_help = false;
            return false;
        }

        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('1' | 'd') => self.go(Screen::Overview),
            KeyCode::Char('2' | 'n') => self.go(Screen::Devices),
            KeyCode::Char('f') if matches!(self.detail, Some(Detail::Device(_))) => {
                self.show_device_findings();
            }
            KeyCode::Char('3' | 'f') => self.go(Screen::Findings),
            KeyCode::Char('4' | 't') => self.go(Screen::Actions),
            KeyCode::Char('5' | 'a') => self.go(Screen::AttackPaths),
            KeyCode::Right | KeyCode::Tab => self.cycle(1),
            KeyCode::Left | KeyCode::BackTab => self.cycle(Screen::ALL.len() - 1),
            KeyCode::Char('s') if !self.scanning() => return true,
            KeyCode::Char('l') => {
                self.severity_filter = match self.severity_filter {
                    SeverityFilter::ActionableOnly => SeverityFilter::All,
                    SeverityFilter::All => SeverityFilter::ActionableOnly,
                };
                self.reset_list_position();
            }
            KeyCode::Char('o') => {
                self.device_sort = match self.device_sort {
                    DeviceSort::Grade => DeviceSort::Address,
                    DeviceSort::Address => DeviceSort::Grade,
                };
                self.reset_list_position();
            }
            KeyCode::Char('/') if self.detail.is_none() => {
                if !self.screen.has_list() {
                    self.go(Screen::Findings);
                }
                self.search_editing = true;
            }
            KeyCode::Char('e') => self.export(),
            KeyCode::Enter => self.open_detail(),
            KeyCode::Esc => {
                if self.detail.take().is_some() {
                    self.text_scroll = 0;
                } else if !self.search.is_empty() || self.only_device.is_some() {
                    self.search.clear();
                    self.only_device = None;
                    self.reset_list_position();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
            KeyCode::PageUp => self.scroll_by(-self.page()),
            KeyCode::PageDown => self.scroll_by(self.page()),
            KeyCode::Home | KeyCode::Char('g') => self.scroll_by(i64::MIN),
            KeyCode::End | KeyCode::Char('G') => self.scroll_by(i64::MAX),
            _ => {}
        }
        false
    }

    fn handle_search_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter => self.search_editing = false,
            KeyCode::Esc => {
                self.search_editing = false;
                self.search.clear();
            }
            KeyCode::Backspace => {
                self.search.pop();
            }
            KeyCode::Char(c) => self.search.push(c),
            _ => return,
        }
        self.reset_list_position();
    }

    /// Handle a mouse event; returns true if a re-scan was requested.
    pub fn handle_mouse(&mut self, event: MouseEvent) -> bool {
        let at = (event.column, event.row).into();
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(&(_, screen)) =
                    self.hit_regions.tabs.iter().find(|(r, _)| r.contains(at))
                {
                    self.go(screen);
                } else if let Some(row) = self.row_at(event.row, at) {
                    let state = self.list_state_mut();
                    if state.selected() == Some(row) {
                        self.open_detail();
                    } else {
                        state.select(Some(row));
                    }
                }
            }
            MouseEventKind::Down(MouseButton::Right) => {
                if let Some(row) = self.row_at(event.row, at) {
                    self.list_state_mut().select(Some(row));
                    self.open_detail();
                }
            }
            MouseEventKind::ScrollUp => self.scroll_by(if self.text_view() { -3 } else { -1 }),
            MouseEventKind::ScrollDown => self.scroll_by(if self.text_view() { 3 } else { 1 }),
            _ => {}
        }
        false
    }

    /// Table row index under a click, if it lands on a data row.
    fn row_at(&self, y: u16, at: ratatui::layout::Position) -> Option<usize> {
        let rows = self.hit_regions.rows.filter(|r| r.contains(at))?;
        if self.detail.is_some() || !self.screen.has_list() {
            return None;
        }
        let (state, len) = match self.screen {
            Screen::Devices => (&self.devices_state, self.device_rows.len()),
            _ => (&self.findings_state, self.finding_rows.len()),
        };
        let row = state.offset() + usize::from(y - rows.y);
        (row < len).then_some(row)
    }

    const fn list_state_mut(&mut self) -> &mut TableState {
        match self.screen {
            Screen::Devices => &mut self.devices_state,
            _ => &mut self.findings_state,
        }
    }

    const fn go(&mut self, screen: Screen) {
        self.screen = screen;
        self.detail = None;
        self.text_scroll = 0;
        self.search_editing = false;
    }

    fn cycle(&mut self, step: usize) {
        self.go(Screen::ALL[(self.screen.index() + step) % Screen::ALL.len()]);
    }

    fn reset_list_position(&mut self) {
        self.findings_state = TableState::default();
        self.devices_state = TableState::default();
        self.rebuild_rows();
    }

    /// Switch from a device's detail view to the Findings tab filtered to that device.
    fn show_device_findings(&mut self) {
        if let Some(Detail::Device(ip)) = self.detail {
            self.go(Screen::Findings);
            self.search.clear();
            self.only_device = Some(ip);
            self.severity_filter = SeverityFilter::All;
            self.reset_list_position();
        }
    }

    fn open_detail(&mut self) {
        if self.detail.is_some() {
            return;
        }
        self.detail = match self.screen {
            Screen::Devices => self.selected_device().map(|d| Detail::Device(d.ip)),
            Screen::Findings => self
                .findings_state
                .selected()
                .and_then(|row| self.finding_rows.get(row))
                .map(|&i| Detail::Finding(i)),
            _ => None,
        };
        self.text_scroll = 0;
    }

    /// The screen shows scrolling text, not a table.
    const fn text_view(&self) -> bool {
        self.detail.is_some() || !self.screen.has_list()
    }

    fn page(&self) -> i64 {
        self.hit_regions
            .rows
            .map_or(10, |r| i64::from(r.height.max(2)) - 1)
    }

    /// Move the table selection, or scroll the text view. Renderers clamp `text_scroll`.
    fn scroll_by(&mut self, delta: i64) {
        if self.text_view() {
            let cur = i64::from(self.text_scroll);
            let next = cur.saturating_add(delta).clamp(0, i64::from(u16::MAX));
            self.text_scroll = u16::try_from(next).unwrap_or(u16::MAX);
            return;
        }
        let len = match self.screen {
            Screen::Devices => self.device_rows.len(),
            _ => self.finding_rows.len(),
        };
        let state = self.list_state_mut();
        if len == 0 {
            state.select(None);
            return;
        }
        let cur = i64::try_from(state.selected().unwrap_or(0)).unwrap_or(0);
        let max = i64::try_from(len - 1).unwrap_or(i64::MAX);
        let next = cur.saturating_add(delta).clamp(0, max);
        state.select(Some(usize::try_from(next).unwrap_or(0)));
    }

    /// Write the results JSON, fix plan and segmentation plan to the working directory.
    fn export(&mut self) {
        let Some(results) = &self.results else {
            self.set_status("No results to export");
            return;
        };
        let stem = format!(
            "rikitikitavi-{}",
            results.scanned_at.format("%Y%m%d-%H%M%S")
        );
        let generated = results.scanned_at.format("%Y-%m-%d %H:%M UTC").to_string();
        let path = |suffix: &str| std::path::PathBuf::from(format!("{stem}{suffix}"));
        let outcome = rikitikitavi_export::export_json(results, &path(".json"))
            .and_then(|()| {
                rikitikitavi_export::export_fix_plan(
                    results,
                    Some(&generated),
                    &path("-fix-plan.md"),
                )
            })
            .and_then(|()| {
                rikitikitavi_export::export_segment_plan(
                    results,
                    Some(&generated),
                    &path("-segment-plan.md"),
                )
            });
        match outcome {
            Ok(()) => self.set_status(format!(
                "Wrote {stem}.json, -fix-plan.md and -segment-plan.md"
            )),
            Err(e) => self.set_status(format!("Export failed: {e}")),
        }
    }

    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status = Some((message.into(), self.tick));
    }

    /// Status message, until it expires.
    pub fn status(&self) -> Option<&str> {
        self.status
            .as_ref()
            .filter(|(_, at)| self.tick.saturating_sub(*at) < STATUS_TICKS)
            .map(|(m, _)| m.as_str())
    }

    pub fn findings(&self) -> &[Finding] {
        self.results.as_ref().map_or(&[], |r| r.findings.as_slice())
    }

    pub fn devices(&self) -> &[Device] {
        self.results.as_ref().map_or(&[], |r| r.devices.as_slice())
    }

    /// Findings shown in the table, in row order.
    pub fn finding_rows(&self) -> impl ExactSizeIterator<Item = &Finding> {
        self.finding_rows.iter().map(|&i| &self.findings()[i])
    }

    /// Devices shown in the table, in row order.
    pub fn device_rows(&self) -> impl ExactSizeIterator<Item = &Device> {
        self.device_rows.iter().map(|&i| &self.devices()[i])
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        let row = self.findings_state.selected()?;
        self.findings().get(*self.finding_rows.get(row)?)
    }

    pub fn selected_device(&self) -> Option<&Device> {
        let row = self.devices_state.selected()?;
        self.devices().get(*self.device_rows.get(row)?)
    }

    pub fn device(&self, ip: IpAddr) -> Option<&Device> {
        self.devices().iter().find(|d| d.ip == ip)
    }

    pub fn report_card(&self, ip: IpAddr) -> Option<&DeviceReportCard> {
        self.results
            .as_ref()?
            .report_cards
            .get(*self.cards.get(&ip)?)
    }

    /// Display name for `ip`, when the scan resolved one.
    pub fn device_name(&self, ip: IpAddr) -> Option<&str> {
        self.names.get(&ip).map(String::as_str)
    }

    /// Proposed segmentation zone for `ip` and the reason.
    pub fn zone(&self, ip: IpAddr) -> Option<(Zone, &str)> {
        self.zones.get(&ip).map(|(z, r)| (*z, r.as_str()))
    }

    /// Store the diff and rebuild the per-finding status cache.
    pub fn set_scan_diff(&mut self, diff: ScanDiff) {
        let mut cache = HashMap::new();
        for f in &diff.new_findings {
            cache.insert(f.fingerprint(), DiffStatus::New);
        }
        for sc in &diff.severity_changes {
            cache.insert(sc.finding.fingerprint(), DiffStatus::SeverityChanged);
        }
        for f in &diff.unchanged_findings {
            cache.insert(f.fingerprint(), DiffStatus::Unchanged);
        }
        self.diff_status = cache;
        self.scan_diff = Some(diff);
    }

    pub fn finding_diff_status(&self, finding: &Finding) -> Option<DiffStatus> {
        self.diff_status.get(&finding.fingerprint()).copied()
    }
}

fn index_by_ip(ips: impl Iterator<Item = IpAddr>) -> HashMap<IpAddr, usize> {
    ips.enumerate().map(|(i, ip)| (ip, i)).collect()
}

/// Select `row` (or the current row, clamped); nothing when the list is empty.
fn select(state: &mut TableState, row: Option<usize>, len: usize) {
    if len == 0 {
        *state = TableState::default();
    } else {
        state.select(Some(row.unwrap_or(0).min(len - 1)));
    }
}
