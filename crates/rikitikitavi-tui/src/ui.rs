use ratatui::Frame;

use crate::app::{App, HitRegions, Screen};
use crate::widgets;

/// Render the current screen. Hit regions are rebuilt each frame.
pub fn draw(frame: &mut Frame, app: &mut App) {
    app.hit_regions = HitRegions::default();

    match app.screen {
        Screen::Dashboard => widgets::dashboard::render(frame, app),
        Screen::NetworkMap => widgets::network_map::render(frame, app),
        Screen::Findings => widgets::findings::render(frame, app),
        Screen::AttackPaths => widgets::attack_paths::render(frame, app),
        Screen::TopActions => widgets::top_actions::render(frame, app),
        Screen::DeviceDetail => widgets::devices::render_detail(frame, app),
    }
}
