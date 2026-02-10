use ratatui::Frame;

use crate::app::{App, HitRegions, Screen};
use crate::widgets;

/// Main render function — dispatches to the appropriate screen widget.
pub fn draw(frame: &mut Frame, app: &mut App) {
    // Reset hit regions for this frame
    app.hit_regions = HitRegions::default();

    match app.screen {
        Screen::Dashboard => widgets::dashboard::render(frame, app),
        Screen::NetworkMap => widgets::network_map::render(frame, app),
        Screen::Findings => widgets::findings::render(frame, app),
        Screen::AttackPaths => widgets::attack_paths::render(frame, app),
        Screen::DeviceDetail => widgets::devices::render_detail(frame, app),
    }
}
