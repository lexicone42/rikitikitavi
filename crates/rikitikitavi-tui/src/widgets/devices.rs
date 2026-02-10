use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

/// Render the device detail screen.
pub fn render_detail(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let text = app.selected_device.as_ref().map_or_else(
        || vec![Line::from("  No device selected.")],
        |device| {
            vec![
                Line::from(format!("  IP Address:    {}", device.ip)),
                Line::from(format!(
                    "  MAC Address:   {}",
                    device.mac.as_deref().unwrap_or("Unknown")
                )),
                Line::from(format!(
                    "  Hostname:      {}",
                    device.hostname.as_deref().unwrap_or("Unknown")
                )),
                Line::from(format!(
                    "  Vendor:        {}",
                    device.vendor.as_deref().unwrap_or("Unknown")
                )),
                Line::from(format!("  Type:          {:?}", device.device_type)),
                Line::from(format!("  Open Ports:    {}", device.open_ports.len())),
            ]
        },
    );

    let block = Paragraph::new(text).block(
        Block::default()
            .title(" Device Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(block, frame.area());
}
