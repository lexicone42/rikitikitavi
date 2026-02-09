use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

pub fn render(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let devices = app.devices();
    let mut lines = vec![
        Line::from(""),
        Line::from("                    [ INTERNET ]"),
        Line::from("                         |"),
        Line::from("                    [ ROUTER  ]"),
        Line::from("                         |"),
    ];

    if devices.is_empty() {
        lines.push(Line::from("              (no devices discovered)"));
    } else {
        lines.push(Line::from("          ---------------------"));
        for device in devices.iter().take(10) {
            let ip_str = device.ip.to_string();
            let label = device.hostname.as_deref().unwrap_or(&ip_str);
            lines.push(Line::from(format!("          |-- [{label}]")));
        }
        if devices.len() > 10 {
            lines.push(Line::from(format!(
                "          |-- ... +{} more",
                devices.len() - 10
            )));
        }
    }

    let map = Paragraph::new(lines).block(
        Block::default()
            .title(" Network Map ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(map, frame.area());
}
