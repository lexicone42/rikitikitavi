use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::theme::Palette;

/// Icon for a device type.
const fn device_icon(device: &rikitikitavi_models::Device) -> &'static str {
    match device.device_type {
        rikitikitavi_models::DeviceType::Router => "🌐",
        rikitikitavi_models::DeviceType::Switch => "🔀",
        rikitikitavi_models::DeviceType::AccessPoint => "📡",
        rikitikitavi_models::DeviceType::Desktop | rikitikitavi_models::DeviceType::Laptop => "💻",
        rikitikitavi_models::DeviceType::Tablet | rikitikitavi_models::DeviceType::Phone => "📱",
        rikitikitavi_models::DeviceType::Server => "🖥",
        rikitikitavi_models::DeviceType::Nas => "💾",
        rikitikitavi_models::DeviceType::Printer => "🖨",
        rikitikitavi_models::DeviceType::Camera => "📷",
        rikitikitavi_models::DeviceType::SmartTv => "📺",
        rikitikitavi_models::DeviceType::IoT => "🏠",
        rikitikitavi_models::DeviceType::GameConsole => "🎮",
        rikitikitavi_models::DeviceType::MediaPlayer => "🎵",
        rikitikitavi_models::DeviceType::Hub => "🔗",
        rikitikitavi_models::DeviceType::SmartLock => "🔒",
        rikitikitavi_models::DeviceType::Thermostat => "🌡",
        rikitikitavi_models::DeviceType::EvCharger => "🚗",
        rikitikitavi_models::DeviceType::Inverter => "☀",
        rikitikitavi_models::DeviceType::Nvr => "📼",
        rikitikitavi_models::DeviceType::Doorbell => "🔔",
        rikitikitavi_models::DeviceType::Vacuum => "🧹",
        rikitikitavi_models::DeviceType::SmartPlug => "🔌",
        rikitikitavi_models::DeviceType::Speaker => "🔊",
        rikitikitavi_models::DeviceType::Appliance => "🧺",
        rikitikitavi_models::DeviceType::Printer3d => "⚙",
        rikitikitavi_models::DeviceType::Sensor => "📊",
        rikitikitavi_models::DeviceType::Unknown => "❓",
    }
}

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &mut App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Map
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    let devices = app.devices();

    // Snake position oscillates with the tick counter.
    #[allow(clippy::cast_possible_truncation)]
    let snake_pos = (app.tick / 5 % 10) as usize;
    let snake_padding = if snake_pos < 5 {
        " ".repeat(14 + snake_pos)
    } else {
        " ".repeat(14 + 10 - snake_pos)
    };

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::raw(snake_padding),
            Span::styled(
                "~§>",
                Style::default()
                    .fg(palette.critical)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                     "),
            Span::styled(
                "╔═══════════╗",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("           ☁ ───────"),
            Span::styled(
                "║  INTERNET ║",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                     "),
            Span::styled(
                "╚═════╤═════╝",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                           "),
            Span::styled("│", Style::default().fg(palette.accent)),
        ]),
        Line::from(vec![
            Span::raw("                     "),
            Span::styled(
                "╔═════╧═════╗",
                Style::default()
                    .fg(palette.high)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                     "),
            Span::styled(
                "║   ROUTER  ║",
                Style::default()
                    .fg(palette.high)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                     "),
            Span::styled(
                "╚═════╤═════╝",
                Style::default()
                    .fg(palette.high)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("                           "),
            Span::styled("│", Style::default().fg(palette.border)),
        ]),
    ];

    // Rows above the first device row: top border + every line pushed before the loop.
    let mut list_header_offset: u16 = 1;

    if devices.is_empty() {
        lines.push(Line::from(Span::styled(
            "              (no devices discovered)",
            Style::default()
                .fg(palette.border)
                .add_modifier(Modifier::ITALIC),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::raw("           "),
            Span::styled(
                "┌──────────────┴──────────────┐",
                Style::default().fg(palette.border),
            ),
        ]));
        list_header_offset += u16::try_from(lines.len()).unwrap_or(u16::MAX);

        for (i, device) in devices.iter().take(15).enumerate() {
            let ip_str = device.ip.to_string();
            let label = device.hostname.as_deref().unwrap_or(&ip_str);
            let icon = device_icon(device);
            let ports_info = if device.open_ports.is_empty() {
                String::new()
            } else {
                format!(" ({} ports)", device.open_ports.len())
            };

            let connector = if i == devices.len().min(15) - 1 {
                "└──"
            } else {
                "├──"
            };

            let is_selected = i == app.selected_device_index;
            let style = if is_selected {
                palette.selected_style
            } else {
                Style::default().fg(palette.fg)
            };

            lines.push(Line::from(vec![
                Span::raw("           "),
                Span::styled(connector, Style::default().fg(palette.border)),
                Span::styled(format!(" {icon} {label}"), style),
                Span::styled(ports_info, Style::default().fg(palette.border)),
            ]));
        }

        if devices.len() > 15 {
            lines.push(Line::from(vec![
                Span::raw("           "),
                Span::styled(
                    format!("    ... +{} more devices", devices.len() - 15),
                    Style::default()
                        .fg(palette.border)
                        .add_modifier(Modifier::ITALIC),
                ),
            ]));
        }
    }

    let map_area = chunks[0];
    let map = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                format!(" Network Map ({} devices) ", devices.len()),
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(map, map_area);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Network Map] ",
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[Up/Down]", Style::default().fg(palette.accent)),
        Span::styled(" Select  ", Style::default().fg(palette.fg)),
        Span::styled("[Enter]", Style::default().fg(palette.accent)),
        Span::styled(" Details  ", Style::default().fg(palette.fg)),
        Span::styled("[D]", Style::default().fg(palette.accent)),
        Span::styled("ashboard  ", Style::default().fg(palette.fg)),
        Span::styled("[Q]", Style::default().fg(palette.accent)),
        Span::styled("uit", Style::default().fg(palette.fg)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(footer, chunks[1]);

    app.hit_regions.list_area = Some(map_area);
    app.hit_regions.list_header_offset = list_header_offset;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Screen, TuiConfig};
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use rikitikitavi_models::{Device, ScanResults};

    fn device(ip: &str, host: &str) -> Device {
        let mut d = Device::new(ip.parse().unwrap());
        d.hostname = Some(host.to_owned());
        d
    }

    fn row_text(buf: &Buffer, y: u16) -> String {
        (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect()
    }

    #[test]
    fn click_offset_matches_rendered_device_rows() {
        let mut app = App::new(TuiConfig::default());
        app.screen = Screen::NetworkMap;
        app.results = Some(ScanResults {
            devices: vec![
                device("10.0.0.1", "alpha"),
                device("10.0.0.2", "bravo"),
                device("10.0.0.3", "charlie"),
            ],
            ..Default::default()
        });

        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal.draw(|frame| render(frame, &mut app)).unwrap();

        let buf = terminal.backend().buffer();
        let first_row = (0..buf.area.height)
            .find(|&y| row_text(buf, y).contains("alpha"))
            .expect("first device row rendered");
        let area = app.hit_regions.list_area.unwrap();
        assert_eq!(area.y + app.hit_regions.list_header_offset, first_row);

        for (i, row) in (first_row..first_row + 3).enumerate() {
            app.handle_mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: area.x + 15,
                row,
                modifiers: KeyModifiers::empty(),
            });
            assert_eq!(app.selected_device_index, i, "click on row {row}");
        }
    }
}
