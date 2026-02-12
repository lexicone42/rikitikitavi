use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

/// Render the device detail screen.
#[allow(clippy::too_many_lines)]
pub fn render_detail(frame: &mut Frame, app: &mut App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Detail
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    let text = app.selected_device.as_ref().map_or_else(
        || {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No device selected. Press [Esc] to go back.",
                    Style::default()
                        .fg(palette.border)
                        .add_modifier(Modifier::ITALIC),
                )),
            ]
        },
        |device| {
            let icon = match device.device_type {
                rikitikitavi_models::DeviceType::Router => "🌐",
                rikitikitavi_models::DeviceType::Switch => "🔀",
                rikitikitavi_models::DeviceType::AccessPoint => "📡",
                rikitikitavi_models::DeviceType::Desktop
                | rikitikitavi_models::DeviceType::Laptop => "💻",
                rikitikitavi_models::DeviceType::Tablet
                | rikitikitavi_models::DeviceType::Phone => "📱",
                rikitikitavi_models::DeviceType::Server => "🖥",
                rikitikitavi_models::DeviceType::Nas => "💾",
                rikitikitavi_models::DeviceType::Printer => "🖨",
                rikitikitavi_models::DeviceType::Camera => "📷",
                rikitikitavi_models::DeviceType::SmartTv => "📺",
                rikitikitavi_models::DeviceType::IoT => "🏠",
                rikitikitavi_models::DeviceType::GameConsole => "🎮",
                rikitikitavi_models::DeviceType::MediaPlayer => "🎵",
                rikitikitavi_models::DeviceType::Unknown => "❓",
            };

            let ip_str = device.ip.to_string();
            let display_name = device.hostname.as_deref().unwrap_or(&ip_str).to_owned();
            let type_str = format!("{:?}", device.device_type);

            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(format!("  {icon}  "), Style::default().fg(palette.accent)),
                    Span::styled(
                        display_name,
                        Style::default()
                            .fg(palette.accent)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                detail_line("  IP Address", &ip_str, &palette),
                detail_line(
                    "  MAC Address",
                    device.mac.as_deref().unwrap_or("Unknown"),
                    &palette,
                ),
                detail_line(
                    "  Hostname",
                    device.hostname.as_deref().unwrap_or("Unknown"),
                    &palette,
                ),
                detail_line(
                    "  Vendor",
                    device.vendor.as_deref().unwrap_or("Unknown"),
                    &palette,
                ),
                detail_line("  Type", &type_str, &palette),
            ];

            // Open ports section
            lines.push(Line::from(""));
            if device.open_ports.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  No open ports detected",
                    Style::default()
                        .fg(palette.border)
                        .add_modifier(Modifier::ITALIC),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("  Open Ports ({}):", device.open_ports.len()),
                    Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
                )));
                for op in &device.open_ports {
                    let service = op
                        .service
                        .as_deref()
                        .unwrap_or_else(|| well_known_service(op.port));
                    lines.push(Line::from(vec![
                        Span::styled("    ", Style::default()),
                        Span::styled(
                            format!("{:>5}", op.port),
                            Style::default()
                                .fg(palette.accent)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("  {service}"), Style::default().fg(palette.border)),
                    ]));
                }
            }

            lines
        },
    );

    let block = Paragraph::new(text).block(
        Block::default()
            .title(Span::styled(
                " Device Details ",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(block, chunks[0]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Device Detail] ",
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[Esc]", Style::default().fg(palette.accent)),
        Span::styled(" Back  ", Style::default().fg(palette.fg)),
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
}

fn detail_line(label: &str, value: &str, palette: &Palette) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}:  "), Style::default().fg(palette.border)),
        Span::styled(value.to_owned(), Style::default().fg(palette.fg)),
    ])
}

const fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        554 => "RTSP (Camera)",
        631 => "IPP (Printing)",
        993 => "IMAPS",
        995 => "POP3S",
        1883 => "MQTT (IoT)",
        3000 => "Dev Server",
        3306 => "MySQL",
        3389 => "RDP",
        5000 => "Synology NAS",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP Proxy",
        8443 => "HTTPS Alt / UniFi",
        8883 => "MQTT-TLS",
        9100 => "Printer (RAW)",
        27017 => "MongoDB",
        32400 => "Plex",
        _ => "",
    }
}
