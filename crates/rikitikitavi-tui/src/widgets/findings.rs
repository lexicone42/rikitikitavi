use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Table
            Constraint::Length(10), // Detail pane
            Constraint::Length(3),  // Footer
        ])
        .split(frame.area());

    let findings = app.findings();

    // Findings table with colored severity badges
    let rows: Vec<Row> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_color = palette.severity_color(f.severity);
            let base_style = if i == app.selected_finding_index {
                palette.selected_style
            } else {
                Style::default()
            };

            let sev_badge = match f.severity {
                rikitikitavi_core::Severity::Critical => " CRIT ",
                rikitikitavi_core::Severity::High => " HIGH ",
                rikitikitavi_core::Severity::Medium => " MED  ",
                rikitikitavi_core::Severity::Low => " LOW  ",
                rikitikitavi_core::Severity::Info => " INFO ",
            };

            Row::new(vec![
                Line::from(Span::styled(
                    sev_badge,
                    Style::default()
                        .fg(palette.bg)
                        .bg(sev_color)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(f.title.clone(), base_style.fg(palette.fg))),
                Line::from(Span::styled(
                    f.affected_ip
                        .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                    base_style.fg(palette.fg),
                )),
                Line::from(Span::styled(f.scanner.clone(), base_style.fg(palette.border))),
            ])
            .style(base_style)
        })
        .collect();

    let header_row = Row::new(vec![
        Line::from(Span::styled("SEV", palette.header_style)),
        Line::from(Span::styled("FINDING", palette.header_style)),
        Line::from(Span::styled("DEVICE", palette.header_style)),
        Line::from(Span::styled("MODULE", palette.header_style)),
    ])
    .style(palette.header_style);

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(30),
            Constraint::Length(16),
            Constraint::Length(14),
        ],
    )
    .header(header_row)
    .block(
        Block::default()
            .title(Span::styled(
                format!(" Findings ({}) ", findings.len()),
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(table, chunks[0]);

    // Detail pane for selected finding
    let detail_text = findings.get(app.selected_finding_index).map_or_else(
        || {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Select a finding to see details.",
                    Style::default()
                        .fg(palette.border)
                        .add_modifier(Modifier::ITALIC),
                )),
            ]
        },
        |f| {
            let sev_color = palette.severity_color(f.severity);
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!(" {} ", f.severity),
                        Style::default()
                            .fg(palette.bg)
                            .bg(sev_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("  {}", f.title),
                        Style::default()
                            .fg(palette.fg)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {}", f.description),
                    Style::default().fg(palette.fg),
                )),
            ];

            if let Some(cwe) = &f.cwe_id {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("  CWE: ", Style::default().fg(palette.border)),
                    Span::styled(
                        cwe.clone(),
                        Style::default()
                            .fg(palette.accent)
                            .add_modifier(Modifier::UNDERLINED),
                    ),
                ]));
            }

            if let Some(ip) = f.affected_ip {
                lines.push(Line::from(vec![
                    Span::styled("  Device: ", Style::default().fg(palette.border)),
                    Span::styled(ip.to_string(), Style::default().fg(palette.fg)),
                ]));
            }

            lines
        },
    );

    let detail = Paragraph::new(detail_text).block(
        Block::default()
            .title(Span::styled(
                " Finding Details ",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(detail, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Findings] ",
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[Up/Down]", Style::default().fg(palette.accent)),
        Span::styled(" Select  ", Style::default().fg(palette.fg)),
        Span::styled("[E]", Style::default().fg(palette.accent)),
        Span::styled("xport  ", Style::default().fg(palette.fg)),
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
    frame.render_widget(footer, chunks[2]);
}
