use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

pub fn render(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Table
            Constraint::Length(8), // Detail pane
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    let findings = app.findings();

    // Findings table
    let rows: Vec<Row> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let style = if i == app.selected_finding_index {
                palette.selected_style
            } else {
                Style::default()
            };
            Row::new(vec![
                f.severity.to_string(),
                f.title.clone(),
                f.affected_ip
                    .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                f.scanner.clone(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Min(30),
            Constraint::Length(16),
            Constraint::Length(14),
        ],
    )
    .header(Row::new(vec!["SEV", "FINDING", "DEVICE", "MODULE"]).style(palette.header_style))
    .block(
        Block::default()
            .title(format!(" Findings ({}) ", findings.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(table, chunks[0]);

    // Detail pane for selected finding
    let detail_text = if let Some(f) = findings.get(app.selected_finding_index) {
        vec![
            Line::from(format!("  {}", f.title))
                .style(Style::default().add_modifier(Modifier::BOLD)),
            Line::from(""),
            Line::from(format!("  {}", f.description)),
        ]
    } else {
        vec![Line::from("  Select a finding to see details.")]
    };

    let detail = Paragraph::new(detail_text).block(
        Block::default()
            .title(" Finding Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(detail, chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(
        " [Up/Down] Select  [Enter] Expand  [E]xport  [D]ashboard  [Q]uit",
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(footer, chunks[2]);
}
