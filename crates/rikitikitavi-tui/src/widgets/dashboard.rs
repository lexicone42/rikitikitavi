use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

pub fn render(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Body
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Rikitikitavi ",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Home Network Security Auditor"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(header, chunks[0]);

    // Body
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    // Left: Risk summary
    let findings = app.findings();
    let critical = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Low)
        .count();

    let risk_text = vec![
        Line::from(format!("  Critical: {critical}")),
        Line::from(format!("  High:     {high}")),
        Line::from(format!("  Medium:   {medium}")),
        Line::from(format!("  Low:      {low}")),
        Line::from(""),
        Line::from(format!("  Devices:  {}", app.devices().len())),
    ];

    let risk_summary = Paragraph::new(risk_text).block(
        Block::default()
            .title(" Risk Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(risk_summary, body_chunks[0]);

    // Right: Recent findings
    let recent: Vec<Line> = findings
        .iter()
        .take(10)
        .map(|f| Line::from(format!("  {:8} {}", f.severity.to_string(), f.title)))
        .collect();

    let recent_findings = Paragraph::new(if recent.is_empty() {
        vec![Line::from("  No findings yet. Run a scan with [S].")]
    } else {
        recent
    })
    .block(
        Block::default()
            .title(" Recent Findings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(recent_findings, body_chunks[1]);

    // Footer
    let footer = Paragraph::new(Line::from(
        " [D]ashboard [N]etwork Map [F]indings [A]ttack Paths [S]can [Q]uit",
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(footer, chunks[2]);
}
