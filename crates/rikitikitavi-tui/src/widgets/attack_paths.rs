use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;
use crate::theme::Palette;

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &mut App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    let paths = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.attack_paths.as_slice());

    let mut lines = Vec::new();

    if paths.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No attack paths identified.",
            Style::default().fg(palette.fg),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Run a scan with --attack-paths to generate attack path analysis.",
            Style::default()
                .fg(palette.border)
                .add_modifier(Modifier::ITALIC),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Attack paths show how an attacker could chain vulnerabilities",
            Style::default().fg(palette.border),
        )));
        lines.push(Line::from(Span::styled(
            "  to reach high-value targets on your network.",
            Style::default().fg(palette.border),
        )));
    } else {
        for (i, path) in paths.iter().enumerate() {
            let sev_color = palette.severity_color(path.severity);
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!(" PATH {} ", i + 1),
                    Style::default()
                        .fg(palette.bg)
                        .bg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {}", path.name),
                    Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  [{}]", path.severity),
                    Style::default().fg(sev_color),
                ),
            ]));

            for (j, step) in path.steps.iter().enumerate() {
                let connector = if j == path.steps.len() - 1 {
                    "  └─"
                } else {
                    "  ├─"
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("    {connector} "),
                        Style::default().fg(palette.border),
                    ),
                    Span::styled(
                        format!("Step {}: ", step.order),
                        Style::default()
                            .fg(palette.accent)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(step.title.clone(), Style::default().fg(palette.fg)),
                    Span::styled(
                        format!("  ({:?})", step.difficulty),
                        Style::default().fg(palette.border),
                    ),
                ]));
            }
        }
    }

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                format!(" Attack Paths ({}) ", paths.len()),
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(widget, chunks[0]);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Attack Paths] ",
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[D]", Style::default().fg(palette.accent)),
        Span::styled("ashboard  ", Style::default().fg(palette.fg)),
        Span::styled("[F]", Style::default().fg(palette.accent)),
        Span::styled("indings  ", Style::default().fg(palette.fg)),
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
