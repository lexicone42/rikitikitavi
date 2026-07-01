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

    let actions = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.priority_actions.as_slice());

    let mut lines = Vec::new();

    if actions.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No priority actions generated.",
            Style::default().fg(palette.fg),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Run a scan to generate findings with remediation guidance.",
            Style::default()
                .fg(palette.border)
                .add_modifier(Modifier::ITALIC),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Priority actions group related findings by their shared fix,",
            Style::default().fg(palette.border),
        )));
        lines.push(Line::from(Span::styled(
            "  so you know the top 5 things to do to improve your security.",
            Style::default().fg(palette.border),
        )));
    } else {
        for action in actions {
            let sev_color = palette.severity_color(action.severity);

            // ── Action header ────────────────────────────────────
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!(" #{} ", action.rank),
                    Style::default()
                        .fg(palette.bg)
                        .bg(sev_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  {}", action.title),
                    Style::default().fg(palette.fg).add_modifier(Modifier::BOLD),
                ),
            ]));

            // ── Stats line ───────────────────────────────────────
            let effort_str = action
                .effort
                .as_deref()
                .map_or(String::new(), |e| format!("  |  Effort: {e}"));
            lines.push(Line::from(vec![
                Span::styled("     ", Style::default()),
                Span::styled(
                    format!("[{}]", action.severity),
                    Style::default().fg(sev_color),
                ),
                Span::styled(
                    format!(
                        "  {} device(s)  |  {} finding(s){}",
                        action.affected_device_count, action.finding_count, effort_str,
                    ),
                    Style::default().fg(palette.border),
                ),
            ]));

            // ── Remediation steps ────────────────────────────────
            if !action.steps.is_empty() {
                for (i, step) in action.steps.iter().enumerate() {
                    let connector = if i == action.steps.len() - 1 {
                        "  └─"
                    } else {
                        "  ├─"
                    };
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("     {connector} "),
                            Style::default().fg(palette.border),
                        ),
                        Span::styled(
                            format!("{}. ", i + 1),
                            Style::default()
                                .fg(palette.accent)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(step.clone(), Style::default().fg(palette.fg)),
                    ]));
                }
            }
        }
    }

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                format!(" Top {} Priority Actions ", actions.len()),
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
            " [Top Actions] ",
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
        Span::styled("[A]", Style::default().fg(palette.accent)),
        Span::styled("ttacks  ", Style::default().fg(palette.fg)),
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
