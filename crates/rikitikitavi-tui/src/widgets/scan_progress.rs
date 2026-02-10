use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

/// Animated spinner frames for scanning indicator.
const SPINNER: &[&str] = &["◐", "◓", "◑", "◒"];

/// Render a scan progress bar into the given area.
pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    if app.scanning {
        // Animate the spinner based on progress
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let spinner_idx =
            ((app.scan_progress * 20.0).max(0.0) as usize) % SPINNER.len();
        let spinner = SPINNER[spinner_idx];

        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(Span::styled(
                        format!(" {spinner} Scanning... "),
                        Style::default()
                            .fg(palette.accent)
                            .add_modifier(Modifier::BOLD),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(palette.accent))
                    .border_type(ratatui::widgets::BorderType::Rounded),
            )
            .gauge_style(Style::default().fg(palette.accent).bg(palette.bg))
            .ratio(app.scan_progress.clamp(0.0, 1.0))
            .label(Span::styled(
                format!(
                    "{:.0}% ─ {}",
                    app.scan_progress * 100.0,
                    app.scan_status
                ),
                Style::default()
                    .fg(palette.fg)
                    .add_modifier(Modifier::BOLD),
            ));
        frame.render_widget(gauge, area);
    } else {
        let idle = Paragraph::new(Line::from(vec![
            Span::styled("  ● ", Style::default().fg(palette.low)),
            Span::styled("Ready", Style::default().fg(palette.fg)),
            Span::styled(
                "  ─  Press [S] to start a scan",
                Style::default().fg(palette.border),
            ),
        ]))
        .block(
            Block::default()
                .title(Span::styled(
                    " Scan Status ",
                    Style::default()
                        .fg(palette.accent)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border))
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
        frame.render_widget(idle, area);
    }
}
