use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

/// Render a scan progress bar into the given area.
pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    if app.scanning {
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(" Scan Progress ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(palette.border)),
            )
            .gauge_style(Style::default().fg(palette.accent))
            .ratio(app.scan_progress.clamp(0.0, 1.0))
            .label(format!(
                "{:.0}% - {}",
                app.scan_progress * 100.0,
                app.scan_status
            ));
        frame.render_widget(gauge, area);
    } else {
        let idle = Paragraph::new(Line::from("  Press [S] to start a scan")).block(
            Block::default()
                .title(" Scan ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(palette.border)),
        );
        frame.render_widget(idle, area);
    }
}
