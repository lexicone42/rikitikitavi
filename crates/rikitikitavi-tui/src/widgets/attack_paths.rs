use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::theme::Palette;

pub fn render(frame: &mut Frame, app: &App) {
    let palette = Palette::from_theme(app.config.theme);

    let paths = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.attack_paths.as_slice());

    let mut lines = Vec::new();

    if paths.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("  No attack paths identified."));
        lines.push(Line::from("  Run a scan to generate attack path analysis."));
    } else {
        for (i, path) in paths.iter().enumerate() {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "  PATH {}: {} [{}]",
                i + 1,
                path.name,
                path.severity
            )));
            for step in &path.steps {
                lines.push(Line::from(format!(
                    "    Step {}: {} ({:?})",
                    step.order, step.title, step.difficulty
                )));
            }
        }
    }

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(format!(" Attack Paths ({}) ", paths.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border)),
    );
    frame.render_widget(widget, frame.area());
}
