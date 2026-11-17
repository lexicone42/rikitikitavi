use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};

use crate::app::App;
use crate::chrome::panel;

const KEYS: [(&str, &str); 14] = [
    ("1-5, Tab, ←→", "switch tab (also d n f t a)"),
    ("↑↓ j k", "move the selection, or scroll"),
    ("PgUp PgDn g G", "page, top, bottom"),
    ("Enter", "open the selected device or finding"),
    ("Esc", "back; clear the search"),
    ("/", "search devices or findings"),
    ("l", "show or hide Low and Info findings"),
    ("o", "sort devices by grade or by address"),
    ("f", "in a device: its findings"),
    ("s", "scan again"),
    ("e", "write results, fix plan and segment plan here"),
    ("?", "this help"),
    ("q, Ctrl-C", "quit"),
    (
        "mouse",
        "click a tab or row, click again to open, wheel scrolls",
    ),
];

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let width = 76.min(area.width);
    let height = (u16::try_from(KEYS.len()).unwrap_or(0) + 2).min(area.height);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let lines: Vec<Line> = KEYS
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(
                    format!(" {key:<15}"),
                    Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*what, Style::default().fg(p.fg)),
            ])
        })
        .collect();
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::default().bg(p.bg))
            .block(panel("Keys", &p)),
        popup,
    );
}
