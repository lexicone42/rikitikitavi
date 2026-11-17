use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use crate::app::App;
use crate::chrome::{render_doc, sev_badge};
use crate::text::Doc;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    render_doc(frame, area, app, "Attack paths", paths_doc);
}

fn paths_doc(app: &App, doc: &mut Doc) {
    let p = app.palette;
    let paths = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.attack_paths.as_slice());
    let dim = Style::default().fg(p.border);
    let fg = Style::default().fg(p.fg);

    if paths.is_empty() {
        doc.blank();
        let text = if app.results.is_none() {
            "No scan results yet."
        } else {
            "No attack path found: this scan saw no chain of findings that leads from one device to another."
        };
        doc.para(1, text, fg);
        return;
    }

    for path in paths {
        doc.blank();
        doc.line(vec![
            Span::raw(" "),
            sev_badge(path.severity, &p),
            Span::styled(format!(" {}", path.name), fg.add_modifier(Modifier::BOLD)),
        ]);
        doc.para(1, &path.description, dim);
        for step in &path.steps {
            doc.item(
                3,
                &format!("{}. ", step.order),
                Style::default().fg(p.accent),
                &format!(
                    "{} ({})",
                    step.title,
                    format!("{:?}", step.difficulty).to_lowercase()
                ),
                fg,
            );
            doc.para(6, &step.description, dim);
        }
    }
}
