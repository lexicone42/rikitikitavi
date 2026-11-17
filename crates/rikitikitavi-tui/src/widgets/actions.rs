use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use crate::app::App;
use crate::chrome::{badge, render_doc};
use crate::text::Doc;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    render_doc(frame, area, app, "Top actions", actions_doc);
}

fn actions_doc(app: &App, doc: &mut Doc) {
    let p = app.palette;
    let actions = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.priority_actions.as_slice());
    let dim = Style::default().fg(p.border);
    let fg = Style::default().fg(p.fg);

    if actions.is_empty() {
        doc.blank();
        let text = if app.results.is_none() {
            "No scan results yet."
        } else {
            "Nothing to do: no finding in this scan has a fix attached."
        };
        doc.para(1, text, fg);
        return;
    }

    doc.para(
        1,
        "Findings that share a fix are grouped; the order is by severity and how many devices each fix covers.",
        dim,
    );
    for action in actions {
        doc.blank();
        doc.item(
            1,
            &format!("{}. ", action.rank),
            Style::default()
                .fg(p.severity_color(action.severity))
                .add_modifier(Modifier::BOLD),
            &action.title,
            fg.add_modifier(Modifier::BOLD),
        );
        let effort = action
            .effort
            .as_deref()
            .map_or_else(String::new, |e| format!(" · {e}"));
        doc.line(vec![
            Span::raw("    "),
            badge_for(action.severity, app),
            Span::styled(
                format!(
                    "  {} · {}{effort}",
                    plural(action.affected_device_count, "device"),
                    plural(action.finding_count, "finding"),
                ),
                dim,
            ),
        ]);
        for (i, step) in action.steps.iter().enumerate() {
            doc.item(
                4,
                &format!("{:>2}. ", i + 1),
                Style::default().fg(p.accent),
                step,
                fg,
            );
        }
    }
}

fn badge_for(severity: rikitikitavi_core::Severity, app: &App) -> Span<'static> {
    let p = app.palette;
    match severity {
        rikitikitavi_core::Severity::Critical => badge(" CRITICAL ", p.critical, &p),
        rikitikitavi_core::Severity::High => badge(" HIGH ", p.high, &p),
        rikitikitavi_core::Severity::Medium => badge(" MEDIUM ", p.medium, &p),
        rikitikitavi_core::Severity::Low => badge(" LOW ", p.low, &p),
        rikitikitavi_core::Severity::Info => badge(" INFO ", p.info, &p),
    }
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}
