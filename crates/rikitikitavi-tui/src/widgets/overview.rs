use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use rikitikitavi_core::Severity;
use rikitikitavi_models::Grade;

use crate::app::App;
use crate::art;
use crate::chrome::{panel, sev_badge};
use crate::text::truncate;

/// Eighth-block characters for the severity bars.
const BLOCKS: [char; 9] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];

const SEVERITIES: [(Severity, &str); 5] = [
    (Severity::Critical, "Critical"),
    (Severity::High, "High"),
    (Severity::Medium, "Medium"),
    (Severity::Low, "Low"),
    (Severity::Info, "Info"),
];

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let [top, bottom] =
        Layout::vertical([Constraint::Length(art::HEIGHT + 2), Constraint::Min(0)]).areas(area);

    let mascot_width = art::WIDTH + 3;
    let show_mascot = top.width >= mascot_width + 44;
    let [mascot, risk] = Layout::horizontal([
        Constraint::Length(if show_mascot { mascot_width } else { 0 }),
        Constraint::Min(0),
    ])
    .areas(top);
    if show_mascot {
        let mut lines = art::mascot(app.tick, &app.palette);
        for line in &mut lines {
            line.spans.insert(0, Span::raw(" "));
        }
        let title = if app.scanning() {
            "Hunting"
        } else {
            "On watch"
        };
        frame.render_widget(
            Paragraph::new(lines).block(panel(title, &app.palette)),
            mascot,
        );
    }
    render_risk(frame, risk, app);

    let [devices, actions] = if bottom.width >= 100 {
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(bottom)
    } else {
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(bottom)
    };
    render_worst_devices(frame, devices, app);
    render_actions(frame, actions, app);
}

fn render_risk(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let block = panel("Risk", &p);
    let Some(results) = &app.results else {
        let text = if app.scanning() {
            "  First scan in progress. Results appear here when it finishes."
        } else {
            "  No scan results. Press s to scan."
        };
        frame.render_widget(
            Paragraph::new(vec![Line::default(), Line::from(text)]).block(block),
            area,
        );
        return;
    };

    let count = |s: Severity| results.findings.iter().filter(|f| f.severity == s).count();
    let counts: Vec<usize> = SEVERITIES.iter().map(|(s, _)| count(*s)).collect();
    let max = counts.iter().copied().max().unwrap_or(0).max(1);
    let bar_width = usize::from(area.width).saturating_sub(22).clamp(4, 36);

    let (grade, hint) = rikitikitavi_analysis::risk_grade(counts[0], counts[1], counts[2]);
    let grade_color = match hint {
        "critical" => p.critical,
        "high" => p.high,
        "medium" => p.medium,
        "low" => p.low,
        _ => p.info,
    };
    let bold = Modifier::BOLD;
    let mut notes = vec![format!(
        "{} devices · {} findings",
        results.devices.len(),
        results.findings.len()
    )];
    if let Some(diff) = &app.scan_diff {
        notes.push(format!(
            "+{} new, -{} resolved",
            diff.new_findings.len(),
            diff.resolved_findings.len()
        ));
    }
    let kev = results.findings.iter().filter(|f| f.is_kev).count();
    if kev > 0 {
        notes.push(format!("{kev} known exploited"));
    }
    if !results.accepted.is_empty() {
        notes.push(format!("{} accepted", results.accepted.len()));
    }
    let mut lines = vec![
        Line::from(vec![
            Span::styled(" Network grade  ", Style::default().fg(p.border)),
            Span::styled(grade, Style::default().fg(grade_color).add_modifier(bold)),
        ]),
        Line::from(Span::styled(
            format!(" {}", notes.join(" · ")),
            Style::default().fg(p.fg),
        )),
        Line::default(),
    ];
    for ((severity, label), n) in SEVERITIES.iter().zip(&counts) {
        lines.push(bar_line(
            label,
            *n,
            max,
            bar_width,
            p.severity_color(*severity),
        ));
    }
    lines.push(Line::default());

    let mut grades = vec![Span::styled(
        " Device grades  ",
        Style::default().fg(p.border),
    )];
    for g in Grade::ALL {
        let n = results.report_cards.iter().filter(|c| c.grade == g).count();
        if n > 0 {
            grades.push(Span::styled(
                format!("{} {n}  ", g.letter()),
                Style::default().fg(p.grade_color(g)).add_modifier(bold),
            ));
        }
    }
    lines.push(Line::from(grades));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Proportional bar; a non-zero count always shows at least one eighth.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn bar_line(label: &str, count: usize, max: usize, width: usize, color: Color) -> Line<'static> {
    let eighths = ((count as f64 / max as f64) * (width * 8) as f64).round() as usize;
    let eighths = eighths.clamp(usize::from(count > 0), width * 8);
    let mut bar = "█".repeat(eighths / 8);
    if eighths % 8 > 0 {
        bar.push(BLOCKS[eighths % 8]);
    }
    let pad = width.saturating_sub(bar.chars().count());
    Line::from(vec![
        Span::styled(format!(" {label:<9}"), Style::default().fg(color)),
        Span::styled(
            format!("{bar}{}", " ".repeat(pad)),
            Style::default().fg(color),
        ),
        Span::styled(
            format!(" {count}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn render_worst_devices(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let block = panel("Devices needing attention", &p);
    let rows = usize::from(block.inner(area).height);
    let width = usize::from(block.inner(area).width);
    let Some(results) = &app.results else {
        frame.render_widget(block, area);
        return;
    };

    let mut cards: Vec<_> = results
        .report_cards
        .iter()
        .filter(|c| c.actionable() > 0 && c.grade != Grade::A)
        .collect();
    cards.sort_by(|a, b| {
        b.grade
            .cmp(&a.grade)
            .then(b.actionable().cmp(&a.actionable()))
            .then(a.ip.cmp(&b.ip))
    });
    let total = cards.len();

    let mut lines: Vec<Line> = cards
        .iter()
        .take(if total > rows {
            rows.saturating_sub(1)
        } else {
            rows
        })
        .map(|c| {
            let name = app
                .device_name(c.ip)
                .map_or_else(|| c.ip.to_string(), str::to_owned);
            let name_width = width.saturating_sub(5).min(28);
            let rest = width.saturating_sub(5 + name_width + 2);
            Line::from(vec![
                Span::styled(
                    format!("  {}  ", c.grade.letter()),
                    Style::default()
                        .fg(p.grade_color(c.grade))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<name_width$}", truncate(&name, name_width)),
                    Style::default().fg(p.fg),
                ),
                Span::styled(
                    format!("  {}", truncate(&c.rationale, rest)),
                    Style::default().fg(p.border),
                ),
            ])
        })
        .collect();
    if total > rows {
        lines.push(more_line(
            total - rows.saturating_sub(1),
            "2 for all devices",
            app,
        ));
    }
    if total == 0 {
        lines.push(Line::from(Span::styled(
            "  Every device with findings is graded A.",
            Style::default().fg(p.low),
        )));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_actions(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let block = panel("What to fix first", &p);
    let rows = usize::from(block.inner(area).height);
    let width = usize::from(block.inner(area).width);
    let actions = app
        .results
        .as_ref()
        .map_or(&[][..], |r| r.priority_actions.as_slice());
    let total = actions.len();

    let mut lines: Vec<Line> = actions
        .iter()
        .take(if total > rows {
            rows.saturating_sub(1)
        } else {
            rows
        })
        .map(|a| {
            let scope = if a.affected_device_count == 1 {
                "  1 device".to_owned()
            } else {
                format!("  {} devices", a.affected_device_count)
            };
            let room = width.saturating_sub(9 + scope.len());
            Line::from(vec![
                Span::raw(" "),
                sev_badge(a.severity, &p),
                Span::styled(
                    format!(" {}", truncate(&a.title, room)),
                    Style::default().fg(p.fg),
                ),
                Span::styled(scope, Style::default().fg(p.border)),
            ])
        })
        .collect();
    if total > rows {
        lines.push(more_line(
            total - rows.saturating_sub(1),
            "4 for the steps",
            app,
        ));
    }
    if total == 0 && app.results.is_some() {
        lines.push(Line::from(Span::styled(
            "  No finding in this scan has a fix attached.",
            Style::default().fg(p.low),
        )));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn more_line(hidden: usize, hint: &str, app: &App) -> Line<'static> {
    Line::from(Span::styled(
        format!("  … {hidden} more ({hint})"),
        Style::default()
            .fg(app.palette.border)
            .add_modifier(Modifier::ITALIC),
    ))
}
