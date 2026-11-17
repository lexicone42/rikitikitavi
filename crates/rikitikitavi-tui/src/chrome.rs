use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use rikitikitavi_core::Severity;
use unicode_width::UnicodeWidthStr;

use crate::app::{App, Detail, HitRegions, Screen};
use crate::text::{Doc, truncate};
use crate::theme::Palette;
use crate::widgets;

const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

/// Render one frame: tab bar, the current screen, hint line. Hit regions are rebuilt.
pub fn draw(frame: &mut Frame, app: &mut App) {
    app.hit_regions = HitRegions::default();
    let p = app.palette;
    frame.render_widget(
        Block::default().style(Style::default().bg(p.bg).fg(p.fg)),
        frame.area(),
    );

    let [tabs, body, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_tabs(frame, tabs, app);
    match (app.detail, app.screen) {
        (Some(Detail::Device(ip)), _) => widgets::devices::render_detail(frame, body, app, ip),
        (Some(Detail::Finding(i)), _) => widgets::findings::render_detail(frame, body, app, i),
        (None, Screen::Overview) => widgets::overview::render(frame, body, app),
        (None, Screen::Devices) => widgets::devices::render(frame, body, app),
        (None, Screen::Findings) => widgets::findings::render(frame, body, app),
        (None, Screen::Actions) => widgets::actions::render(frame, body, app),
        (None, Screen::AttackPaths) => widgets::attack_paths::render(frame, body, app),
    }
    render_hints(frame, hints, app);
    if app.show_help {
        widgets::help::render(frame, body, app);
    }
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &mut App) {
    let p = app.palette;
    let brand = if area.width < 100 {
        " "
    } else {
        " rikitikitavi "
    };
    let mut spans = vec![Span::styled(
        brand,
        Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
    )];
    let mut x = area.x + u16::try_from(brand.len()).unwrap_or(0);
    for (i, screen) in Screen::ALL.into_iter().enumerate() {
        let name = if area.width < 110 {
            screen.short_title()
        } else {
            screen.title()
        };
        let label = format!(" {} {name} ", i + 1);
        let width = u16::try_from(label.width()).unwrap_or(0);
        let style = if screen == app.screen {
            Style::default()
                .fg(p.bg)
                .bg(p.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(p.fg)
        };
        if x + width <= area.right() {
            app.hit_regions
                .tabs
                .push((Rect::new(x, area.y, width, 1), screen));
        }
        spans.push(Span::styled(label, style));
        x += width;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);

    let room = usize::from(area.right().saturating_sub(x + 1));
    let state = [scan_state(app, true), scan_state(app, false)]
        .into_iter()
        .find(|s| s.width() <= room);
    if let Some(state) = state {
        let width = u16::try_from(state.width()).unwrap_or(0);
        let style = Style::default().fg(if app.scanning() { p.accent } else { p.border });
        frame.render_widget(
            Paragraph::new(Span::styled(state, style)),
            Rect::new(area.right() - width, area.y, width, 1),
        );
    }
}

/// Right side of the tab bar: scan in progress, or when the shown results were taken.
fn scan_state(app: &App, long: bool) -> String {
    let taken = app.results.as_ref().map(|r| {
        r.scanned_at
            .with_timezone(&chrono::Local)
            .format("%b %-d %H:%M")
            .to_string()
    });
    match (app.scan_started, taken) {
        (Some(since), taken) => {
            #[allow(clippy::cast_possible_truncation)]
            let frame = SPINNER[(app.tick / 2 % 8) as usize];
            let shown = taken
                .filter(|_| long)
                .map_or_else(String::new, |t| format!(" · showing {t}"));
            format!("{frame} scanning {}s{shown} ", since.elapsed().as_secs())
        }
        (None, Some(taken)) if long => {
            let secs = app.results.as_ref().map_or(0, |r| r.scan_duration_secs);
            format!("scanned {taken} in {secs}s ")
        }
        (None, Some(taken)) => format!("{taken} "),
        (None, None) => String::new(),
    }
}

fn render_hints(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let key = Style::default().fg(p.accent).add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(p.border);

    if app.search_editing {
        let line = Line::from(vec![
            Span::styled(" /", key),
            Span::styled(app.search.clone(), Style::default().fg(p.fg)),
            Span::styled("▏", key),
            Span::styled("  Enter keep · Esc clear", dim),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    let hints: &[(&str, &str)] = match (app.detail, app.screen) {
        (Some(Detail::Device(_)), _) => &[("↑↓", "scroll"), ("f", "its findings"), ("Esc", "back")],
        (Some(Detail::Finding(_)), _) => &[("↑↓", "scroll"), ("Esc", "back")],
        (None, Screen::Devices) => &[
            ("↑↓", "select"),
            ("Enter", "open"),
            ("/", "search"),
            ("o", "sort"),
        ],
        (None, Screen::Findings) => &[
            ("↑↓", "select"),
            ("Enter", "open"),
            ("/", "search"),
            ("l", "low/info"),
        ],
        (None, Screen::Overview) => &[("1-5", "tabs")],
        (None, _) => &[("↑↓", "scroll")],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, what) in
        hints
            .iter()
            .chain(&[("s", "scan"), ("e", "export"), ("?", "help"), ("q", "quit")])
    {
        spans.push(Span::styled((*k).to_owned(), key));
        spans.push(Span::styled(format!(" {what}  "), dim));
    }
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    frame.render_widget(Paragraph::new(Line::from(spans)), area);

    let room = usize::from(area.width).saturating_sub(used + 1);
    if let Some(status) = app.status()
        && room > 8
    {
        let text = truncate(status, room);
        let width = u16::try_from(text.width()).unwrap_or(0);
        frame.render_widget(
            Paragraph::new(Span::styled(text, Style::default().fg(p.low))),
            Rect::new(area.right() - width - 1, area.y, width, 1),
        );
    }
}

/// `Name 3/45`: the selected row and the number of rows.
pub fn list_title(name: &str, state: &ratatui::widgets::TableState, shown: usize) -> String {
    format!(
        "{name} {}/{shown}",
        state.selected().map_or(0, |row| row + 1)
    )
}

/// One dim line inside an empty table, below its header.
pub fn empty_note(frame: &mut Frame, inner: Rect, text: &str, p: &Palette) {
    frame.render_widget(
        Paragraph::new(Span::styled(text.to_owned(), Style::default().fg(p.border))),
        Rect::new(inner.x + 1, inner.y + 2, inner.width.saturating_sub(1), 1),
    );
}

/// Data rows of a table drawn in `inner` with a one-line header.
pub const fn data_rows(inner: Rect) -> Rect {
    Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    )
}

/// Rounded, titled panel.
pub fn panel<'a>(title: impl Into<String>, p: &Palette) -> Block<'a> {
    Block::default()
        .title(Span::styled(
            format!(" {} ", title.into()),
            Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(p.border))
}

/// Six-column severity badge.
pub fn sev_badge(severity: Severity, p: &Palette) -> Span<'static> {
    let text = match severity {
        Severity::Critical => " CRIT ",
        Severity::High => " HIGH ",
        Severity::Medium => " MED  ",
        Severity::Low => " LOW  ",
        Severity::Info => " INFO ",
    };
    badge(text, p.severity_color(severity), p)
}

pub fn badge(text: &'static str, color: Color, p: &Palette) -> Span<'static> {
    Span::styled(
        text,
        Style::default()
            .fg(p.bg)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

/// Render `build`'s document in a panel, scrolled by `app.text_scroll` (clamped here).
pub fn render_doc(
    frame: &mut Frame,
    area: Rect,
    app: &mut App,
    title: &str,
    build: impl FnOnce(&App, &mut Doc),
) {
    let p = app.palette;
    let mut block = panel(title, &p);
    let inner = block.inner(area);
    let mut doc = Doc::new(inner.width.saturating_sub(1));
    build(app, &mut doc);

    let total = doc.lines.len();
    let visible = usize::from(inner.height);
    let max = u16::try_from(total.saturating_sub(visible)).unwrap_or(u16::MAX);
    app.text_scroll = app.text_scroll.min(max);
    if max > 0 {
        let first = usize::from(app.text_scroll) + 1;
        let last = (first + visible - 1).min(total);
        block = block.title_top(
            Line::from(Span::styled(
                format!(" {first}-{last} of {total} "),
                Style::default().fg(p.border),
            ))
            .right_aligned(),
        );
    }
    frame.render_widget(
        Paragraph::new(doc.lines)
            .block(block)
            .scroll((app.text_scroll, 0)),
        area,
    );
}

/// Dim "label" column followed by a wrapped value.
pub fn field(doc: &mut Doc, label: &str, value: &str, p: &Palette) {
    doc.item(
        1,
        &format!("{label:<13}"),
        Style::default().fg(p.border),
        value,
        Style::default().fg(p.fg),
    );
}

pub fn heading(doc: &mut Doc, text: impl Into<String>, p: &Palette) {
    doc.blank();
    doc.line(vec![Span::styled(
        format!(" {}", text.into()),
        Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
    )]);
}
