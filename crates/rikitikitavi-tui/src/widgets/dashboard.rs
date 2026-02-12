use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use rikitikitavi_models::Finding;

use crate::app::App;
use crate::theme::Palette;

/// The Rikki-Tikki-Tavi mascot — proud mongoose with a cobra in its jaws!
/// Lines above the animated snake chin line.
const MONGOOSE_TOP: &[&str] = &[
    r"             ,,,,,      ",
    r"           ,:::::::,    ",
    r"          ,::/^\:::::,  ",
    r"         ,::( ^  ^)::,  ",
    r"         `:::\ w  /::;  ",
];

/// The mongoose's chin/face line (before the dangling snake).
const SNAKE_FACE: &str = "           ';:`. .':;'";

/// Animated snake dangling from the mongoose's jaws — 4 wiggle frames.
const SNAKE_DANGLE: &[&str] = &["~§>", "§~>", "~>§", ">§~"];

/// Mongoose body below the face — shared across all animation frames.
const MONGOOSE_BOTTOM: &[&str] = &[
    r"             / `'` \    ",
    r"            / .---. \   ",
    r"           / /     \ \  ",
    r"          ( (  \ /  ) ) ",
    r"          `-\  |Y|  /-' ",
    r"             | |=| |    ",
    r"             |_| |_|    ",
];

/// Severity bar sparkline characters.
const BLOCKS: &[char] = &[' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &mut App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(15), // Mascot + Risk overview
            Constraint::Min(6),     // Recent findings
            Constraint::Length(3),  // Scan status
            Constraint::Length(3),  // Footer
        ])
        .split(frame.area());

    // ── Header ──────────────────────────────────────────────────────────
    render_header(frame, chunks[0], &palette, app);

    // ── Mascot + Risk Summary ───────────────────────────────────────────
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(chunks[1]);

    render_mascot(frame, top_chunks[0], &palette, app.tick);
    render_risk_summary(frame, top_chunks[1], app, &palette);

    // ── Recent Findings ─────────────────────────────────────────────────
    render_recent_findings(frame, chunks[2], app, &palette);

    // ── Scan Status ─────────────────────────────────────────────────────
    super::scan_progress::render(frame, chunks[3], app);

    // ── Footer ──────────────────────────────────────────────────────────
    render_footer(frame, chunks[4], &palette, app);

    // Record recent findings area as clickable list
    app.hit_regions.list_area = Some(chunks[2]);
    // 1 row for top border, no header row
    app.hit_regions.list_header_offset = 1;
}

fn render_header(frame: &mut Frame, area: Rect, palette: &Palette, app: &App) {
    let title_spans = vec![
        Span::styled(
            "  ╱╱  ",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "rikitikitavi",
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  ─  Home Network Security Auditor",
            Style::default().fg(palette.fg),
        ),
    ];

    // Show status message on the right if available
    let status = app.status_message.as_deref().map_or_else(Vec::new, |msg| {
        vec![Span::styled(
            format!("  [{msg}]"),
            Style::default()
                .fg(palette.low)
                .add_modifier(Modifier::ITALIC),
        )]
    });

    let mut spans = title_spans;
    spans.extend(status);

    let header = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(header, area);
}

fn render_mascot(frame: &mut Frame, area: Rect, palette: &Palette, tick: u64) {
    #[allow(clippy::cast_possible_truncation)]
    let snake_frame = (tick / 3 % 4) as usize;

    // Top lines: mongoose head with proud eyes and biting mouth
    let mut lines: Vec<Line> = MONGOOSE_TOP
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                (*line).to_owned(),
                Style::default().fg(palette.accent),
            ))
        })
        .collect();

    // Animated chin line: face in accent color + dangling snake in green
    lines.push(Line::from(vec![
        Span::styled(SNAKE_FACE.to_owned(), Style::default().fg(palette.accent)),
        Span::styled(
            SNAKE_DANGLE[snake_frame].to_owned(),
            Style::default()
                .fg(palette.low)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // Bottom lines: mongoose body
    lines.extend(MONGOOSE_BOTTOM.iter().map(|line| {
        Line::from(Span::styled(
            (*line).to_owned(),
            Style::default().fg(palette.accent),
        ))
    }));

    let mascot = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                " Rikki-Tikki-Tavi ",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(mascot, area);
}

#[allow(clippy::too_many_lines)]
fn render_risk_summary(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let findings = app.findings();
    let total = findings.len();
    let critical = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Low)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == rikitikitavi_core::Severity::Info)
        .count();

    // Build visual severity bars
    let max_count = [critical, high, medium, low, info]
        .into_iter()
        .max()
        .unwrap_or(1)
        .max(1);

    let bar_width: usize = 20;

    let mut lines = vec![
        Line::from(""),
        severity_bar_line(
            "  CRITICAL ",
            critical,
            max_count,
            bar_width,
            palette.critical,
        ),
        severity_bar_line("  HIGH     ", high, max_count, bar_width, palette.high),
        severity_bar_line("  MEDIUM   ", medium, max_count, bar_width, palette.medium),
        Line::from(Span::styled(
            format!("  Low/Info: {low} + {info}"),
            Style::default().fg(palette.border),
        )),
        Line::from(""),
    ];

    // Action required callout
    if critical + high > 0 {
        lines.push(Line::from(vec![Span::styled(
            format!("  Action Required: {} findings", critical + high),
            Style::default()
                .fg(palette.critical)
                .add_modifier(Modifier::BOLD),
        )]));
    }

    lines.push(Line::from(vec![
        Span::styled("  Devices: ", Style::default().fg(palette.fg)),
        Span::styled(
            format!("{}", app.devices().len()),
            Style::default()
                .fg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   Findings: ", Style::default().fg(palette.fg)),
        Span::styled(
            format!("{total}"),
            Style::default()
                .fg(if critical > 0 {
                    palette.critical
                } else if high > 0 {
                    palette.high
                } else {
                    palette.low
                })
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // Diff summary (when comparison data is available)
    if let Some(diff) = &app.scan_diff {
        lines.push(Line::from(Span::styled(
            format!(
                "  Since last: +{} new, -{} resolved",
                diff.new_findings.len(),
                diff.resolved_findings.len(),
            ),
            Style::default().fg(palette.accent),
        )));
    }

    // Risk grade
    let grade = map_risk_grade(critical, high, medium, palette);
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  Risk Grade: ", Style::default().fg(palette.fg)),
        Span::styled(
            grade.0,
            Style::default().fg(grade.1).add_modifier(Modifier::BOLD),
        ),
    ]));

    let risk = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                " Risk Overview ",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(risk, area);
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn severity_bar_line(
    label: &str,
    count: usize,
    max_count: usize,
    bar_width: usize,
    color: ratatui::style::Color,
) -> Line<'_> {
    let filled_exact = if max_count > 0 {
        (count as f64 / max_count as f64) * bar_width as f64
    } else {
        0.0
    };
    let full_blocks = filled_exact.max(0.0) as usize;
    let remainder = filled_exact - full_blocks as f64;
    let partial_idx = (remainder * 8.0).max(0.0) as usize;

    let mut bar = String::with_capacity(bar_width);
    for _ in 0..full_blocks.min(bar_width) {
        bar.push(BLOCKS[8]); // full block
    }
    if full_blocks < bar_width && partial_idx > 0 {
        bar.push(BLOCKS[partial_idx]);
        for _ in (full_blocks + 1)..bar_width {
            bar.push(' ');
        }
    } else {
        for _ in full_blocks..bar_width {
            bar.push(' ');
        }
    }

    Line::from(vec![
        Span::styled(label.to_owned(), Style::default().fg(color)),
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(
            format!(" {count}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

fn map_risk_grade(
    critical: usize,
    high: usize,
    medium: usize,
    palette: &Palette,
) -> (&'static str, ratatui::style::Color) {
    let (label, color_hint) = rikitikitavi_analysis::risk_grade(critical, high, medium);
    let color = match color_hint {
        "critical" => palette.critical,
        "high" => palette.high,
        "medium" => palette.medium,
        "low" => palette.low,
        _ => palette.info,
    };
    (label, color)
}

fn render_recent_findings(frame: &mut Frame, area: Rect, app: &App, palette: &Palette) {
    let findings = app.findings();

    // Sort by severity descending so Critical/High appear first
    let mut sorted_findings: Vec<&Finding> = findings.iter().collect();
    sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    #[allow(clippy::cast_possible_truncation)]
    let snake_frame = (app.tick / 4 % 4) as usize;
    let idle_snake = SNAKE_DANGLE[snake_frame];

    let recent: Vec<Line> = if sorted_findings.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No findings yet. Press [S] to hunt for cobras!",
                Style::default().fg(palette.fg),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "  The mongoose stalks through your network",
                    Style::default()
                        .fg(palette.border)
                        .add_modifier(Modifier::ITALIC),
                ),
                Span::styled(
                    format!("  {idle_snake}"),
                    Style::default()
                        .fg(palette.low)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ]
    } else {
        sorted_findings
            .iter()
            .take(12)
            .map(|f| {
                let sev_color = palette.severity_color(f.severity);
                let badge = match f.severity {
                    rikitikitavi_core::Severity::Critical => " CRIT ",
                    rikitikitavi_core::Severity::High => " HIGH ",
                    rikitikitavi_core::Severity::Medium => " MED  ",
                    rikitikitavi_core::Severity::Low => " LOW  ",
                    rikitikitavi_core::Severity::Info => " INFO ",
                };
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        badge,
                        Style::default()
                            .fg(palette.bg)
                            .bg(sev_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled(truncate_str(&f.title, 60), Style::default().fg(palette.fg)),
                    Span::styled(
                        format!("  ({})", f.scanner),
                        Style::default().fg(palette.border),
                    ),
                ])
            })
            .collect()
    };

    let recent_findings = Paragraph::new(recent).block(
        Block::default()
            .title(Span::styled(
                format!(" Recent Findings ({}) ", findings.len()),
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(recent_findings, area);
}

fn render_footer(frame: &mut Frame, area: Rect, palette: &Palette, app: &mut App) {
    use crate::app::Screen;

    let screen_indicator = match app.screen {
        crate::app::Screen::Dashboard => "Dashboard",
        crate::app::Screen::NetworkMap => "Network Map",
        crate::app::Screen::Findings => "Findings",
        crate::app::Screen::AttackPaths => "Attack Paths",
        crate::app::Screen::TopActions => "Top Actions",
        crate::app::Screen::DeviceDetail => "Device Detail",
    };

    // Build the screen indicator text to compute its width
    let indicator_text = format!(" [{screen_indicator}] ");
    #[allow(clippy::cast_possible_truncation)]
    let indicator_width = indicator_text.len() as u16;

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            indicator_text,
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[D]", Style::default().fg(palette.accent)),
        Span::styled("ash  ", Style::default().fg(palette.fg)),
        Span::styled("[N]", Style::default().fg(palette.accent)),
        Span::styled("etwork  ", Style::default().fg(palette.fg)),
        Span::styled("[F]", Style::default().fg(palette.accent)),
        Span::styled("indings  ", Style::default().fg(palette.fg)),
        Span::styled("[A]", Style::default().fg(palette.accent)),
        Span::styled("ttacks  ", Style::default().fg(palette.fg)),
        Span::styled("[T]", Style::default().fg(palette.accent)),
        Span::styled("op Actions  ", Style::default().fg(palette.fg)),
        Span::styled("[S]", Style::default().fg(palette.accent)),
        Span::styled("can  ", Style::default().fg(palette.fg)),
        Span::styled("[E]", Style::default().fg(palette.accent)),
        Span::styled("xport  ", Style::default().fg(palette.fg)),
        Span::styled("[Q]", Style::default().fg(palette.accent)),
        Span::styled("uit", Style::default().fg(palette.fg)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(footer, area);

    // Record clickable tab regions in the footer.
    // The footer content starts at area.x + 1 (border) + indicator_width + 2 (spacing).
    let content_y = area.y + 1; // row inside the border
    let mut x = area.x + 1 + indicator_width + 2;
    let tabs: &[(&str, Screen)] = &[
        ("[D]ash", Screen::Dashboard),
        ("[N]etwork", Screen::NetworkMap),
        ("[F]indings", Screen::Findings),
        ("[A]ttacks", Screen::AttackPaths),
        ("[T]op Actions", Screen::TopActions),
    ];
    for &(label, screen) in tabs {
        #[allow(clippy::cast_possible_truncation)]
        let w = label.len() as u16 + 2; // label + trailing spaces
        app.hit_regions
            .footer_tabs
            .push((Rect::new(x, content_y, w, 1), screen));
        x += w;
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
