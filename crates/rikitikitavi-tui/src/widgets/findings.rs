use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::{App, SeverityFilter};
use crate::theme::Palette;

#[allow(clippy::too_many_lines)]
pub fn render(frame: &mut Frame, app: &mut App) {
    let palette = Palette::from_theme(app.config.theme);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Table
            Constraint::Length(12), // Detail pane (slightly taller for remediation)
            Constraint::Length(3),  // Footer
        ])
        .split(frame.area());

    // Build all owned data from filtered findings, then drop the borrow.
    // This lets us mutably borrow `app.findings_table_state` for the stateful render.
    let (rows, scroll_info, detail_text) = {
        let filtered = app.filtered_findings();
        let filtered_count = filtered.len();

        let scroll_info = if filtered_count > 0 {
            let pos = app.selected_finding_index + 1;
            format!(" Findings ({pos}/{filtered_count}) ")
        } else {
            match app.severity_filter {
                SeverityFilter::ActionableOnly => {
                    format!(" Findings ({filtered_count} Critical/High/Medium) ")
                }
                SeverityFilter::All => {
                    format!(" Findings ({filtered_count} All) ")
                }
            }
        };

        let rows: Vec<Row> = filtered
            .iter()
            .map(|f| {
                let sev_color = palette.severity_color(f.severity);

                let sev_badge = match f.severity {
                    rikitikitavi_core::Severity::Critical => " CRIT ",
                    rikitikitavi_core::Severity::High => " HIGH ",
                    rikitikitavi_core::Severity::Medium => " MED  ",
                    rikitikitavi_core::Severity::Low => " LOW  ",
                    rikitikitavi_core::Severity::Info => " INFO ",
                };

                Row::new(vec![
                    Line::from(Span::styled(
                        sev_badge,
                        Style::default()
                            .fg(palette.bg)
                            .bg(sev_color)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(
                        f.title.clone(),
                        Style::default().fg(palette.fg),
                    )),
                    Line::from(Span::styled(
                        f.affected_ip
                            .map_or_else(|| "-".to_owned(), |ip| ip.to_string()),
                        Style::default().fg(palette.fg),
                    )),
                    Line::from(Span::styled(
                        f.scanner.clone(),
                        Style::default().fg(palette.border),
                    )),
                ])
            })
            .collect();

        // Build detail pane content (all owned Strings, no borrows retained)
        let detail_text = filtered.get(app.selected_finding_index).map_or_else(
            || {
                vec![
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Select a finding to see details.",
                        Style::default()
                            .fg(palette.border)
                            .add_modifier(Modifier::ITALIC),
                    )),
                ]
            },
            |f| {
                let sev_color = palette.severity_color(f.severity);
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(
                            format!(" {} ", f.severity),
                            Style::default()
                                .fg(palette.bg)
                                .bg(sev_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("  {}", f.title),
                            Style::default()
                                .fg(palette.fg)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        format!("  {}", f.description),
                        Style::default().fg(palette.fg),
                    )),
                ];

                if let Some(cwe) = &f.cwe_id {
                    lines.push(Line::from(vec![
                        Span::styled("  CWE: ", Style::default().fg(palette.border)),
                        Span::styled(
                            cwe.clone(),
                            Style::default()
                                .fg(palette.accent)
                                .add_modifier(Modifier::UNDERLINED),
                        ),
                    ]));
                }

                if let Some(ip) = f.affected_ip {
                    lines.push(Line::from(vec![
                        Span::styled("  Device: ", Style::default().fg(palette.border)),
                        Span::styled(ip.to_string(), Style::default().fg(palette.fg)),
                    ]));
                }

                // Show remediation if present
                if let Some(remediation) = &f.remediation {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!("  Fix: {}", remediation.description),
                        Style::default()
                            .fg(palette.accent)
                            .add_modifier(Modifier::BOLD),
                    )));
                    if let Some(effort) = &remediation.effort {
                        lines.push(Line::from(Span::styled(
                            format!("  Effort: {effort}"),
                            Style::default().fg(palette.border),
                        )));
                    }
                }

                lines
            },
        );

        (rows, scroll_info, detail_text)
    };
    // `filtered` is now dropped — safe to mutably borrow app.findings_table_state

    let header_row = Row::new(vec![
        Line::from(Span::styled("SEV", palette.header_style)),
        Line::from(Span::styled("FINDING", palette.header_style)),
        Line::from(Span::styled("DEVICE", palette.header_style)),
        Line::from(Span::styled("MODULE", palette.header_style)),
    ])
    .style(palette.header_style);

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(30),
            Constraint::Length(16),
            Constraint::Length(14),
        ],
    )
    .header(header_row)
    .row_highlight_style(palette.selected_style)
    .block(
        Block::default()
            .title(Span::styled(
                scroll_info,
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    let table_area = chunks[0];
    // Sync TableState selection before render so the widget auto-scrolls
    app.findings_table_state
        .select(Some(app.selected_finding_index));
    frame.render_stateful_widget(table, table_area, &mut app.findings_table_state);

    // Detail pane for selected finding
    let detail = Paragraph::new(detail_text).block(
        Block::default()
            .title(Span::styled(
                " Finding Details ",
                Style::default()
                    .fg(palette.accent)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(palette.border))
            .border_type(ratatui::widgets::BorderType::Rounded),
    );
    frame.render_widget(detail, chunks[1]);

    // Footer with filter toggle hint
    let filter_hint = match app.severity_filter {
        SeverityFilter::ActionableOnly => "[L]ow/Info: hidden",
        SeverityFilter::All => "[L]ow/Info: shown",
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            " [Findings] ",
            Style::default()
                .fg(palette.bg)
                .bg(palette.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("[j/k]", Style::default().fg(palette.accent)),
        Span::styled(" Scroll  ", Style::default().fg(palette.fg)),
        Span::styled("[PgUp/Dn]", Style::default().fg(palette.accent)),
        Span::styled(" Page  ", Style::default().fg(palette.fg)),
        Span::styled(filter_hint, Style::default().fg(palette.border)),
        Span::styled("  ", Style::default()),
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
    frame.render_widget(footer, chunks[2]);

    // Record the table as a clickable list area (after borrows are dropped)
    // Border (1) + header row (1) = 2 rows before data
    app.hit_regions.list_area = Some(table_area);
    app.hit_regions.list_header_offset = 2;
}
