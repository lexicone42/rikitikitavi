use std::fmt::Write as _;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use rikitikitavi_models::Finding;

use crate::app::{App, DiffStatus, SeverityFilter};
use crate::chrome::{
    badge, data_rows, empty_note, field, heading, list_title, panel, render_doc, sev_badge,
};
use crate::text::{Doc, short_title};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let p = app.palette;
    let preview_height = (area.height * 2 / 5)
        .max(8)
        .min(area.height.saturating_sub(6));
    let [table_area, preview_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(preview_height)]).areas(area);

    let has_diff = app.scan_diff.is_some();
    let modules = area.width >= 100;

    let mut header = vec!["SEV"];
    let mut widths = vec![Constraint::Length(6)];
    if has_diff {
        header.push("");
        widths.push(Constraint::Length(3));
    }
    header.extend(["FINDING", "DEVICE", "PORT"]);
    widths.extend([
        Constraint::Min(24),
        Constraint::Length(if area.width >= 100 { 26 } else { 18 }),
        Constraint::Length(5),
    ]);
    if modules {
        header.push("MODULE");
        widths.push(Constraint::Length(13));
    }

    let rows: Vec<Row> = app
        .finding_rows()
        .map(|f| {
            let fg = Style::default().fg(p.fg);
            let dim = Style::default().fg(p.border);
            let mut cells = vec![Line::from(sev_badge(f.severity, &p))];
            if has_diff {
                cells.push(Line::from(match app.finding_diff_status(f) {
                    Some(DiffStatus::New) => badge("NEW", p.accent, &p),
                    Some(DiffStatus::SeverityChanged) => badge("CHG", p.medium, &p),
                    _ => Span::raw(""),
                }));
            }
            let mut title = Vec::new();
            if f.is_kev {
                title.push(badge("KEV", p.critical, &p));
                title.push(Span::raw(" "));
            }
            title.push(Span::styled(short_title(f).to_owned(), fg));
            cells.push(Line::from(title));
            cells.push(Line::from(Span::styled(device_label(app, f), fg)));
            cells.push(Line::from(Span::styled(
                f.affected_port
                    .map_or_else(String::new, |n| format!("{n:>5}")),
                dim,
            )));
            if modules {
                cells.push(Line::from(Span::styled(f.scanner.clone(), dim)));
            }
            Row::new(cells)
        })
        .collect();

    let shown = rows.len();
    let block = panel(table_title(app, shown), &p);
    let inner = block.inner(table_area);
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(p.header_style))
        .column_spacing(2)
        .row_highlight_style(p.selected_style)
        .block(block);
    frame.render_stateful_widget(table, table_area, &mut app.findings_state);
    if shown == 0 {
        let hidden = app.findings().len();
        let text = if app.results.is_none() {
            "No scan results yet.".to_owned()
        } else if !app.search.is_empty() || app.only_device.is_some() {
            "No finding matches. Esc clears the filter.".to_owned()
        } else if hidden > 0 {
            format!("Nothing of Medium severity or worse. Press l to show {hidden} Low/Info.")
        } else {
            "No findings.".to_owned()
        };
        empty_note(frame, inner, &text, &p);
    }
    app.hit_regions.rows = Some(data_rows(inner));

    render_preview(frame, preview_area, app);
}

fn table_title(app: &App, shown: usize) -> String {
    let mut title = list_title("Findings", &app.findings_state, shown);
    title.push_str(match app.severity_filter {
        SeverityFilter::ActionableOnly => " · Medium and worse",
        SeverityFilter::All => " · all severities",
    });
    if let Some(ip) = app.only_device {
        let name = app
            .device_name(ip)
            .map_or_else(|| ip.to_string(), str::to_owned);
        let _ = write!(title, " · on {name} (Esc for all)");
    }
    if !app.search.is_empty() {
        let _ = write!(title, " · matching \"{}\"", app.search);
    }
    title
}

/// The selected finding, cut to the pane; Enter opens the scrolling view.
fn render_preview(frame: &mut Frame, area: Rect, app: &App) {
    let p = app.palette;
    let mut block = panel("Selected finding", &p);
    let inner = block.inner(area);
    let mut doc = Doc::new(inner.width.saturating_sub(1));
    if let Some(f) = app.selected_finding() {
        finding_doc(app, &mut doc, f);
    }
    if doc.lines.len() > usize::from(inner.height) {
        block = block.title_top(
            Line::from(Span::styled(
                " Enter for the rest ",
                Style::default().fg(p.border),
            ))
            .right_aligned(),
        );
    }
    frame.render_widget(Paragraph::new(doc.lines).block(block), area);
}

pub fn render_detail(frame: &mut Frame, area: Rect, app: &mut App, index: usize) {
    render_doc(frame, area, app, "Finding", |app, doc| {
        if let Some(f) = app.findings().get(index) {
            finding_doc(app, doc, f);
        }
    });
}

/// Device name when the scan resolved one, else the address; `—` for network-wide findings.
fn device_label(app: &App, f: &Finding) -> String {
    f.affected_ip.map_or_else(
        || "—".to_owned(),
        |ip| {
            app.device_name(ip)
                .map_or_else(|| ip.to_string(), str::to_owned)
        },
    )
}

fn finding_doc(app: &App, doc: &mut Doc, f: &Finding) {
    let p = app.palette;
    let fg = Style::default().fg(p.fg);
    let bold = fg.add_modifier(Modifier::BOLD);

    doc.item(1, "", Style::default(), &f.title, bold);
    let mut tags = vec![Span::raw(" "), sev_badge(f.severity, &p)];
    if f.is_kev {
        tags.push(Span::raw(" "));
        tags.push(badge(" KNOWN EXPLOITED ", p.critical, &p));
    }
    tags.push(Span::styled(
        format!("  {:?} · {}", f.confidence, f.scanner).to_lowercase(),
        Style::default().fg(p.border),
    ));
    doc.line(tags);
    doc.blank();

    if let Some(ip) = f.affected_ip {
        let mut target = app
            .device_name(ip)
            .map_or_else(|| ip.to_string(), |name| format!("{name} ({ip})"));
        if let Some(port) = f.affected_port {
            let _ = write!(target, ", port {port}");
        }
        field(doc, "Device", &target, &p);
    }
    if !f.cve_ids.is_empty() {
        let mut cves = f.cve_ids.join(", ");
        if let Some(epss) = f.epss {
            let _ = write!(cves, "  (EPSS {:.0}%)", epss * 100.0);
        }
        field(doc, "CVEs", &cves, &p);
    }
    if let Some(cwe) = &f.cwe_id {
        field(doc, "Weakness", cwe, &p);
    }
    match app.finding_diff_status(f) {
        Some(DiffStatus::New) => field(doc, "Since last", "new", &p),
        Some(DiffStatus::SeverityChanged) => field(doc, "Since last", "severity changed", &p),
        _ => {}
    }
    field(doc, "Fingerprint", &f.fingerprint().to_string(), &p);

    doc.blank();
    doc.para(1, &f.description, fg);
    if let Some(evidence) = &f.evidence {
        heading(doc, "Evidence", &p);
        doc.para(1, evidence, Style::default().fg(p.medium));
    }
    if let Some(fix) = &f.remediation {
        heading(doc, "Fix", &p);
        doc.para(1, &fix.description, bold);
        for (i, step) in fix.steps.iter().enumerate() {
            doc.item(
                1,
                &format!("{:>2}. ", i + 1),
                Style::default().fg(p.accent),
                step,
                fg,
            );
        }
        if let Some(effort) = &fix.effort {
            doc.blank();
            field(doc, "Effort", effort, &p);
        }
    }
    if !f.standards.is_empty() {
        doc.blank();
        field(doc, "Standards", &f.standards.join(", "), &p);
    }
}
