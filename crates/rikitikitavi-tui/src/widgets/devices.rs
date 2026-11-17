use std::fmt::Write as _;
use std::net::IpAddr;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Row, Table};
use rikitikitavi_core::Severity;
use rikitikitavi_models::{DeviceReportCard, Finding};

use crate::app::{App, DeviceSort};
use crate::chrome::{
    data_rows, empty_note, field, heading, list_title, panel, render_doc, sev_badge,
};
use crate::text::{Doc, short_title};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let p = app.palette;
    let wide = area.width >= 112;
    let zones = area.width >= 92;

    let mut header = vec!["", "NAME", "ADDRESS", "TYPE"];
    let mut widths = vec![
        Constraint::Length(3),
        Constraint::Min(16),
        Constraint::Length(15),
        Constraint::Length(13),
    ];
    if zones {
        header.push("ZONE");
        widths.push(Constraint::Length(14));
    }
    if wide {
        header.push("VENDOR");
        widths.push(Constraint::Length(18));
    }
    header.extend(["PORTS", "FINDINGS"]);
    widths.extend([Constraint::Length(5), Constraint::Length(12)]);

    let rows: Vec<Row> = app
        .device_rows()
        .map(|d| {
            let card = app.report_card(d.ip);
            let (letter, color) = card.map_or(('-', p.border), |c| {
                (c.grade.letter(), p.grade_color(c.grade))
            });
            let fg = Style::default().fg(p.fg);
            let dim = Style::default().fg(p.border);
            let mut cells = vec![
                Line::from(Span::styled(
                    format!(" {letter}"),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    d.hostname.clone().unwrap_or_else(|| "—".to_owned()),
                    fg,
                )),
                Line::from(Span::styled(d.ip.to_string(), fg)),
                Line::from(Span::styled(d.device_type.label(), dim)),
            ];
            if zones {
                let zone = app.zone(d.ip).map_or("", |(z, _)| z.label());
                cells.push(Line::from(Span::styled(zone, dim)));
            }
            if wide {
                cells.push(Line::from(Span::styled(
                    d.vendor.clone().unwrap_or_default(),
                    dim,
                )));
            }
            cells.push(Line::from(Span::styled(
                format!("{:>5}", d.open_ports.len()),
                dim,
            )));
            cells.push(card.map_or_else(Line::default, |c| counts_line(c, app)));
            Row::new(cells)
        })
        .collect();

    let shown = rows.len();
    let block = panel(table_title(app, shown), &p);
    let inner = block.inner(area);
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(p.header_style))
        .column_spacing(2)
        .row_highlight_style(p.selected_style)
        .block(block);
    frame.render_stateful_widget(table, area, &mut app.devices_state);
    if shown == 0 {
        let text = if app.results.is_none() {
            "No scan results yet."
        } else {
            "No device matches the search. Esc clears it."
        };
        empty_note(frame, inner, text, &p);
    }
    app.hit_regions.rows = Some(data_rows(inner));
}

fn table_title(app: &App, shown: usize) -> String {
    let mut title = list_title("Devices", &app.devices_state, shown);
    let total = app.devices().len();
    if shown != total {
        let _ = write!(title, " of {total}");
    }
    title.push_str(match app.device_sort {
        DeviceSort::Grade => " · worst grade first",
        DeviceSort::Address => " · by address",
    });
    if !app.search.is_empty() {
        let _ = write!(title, " · matching \"{}\"", app.search);
    }
    title
}

/// Non-zero severity counts, each in its severity color, e.g. `2H 3M 5L`.
fn counts_line(card: &DeviceReportCard, app: &App) -> Line<'static> {
    let p = app.palette;
    let spans: Vec<Span> = [
        (card.critical, "C", Severity::Critical),
        (card.high, "H", Severity::High),
        (card.medium, "M", Severity::Medium),
        (card.low, "L", Severity::Low),
    ]
    .into_iter()
    .filter(|(n, _, _)| *n > 0)
    .map(|(n, tag, severity)| {
        Span::styled(
            format!("{n}{tag} "),
            Style::default().fg(p.severity_color(severity)),
        )
    })
    .collect();
    Line::from(spans)
}

pub fn render_detail(frame: &mut Frame, area: Rect, app: &mut App, ip: IpAddr) {
    render_doc(frame, area, app, "Device", |app, doc| {
        device_doc(app, doc, ip);
    });
}

fn device_doc(app: &App, doc: &mut Doc, ip: IpAddr) {
    let p = app.palette;
    let Some(device) = app.device(ip) else {
        doc.line(vec![Span::raw(" This device is not in the current scan.")]);
        return;
    };
    let card = app.report_card(ip);

    let mut title = vec![Span::styled(
        format!(
            " {}",
            device.hostname.as_deref().unwrap_or("Unnamed device")
        ),
        Style::default().fg(p.accent).add_modifier(Modifier::BOLD),
    )];
    if let Some(card) = card {
        title.push(Span::styled(
            format!("   grade {}", card.grade.letter()),
            Style::default()
                .fg(p.grade_color(card.grade))
                .add_modifier(Modifier::BOLD),
        ));
    }
    doc.line(title);
    doc.blank();

    field(doc, "Address", &ip.to_string(), &p);
    if let Some(mac) = device.mac {
        field(doc, "MAC", &mac.to_string(), &p);
    }
    let kind = device.device_subtype.as_ref().map_or_else(
        || device.device_type.label().to_owned(),
        |sub| format!("{} ({sub})", device.device_type.label()),
    );
    field(doc, "Type", &kind, &p);
    if let Some(vendor) = &device.vendor {
        field(doc, "Vendor", vendor, &p);
    }
    if let Some(os) = &device.os_guess {
        field(doc, "OS", os, &p);
    }
    if let Some(card) = card {
        field(doc, "Grade", &card.rationale, &p);
        if card.status != rikitikitavi_models::DeviceStatus::Untracked {
            field(doc, "Tracking", card.status.as_str(), &p);
        }
    }
    if let Some((zone, reason)) = app.zone(ip) {
        field(doc, "Zone", &format!("{} — {reason}", zone.label()), &p);
    }
    if !device.seen_by.is_empty() {
        field(doc, "Seen by", &device.seen_by.join(", "), &p);
    }

    heading(doc, format!("Open ports ({})", device.open_ports.len()), &p);
    for port in &device.open_ports {
        let what = [port.service.as_deref(), port.version.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        doc.item(
            1,
            &format!("{:>5}  ", port.port),
            Style::default().fg(p.accent),
            &what,
            Style::default().fg(p.fg),
        );
    }
    if device.open_ports.is_empty() {
        doc.line(vec![Span::styled(
            " none found",
            Style::default().fg(p.border),
        )]);
    }

    let mut findings: Vec<&Finding> = app
        .findings()
        .iter()
        .filter(|f| f.affected_ip == Some(ip))
        .collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.title.cmp(&b.title)));
    heading(doc, format!("Findings ({})", findings.len()), &p);
    for f in &findings {
        let port = f
            .affected_port
            .map_or_else(String::new, |n| format!("  port {n}"));
        doc.line(vec![
            Span::raw(" "),
            sev_badge(f.severity, &p),
            Span::styled(format!(" {}", short_title(f)), Style::default().fg(p.fg)),
            Span::styled(port, Style::default().fg(p.border)),
        ]);
    }
    if findings.is_empty() {
        doc.line(vec![Span::styled(" none", Style::default().fg(p.border))]);
    } else {
        doc.blank();
        doc.line(vec![Span::styled(
            " Press f to open these in the Findings tab.",
            Style::default().fg(p.border).add_modifier(Modifier::ITALIC),
        )]);
    }
}
