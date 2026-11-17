use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use rikitikitavi_core::Severity;
use rikitikitavi_models::{Device, Finding, Remediation, ScanResults};
use rikitikitavi_tui::app::{Detail, Screen, SeverityFilter};
use rikitikitavi_tui::{App, TuiConfig, draw};

fn device(n: u8) -> Device {
    let mut d = Device::new(format!("10.0.0.{n}").parse().unwrap());
    d.hostname = Some(format!("host-{n}"));
    d
}

fn finding(n: u8, severity: Severity) -> Finding {
    Finding::new(
        "ports",
        &format!("Telnet open on 10.0.0.{n}:23"),
        &"Telnet sends credentials in clear text. ".repeat(12),
        severity,
    )
    .with_ip(format!("10.0.0.{n}").parse().unwrap())
    .with_port(23)
    .with_remediation(Remediation {
        description: "Disable Telnet".to_owned(),
        steps: vec!["Open the admin page and turn Telnet off under Services.".to_owned()],
        effort: None,
    })
}

/// 60 devices; the first 30 each have one High finding, the rest one Low.
fn results() -> ScanResults {
    let devices: Vec<Device> = (1..=60).map(device).collect();
    let findings: Vec<Finding> = (1..=60)
        .map(|n| {
            finding(
                n,
                if n <= 30 {
                    Severity::High
                } else {
                    Severity::Low
                },
            )
        })
        .collect();
    let mut r = ScanResults {
        report_cards: rikitikitavi_analysis::grade_devices(&devices, &findings),
        priority_actions: rikitikitavi_analysis::generate_priority_actions(&findings),
        devices,
        findings,
        ..Default::default()
    };
    r.risk_score = 50.0;
    r
}

fn app() -> App {
    let mut app = App::new(TuiConfig::default());
    app.set_results(results());
    app
}

fn render(app: &mut App, width: u16, height: u16) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| draw(frame, app)).unwrap();
    let buf = terminal.backend().buffer();
    (0..height)
        .map(|y| (0..width).map(|x| buf[(x, y)].symbol()).collect())
        .collect()
}

fn key(app: &mut App, code: KeyCode) -> bool {
    app.handle_key(code.into())
}

fn click(app: &mut App, column: u16, row: u16) {
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    });
}

fn find(screen: &[String], needle: &str) -> Option<(u16, u16)> {
    screen.iter().enumerate().find_map(|(y, row)| {
        let at = row.find(needle)?;
        let x = row[..at].chars().count();
        Some((u16::try_from(x).unwrap(), u16::try_from(y).unwrap()))
    })
}

#[test]
fn every_view_renders_at_any_size() {
    for with_results in [false, true] {
        for (w, h) in [(1, 1), (10, 3), (40, 10), (80, 24), (120, 40), (250, 70)] {
            let mut app = if with_results {
                app()
            } else {
                App::new(TuiConfig::default())
            };
            for screen in Screen::ALL {
                app.screen = screen;
                render(&mut app, w, h);
            }
            app.screen = Screen::Devices;
            app.detail = Some(Detail::Device("10.0.0.1".parse().unwrap()));
            render(&mut app, w, h);
            app.detail = Some(Detail::Finding(0));
            render(&mut app, w, h);
            app.detail = None;
            app.show_help = true;
            render(&mut app, w, h);
            app.show_help = false;
            app.search_editing = true;
            render(&mut app, w, h);
        }
    }
}

#[test]
fn clicking_a_tab_label_switches_to_it() {
    for width in [80, 140] {
        let mut app = app();
        let screen = render(&mut app, width, 24);
        for (label, target) in [
            ("2 Devices", Screen::Devices),
            ("3 Findings", Screen::Findings),
            ("5 ", Screen::AttackPaths),
            ("1 Overview", Screen::Overview),
        ] {
            let (x, y) = find(&screen, label).expect(label);
            click(&mut app, x + 1, y);
            assert_eq!(app.screen, target, "{label} at width {width}");
        }
    }
}

#[test]
fn every_device_is_reachable_by_scrolling() {
    let mut app = app();
    key(&mut app, KeyCode::Char('2'));
    key(&mut app, KeyCode::Char('o'));
    assert!(find(&render(&mut app, 100, 24), "host-60").is_none());
    key(&mut app, KeyCode::End);
    let screen = render(&mut app, 100, 24);
    assert!(find(&screen, "host-60").is_some());
    assert!(find(&screen, "Devices 60/60").is_some());
    key(&mut app, KeyCode::Enter);
    assert_eq!(
        app.detail,
        Some(Detail::Device("10.0.0.60".parse().unwrap()))
    );
}

#[test]
fn clicking_a_row_selects_it_and_a_second_click_opens_it() {
    let mut app = app();
    key(&mut app, KeyCode::Char('2'));
    key(&mut app, KeyCode::Char('o'));
    key(&mut app, KeyCode::End);
    let screen = render(&mut app, 100, 24);
    let (x, y) = find(&screen, "host-55 ").expect("row visible after scrolling");
    click(&mut app, x, y);
    assert_eq!(app.selected_device().unwrap().ip.to_string(), "10.0.0.55");
    assert_eq!(app.detail, None);
    click(&mut app, x, y);
    assert_eq!(
        app.detail,
        Some(Detail::Device("10.0.0.55".parse().unwrap()))
    );
}

#[test]
fn clicks_outside_the_rows_do_nothing() {
    let mut app = app();
    key(&mut app, KeyCode::Char('3'));
    render(&mut app, 100, 24);
    let before = app.findings_state.selected();
    // Table header row and the preview pane.
    click(&mut app, 10, 2);
    click(&mut app, 10, 20);
    assert_eq!(app.findings_state.selected(), before);
    assert_eq!(app.detail, None);
}

#[test]
fn search_filters_both_tables_and_esc_clears() {
    let mut app = app();
    key(&mut app, KeyCode::Char('3'));
    key(&mut app, KeyCode::Char('/'));
    for c in "host-7".chars() {
        key(&mut app, KeyCode::Char(c));
    }
    // 'q' while typing is text, not quit.
    assert!(!app.should_quit);
    key(&mut app, KeyCode::Enter);
    assert_eq!(app.finding_rows().len(), 1);
    key(&mut app, KeyCode::Char('2'));
    assert_eq!(app.device_rows().len(), 1);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.device_rows().len(), 60);
}

#[test]
fn typing_q_in_search_does_not_quit() {
    let mut app = app();
    key(&mut app, KeyCode::Char('/'));
    key(&mut app, KeyCode::Char('q'));
    assert!(!app.should_quit);
    assert_eq!(app.search, "q");
    assert_eq!(app.screen, Screen::Findings);
}

#[test]
fn ctrl_c_quits_from_anywhere() {
    let mut app = app();
    key(&mut app, KeyCode::Char('/'));
    app.handle_key(crossterm::event::KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL,
    ));
    assert!(app.should_quit);
}

#[test]
fn low_findings_are_hidden_until_toggled() {
    let mut app = app();
    assert_eq!(app.finding_rows().len(), 30);
    key(&mut app, KeyCode::Char('l'));
    assert_eq!(app.severity_filter, SeverityFilter::All);
    assert_eq!(app.finding_rows().len(), 60);
}

#[test]
fn device_detail_lists_its_findings_and_f_filters_to_them() {
    let mut app = app();
    key(&mut app, KeyCode::Char('2'));
    key(&mut app, KeyCode::Enter);
    let ip = app.selected_device().unwrap().ip;
    let screen = render(&mut app, 100, 30);
    assert!(find(&screen, "Findings (1)").is_some());
    assert!(find(&screen, "Telnet open").is_some());
    key(&mut app, KeyCode::Char('f'));
    assert_eq!(app.screen, Screen::Findings);
    assert_eq!(app.detail, None);
    assert_eq!(app.finding_rows().len(), 1);
    assert_eq!(app.selected_finding().unwrap().affected_ip, Some(ip));
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.finding_rows().len(), 60);
}

#[test]
fn finding_detail_wraps_and_scroll_stops_at_the_end() {
    let mut app = app();
    key(&mut app, KeyCode::Char('3'));
    key(&mut app, KeyCode::Enter);
    assert!(matches!(app.detail, Some(Detail::Finding(_))));
    let screen = render(&mut app, 60, 12);
    // The description is longer than one row and no row runs into the border.
    assert!(screen.iter().filter(|r| r.contains("Telnet sends")).count() >= 2);
    for _ in 0..500 {
        key(&mut app, KeyCode::Down);
    }
    let screen = render(&mut app, 60, 12);
    assert!(
        find(&screen, "turn Telnet off").is_some(),
        "last step visible"
    );
    let end = app.text_scroll;
    key(&mut app, KeyCode::Down);
    render(&mut app, 60, 12);
    assert_eq!(app.text_scroll, end);
    key(&mut app, KeyCode::Esc);
    assert_eq!(app.detail, None);
}

#[test]
fn rescan_keeps_the_selection_by_identity() {
    let mut app = app();
    key(&mut app, KeyCode::Char('2'));
    key(&mut app, KeyCode::Char('o'));
    for _ in 0..9 {
        key(&mut app, KeyCode::Down);
    }
    assert_eq!(app.selected_device().unwrap().ip.to_string(), "10.0.0.10");
    let mut next = results();
    next.devices.remove(0);
    next.findings.remove(0);
    app.set_results(next);
    assert_eq!(app.selected_device().unwrap().ip.to_string(), "10.0.0.10");
}

#[test]
fn s_requests_a_scan_only_when_idle() {
    let mut app = app();
    assert!(key(&mut app, KeyCode::Char('s')));
    app.scan_started = Some(std::time::Instant::now());
    assert!(!key(&mut app, KeyCode::Char('s')));
    assert!(find(&render(&mut app, 120, 24), "scanning").is_some());
}

#[test]
fn status_message_expires() {
    let mut app = app();
    app.set_status("Wrote files");
    assert!(find(&render(&mut app, 120, 24), "Wrote files").is_some());
    app.tick += 200;
    assert_eq!(app.status(), None);
}

#[test]
fn overview_shows_the_mascot_at_80_columns() {
    let mut app = app();
    let screen = render(&mut app, 80, 24);
    assert!(find(&screen, "( o o )").is_some());
    assert!(find(&screen, "Network grade").is_some());
    assert!(find(&screen, "What to fix first").is_some());
}
