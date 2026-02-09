use ratatui::style::{Color, Style};

use crate::app::Theme;

/// Resolved color palette for a theme.
pub struct Palette {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub border: Color,
    pub critical: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
    pub info: Color,
    pub header_style: Style,
    pub selected_style: Style,
}

impl Palette {
    pub fn from_theme(theme: Theme) -> Self {
        match theme {
            Theme::Dark => Self {
                bg: Color::Rgb(30, 30, 46),
                fg: Color::Rgb(205, 214, 244),
                accent: Color::Rgb(137, 180, 250),
                border: Color::Rgb(88, 91, 112),
                critical: Color::Red,
                high: Color::Rgb(250, 179, 135),
                medium: Color::Yellow,
                low: Color::Rgb(166, 227, 161),
                info: Color::Rgb(148, 226, 213),
                header_style: Style::default()
                    .fg(Color::Rgb(137, 180, 250))
                    .add_modifier(ratatui::style::Modifier::BOLD),
                selected_style: Style::default()
                    .bg(Color::Rgb(69, 71, 90))
                    .add_modifier(ratatui::style::Modifier::BOLD),
            },
            Theme::Light => Self {
                bg: Color::White,
                fg: Color::Black,
                accent: Color::Blue,
                border: Color::Gray,
                critical: Color::Red,
                high: Color::Rgb(230, 126, 34),
                medium: Color::Rgb(241, 196, 15),
                low: Color::Green,
                info: Color::Cyan,
                header_style: Style::default()
                    .fg(Color::Blue)
                    .add_modifier(ratatui::style::Modifier::BOLD),
                selected_style: Style::default()
                    .bg(Color::Rgb(220, 220, 220))
                    .add_modifier(ratatui::style::Modifier::BOLD),
            },
            Theme::Hacker => Self {
                bg: Color::Black,
                fg: Color::Green,
                accent: Color::LightGreen,
                border: Color::DarkGray,
                critical: Color::LightRed,
                high: Color::LightYellow,
                medium: Color::Yellow,
                low: Color::Green,
                info: Color::DarkGray,
                header_style: Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(ratatui::style::Modifier::BOLD),
                selected_style: Style::default()
                    .bg(Color::Rgb(0, 40, 0))
                    .add_modifier(ratatui::style::Modifier::BOLD),
            },
            Theme::Accessible => Self {
                bg: Color::Black,
                fg: Color::White,
                accent: Color::Cyan,
                border: Color::White,
                critical: Color::LightRed,
                high: Color::LightYellow,
                medium: Color::Yellow,
                low: Color::LightGreen,
                info: Color::LightCyan,
                header_style: Style::default().fg(Color::Cyan).add_modifier(
                    ratatui::style::Modifier::BOLD | ratatui::style::Modifier::UNDERLINED,
                ),
                selected_style: Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            },
        }
    }

    /// Get the color for a severity level.
    pub const fn severity_color(&self, severity: rikitikitavi_core::Severity) -> Color {
        match severity {
            rikitikitavi_core::Severity::Critical => self.critical,
            rikitikitavi_core::Severity::High => self.high,
            rikitikitavi_core::Severity::Medium => self.medium,
            rikitikitavi_core::Severity::Low => self.low,
            rikitikitavi_core::Severity::Info => self.info,
        }
    }
}
