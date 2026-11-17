use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::theme::Palette;

/// Columns the mascot needs, snake included.
pub const WIDTH: u16 = 32;
pub const HEIGHT: u16 = 10;

const MONGOOSE: [&str; 10] = [
    r"         n,---.n      ",
    r"         ( o o )      ",
    r"          \ Y /       ",
    r"         /`---'\      ",
    r"        / /| |\ \     ",
    r"       ( ( | | ) )    ",
    r"        \_\| |/_/     ",
    r"          |   |       ",
    r"          | | |       ",
    r" ~-..__.-(_/ \_)      ",
];

const EYES_ROW: usize = 1;
const BLINK: &str = r"         ( - - )      ";

const SNAKE: [&str; 10] = [
    r"",
    r"",
    r"       __",
    r"     <'o )",
    r"       ) )",
    r"      / /",
    r"     ( (",
    r"      \ \",
    r" ~-.__/ /",
    r"  `----'",
];

const TONGUE_ROW: usize = 3;
const TONGUE: [&str; 4] = ["   ", "  -", " ~-", "  ~"];

/// Mascot lines. The snake flicks its tongue; the mongoose blinks.
pub fn mascot(tick: u64, p: &Palette) -> Vec<Line<'static>> {
    #[allow(clippy::cast_possible_truncation)]
    let tongue = TONGUE[(tick / 3 % 4) as usize];
    let blink = tick % 40 == 39;
    let body = Style::default().fg(p.accent);
    let snake = Style::default().fg(p.low).add_modifier(Modifier::BOLD);
    (0..MONGOOSE.len())
        .map(|row| {
            let left = if blink && row == EYES_ROW {
                BLINK
            } else {
                MONGOOSE[row]
            };
            let right = if row == TONGUE_ROW {
                format!("{tongue}{}", &SNAKE[row][3..])
            } else {
                SNAKE[row].to_owned()
            };
            Line::from(vec![Span::styled(left, body), Span::styled(right, snake)])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Theme;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn every_frame_fits_the_declared_size() {
        let p = Palette::from_theme(Theme::Dark);
        for tick in 0..80 {
            let lines = mascot(tick, &p);
            assert_eq!(lines.len(), usize::from(HEIGHT));
            for line in lines {
                let width: usize = line.spans.iter().map(|s| s.content.width()).sum();
                assert!(width <= usize::from(WIDTH), "tick {tick}: {width}");
            }
        }
    }

    #[test]
    fn mongoose_rows_share_one_width() {
        let width = MONGOOSE[0].width();
        assert!(MONGOOSE.iter().all(|row| row.width() == width));
        assert_eq!(BLINK.width(), width);
    }
}
