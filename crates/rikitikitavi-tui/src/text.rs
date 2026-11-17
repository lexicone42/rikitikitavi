use ratatui::style::Style;
use ratatui::text::{Line, Span};
use rikitikitavi_models::Finding;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Finding title without a trailing ` on <ip>[:port]`; tables show the device in its own column.
pub fn short_title(f: &Finding) -> &str {
    let Some(ip) = f.affected_ip else {
        return &f.title;
    };
    let needle = format!(" on {ip}");
    let Some(at) = f.title.rfind(&needle) else {
        return &f.title;
    };
    let rest = &f.title[at + needle.len()..];
    let port_only = rest
        .strip_prefix(':')
        .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if rest.is_empty() || port_only {
        &f.title[..at]
    } else {
        &f.title
    }
}

/// Cut to `width` terminal columns, ending in `…` when cut.
pub fn truncate(s: &str, width: usize) -> String {
    if s.width() <= width {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w + 1 > width {
            break;
        }
        out.push(c);
        used += w;
    }
    if width > 0 {
        out.push('…');
    }
    out
}

/// Greedy word wrap to `width` columns. Words wider than a line are split.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for para in text.lines() {
        let mut cur = String::new();
        let mut cur_w = 0;
        for word in para.split_whitespace() {
            let mut word = word;
            loop {
                let w = word.width();
                let sep = usize::from(cur_w > 0);
                if cur_w + sep + w <= width {
                    if sep == 1 {
                        cur.push(' ');
                    }
                    cur.push_str(word);
                    cur_w += sep + w;
                    break;
                }
                if cur_w > 0 {
                    lines.push(std::mem::take(&mut cur));
                    cur_w = 0;
                    continue;
                }
                let cut = split_at_width(word, width);
                lines.push(word[..cut].to_owned());
                word = &word[cut..];
                if word.is_empty() {
                    break;
                }
            }
        }
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Byte index of the longest prefix of `s` that fits `width` columns (at least one char).
fn split_at_width(s: &str, width: usize) -> usize {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        let w = c.width().unwrap_or(0);
        if used + w > width && i > 0 {
            return i;
        }
        used += w;
    }
    s.len()
}

/// Styled lines pre-wrapped to a fixed width, so the line count is exact for scrolling.
pub struct Doc {
    pub lines: Vec<Line<'static>>,
    width: usize,
}

impl Doc {
    pub fn new(width: u16) -> Self {
        Self {
            lines: Vec::new(),
            width: usize::from(width),
        }
    }

    pub fn blank(&mut self) {
        self.lines.push(Line::default());
    }

    /// One unwrapped line.
    pub fn line(&mut self, spans: Vec<Span<'static>>) {
        self.lines.push(Line::from(spans));
    }

    /// Wrapped paragraph indented by `indent` columns.
    pub fn para(&mut self, indent: usize, text: &str, style: Style) {
        self.item(indent, "", Style::default(), text, style);
    }

    /// `marker` followed by wrapped `text`; continuation lines align under the text.
    pub fn item(
        &mut self,
        indent: usize,
        marker: &str,
        marker_style: Style,
        text: &str,
        style: Style,
    ) {
        let lead = indent + marker.width();
        let avail = self.width.saturating_sub(lead).max(8);
        for (i, chunk) in wrap(text, avail).into_iter().enumerate() {
            let mut spans = Vec::with_capacity(3);
            if i == 0 {
                spans.push(Span::raw(" ".repeat(indent)));
                spans.push(Span::styled(marker.to_owned(), marker_style));
            } else {
                spans.push(Span::raw(" ".repeat(lead)));
            }
            spans.push(Span::styled(chunk, style));
            self.lines.push(Line::from(spans));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rikitikitavi_core::Severity;

    fn finding(title: &str, ip: Option<&str>) -> Finding {
        let f = Finding::new("t", title, "d", Severity::Low);
        match ip {
            Some(ip) => f.with_ip(ip.parse().unwrap()),
            None => f,
        }
    }

    #[test]
    fn short_title_strips_ip_and_port_suffix() {
        let f = finding("Vulnerable OpenSSH on 10.0.0.2:22", Some("10.0.0.2"));
        assert_eq!(short_title(&f), "Vulnerable OpenSSH");
        let f = finding("VNC open on 10.0.0.2", Some("10.0.0.2"));
        assert_eq!(short_title(&f), "VNC open");
    }

    #[test]
    fn short_title_keeps_other_titles() {
        let f = finding("DNSSEC validation not enforced", None);
        assert_eq!(short_title(&f), "DNSSEC validation not enforced");
        let f = finding("Open on 10.0.0.2 and more", Some("10.0.0.2"));
        assert_eq!(short_title(&f), "Open on 10.0.0.2 and more");
        let f = finding("Open on 10.0.0.22:80", Some("10.0.0.2"));
        assert_eq!(short_title(&f), "Open on 10.0.0.22:80");
    }

    #[test]
    fn truncate_counts_columns() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
        assert_eq!(truncate("網網網網", 5), "網網…");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn wrap_breaks_on_words_and_splits_long_words() {
        assert_eq!(wrap("aa bb cc", 5), vec!["aa bb", "cc"]);
        assert_eq!(wrap("abcdefgh", 3), vec!["abc", "def", "gh"]);
        assert_eq!(wrap("", 5), vec![""]);
        assert_eq!(wrap("a\nb", 5), vec!["a", "b"]);
    }

    #[test]
    fn wrap_lines_never_exceed_width() {
        let text = "Update the firmware from the Kasa app, 網網網網網網 then re-scan.";
        for width in 1..40 {
            for line in wrap(text, width) {
                assert!(line.width() <= width.max(2), "{width}: {line:?}");
            }
        }
    }

    #[test]
    fn doc_item_hangs_continuation_under_text() {
        let mut doc = Doc::new(12);
        doc.item(
            2,
            "1. ",
            Style::default(),
            "aaaa bbbb cccc",
            Style::default(),
        );
        let rows: Vec<String> = doc
            .lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert_eq!(rows, vec!["  1. aaaa", "     bbbb", "     cccc"]);
    }
}
