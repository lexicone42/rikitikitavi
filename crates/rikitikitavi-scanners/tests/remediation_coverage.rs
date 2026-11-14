//! Remediation coverage gate: every `Finding::new` site in scanner sources whose
//! severity is not the literal `Severity::Info` attaches a remediation in its
//! builder chain, or is on `ALLOWLIST`. Sites are keyed by file name and the
//! title's string literal (or the title expression when it has none).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Scanner source roots, relative to this crate's manifest directory.
const ROOTS: &[&str] = &["src", "../rikitikitavi-unifi/src"];

/// `(file, title, reason)`. Shrink-only: an entry whose site gains a
/// remediation, or no longer exists, fails `allowlist_only_shrinks`.
const ALLOWLIST: &[(&str, &str, &str)] = &[];

#[derive(Debug)]
struct Site {
    file: String,
    title: String,
    line: usize,
    info_only: bool,
    has_remediation: bool,
}

/// Source with `//` and `/* */` comments blanked; string, raw-string and char
/// literals are kept verbatim. Newlines are preserved so line numbers hold.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
            out.extend(src[i..end].chars().filter(|&c| c == '\n'));
            i = end;
        } else if let Some(end) = literal_end(b, i) {
            out.push_str(&src[i..end]);
            i = end;
        } else {
            let ch = src[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// End index of a string, raw-string or char literal starting at `i`.
fn literal_end(b: &[u8], i: usize) -> Option<usize> {
    let prev_ident = i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
    match b[i] {
        b'"' => {
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'\\' => j += 2,
                    b'"' => return Some(j + 1),
                    _ => j += 1,
                }
            }
            Some(b.len())
        }
        b'r' if !prev_ident => {
            let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                return None;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = i + 2 + hashes;
            b[body..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map(|p| body + p + close.len())
        }
        b'\'' => {
            if b.get(i + 1) == Some(&b'\\') {
                b[i + 3..]
                    .iter()
                    .position(|&c| c == b'\'')
                    .map(|p| i + 4 + p)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                let ch_len = std::str::from_utf8(&b[i + 1..(i + 5).min(b.len())])
                    .ok()
                    .and_then(|s| s.chars().next())
                    .map_or(1, char::len_utf8);
                (b.get(i + 1 + ch_len) == Some(&b'\'')).then_some(i + 2 + ch_len)
            }
        }
        _ => None,
    }
}

/// Index just past the bracket closing the one at `open`.
fn close_of(b: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        if let Some(end) = literal_end(b, i) {
            i = end;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// Top-level comma-separated arguments of `src` (the text between parentheses).
fn split_args(src: &str) -> Vec<&str> {
    let b = src.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        if let Some(end) = literal_end(b, i) {
            i = end;
            continue;
        }
        match b[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                args.push(src[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if !src[start..].trim().is_empty() {
        args.push(src[start..].trim());
    }
    args
}

/// End of the `.method(...)` chain starting at `i`.
fn chain_end(b: &[u8], mut i: usize) -> usize {
    loop {
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'.') {
            return i;
        }
        j += 1;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b'(') {
            return i;
        }
        i = close_of(b, j);
    }
}

/// Title key: the first string literal in the title argument, else the argument.
fn title_key(arg: &str) -> String {
    let b = arg.as_bytes();
    let raw = b
        .iter()
        .position(|&c| c == b'"')
        .and_then(|s| literal_end(b, s).map(|e| &arg[s + 1..e - 1]))
        .unwrap_or(arg);
    let joined = raw.split("\\\n").map(str::trim_start).collect::<String>();
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `name` when the text before `pos` ends in `let name =` or `let mut name =`.
fn bound_name(code: &str, pos: usize) -> Option<&str> {
    let before = code[..pos].trim_end().strip_suffix('=')?.trim_end();
    let name_start = before
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |p| p + 1);
    let name = &before[name_start..];
    let rest = before[..name_start].trim_end();
    (rest.ends_with("let") || rest.ends_with("let mut")).then_some(name)
}

fn sites_in(file: &str, src: &str) -> Vec<Site> {
    let code = strip_comments(src);
    let code = code
        .find("#[cfg(test)]\nmod tests")
        .map_or(code.as_str(), |p| &code[..p]);
    let b = code.as_bytes();
    let mut sites = Vec::new();
    let mut from = 0;
    while let Some(p) = code[from..].find("Finding::new(") {
        let start = from + p;
        let open = start + "Finding::new".len();
        let close = close_of(b, open);
        let args = split_args(&code[open + 1..close - 1]);
        let end = chain_end(b, close);
        let mut has_remediation = code[close..end].contains("remediation");
        if !has_remediation && let Some(name) = bound_name(code, start) {
            let tail = &code[end..(end + 4000).min(code.len())];
            has_remediation = [".remediation", ".with_remediation", ".with_opt_remediation"]
                .iter()
                .any(|m| tail.contains(&format!("{name}{m}")));
        }
        sites.push(Site {
            file: file.to_owned(),
            title: args.get(1).map_or_else(String::new, |a| title_key(a)),
            line: code[..start].matches('\n').count() + 1,
            info_only: args.get(3).is_some_and(|a| *a == "Severity::Info"),
            has_remediation,
        });
        from = close;
    }
    sites
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && path.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(path);
        }
    }
}

fn sources() -> Vec<(String, String)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for root in ROOTS {
        rust_files(&manifest.join(root), &mut files);
    }
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 file name")
                .to_owned();
            (name, fs::read_to_string(&p).expect("readable source"))
        })
        .collect()
}

fn all_sites() -> Vec<Site> {
    sources()
        .iter()
        .flat_map(|(name, src)| sites_in(name, src))
        .collect()
}

fn allowlist() -> BTreeMap<(&'static str, &'static str), &'static str> {
    ALLOWLIST.iter().map(|&(f, t, r)| ((f, t), r)).collect()
}

#[test]
fn every_low_plus_finding_has_remediation_or_is_allowlisted() {
    let allow = allowlist();
    let missing: Vec<String> = all_sites()
        .iter()
        .filter(|s| !s.info_only && !s.has_remediation)
        .filter(|s| !allow.contains_key(&(s.file.as_str(), s.title.as_str())))
        .map(|s| format!("{}:{} \"{}\"", s.file, s.line, s.title))
        .collect();
    assert!(
        missing.is_empty(),
        "findings at severity >= Low without a remediation (attach one, or allowlist with a reason):\n{}",
        missing.join("\n")
    );
}

#[test]
fn allowlist_only_shrinks() {
    let sites = all_sites();
    let uncovered: BTreeSet<(&str, &str)> = sites
        .iter()
        .filter(|s| !s.info_only && !s.has_remediation)
        .map(|s| (s.file.as_str(), s.title.as_str()))
        .collect();
    assert_eq!(
        allowlist().len(),
        ALLOWLIST.len(),
        "duplicate allowlist entry"
    );
    for (file, title, reason) in ALLOWLIST {
        assert!(
            !reason.trim().is_empty(),
            "{file} \"{title}\": empty reason"
        );
        assert!(
            uncovered.contains(&(*file, *title)),
            "{file} \"{title}\" now has a remediation or no longer exists: remove it from ALLOWLIST"
        );
    }
}

#[test]
fn every_referenced_template_exists() {
    let mut missing = Vec::new();
    for (name, src) in sources() {
        let code = strip_comments(&src);
        let mut from = 0;
        while let Some(p) = code[from..].find("remediation::get(") {
            let open = from + p + "remediation::get".len();
            let close = close_of(code.as_bytes(), open);
            if let Some(arg) = split_args(&code[open + 1..close - 1]).first()
                && let Some(id) = arg.strip_prefix('"').and_then(|a| a.strip_suffix('"'))
                && rikitikitavi_scanners::remediation::get(id, &[]).is_none()
            {
                missing.push(format!("{name}: {id}"));
            }
            from = close;
        }
    }
    assert!(
        missing.is_empty(),
        "unknown template ids:\n{}",
        missing.join("\n")
    );
}

#[test]
fn enumeration_sees_the_scanner_catalogue() {
    let sites = all_sites();
    let files: BTreeSet<&str> = sites.iter().map(|s| s.file.as_str()).collect();
    assert!(
        sites.len() > 200,
        "only {} Finding::new sites parsed",
        sites.len()
    );
    for f in [
        "ports.rs",
        "ssl.rs",
        "credentials.rs",
        "mdns.rs",
        "scanner.rs",
    ] {
        assert!(files.contains(f), "no sites parsed from {f}");
    }
    assert!(sites.iter().all(|s| !s.title.is_empty()));
}

#[test]
fn parser_handles_comments_chains_and_bindings() {
    let src = r#"
fn a() {
    // Finding::new("x", "commented", "", Severity::High)
    let c = '"';
    findings.push(Finding::new("s", &format!("Chained {ip}"), "d", Severity::High)
        // between
        .with_ip(ip)
        .with_opt_remediation(crate::remediation::get("t", &[])));
    findings.push(Finding::new("s", "Bare", "d", Severity::Low));
    findings.push(Finding::new("s", "Info", "d", Severity::Info));
    let mut f = Finding::new("s", "Late", "d", severity).with_ip(ip);
    f = f.with_remediation(r);
}
#[cfg(test)]
mod tests {
    fn t() { Finding::new("s", "In tests", "d", Severity::High); }
}
"#;
    let sites = sites_in("x.rs", src);
    let got: Vec<(&str, bool, bool)> = sites
        .iter()
        .map(|s| (s.title.as_str(), s.info_only, s.has_remediation))
        .collect();
    assert_eq!(
        got,
        [
            ("Chained {ip}", false, true),
            ("Bare", false, false),
            ("Info", true, false),
            ("Late", false, true),
        ]
    );
}
