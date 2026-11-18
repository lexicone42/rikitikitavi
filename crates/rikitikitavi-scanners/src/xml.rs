//! Tag-text extraction for device XML. Substring matching, not an XML parser:
//! attributes, namespaces prefixes, CDATA and entities are not interpreted.

/// Trimmed text between the first `<tag>` and the next `</tag>`; `None` if absent or empty.
pub fn tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let rest = xml.get(start..)?;
    let end = rest.find(&close)?;
    let content = rest.get(..end)?.trim();
    (!content.is_empty()).then(|| content.to_owned())
}

#[cfg(test)]
mod tests {
    use super::tag_text;

    #[test]
    fn reads_first_match_trimmed() {
        let xml = "<a><n> one </n><n>two</n></a>";
        assert_eq!(tag_text(xml, "n").as_deref(), Some("one"));
    }

    #[test]
    fn absent_empty_and_unclosed_are_none() {
        assert_eq!(tag_text("<a></a>", "n"), None);
        assert_eq!(tag_text("<n>  </n>", "n"), None);
        assert_eq!(tag_text("<n>x", "n"), None);
        assert_eq!(tag_text("<n attr=\"1\">x</n>", "n"), None);
    }
}
