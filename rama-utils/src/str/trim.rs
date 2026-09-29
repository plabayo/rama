/// Trim HTTP optional whitespace (SP and HTAB, RFC 9110 §5.6.3), see [`crate::bytes::trim_ows`].
#[must_use]
pub fn trim_ows(value: &str) -> &str {
    let bytes = value.as_bytes();
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |last| last.saturating_add(1));
    // SP and HTAB are ASCII, so both cuts are char boundaries
    value.get(start..end).unwrap_or_default()
}

/// Trim surrounding whitespace and return `None` when nothing remains.
#[must_use]
pub fn trim_non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

/// Trim surrounding whitespace and ASCII quote marks.
///
/// This accepts the presentation used by command-line configuration tools:
/// either single or double quote marks may occur at either edge. Whitespace is
/// trimmed again after the quote marks, and an empty result is returned as
/// `None`. The returned string is always a slice of the input.
#[must_use]
pub fn trim_ascii_quotes_non_empty(value: &str) -> Option<&str> {
    trim_non_empty(value)
        .map(|value| value.trim_matches(['\'', '"']))
        .and_then(trim_non_empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_only_ows() {
        for (input, expected) in [
            ("", ""),
            (" \t ", ""),
            (" \ta b\t ", "a b"),
            ("\u{a0}a\u{a0}", "\u{a0}a\u{a0}"),
            ("\t\r\u{2003}é\n ", "\r\u{2003}é\n"),
        ] {
            assert_eq!(trim_ows(input), expected, "{input:?}");
        }
    }

    #[test]
    fn trims_without_allocating() {
        let value = String::from("  value  ");
        let trimmed = trim_non_empty(&value).unwrap();
        assert_eq!(trimmed, "value");
        assert!(core::ptr::eq(trimmed.as_ptr(), value[2..].as_ptr()));

        assert_eq!(trim_non_empty(" \t\n "), None);
    }

    #[test]
    fn trims_ascii_quotes_and_inner_edge_whitespace() {
        for (value, expected) in [
            ("  'value'  ", Some("value")),
            ("\"  value  \"", Some("value")),
            ("'\"value\"'", Some("value")),
            ("  ''  ", None),
            (" \" \t \" ", None),
        ] {
            assert_eq!(trim_ascii_quotes_non_empty(value), expected);
        }
    }
}
