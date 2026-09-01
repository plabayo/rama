use std::borrow::Cow;

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_utils::byte_set::{set_each, set_range};

const QDTEXT_BYTES: [bool; 256] = set_each(
    set_range(
        set_range(set_range([false; 256], 0x23, 0x5c), 0x5d, 0x7f),
        0x80,
        0xff,
    ),
    &[b'\t', b' ', b'!', 0xff],
);

const QUOTED_PAIR_BYTES: [bool; 256] = set_each(
    set_range(set_range([false; 256], 0x21, 0x7f), 0x80, 0xff),
    &[b'\t', b' ', 0xff],
);

/// Iterate comma-delimited HTTP list members without copying.
///
/// Commas inside RFC 7230 quoted strings are preserved. Empty members are
/// yielded so each header can apply its own `#rule` requirements.
pub(crate) struct ListMembers<'a> {
    input: &'a [u8],
    cursor: usize,
    done: bool,
}

impl<'a> ListMembers<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cursor: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for ListMembers<'a> {
    type Item = Result<&'a [u8], BoxError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let start = self.cursor;
        while let Some(&byte) = self.input.get(self.cursor) {
            if byte == b'"' {
                if let Err(error) = scan_quoted_string(self.input, &mut self.cursor) {
                    self.done = true;
                    return Some(Err(error));
                }
            } else if byte == b',' {
                let member = &self.input[start..self.cursor];
                self.cursor = self.cursor.saturating_add(1);
                return Some(Ok(member));
            } else {
                self.cursor = self.cursor.saturating_add(1);
            }
        }

        self.done = true;
        Some(Ok(&self.input[start..]))
    }
}

/// A validated RFC 7230 quoted-string body.
#[derive(Clone, Copy)]
pub(crate) struct QuotedString<'a>(&'a [u8]);

impl<'a> QuotedString<'a> {
    pub(crate) const fn raw(self) -> &'a [u8] {
        self.0
    }

    /// Borrow an unescaped body or allocate only when quoted-pairs occur.
    pub(crate) fn decode(self) -> Cow<'a, [u8]> {
        if !self.0.contains(&b'\\') {
            return Cow::Borrowed(self.0);
        }

        let mut decoded = Vec::with_capacity(self.0.len());
        let mut cursor = 0;
        while let Some(&byte) = self.0.get(cursor) {
            if byte == b'\\' {
                cursor = cursor.saturating_add(1);
                // Construction validates that every escape has one byte.
                if let Some(&escaped) = self.0.get(cursor) {
                    decoded.push(escaped);
                }
            } else {
                decoded.push(byte);
            }
            cursor = cursor.saturating_add(1);
        }
        Cow::Owned(decoded)
    }
}

/// Scan one quoted string at `cursor`, returning its raw body.
pub(crate) fn scan_quoted_string<'a>(
    input: &'a [u8],
    cursor: &mut usize,
) -> Result<QuotedString<'a>, BoxError> {
    if input.get(*cursor) != Some(&b'"') {
        return Err(BoxError::from_static_str(
            "HTTP value does not start with a quoted string",
        ));
    }
    *cursor = cursor.saturating_add(1);
    let body_start = *cursor;

    while let Some(&byte) = input.get(*cursor) {
        if byte == b'"' {
            let body = &input[body_start..*cursor];
            *cursor = cursor.saturating_add(1);
            return Ok(QuotedString(body));
        }
        if byte == b'\\' {
            let escaped = *input.get(cursor.saturating_add(1)).ok_or_else(|| {
                BoxError::from_static_str("HTTP quoted string has a truncated escape")
            })?;
            if !is_quoted_pair_byte(escaped) {
                return Err(BoxError::from_static_str(
                    "HTTP quoted string contains an invalid escaped octet",
                ));
            }
            *cursor = cursor.saturating_add(2);
            continue;
        }
        if !is_qdtext(byte) {
            return Err(BoxError::from_static_str(
                "HTTP quoted string contains an invalid octet",
            ));
        }
        *cursor = cursor.saturating_add(1);
    }

    Err(BoxError::from_static_str(
        "HTTP value contains an unterminated quoted string",
    ))
}

pub(crate) fn skip_ows(input: &[u8], cursor: &mut usize) {
    while input
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *cursor = cursor.saturating_add(1);
    }
}

pub(crate) fn trim_ows(mut input: &[u8]) -> &[u8] {
    while input
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        input = &input[1..];
    }
    while let Some((&last, rest)) = input.split_last() {
        if !matches!(last, b' ' | b'\t') {
            break;
        }
        input = rest;
    }
    input
}

#[inline(always)]
const fn is_qdtext(byte: u8) -> bool {
    QDTEXT_BYTES[byte as usize]
}

#[inline(always)]
const fn is_quoted_pair_byte(byte: u8) -> bool {
    QUOTED_PAIR_BYTES[byte as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_members_preserve_quotes_and_empty_elements() {
        let members: Vec<_> = ListMembers::new(b", a=\"b,c\",, d,")
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(members, [b"".as_slice(), b" a=\"b,c\"", b"", b" d", b""]);
    }

    #[test]
    fn list_members_honor_quoted_pairs() {
        let members: Vec<_> = ListMembers::new(br#"a="b\",c", d"#)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(members, [br#"a="b\",c""#.as_slice(), b" d"]);
    }

    #[test]
    fn quoted_string_borrows_or_unescapes_as_needed() {
        let mut cursor = 0;
        let plain = scan_quoted_string(br#""plain""#, &mut cursor).unwrap();
        assert!(matches!(plain.decode(), Cow::Borrowed(b"plain")));

        let mut cursor = 0;
        let escaped = scan_quoted_string(br#""a\"b\\c""#, &mut cursor).unwrap();
        assert_eq!(escaped.decode().as_ref(), b"a\"b\\c");
    }

    #[test]
    fn rejects_invalid_or_unterminated_quoted_strings() {
        for input in [
            b"plain".as_slice(),
            br#""open"#,
            b"\"bad\\".as_slice(),
            b"\"a\\\r\"".as_slice(),
            b"\"\r\"".as_slice(),
        ] {
            assert!(
                scan_quoted_string(input, &mut 0).is_err(),
                "accepted {input:?}"
            );
        }
        ListMembers::new(br#"a="open"#).next().unwrap().unwrap_err();
    }

    #[test]
    fn trims_and_skips_only_optional_whitespace() {
        assert_eq!(trim_ows(b" \t value\t "), b"value");
        assert_eq!(trim_ows(b"\rvalue\n"), b"\rvalue\n");

        let mut cursor = 0;
        skip_ows(b" \tvalue", &mut cursor);
        assert_eq!(cursor, 2);
    }

    #[test]
    fn byte_tables_match_rfc_7230_classes() {
        for byte in 0..=u8::MAX {
            let expected_qdtext = matches!(
                byte,
                b'\t' | b' ' | b'!' | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff
            );
            let expected_quoted_pair = matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff);
            assert_eq!(is_qdtext(byte), expected_qdtext, "qdtext byte {byte:#04x}");
            assert_eq!(
                is_quoted_pair_byte(byte),
                expected_quoted_pair,
                "quoted-pair byte {byte:#04x}"
            );
        }
    }
}
