use std::{borrow::Cow, iter, ops::Range};

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
                let member = self.input.get(start..self.cursor).unwrap_or_default();
                self.cursor = self.cursor.saturating_add(1);
                return Some(Ok(member));
            } else {
                self.cursor = self.cursor.saturating_add(1);
            }
        }

        self.done = true;
        Some(Ok(self.input.get(start..).unwrap_or_default()))
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
            let body = input.get(body_start..*cursor).unwrap_or_default();
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

/// Byte ranges of the `SEP`-separated members of `input`, never cut inside a quoted-string.
///
/// A quoted-pair never closes the string (RFC 9110 §5.6.4); an unterminated one yields
/// `Err(start)` for the rest of the input, which ends the iteration.
pub(crate) fn unquoted_members<const SEP: u8>(
    input: &[u8],
) -> impl Iterator<Item = Result<Range<usize>, usize>> + '_ {
    let mut start = Some(0_usize);
    iter::from_fn(move || {
        let from = start.take()?;
        let mut cursor = from;
        loop {
            let found = input
                .get(cursor..)
                .unwrap_or_default()
                .iter()
                .position(|byte| *byte == SEP || *byte == b'"')
                .map(|offset| cursor.saturating_add(offset));
            match found {
                Some(end) if input.get(end) == Some(&SEP) => {
                    start = Some(end.saturating_add(1));
                    return Some(Ok(from..end));
                }
                Some(quote) => match skip_quoted(input, quote) {
                    Some(next) => cursor = next,
                    None => return Some(Err(from)),
                },
                None => return Some(Ok(from..input.len())),
            }
        }
    })
}

/// [`unquoted_members`] of a `str` for an ASCII `SEP`; an unterminated quoted-string runs to the end.
pub(crate) fn split_unquoted<const SEP: u8>(s: &str) -> impl Iterator<Item = &str> {
    // `SEP` and `"` are ASCII, so every cut keeps a char boundary
    unquoted_members::<SEP>(s.as_bytes()).map(move |member| {
        let range = member.unwrap_or_else(|from| from..s.len());
        s.get(range).unwrap_or_default()
    })
}

/// The offset past the quoted string opening at `quote`, if terminated (content unchecked).
pub(crate) fn skip_quoted(input: &[u8], quote: usize) -> Option<usize> {
    let mut cursor = quote.saturating_add(1);
    loop {
        match input.get(cursor)? {
            b'"' => return Some(cursor.saturating_add(1)),
            b'\\' => cursor = cursor.saturating_add(2),
            _ => cursor = cursor.saturating_add(1),
        }
    }
}

pub(crate) fn skip_ows(input: &[u8], cursor: &mut usize) {
    while input
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *cursor = cursor.saturating_add(1);
    }
}

/// Largest `delta-seconds` kept (RFC 9111 §1.2.2); larger values clamp to it.
pub(crate) const MAX_DELTA_SECONDS: u64 = 2_147_483_648;

/// Parse `delta-seconds` (`1*DIGIT`), clamping to [`MAX_DELTA_SECONDS`].
pub(crate) fn parse_delta_seconds(digits: impl IntoIterator<Item = u8>) -> Option<u64> {
    let mut value = None;
    for byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(byte.wrapping_sub(b'0'));
        value = Some(
            value
                .unwrap_or(0_u64)
                .saturating_mul(10)
                .saturating_add(digit)
                .min(MAX_DELTA_SECONDS),
        );
    }
    value
}

/// Parse a `1*DIGIT` port.
pub(crate) fn parse_port(s: &str) -> Option<u16> {
    parse_digits(s).and_then(|port| u16::try_from(port).ok())
}

/// Parse `1*DIGIT` as a `u64`; `u64::from_str` alone would also accept a leading `+`.
pub(crate) fn parse_digits(s: &str) -> Option<u64> {
    // after a leading digit `u64::from_str` accepts digits only
    if !s.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    s.parse().ok()
}

#[inline(always)]
#[expect(
    clippy::indexing_slicing,
    reason = "a u8 index into a 256-entry table is always in bounds"
)]
const fn is_qdtext(byte: u8) -> bool {
    QDTEXT_BYTES[byte as usize]
}

#[inline(always)]
#[expect(
    clippy::indexing_slicing,
    reason = "a u8 index into a 256-entry table is always in bounds"
)]
const fn is_quoted_pair_byte(byte: u8) -> bool {
    QUOTED_PAIR_BYTES[byte as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::for_each_small_input;
    use rama_utils::bytes::trim_ows;
    use std::assert_matches;

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
        assert_matches!(plain.decode(), Cow::Borrowed(b"plain"));

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
    fn skips_only_optional_whitespace() {
        let mut cursor = 0;
        skip_ows(b" \tvalue", &mut cursor);
        assert_eq!(cursor, 2);
    }

    #[test]
    fn small_inputs_never_panic() {
        for_each_small_input(b"\"\\, \ta\x80\0", 6, |input| {
            for member in ListMembers::new(input) {
                let Ok(member) = member else {
                    break;
                };
                _ = trim_ows(member);
            }
            for start in 0..=input.len().saturating_add(1) {
                let mut cursor = start;
                if let Ok(quoted) = scan_quoted_string(input, &mut cursor) {
                    assert!(cursor <= input.len(), "input: {input:?}");
                    _ = quoted.decode();
                }
                let mut cursor = start;
                skip_ows(input, &mut cursor);
            }
        });
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
