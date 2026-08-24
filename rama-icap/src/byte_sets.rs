//! Byte-class tables shared by the ICAP grammar.

use rama_utils::byte_set::{set_ascii_alphanum, set_each, set_range};

/// RFC 2616 `token`, used by ICAP methods, field names, and chunk extensions.
const TOKEN_BYTE_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"!#$%&'*+-.^_`|~");

/// RFC 2616 `TEXT` after the parser has excluded line endings.
// `set_range` has an exclusive upper bound; `\xff` closes the obs-text range.
const FIELD_VALUE_BYTE_SET: [bool; 256] = set_each(
    set_range(set_range([false; 256], b' ', 0x7f), 0x80, 0xff),
    b"\t\xff",
);

/// RFC 2616 quoted text with quote and backslash handled by the caller.
const QUOTED_TEXT_BYTE_SET: [bool; 256] = set_each(
    set_range(
        set_range(
            set_range(set_range([false; 256], b' ', b'"'), b'#', b'\\'),
            b']',
            0x7f,
        ),
        0x80,
        0xff,
    ),
    b"\t\xff",
);

const HORIZONTAL_WHITESPACE_BYTE_SET: [bool; 256] = set_each([false; 256], b" \t");

#[inline(always)]
pub(crate) const fn is_token_byte(byte: u8) -> bool {
    TOKEN_BYTE_SET[byte as usize]
}

#[inline(always)]
pub(crate) const fn is_field_value_byte(byte: u8) -> bool {
    FIELD_VALUE_BYTE_SET[byte as usize]
}

#[inline(always)]
pub(crate) const fn is_quoted_text_byte(byte: u8) -> bool {
    QUOTED_TEXT_BYTE_SET[byte as usize]
}

#[inline(always)]
pub(crate) const fn is_horizontal_whitespace_byte(byte: u8) -> bool {
    HORIZONTAL_WHITESPACE_BYTE_SET[byte as usize]
}

pub(crate) fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| is_horizontal_whitespace_byte(*byte))
    {
        value = &value[..value.len() - 1];
    }
    value
}

pub(crate) fn comma_separated_items(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|byte| *byte == b',').map(trim_ows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_tables_match_the_protocol_classes() {
        for byte in u8::MIN..=u8::MAX {
            let token = matches!(byte, 0x21..=0x7e) && !b"()<>@,;:\\\"/[]?={}".contains(&byte);
            assert_eq!(is_token_byte(byte), token, "token byte {byte:#04x}");

            let field_value = matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff);
            assert_eq!(
                is_field_value_byte(byte),
                field_value,
                "field-value byte {byte:#04x}"
            );

            let quoted_text = matches!(
                byte,
                b'\t' | b' '..=b'!' | b'#'..=b'[' | b']'..=b'~'
                    | 0x80..=0xff
            );
            assert_eq!(
                is_quoted_text_byte(byte),
                quoted_text,
                "quoted-text byte {byte:#04x}"
            );

            assert_eq!(
                is_horizontal_whitespace_byte(byte),
                matches!(byte, b' ' | b'\t'),
                "whitespace byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn comma_items_trim_only_optional_whitespace() {
        let items = comma_separated_items(b"\t one , ,two\t,three\x0b ").collect::<Vec<_>>();
        assert_eq!(items, [b"one".as_slice(), b"", b"two", b"three\x0b"]);
    }
}
