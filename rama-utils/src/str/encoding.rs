//! Text decoding helpers.

use crate::std::{borrow::Cow, string::String, vec::Vec};

/// Decode bytes as UTF-8, falling back to ISO-8859-1 (Latin-1) when the
/// complete input is not valid UTF-8.
///
/// Valid UTF-8 is returned borrowed and does not allocate. The fallback maps
/// every byte directly to the Unicode code point with the same value; it is
/// deliberately not lossy UTF-8 decoding and not Windows-1252 decoding.
#[must_use]
pub fn decode_utf8_or_latin1(bytes: &[u8]) -> Cow<'_, str> {
    match core::str::from_utf8(bytes) {
        Ok(text) => Cow::Borrowed(text),
        Err(_) => Cow::Owned(bytes.iter().copied().map(char::from).collect()),
    }
}

/// Decode owned bytes as UTF-8, falling back to ISO-8859-1 (Latin-1) when the
/// complete input is not valid UTF-8.
///
/// The valid UTF-8 path reuses the input allocation. The fallback maps every
/// byte directly to the Unicode code point with the same value.
#[must_use]
pub fn decode_utf8_or_latin1_owned(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => error.into_bytes().into_iter().map(char::from).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_utf8_is_borrowed() {
        let bytes = "café".as_bytes();
        let decoded = decode_utf8_or_latin1(bytes);
        assert!(matches!(decoded, Cow::Borrowed("café")));
    }

    #[test]
    fn invalid_utf8_decodes_the_complete_input_as_latin1() {
        let decoded = decode_utf8_or_latin1(b"caf\xe9");
        assert!(matches!(decoded, Cow::Owned(ref text) if text == "café"));

        assert_eq!(decode_utf8_or_latin1(b"\xc3("), "Ã(");
    }

    #[test]
    fn owned_decoder_handles_both_encodings() {
        assert_eq!(
            decode_utf8_or_latin1_owned("café".as_bytes().to_vec()),
            "café"
        );
        assert_eq!(decode_utf8_or_latin1_owned(b"caf\xe9".to_vec()), "café");
    }
}
