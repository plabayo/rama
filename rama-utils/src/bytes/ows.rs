//! HTTP optional whitespace (`OWS = *( SP / HTAB )`, RFC 9110 §5.6.3).
//!
//! Unlike [`slice::trim_ascii`], only SP and HTAB are trimmed: CR, LF and other
//! control bytes stay, so a later field-value check can still reject them.

/// Trim leading and trailing OWS (SP and HTAB).
#[must_use]
pub const fn trim_ows(bytes: &[u8]) -> &[u8] {
    trim_ows_end(trim_ows_start(bytes))
}

/// Trim leading OWS (SP and HTAB).
#[must_use]
pub const fn trim_ows_start(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// Trim trailing OWS (SP and HTAB).
#[must_use]
pub const fn trim_ows_end(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_only_sp_and_htab() {
        for (input, both, start, end) in [
            (
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
                b"".as_slice(),
            ),
            (b" \t \t", b"", b"", b""),
            (b"a", b"a", b"a", b"a"),
            (b" \ta b\t ", b"a b", b"a b\t ", b" \ta b"),
            // CR, LF, VT, FF and NBSP are not OWS
            (
                b"\r\na\x0b\x0c",
                b"\r\na\x0b\x0c",
                b"\r\na\x0b\x0c",
                b"\r\na\x0b\x0c",
            ),
            (
                b" \xc2\xa0a\xc2\xa0 ",
                b"\xc2\xa0a\xc2\xa0",
                b"\xc2\xa0a\xc2\xa0 ",
                b" \xc2\xa0a\xc2\xa0",
            ),
            (b"\t\ra\n\t", b"\ra\n", b"\ra\n\t", b"\t\ra\n"),
        ] {
            assert_eq!(trim_ows(input), both, "{input:?}");
            assert_eq!(trim_ows_start(input), start, "{input:?}");
            assert_eq!(trim_ows_end(input), end, "{input:?}");
        }
    }
}
