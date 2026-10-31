//! Scheme parsing — RFC 3986 §3.1.
//!
//! `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed by `:`.

use crate::byte_sets::{is_scheme_first_byte, is_scheme_rest_byte};

/// If `bytes` starts with `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed
/// by `:`, return the byte index of the `:`. Otherwise `None`.
///
/// # Safety-usable invariant
///
/// On `Some(i)`, `bytes[i] == b':'` and every byte of `bytes[..i]` is ASCII.
pub(super) fn find_scheme_end(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.first()?;
    if !is_scheme_first_byte(first) {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b':' {
            return Some(i);
        }
        if !is_scheme_rest_byte(b) {
            return None;
        }
        i += 1;
    }
    None
}

/// [`find_scheme_end`], returning the scheme (without its `:`) as `str`.
pub(super) fn find_scheme(bytes: &[u8]) -> Option<&str> {
    let colon = find_scheme_end(bytes)?;
    let scheme = &bytes[..colon];
    // SAFETY: `str::from_utf8_unchecked` requires valid UTF-8. By the
    // safety-usable invariant of `find_scheme_end` every byte of `scheme` is
    // ASCII (each passed `is_scheme_first_byte` / `is_scheme_rest_byte`, which
    // accept only ASCII), and ASCII is valid UTF-8.
    Some(unsafe { core::str::from_utf8_unchecked(scheme) })
}
