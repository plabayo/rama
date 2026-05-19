//! Scheme parsing — RFC 3986 §3.1.
//!
//! `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed by `:`.

use super::byte_sets::{is_scheme_first_byte, is_scheme_rest_byte};

/// If `bytes` starts with `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed
/// by `:`, return the byte index of the `:`. Otherwise `None`.
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
