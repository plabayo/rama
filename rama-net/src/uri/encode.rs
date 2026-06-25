//! Per-component percent-encoding for URI setters.
//!
//! Each setter accepts arbitrary input and writes a valid URI component
//! to the wire. Bytes outside the relevant RFC 3986 grammar are
//! percent-encoded; bytes inside it pass through verbatim.

use std::borrow::Cow;

use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use rama_core::bytes::BytesMut;

use crate::byte_sets::{is_path_byte, is_query_fragment_byte};

use super::component_input::IntoUriComponent;

// ---------------------------------------------------------------------------
// `AsciiSet`s used by the `percent_encoding` crate's encoder.
//
// These mirror the byte sets exposed by `parser::byte_sets` (so the fast-path
// check and the actual encoder agree on what's legal) — but with one
// difference: `%` is encoded by the setters (raw user content is treated as
// content, not pre-encoded), while the parser allows `%` as the lead byte of
// a percent-escape triple.
// ---------------------------------------------------------------------------

/// Bytes encoded inside a URI path. Legal pass-through: `pchar ∪ {'/'}`.
pub(super) const PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Bytes encoded inside a URI query. Legal pass-through:
/// `pchar ∪ {'/', '?'}`. `#` is encoded — it would otherwise start a
/// fragment.
pub(super) const QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Fragment grammar matches query (`pchar / "/" / "?"`).
pub(super) const FRAGMENT_ENCODE_SET: &AsciiSet = QUERY_ENCODE_SET;

/// Bytes encoded inside one path segment. Legal pass-through: `pchar`.
/// `/` is encoded — it would otherwise start a new segment.
pub(super) const SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Bytes encoded inside a query name-or-value (one half of a pair).
/// Legal pass-through: `pchar` minus `=`. `&`, `=`, `+` are encoded so
/// the pair structure stays intact and form-decoding round-trips.
pub(super) const PAIR_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

// ---------------------------------------------------------------------------
// Fast-path predicates — reuse the parser's `[bool; 256]` byte tables, plus
// the `%` exclusion (setter input is raw content, not pre-encoded).
// ---------------------------------------------------------------------------

#[inline]
fn path_needs_encoding(input: &[u8]) -> bool {
    input.iter().any(|&b| b == b'%' || !is_path_byte(b))
}

#[inline]
fn query_or_fragment_needs_encoding(input: &[u8]) -> bool {
    input
        .iter()
        .any(|&b| b == b'%' || !is_query_fragment_byte(b))
}

// ---------------------------------------------------------------------------
// Encoder entry points
// ---------------------------------------------------------------------------

/// Common encode driver shared by all component setters.
///
/// Fast-path: when `needs_encoding` returns `false` for the input
/// bytes, owned input types (`String`, `Vec<u8>`, `BytesMut`, `Bytes`)
/// move into storage without copying via
/// [`IntoUriComponent::into_uri_component_bytes_mut`].
///
/// Slow-path: percent-encode under the given `AsciiSet` into a fresh
/// `BytesMut` sized to the input.
#[inline]
fn encode<T: IntoUriComponent, F: Fn(&[u8]) -> bool>(
    input: T,
    needs_encoding: F,
    encode_set: &'static AsciiSet,
) -> BytesMut {
    if needs_encoding(&input.as_uri_component_bytes()) {
        let bytes = input.as_uri_component_bytes();
        let mut out = BytesMut::with_capacity(bytes.len());
        for chunk in percent_encode(&bytes, encode_set) {
            out.extend_from_slice(chunk.as_bytes());
        }
        out
    } else {
        input.into_uri_component_bytes_mut()
    }
}

/// Encode the path input into a [`BytesMut`]. Owned-input fast-path
/// avoids the copy when the bytes are already path-legal.
#[inline]
pub(super) fn encode_path<T: IntoUriComponent>(input: T) -> BytesMut {
    encode(input, path_needs_encoding, PATH_ENCODE_SET)
}

/// Encode the query input.
#[inline]
pub(super) fn encode_query<T: IntoUriComponent>(input: T) -> BytesMut {
    encode(input, query_or_fragment_needs_encoding, QUERY_ENCODE_SET)
}

/// Encode the fragment input. The query and fragment grammars accept
/// the same bytes, so the `needs_encoding` predicate is shared with
/// `encode_query`; only the [`AsciiSet`] differs (fragment doesn't
/// encode `?`).
#[inline]
pub(super) fn encode_fragment<T: IntoUriComponent>(input: T) -> BytesMut {
    encode(input, query_or_fragment_needs_encoding, FRAGMENT_ENCODE_SET)
}

/// Append `input` to `target`, percent-encoding under the segment
/// policy. Used by [`PathMut::push_segment`](super::PathMut::push_segment)
/// where we always extend (no zero-copy opportunity).
pub(super) fn extend_encoded_segment(target: &mut BytesMut, input: &[u8]) {
    for chunk in percent_encode(input, SEGMENT_ENCODE_SET) {
        target.extend_from_slice(chunk.as_bytes());
    }
}

/// Append `input` to `target`, percent-encoding under the pair policy.
/// Used by [`QueryMut::push_pair`](super::QueryMut::push_pair) /
/// [`QueryMut::push_key`](super::QueryMut::push_key).
pub(super) fn extend_encoded_pair(target: &mut BytesMut, input: &[u8]) {
    for chunk in percent_encode(input, PAIR_ENCODE_SET) {
        target.extend_from_slice(chunk.as_bytes());
    }
}

#[inline]
fn is_segment_byte(b: u8) -> bool {
    is_path_byte(b) && b != b'/'
}

#[inline]
fn is_pair_component_byte(b: u8) -> bool {
    is_query_fragment_byte(b) && !matches!(b, b'&' | b'=' | b'+')
}

#[inline]
fn is_pct_triplet(input: &[u8], i: usize) -> bool {
    i + 2 < input.len() && rama_utils::hex::decode_pair(input[i + 1], input[i + 2]).is_some()
}

#[inline]
fn push_pct_encoded(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0x0f) as usize] as char);
}

fn extend_pct_encoded(out: &mut BytesMut, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]);
}

fn encode_preserving_pct<'a>(input: &'a [u8], is_allowed: impl Fn(u8) -> bool) -> Cow<'a, str> {
    let mut i = 0;
    let mut needs_encoding = std::str::from_utf8(input).is_err();
    while i < input.len() {
        match input[i] {
            b'%' if is_pct_triplet(input, i) => i += 3,
            b'%' => {
                needs_encoding = true;
                break;
            }
            b if is_allowed(b) => i += 1,
            _ => {
                needs_encoding = true;
                break;
            }
        }
    }

    if !needs_encoding {
        // Safety: checked above.
        return Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(input) });
    }

    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' && is_pct_triplet(input, i) {
            out.push('%');
            out.push(input[i + 1] as char);
            out.push(input[i + 2] as char);
            i += 3;
        } else if b == b'%' {
            push_pct_encoded(&mut out, b);
            i += 1;
        } else if is_allowed(b) {
            out.push(b as char);
            i += 1;
        } else {
            push_pct_encoded(&mut out, b);
            i += 1;
        }
    }
    Cow::Owned(out)
}

fn extend_encoded_preserving_pct(
    out: &mut BytesMut,
    input: &[u8],
    is_allowed: impl Fn(u8) -> bool,
) {
    let mut i = 0;
    let mut needs_encoding = std::str::from_utf8(input).is_err();
    while i < input.len() {
        match input[i] {
            b'%' if is_pct_triplet(input, i) => i += 3,
            b'%' => {
                needs_encoding = true;
                break;
            }
            b if is_allowed(b) => i += 1,
            _ => {
                needs_encoding = true;
                break;
            }
        }
    }

    if !needs_encoding {
        out.extend_from_slice(input);
        return;
    }

    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' && is_pct_triplet(input, i) {
            out.extend_from_slice(&input[i..i + 3]);
            i += 3;
        } else if b == b'%' {
            extend_pct_encoded(out, b);
            i += 1;
        } else if is_allowed(b) {
            out.extend_from_slice(&[b]);
            i += 1;
        } else {
            extend_pct_encoded(out, b);
            i += 1;
        }
    }
}

#[inline]
pub(super) fn encoded_path(input: &[u8]) -> Cow<'_, str> {
    encode_preserving_pct(input, is_path_byte)
}

#[inline]
pub(super) fn extend_encoded_path(out: &mut BytesMut, input: &[u8]) {
    extend_encoded_preserving_pct(out, input, is_path_byte);
}

#[inline]
pub(super) fn encoded_segment(input: &[u8]) -> Cow<'_, str> {
    encode_preserving_pct(input, is_segment_byte)
}

#[inline]
pub(super) fn encoded_query(input: &[u8]) -> Cow<'_, str> {
    encode_preserving_pct(input, is_query_fragment_byte)
}

#[inline]
pub(super) fn extend_encoded_query(out: &mut BytesMut, input: &[u8]) {
    extend_encoded_preserving_pct(out, input, is_query_fragment_byte);
}

#[inline]
pub(super) fn encoded_fragment(input: &[u8]) -> Cow<'_, str> {
    encode_preserving_pct(input, is_query_fragment_byte)
}

#[inline]
pub(super) fn encoded_pair_component(input: &[u8]) -> Cow<'_, str> {
    encode_preserving_pct(input, is_pair_component_byte)
}

#[cfg(test)]
mod tests {
    use rama_core::bytes::BytesMut;

    use super::{encoded_path, encoded_query, extend_encoded_path, extend_encoded_query};

    #[test]
    fn direct_encoded_writers_match_string_views() {
        let inputs: &[&[u8]] = &[
            b"/simple/path",
            b"/hello world/%2F/%zz/%",
            b"a=1\r\nInjected: yes #frag",
            &[b'a', 0xff, b'%', b'2', b'F'],
        ];

        for input in inputs {
            let mut path = BytesMut::new();
            extend_encoded_path(&mut path, input);
            assert_eq!(&path[..], encoded_path(input).as_ref().as_bytes());

            let mut query = BytesMut::new();
            extend_encoded_query(&mut query, input);
            assert_eq!(&query[..], encoded_query(input).as_ref().as_bytes());
        }
    }
}
