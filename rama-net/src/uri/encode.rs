//! Per-component percent-encoding for URI setters.
//!
//! Each setter accepts arbitrary input and writes a valid URI component
//! to the wire. Bytes outside the relevant RFC 3986 grammar are
//! percent-encoded; bytes inside it pass through verbatim.

use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use rama_core::bytes::BytesMut;

use super::component_input::IntoUriComponent;
use super::parser::{is_path_byte, is_query_fragment_byte};

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

/// Encode the path input into a [`BytesMut`]. Fast-path: when the
/// input is already legal under the path grammar, owned input types
/// (`String`, `Vec<u8>`, `BytesMut`, `Bytes`) move into storage without
/// copying.
pub(super) fn encode_path<T: IntoUriComponent>(input: T) -> BytesMut {
    if path_needs_encoding(input.as_uri_component_bytes()) {
        let bytes = input.as_uri_component_bytes();
        let mut out = BytesMut::with_capacity(bytes.len());
        for chunk in percent_encode(bytes, PATH_ENCODE_SET) {
            out.extend_from_slice(chunk.as_bytes());
        }
        out
    } else {
        input.into_uri_component_bytes_mut()
    }
}

/// Encode the query input. See [`encode_path`] for the fast-path behaviour.
pub(super) fn encode_query<T: IntoUriComponent>(input: T) -> BytesMut {
    if query_or_fragment_needs_encoding(input.as_uri_component_bytes()) {
        let bytes = input.as_uri_component_bytes();
        let mut out = BytesMut::with_capacity(bytes.len());
        for chunk in percent_encode(bytes, QUERY_ENCODE_SET) {
            out.extend_from_slice(chunk.as_bytes());
        }
        out
    } else {
        input.into_uri_component_bytes_mut()
    }
}

/// Encode the fragment input. See [`encode_path`] for the fast-path behaviour.
pub(super) fn encode_fragment<T: IntoUriComponent>(input: T) -> BytesMut {
    if query_or_fragment_needs_encoding(input.as_uri_component_bytes()) {
        let bytes = input.as_uri_component_bytes();
        let mut out = BytesMut::with_capacity(bytes.len());
        for chunk in percent_encode(bytes, FRAGMENT_ENCODE_SET) {
            out.extend_from_slice(chunk.as_bytes());
        }
        out
    } else {
        input.into_uri_component_bytes_mut()
    }
}

/// Append `input` to `target`, percent-encoding under the segment
/// policy. Used by [`PathMut::push_segment`](super::PathMut::push_segment)
/// where we always extend (no zero-copy opportunity).
pub(super) fn extend_encoded_segment(target: &mut BytesMut, input: &[u8]) {
    for chunk in percent_encode(input, SEGMENT_ENCODE_SET) {
        target.extend_from_slice(chunk.as_bytes());
    }
}
