//! Query component types — owned [`Query`] and borrowed [`QueryRef`].
//!
//! Per RFC 3986 §3.4, the query is opaque bytes between `?` and `#`. The
//! `key=value&…` shape is a convention (HTML forms, most APIs) — not part
//! of the URI grammar. Use [`QueryRef::pairs`] to iterate name/value pairs
//! and [`QueryRef::deserialize`] to read straight into a typed value with
//! `application/x-www-form-urlencoded` semantics.

use std::borrow::Cow;
use std::fmt;

use percent_encoding::percent_decode;
use rama_core::bytes::{Bytes, BytesMut};

/// Owned query component. Cheaply mutable in-place via the
/// [`QueryMut`](super::QueryMut) RAII guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub(crate) bytes: BytesMut,
}

impl Query {
    /// Returns the raw on-the-wire query bytes (no leading `?`).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the raw query as a `&str` (no percent-decoding).
    /// Parser-validated UTF-8.
    #[must_use]
    pub fn as_raw_str(&self) -> &str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Percent-decoded query string. `Cow::Borrowed` when no `%XX`
    /// escapes are present; `Cow::Owned` otherwise. UTF-8 errors fall
    /// back to U+FFFD (matches curl, browsers).
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'_, str> {
        percent_decode(&self.bytes).decode_utf8_lossy()
    }

    /// Borrowed view.
    #[must_use]
    pub fn as_ref(&self) -> QueryRef<'_> {
        QueryRef { bytes: &self.bytes }
    }

    /// Iterator over `name[=value]` pairs in the query string.
    ///
    /// Convenience pass-through to [`QueryRef::pairs`] on the borrowed
    /// view — see that method for the splitting / decoding contract.
    #[must_use]
    pub fn pairs(&self) -> QueryPairs<'_> {
        QueryPairs::new(&self.bytes)
    }

    /// Deserialize the query into `T`. See [`QueryRef::deserialize`] for
    /// the encoding and borrowing contract.
    pub fn deserialize<'de, T>(&'de self) -> Result<T, QueryDeserializeError>
    where
        T: serde::de::Deserialize<'de>,
    {
        self.as_ref().deserialize::<T>()
    }
}

/// Starting-capacity hint per pair when collecting via [`FromIterator`].
/// Covers a typical short `name=value` plus the `&` separator with
/// margin; [`BytesMut`] grows further if the iterator turns out to
/// produce longer content.
const COLLECT_BYTES_PER_PAIR: usize = 32;

impl FromIterator<QueryPair> for Query {
    /// Build a [`Query`] by concatenating pre-encoded pair bytes with
    /// `&` separators. No re-encoding — the pairs' bytes are assumed to
    /// already be in canonical on-wire form (which they are, when they
    /// come from [`QueryRef::pairs`], [`QueryMut::pop`](super::QueryMut::pop)
    /// or [`QueryMut::drain`](super::QueryMut::drain)).
    fn from_iter<I: IntoIterator<Item = QueryPair>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut bytes = BytesMut::with_capacity(iter.size_hint().0 * COLLECT_BYTES_PER_PAIR);
        for pair in iter {
            if !bytes.is_empty() {
                bytes.extend_from_slice(b"&");
            }
            bytes.extend_from_slice(&pair.raw);
        }
        Self { bytes }
    }
}

impl<'a> FromIterator<QueryPairRef<'a>> for Query {
    /// Build a [`Query`] from borrowed pair views by copying their raw
    /// bytes. See [`FromIterator<QueryPair>`](Query#impl-FromIterator<QueryPair>-for-Query)
    /// for the no-re-encoding contract.
    fn from_iter<I: IntoIterator<Item = QueryPairRef<'a>>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut bytes = BytesMut::with_capacity(iter.size_hint().0 * COLLECT_BYTES_PER_PAIR);
        for pair in iter {
            if !bytes.is_empty() {
                bytes.extend_from_slice(b"&");
            }
            bytes.extend_from_slice(pair.raw);
        }
        Self { bytes }
    }
}

/// Borrowed view of a URI query component (no leading `?`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> QueryRef<'a> {
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the raw query as `&str` (no percent-decoding). UTF-8 by
    /// parser invariant.
    #[must_use]
    pub fn as_raw_str(&self) -> &'a str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Percent-decoded query string. `Cow::Borrowed` when no `%XX`
    /// escapes are present; `Cow::Owned` otherwise. UTF-8 errors fall
    /// back to U+FFFD.
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'a, str> {
        percent_decode(self.bytes).decode_utf8_lossy()
    }

    /// Returns an owned copy.
    #[must_use]
    pub fn to_owned(&self) -> Query {
        Query {
            bytes: BytesMut::from(self.bytes),
        }
    }

    /// Iterator over `name[=value]` pairs.
    ///
    /// Follows WHATWG `URLSearchParams` / form-urlencoded splitting:
    /// `&` delimits pairs, the first `=` in each pair delimits name from
    /// value, empty fragments (`&&`, leading/trailing `&`) are dropped.
    /// Each [`QueryPair`] keeps the bare-vs-empty-value distinction —
    /// `?foo` → `value = None`, `?foo=` → `value = Some("")`.
    #[must_use]
    pub fn pairs(&self) -> QueryPairs<'a> {
        QueryPairs::new(self.bytes)
    }

    /// Deserialize the query into `T` with `application/x-www-form-urlencoded`
    /// semantics: `+` → space, `%XX` → byte, repeated keys collect into a
    /// `Vec<_>` field.
    ///
    /// Bare keys (`?foo`) decode as `foo=""`, matching WHATWG
    /// `URLSearchParams`. This diverges from [`pairs`](Self::pairs)
    /// which keeps the bare-vs-empty distinction — use that iterator
    /// if you need it.
    ///
    /// Fields can borrow from the query bytes: `&'a str` and
    /// `Cow<'a, str>` skip the allocation when the source value has no
    /// `+` / `%XX` to decode. When decoding *is* needed, `&'a str`
    /// fails (the decoded bytes don't live in the input) while
    /// `Cow<'a, str>` falls back to `Cow::Owned`. Prefer `Cow<'a, str>`
    /// or `String` for fields that may contain escapes.
    pub fn deserialize<T>(&self) -> Result<T, QueryDeserializeError>
    where
        T: serde::de::Deserialize<'a>,
    {
        serde_html_form::from_str(self.as_raw_str()).map_err(QueryDeserializeError)
    }
}

/// Returned by [`QueryRef::deserialize`] / [`Query::deserialize`] when the
/// query string cannot be converted into the target type — type mismatch,
/// missing required field, malformed encoding, or an escaped value being
/// fed into a non-owning `&str` field.
#[derive(Debug)]
pub struct QueryDeserializeError(serde_html_form::de::Error);

impl fmt::Display for QueryDeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to deserialize URI query: {}", self.0)
    }
}

impl std::error::Error for QueryDeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// One owned `name[=value]` pair, cheap to clone. Produced by
/// [`QueryMut::pop`](super::QueryMut::pop) and
/// [`QueryMut::drain`](super::QueryMut::drain) — popping a pair off a
/// query doesn't copy the byte content (the buffer is refcount-shared
/// with the source).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryPair {
    raw: Bytes,
    /// Byte offset of `=` within `raw`, or `None` for a bare key.
    ///
    /// `u32` because a single key=value pair built via the mutation API
    /// can exceed `MAX_URI_LEN` (the parser-level 16-bit cap applies
    /// only to parsed inputs, not to caller-built queries). `u16` would
    /// silently truncate the offset for pairs whose key crosses 65535
    /// bytes — caught by the `audit_query_pair_eq_offset_handles_large_pairs`
    /// regression test.
    eq_at: Option<u32>,
}

impl QueryPair {
    /// Construct from raw `name[=value]` bytes (no leading `&`).
    /// Finds the first `=` once at construction; subsequent accessors
    /// slice without rescanning.
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(raw: Bytes) -> Self {
        let eq_at = memchr::memchr(b'=', &raw).map(|i| i as u32);
        Self { raw, eq_at }
    }

    /// Borrowed view.
    #[must_use]
    pub fn as_ref(&self) -> QueryPairRef<'_> {
        QueryPairRef {
            raw: &self.raw,
            eq_at: self.eq_at,
        }
    }

    /// Raw on-wire bytes of the name.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        match self.eq_at {
            Some(i) => &self.raw[..i as usize],
            None => &self.raw,
        }
    }

    /// Name as `&str` with no decoding. Parser-validated UTF-8.
    #[must_use]
    pub fn name_raw(&self) -> &str {
        // Safety: parser invariant.
        unsafe { std::str::from_utf8_unchecked(self.name_bytes()) }
    }

    /// Name with form-urlencoded decoding: `+` → space, `%XX` → byte.
    /// `Cow::Borrowed` when neither escape is present.
    #[must_use]
    pub fn name_decoded(&self) -> Cow<'_, str> {
        form_decode(self.name_bytes())
    }

    /// Raw on-wire bytes of the value, or `None` for a bare key (`?foo`).
    #[must_use]
    pub fn value_bytes(&self) -> Option<&[u8]> {
        self.eq_at.map(|i| &self.raw[i as usize + 1..])
    }

    /// Value as `&str` with no decoding, or `None` for a bare key.
    #[must_use]
    pub fn value_raw(&self) -> Option<&str> {
        // Safety: parser invariant.
        self.value_bytes()
            .map(|v| unsafe { std::str::from_utf8_unchecked(v) })
    }

    /// Value with form-urlencoded decoding (`+` → space, `%XX` → byte),
    /// or `None` for a bare key.
    #[must_use]
    pub fn value_decoded(&self) -> Option<Cow<'_, str>> {
        self.value_bytes().map(form_decode)
    }

    /// `true` if the pair has an `=` separator. `?foo=` → `true`; `?foo` → `false`.
    #[must_use]
    pub fn has_value(&self) -> bool {
        self.eq_at.is_some()
    }
}

/// Borrowed `name[=value]` pair view. Yielded by
/// [`QueryRef::pairs`] / [`Query::pairs`].
///
/// Decoded views apply the form-urlencoded convention (`+` → space,
/// `%XX` → byte) — distinct from [`QueryRef::as_decoded_str`] which only
/// percent-decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPairRef<'a> {
    raw: &'a [u8],
    /// Byte offset of `=` within `raw`, or `None` for a bare key.
    ///
    /// `u32` because a single key=value pair built via the mutation API
    /// can exceed `MAX_URI_LEN` (the parser-level 16-bit cap applies
    /// only to parsed inputs, not to caller-built queries). `u16` would
    /// silently truncate the offset for pairs whose key crosses 65535
    /// bytes — caught by the `audit_query_pair_eq_offset_handles_large_pairs`
    /// regression test.
    eq_at: Option<u32>,
}

impl<'a> QueryPairRef<'a> {
    /// Construct from raw `name[=value]` bytes (no leading `&`).
    #[inline]
    #[must_use]
    pub(crate) fn from_raw(raw: &'a [u8]) -> Self {
        let eq_at = memchr::memchr(b'=', raw).map(|i| i as u32);
        Self { raw, eq_at }
    }

    /// Raw on-wire bytes of the name.
    #[must_use]
    pub fn name_bytes(&self) -> &'a [u8] {
        match self.eq_at {
            Some(i) => &self.raw[..i as usize],
            None => self.raw,
        }
    }

    /// Name as `&str` with no decoding. Parser-validated UTF-8.
    #[must_use]
    pub fn name_raw(&self) -> &'a str {
        // Safety: parser invariant.
        unsafe { std::str::from_utf8_unchecked(self.name_bytes()) }
    }

    /// Name with form-urlencoded decoding: `+` → space, `%XX` → byte.
    /// `Cow::Borrowed` when neither escape is present.
    #[must_use]
    pub fn name_decoded(&self) -> Cow<'a, str> {
        form_decode(self.name_bytes())
    }

    /// Raw on-wire bytes of the value, or `None` for a bare key (`?foo`).
    #[must_use]
    pub fn value_bytes(&self) -> Option<&'a [u8]> {
        self.eq_at.map(|i| &self.raw[i as usize + 1..])
    }

    /// Value as `&str` with no decoding, or `None` for a bare key.
    #[must_use]
    pub fn value_raw(&self) -> Option<&'a str> {
        // Safety: parser invariant.
        self.value_bytes()
            .map(|v| unsafe { std::str::from_utf8_unchecked(v) })
    }

    /// Value with form-urlencoded decoding (`+` → space, `%XX` → byte),
    /// or `None` for a bare key.
    #[must_use]
    pub fn value_decoded(&self) -> Option<Cow<'a, str>> {
        self.value_bytes().map(form_decode)
    }

    /// `true` if the pair has an `=` separator. `?foo=` → `true`; `?foo` → `false`.
    #[must_use]
    pub fn has_value(&self) -> bool {
        self.eq_at.is_some()
    }

    /// Allocate an owned [`QueryPair`] copying the raw bytes.
    #[must_use]
    pub fn to_owned(&self) -> QueryPair {
        QueryPair {
            raw: Bytes::copy_from_slice(self.raw),
            eq_at: self.eq_at,
        }
    }
}

/// Iterator over the `name[=value]` pairs of a URI query string. Created by
/// [`QueryRef::pairs`] / [`Query::pairs`].
#[derive(Debug, Clone)]
pub struct QueryPairs<'a> {
    /// Bytes that haven't been processed yet, excluding any `&` that
    /// triggered the previous yield.
    remaining: &'a [u8],
    /// `true` once all fragments have been consumed.
    exhausted: bool,
}

impl<'a> QueryPairs<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            exhausted: bytes.is_empty(),
        }
    }
}

impl<'a> Iterator for QueryPairs<'a> {
    type Item = QueryPairRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.exhausted {
                return None;
            }
            // Pull off the next `&`-delimited fragment.
            // `memchr` for SIMD-accelerated boundary search.
            let fragment = if let Some(i) = memchr::memchr(b'&', self.remaining) {
                let frag = &self.remaining[..i];
                self.remaining = &self.remaining[i + 1..];
                frag
            } else {
                let frag = self.remaining;
                self.remaining = &[];
                self.exhausted = true;
                frag
            };

            if fragment.is_empty() {
                // Empty fragment (`&&`, leading `&`, trailing `&`) — skip,
                // matching WHATWG URLSearchParams / serde_html_form behaviour.
                continue;
            }

            return Some(QueryPairRef::from_raw(fragment));
        }
    }
}

impl std::iter::FusedIterator for QueryPairs<'_> {}

/// Form-urlencoded decode: `+` → ` `, `%XX` → byte.
///
/// Returns `Cow::Borrowed` when the input contains neither `+` nor `%`.
/// Invalid `%XX` (non-hex or truncated) passes through as a literal `%`.
/// Invalid UTF-8 in the decoded bytes falls back to U+FFFD.
fn form_decode(input: &[u8]) -> Cow<'_, str> {
    // Fast path: nothing to decode.
    let Some(start) = memchr::memchr2(b'+', b'%', input) else {
        // Safety: parser invariant — query bytes are valid UTF-8.
        return Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(input) });
    };

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..start]);

    let mut i = start;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < input.len() => {
                if let Some(byte) = rama_utils::hex::decode_pair(input[i + 1], input[i + 2]) {
                    out.push(byte);
                    i += 3;
                } else {
                    // Malformed `%XX` — emit the `%` literally and move on.
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                // Catches trailing `%` with < 2 chars remaining, and every
                // ordinary byte.
                out.push(b);
                i += 1;
            }
        }
    }

    // Happy path: decoded bytes are valid UTF-8 — promote `Vec<u8>` →
    // `String` without re-allocating. Otherwise fall back to lossy.
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
    }
}

#[cfg(test)]
mod internal_tests {
    //! Direct tests for the private `form_decode` helper. Behavioural
    //! coverage via the public `QueryRef::pairs()` API lives in
    //! `super::super::parser::tests::query_pairs`; these pin the
    //! function-level invariants that don't surface through the iterator.

    use super::form_decode;
    use std::borrow::Cow;

    // ---- form_decode ------------------------------------------------

    #[test]
    fn form_decode_empty_borrows() {
        let out = form_decode(b"");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, "");
    }

    /// Verify the borrowed path is genuinely zero-copy — the returned
    /// `&str` must point at the same address as the input bytes.
    #[test]
    fn form_decode_borrowed_path_is_zero_copy() {
        let input: &[u8] = b"no-escapes-here";
        let out = form_decode(input);
        match out {
            Cow::Borrowed(s) => {
                assert_eq!(s.as_ptr(), input.as_ptr(), "borrowed view re-allocated");
            }
            Cow::Owned(_) => panic!("expected Cow::Borrowed for input without `+` or `%`"),
        }
    }

    /// `%2B` decodes to a literal `+` — the decoder must NOT then
    /// re-interpret that `+` as a space (no double-decoding).
    #[test]
    fn form_decode_pct_2b_is_literal_plus_not_space() {
        assert_eq!(form_decode(b"%2B"), Cow::Borrowed("+"));
        assert_eq!(form_decode(b"a%2Bb"), Cow::Borrowed("a+b"));
    }

    /// `%26` → `&`, `%3D` → `=`. The pair iterator already split on the
    /// raw bytes, so decoded `&`/`=` are inert here.
    #[test]
    fn form_decode_pct_delimiter_bytes() {
        assert_eq!(form_decode(b"%26"), Cow::Borrowed("&"));
        assert_eq!(form_decode(b"%3D"), Cow::Borrowed("="));
        assert_eq!(form_decode(b"a%26b%3Dc"), Cow::Borrowed("a&b=c"));
    }

    /// `%00` produces a null byte in the resulting `String` — Rust
    /// strings tolerate interior NUL.
    #[test]
    fn form_decode_pct_00_null_byte() {
        let out = form_decode(b"a%00b");
        assert_eq!(out.as_bytes(), b"a\x00b");
    }

    /// 3-byte UTF-8: `%E2%82%AC` → `€` (U+20AC).
    #[test]
    fn form_decode_three_byte_utf8() {
        assert_eq!(form_decode(b"%E2%82%AC"), Cow::Borrowed("€"));
    }

    /// 4-byte UTF-8: `%F0%9F%98%80` → 😀 (U+1F600).
    #[test]
    fn form_decode_four_byte_utf8() {
        assert_eq!(form_decode(b"%F0%9F%98%80"), Cow::Borrowed("\u{1F600}"));
    }

    /// Truncated multi-byte UTF-8 — lossy decode emits U+FFFD.
    #[test]
    fn form_decode_truncated_utf8_replacement() {
        // `%E2%82` is the first 2 of 3 bytes for `€` — invalid UTF-8.
        let out = form_decode(b"%E2%82");
        assert!(out.contains('\u{FFFD}'), "got {out:?}");
    }

    /// Mixed `+`, `%XX`, and plain bytes in a single input.
    #[test]
    fn form_decode_mixed_input() {
        assert_eq!(
            form_decode(b"hello+world%20%21"),
            Cow::Borrowed("hello world !"),
        );
    }

    /// Long-string sanity check: 4 KB of mixed-escape content decodes
    /// without panicking and produces the expected length.
    #[test]
    fn form_decode_long_string() {
        // Pattern: "a+b%20" repeats; each repeat decodes "a+b%20" (6 bytes)
        // → "a b " (4 bytes).
        const N: usize = 1000;
        let mut input = Vec::with_capacity(6 * N);
        for _ in 0..N {
            input.extend_from_slice(b"a+b%20");
        }
        let out = form_decode(&input);
        assert_eq!(out.len(), 4 * N);
        // Spot-check a couple of windows.
        assert!(out.starts_with("a b a b "));
        assert!(out.ends_with("a b a b "));
    }

    /// Malformed `%XX` sequences (non-hex digits) pass through
    /// literally — including the `%` itself.
    #[test]
    fn form_decode_malformed_pct_literal_passthrough() {
        assert_eq!(form_decode(b"%ZZ"), Cow::Borrowed("%ZZ"));
        assert_eq!(form_decode(b"%G0"), Cow::Borrowed("%G0"));
        assert_eq!(form_decode(b"%-1"), Cow::Borrowed("%-1"));
    }

    /// Trailing `%` with insufficient remaining bytes — literal `%`.
    #[test]
    fn form_decode_trailing_percent_variants() {
        assert_eq!(form_decode(b"%"), Cow::Borrowed("%"));
        assert_eq!(form_decode(b"a%"), Cow::Borrowed("a%"));
        assert_eq!(form_decode(b"a%A"), Cow::Borrowed("a%A"));
    }
}
