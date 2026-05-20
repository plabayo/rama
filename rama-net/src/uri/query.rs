//! Query component types — owned [`Query`] and borrowed [`QueryRef`].
//!
//! Per RFC 3986 §3.4, the query is opaque bytes between `?` and `#`. The
//! `key=value&…` shape is a *convention* (used by HTML forms and most APIs)
//! but not part of the URI grammar. Two distinct serializers therefore live
//! in this module's neighbourhood (URL-query in this file in M4, and
//! application/x-www-form-urlencoded in `super::form` later).
//!
//! Pair iteration via [`QueryRef::pairs`] / [`Query::pairs`] lands in M4 (e);
//! mutation in M5.

use std::borrow::Cow;

use percent_encoding::percent_decode;
use rama_core::bytes::BytesMut;

/// Owned query component.
///
/// Storage is `BytesMut` so that in Owned mode the path/query/fragment can
/// be mutated cheaply via the RAII guards landing in M5.
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
}

/// Borrowed view of a URI query component (no leading `?`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> QueryRef<'a> {
    /// Construct a [`QueryRef`] from a byte slice. `pub(crate)` — only
    /// the parser / accessors should produce one.
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

    /// Iterator over `name[=value]` pairs in the query string.
    ///
    /// Splitting follows the WHATWG URL Standard's `URLSearchParams` /
    /// `application/x-www-form-urlencoded` parse rules:
    /// - split on `&`
    /// - within each non-empty fragment, split on the *first* `=`
    /// - empty fragments (leading/trailing/double `&`) are dropped
    ///
    /// Each [`QueryPair`] keeps the bare-key vs empty-value distinction
    /// — `?foo` yields `value = None`, `?foo=` yields `value = Some("")`.
    ///
    /// Examples:
    /// ```text
    /// ""              -> []
    /// "foo"           -> [(foo, None)]
    /// "foo="          -> [(foo, Some(""))]
    /// "foo=bar"       -> [(foo, Some("bar"))]
    /// "a=1&b=2"       -> [(a, Some("1")), (b, Some("2"))]
    /// "a&b=2&c"       -> [(a, None), (b, Some("2")), (c, None)]
    /// "a=b=c"         -> [(a, Some("b=c"))]    // first `=` only
    /// "&a=1&&b=2&"    -> [(a, Some("1")), (b, Some("2"))]   // empties dropped
    /// ```
    #[must_use]
    pub fn pairs(&self) -> QueryPairs<'a> {
        QueryPairs::new(self.bytes)
    }
}

/// One `name[=value]` pair from a URI query string.
///
/// See [`QueryRef::pairs`] for the splitting rules.
///
/// Decoded views use the form-urlencoded convention: `+` decodes to space
/// in addition to `%XX` → byte. That intentionally differs from
/// [`QueryRef::as_decoded_str`] (whole-query pct-decode only) — pair-level
/// access is where the form convention applies, since the `key=value&…`
/// shape is itself form-urlencoded territory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPair<'a> {
    name: &'a [u8],
    value: Option<&'a [u8]>,
}

impl<'a> QueryPair<'a> {
    #[inline]
    #[must_use]
    pub(crate) const fn new(name: &'a [u8], value: Option<&'a [u8]>) -> Self {
        Self { name, value }
    }

    /// Raw on-wire bytes of the name.
    #[must_use]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Name as `&str` with no decoding. Parser-validated UTF-8.
    #[must_use]
    pub fn name_raw(&self) -> &'a str {
        // Safety: parser invariant.
        unsafe { std::str::from_utf8_unchecked(self.name) }
    }

    /// Name with form-urlencoded decoding: `+` → space, `%XX` → byte.
    /// `Cow::Borrowed` when neither escape is present.
    #[must_use]
    pub fn name_decoded(&self) -> Cow<'a, str> {
        form_decode(self.name)
    }

    /// Raw on-wire bytes of the value, or `None` for a bare key (`?foo`).
    #[must_use]
    pub fn value_bytes(&self) -> Option<&'a [u8]> {
        self.value
    }

    /// Value as `&str` with no decoding, or `None` for a bare key.
    /// Parser-validated UTF-8.
    #[must_use]
    pub fn value_raw(&self) -> Option<&'a str> {
        // Safety: parser invariant.
        self.value
            .map(|v| unsafe { std::str::from_utf8_unchecked(v) })
    }

    /// Value with form-urlencoded decoding (`+` → space, `%XX` → byte),
    /// or `None` for a bare key.
    #[must_use]
    pub fn value_decoded(&self) -> Option<Cow<'a, str>> {
        self.value.map(form_decode)
    }

    /// `true` if the pair contains an `=` separator. `?foo=` returns
    /// `true` (empty value is still a value); `?foo` returns `false`.
    #[must_use]
    pub fn has_value(&self) -> bool {
        self.value.is_some()
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
    type Item = QueryPair<'a>;

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
                // If this was the last fragment, `exhausted` is already true
                // so the next iteration returns None.
                continue;
            }

            // Split on the *first* `=` only. `a=b=c` → name="a", value="b=c".
            let pair = match memchr::memchr(b'=', fragment) {
                Some(i) => QueryPair::new(&fragment[..i], Some(&fragment[i + 1..])),
                None => QueryPair::new(fragment, None),
            };
            return Some(pair);
        }
    }
}

impl std::iter::FusedIterator for QueryPairs<'_> {}

/// Form-urlencoded decode: `+` → ` `, `%XX` → byte.
///
/// Single-pass: `memchr2` finds the first `+` or `%` (SIMD-accelerated).
/// If neither byte appears, the input is returned borrowed — zero
/// allocations. Otherwise one `Vec<u8>` is allocated for the decoded
/// output (output is never longer than input: `%XX` is 3 → 1, `+` is
/// 1 → 1), then converted to `String` once.
///
/// We don't use `percent_encoding::percent_decode` here because it
/// can't inject the `+` → space substitution mid-decode — composing
/// the two would force an intermediate `Vec` (the rejected double
/// allocation) or pull in `form_urlencoded::decode` which is
/// `pub(crate)` in that crate.
///
/// Invalid `%XX` sequences (non-hex digits, trailing `%`) are passed
/// through as a literal `%`, matching the `percent_encoding` crate.
/// Invalid UTF-8 in the decoded result falls back to U+FFFD.
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
                if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                    out.push((h << 4) | l);
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

/// ASCII hex digit → 0..=15, `None` for non-hex bytes.
///
/// Uses the standard `wrapping_sub` hex-decode idiom: a single subtract
/// then an unsigned-less-than check per branch, with a bit-5 fold to
/// merge upper and lower case. Strictly fewer instructions than a
/// range-match without paying for a rodata lookup table.
#[inline]
const fn hex_val(b: u8) -> Option<u8> {
    // Digit fast-path: '0'..='9' → 0..=9.
    let d = b.wrapping_sub(b'0');
    if d < 10 {
        return Some(d);
    }
    // Case-fold by setting bit 5 ('A' | 0x20 == 'a'); 'a'..='f' → 0..=5.
    // Non-letter bytes wrap to large values and fail the < 6 check.
    let l = (b | 0x20).wrapping_sub(b'a');
    if l < 6 {
        return Some(l + 10);
    }
    None
}

#[cfg(test)]
mod internal_tests {
    //! Direct tests for the private `form_decode` / `hex_val` helpers.
    //! Behavioural coverage via the public `QueryRef::pairs()` API lives in
    //! `super::super::parser::tests::query_pairs`; these are the
    //! function-level invariants that don't surface through the iterator.

    use super::{form_decode, hex_val};
    use std::borrow::Cow;

    // ---- hex_val ----------------------------------------------------

    /// Exhaustive sweep over all 256 byte values: every ASCII hex digit
    /// must produce the right value, every other byte must return `None`.
    #[test]
    fn hex_val_exhaustive_256_bytes() {
        for b in 0u8..=255 {
            let got = hex_val(b);
            let expected = match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            assert_eq!(got, expected, "hex_val(0x{b:02X}) (= {:?})", b as char);
        }
    }

    /// Pin the boundary bytes explicitly — these are the off-by-one
    /// traps for the wrapping_sub idiom.
    #[test]
    fn hex_val_boundary_bytes() {
        // Just before '0' / just after '9'.
        assert_eq!(hex_val(b'/'), None); // 0x2F
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b':'), None); // 0x3A

        // Just before 'A' / just after 'F'.
        assert_eq!(hex_val(b'@'), None); // 0x40
        assert_eq!(hex_val(b'A'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'G'), None); // 0x47

        // Just before 'a' / just after 'f'.
        assert_eq!(hex_val(b'`'), None); // 0x60
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'f'), Some(15));
        assert_eq!(hex_val(b'g'), None); // 0x67

        // High-bit bytes — never accept.
        assert_eq!(hex_val(0x80), None);
        assert_eq!(hex_val(0xFF), None);
    }

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
