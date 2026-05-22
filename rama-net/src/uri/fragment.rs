//! Fragment component types — owned [`Fragment`] and borrowed [`FragmentRef`].
//!
//! Per RFC 3986 §3.5, the fragment is opaque bytes after `#`. Unlike
//! `http::Uri`, rama preserves fragments through parse/serialize round-trips,
//! but the wire writer for HTTP request-targets *strips* the fragment per
//! RFC 9110 §7.1 — fragments are not transmitted as client request-targets.

use std::borrow::Cow;

use percent_encoding::percent_decode;
use rama_core::bytes::BytesMut;

/// Owned fragment component (the part after `#`, sans the `#` itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub(crate) bytes: BytesMut,
}

impl Fragment {
    /// Returns the raw on-the-wire fragment bytes (no leading `#`).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the raw fragment as `&str` (no percent-decoding).
    /// Parser-validated UTF-8.
    #[must_use]
    pub fn as_raw_str(&self) -> &str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Percent-decoded fragment. `Cow::Borrowed` when no `%XX` escapes
    /// are present; `Cow::Owned` otherwise. UTF-8 errors fall back to
    /// U+FFFD.
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'_, str> {
        percent_decode(&self.bytes).decode_utf8_lossy()
    }

    /// Borrowed view. Named `view` (not `as_ref`) so it doesn't shadow
    /// the std `AsRef` trait — see the type-level docs.
    #[must_use]
    #[inline]
    pub fn view(&self) -> FragmentRef<'_> {
        FragmentRef { bytes: &self.bytes }
    }
}

/// Borrowed view of a URI fragment component (no leading `#`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> FragmentRef<'a> {
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

    /// Returns the raw fragment as `&str` (no percent-decoding).
    /// UTF-8 by parser invariant.
    #[must_use]
    pub fn as_raw_str(&self) -> &'a str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Percent-decoded fragment. `Cow::Borrowed` when no `%XX` escapes
    /// are present; `Cow::Owned` otherwise. UTF-8 errors fall back to
    /// U+FFFD.
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'a, str> {
        percent_decode(self.bytes).decode_utf8_lossy()
    }

    /// Returns an owned copy. Named `into_owned` (matching
    /// [`std::borrow::Cow::into_owned`]) so it doesn't shadow the std `ToOwned`
    /// trait method.
    #[must_use]
    pub fn into_owned(self) -> Fragment {
        Fragment {
            bytes: BytesMut::from(self.bytes),
        }
    }
}
