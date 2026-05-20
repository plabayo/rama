//! Query component types — owned [`Query`] and borrowed [`QueryRef`].
//!
//! Per RFC 3986 §3.4, the query is opaque bytes between `?` and `#`. The
//! `key=value&…` shape is a *convention* (used by HTML forms and most APIs)
//! but not part of the URI grammar. Two distinct serializers therefore live
//! in this module's neighbourhood (URL-query in this file in M4, and
//! application/x-www-form-urlencoded in `super::form` later).
//!
//! Iteration (key=value pair access) arrives in M4 (e); mutation in M5.

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
}
