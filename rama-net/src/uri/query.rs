//! Query component types — owned [`Query`] and borrowed [`QueryRef`].
//!
//! Per RFC 3986 §3.4, the query is opaque bytes between `?` and `#`. The
//! `key=value&…` shape is a *convention* (used by HTML forms and most APIs)
//! but not part of the URI grammar. Two distinct serializers therefore live
//! in this module's neighbourhood (URL-query in this file in M4, and
//! application/x-www-form-urlencoded in `super::form` later).
//!
//! Skeleton — iteration and mutation arrive in M4 / M5.

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

    /// Returns the raw query as a `&str` (guaranteed UTF-8 by the parser).
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
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
    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the raw query as `&str` (UTF-8 by parser).
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Returns an owned copy.
    #[must_use]
    pub fn to_owned(&self) -> Query {
        Query {
            bytes: BytesMut::from(self.bytes),
        }
    }
}
