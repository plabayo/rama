//! Borrowed view of a [`Uri`](super::Uri)'s path component.
//!
//! The owned storage for the path lives directly inside `OwnedUriRef` as a
//! `BytesMut` — there is no separate `Path` owned type. The borrowed view
//! is just a `&[u8]` (with `as_str` because the bytes are validated to be
//! safe to interpret).
//!
//! Skeleton — segment iterator and mutating guard land in M4 / M5.

/// Borrowed view of a URI path.
///
/// The bytes are the raw on-the-wire form (percent-encoded). Iteration
/// helpers (segments, percent-decoded segments) land with M4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> PathRef<'a> {
    /// Construct a [`PathRef`] from a byte slice. `pub(crate)` — only
    /// the parser / accessors should produce one; external code goes
    /// through [`Uri::path`](super::Uri::path).
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the raw on-the-wire path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the raw path as a `&str`. The path is guaranteed UTF-8 by the
    /// parser (`graceful` accepts UTF-8 bytes; `strict` only accepts ASCII).
    ///
    /// Skeleton: the safety invariant is enforced by the parser landing in
    /// M3.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: parser ensures the bytes are valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }
}
