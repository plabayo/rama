//! Fragment component types — owned [`Fragment`] and borrowed [`FragmentRef`].
//!
//! Per RFC 3986 §3.5, the fragment is opaque bytes after `#`. Unlike
//! `http::Uri`, rama preserves fragments through parse/serialize round-trips,
//! but the wire writer for HTTP request-targets *strips* the fragment per
//! RFC 9110 §7.1 — fragments are not transmitted as client request-targets.
//!
//! Skeleton.

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

    /// Returns the fragment as `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.bytes) }
    }

    /// Borrowed view.
    #[must_use]
    pub fn as_ref(&self) -> FragmentRef<'_> {
        FragmentRef { bytes: &self.bytes }
    }
}

/// Borrowed view of a URI fragment component (no leading `#`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> FragmentRef<'a> {
    /// Construct a [`FragmentRef`] from a byte slice. `pub(crate)` —
    /// only the parser / accessors should produce one.
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

    /// Returns the fragment as `&str`.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: parser enforces UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Returns an owned copy.
    #[must_use]
    pub fn to_owned(&self) -> Fragment {
        Fragment {
            bytes: BytesMut::from(self.bytes),
        }
    }
}
