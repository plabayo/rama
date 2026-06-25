//! Fragment component types — owned [`Fragment`] and borrowed [`FragmentRef`].
//!
//! Per RFC 3986 §3.5, the fragment is opaque bytes after `#`. Unlike
//! `http::Uri`, rama preserves fragments through parse/serialize round-trips,
//! but the wire writer for HTTP request-targets *strips* the fragment per
//! RFC 9110 §7.1 — fragments are not transmitted as client request-targets.

use std::{borrow::Cow, hash::Hash};

use percent_encoding::percent_decode;
use rama_core::bytes::BytesMut;

use super::encode::{
    encoded_fragment, encoded_fragment_cmp, encoded_fragment_eq, hash_encoded_fragment,
    write_encoded_fragment,
};

/// Owned fragment component (the part after `#`, sans the `#` itself).
///
/// `Default` produces an empty fragment (zero bytes — distinct from
/// "no fragment"; that distinction lives on [`super::Uri::fragment`] /
/// [`super::Uri::set_fragment`]). `Display` writes the raw on-wire
/// bytes (no leading `#`). `Hash` / `PartialOrd` / `Ord` are bytewise —
/// fragments are case-sensitive and pct-encoding-preserving per RFC
/// 3986 §3.5.
#[derive(Debug, Clone, Default)]
pub struct Fragment {
    pub(crate) bytes: BytesMut,
}

impl Fragment {
    /// Percent-encoded fragment string (no leading `#`).
    #[must_use]
    pub fn as_encoded_str(&self) -> Cow<'_, str> {
        encoded_fragment(&self.bytes)
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

impl PartialEq for Fragment {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.view() == other.view()
    }
}

impl Eq for Fragment {}

impl PartialOrd for Fragment {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Fragment {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.view().cmp(&other.view())
    }
}

impl Hash for Fragment {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.view().hash(state);
    }
}

/// Borrowed view of a URI fragment component (no leading `#`).
#[derive(Debug, Clone, Copy)]
pub struct FragmentRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> FragmentRef<'a> {
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrow a fragment string as a [`FragmentRef`] — no allocation.
    ///
    /// The input is treated as component text. When rendered through
    /// [`FragmentRef::as_encoded_str`], bytes outside the fragment grammar are
    /// percent-encoded while valid existing pct triplets are preserved.
    #[must_use]
    #[inline]
    pub fn from_raw_str(fragment: &'a str) -> Self {
        Self::new(fragment.as_bytes())
    }

    /// Percent-encoded fragment string (no leading `#`).
    #[must_use]
    pub fn as_encoded_str(self) -> Cow<'a, str> {
        encoded_fragment(self.bytes)
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

impl PartialEq for FragmentRef<'_> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        encoded_fragment_eq(self.bytes, other.bytes)
    }
}

impl Eq for FragmentRef<'_> {}

impl PartialOrd for FragmentRef<'_> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FragmentRef<'_> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        encoded_fragment_cmp(self.bytes, other.bytes)
    }
}

impl Hash for FragmentRef<'_> {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        hash_encoded_fragment(state, self.bytes);
    }
}

impl std::fmt::Display for Fragment {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.view(), f)
    }
}

impl std::fmt::Display for FragmentRef<'_> {
    /// Renders the encoded fragment bytes (no leading `#`).
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_encoded_fragment(f, self.bytes)
    }
}

impl std::str::FromStr for Fragment {
    type Err = std::convert::Infallible;

    /// Encode arbitrary input as a [`Fragment`] — bytes outside
    /// `pchar ∪ {'/', '?'}` get percent-encoded. Infallible because
    /// every input round-trips after encoding; `str::parse` users with
    /// `?`-ladder code can still use this through the `Result` shape.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            bytes: super::encode::encode_fragment(s),
        })
    }
}
