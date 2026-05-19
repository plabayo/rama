//! Borrowed views into a [`Uri`](super::Uri)'s host component.
//!
//! [`HostRef`] is the public read-side type. It mirrors the existing owned
//! [`Host`](crate::address::Host) enum but borrows from the underlying buffer
//! (or from an owned `Host` field, depending on whether the `Uri` is in
//! lazy or owned form).
//!
//! Skeleton — the conversion impls and accessors land in M4.

use std::net::IpAddr;

use rama_core::bytes::Bytes;

use crate::address::{Domain, Host};

/// Borrowed view of a [`Uri`](super::Uri)'s host component.
///
/// Either:
/// - [`HostRef::Name`] — a [`DomainRef`] borrowing into the source buffer.
/// - [`HostRef::Address`] — an [`IpAddr`] (`Copy`, so always carried by value).
///
/// Convert to an owned [`Host`] via [`HostRef::to_owned`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRef<'a> {
    /// A DNS-style name.
    Name(DomainRef<'a>),
    /// A literal IPv4 or IPv6 address.
    Address(IpAddr),
}

impl HostRef<'_> {
    /// Returns an owned [`Host`] containing a copy of the underlying bytes
    /// (or, for the IP variants, a copy of the address value).
    #[must_use]
    pub fn to_owned(&self) -> Host {
        match *self {
            Self::Name(d) => {
                let bytes = Bytes::copy_from_slice(d.as_bytes());
                // Safety: a `DomainRef`'s contents are by-invariant a
                // validated `Domain` in presentation form.
                Host::Name(unsafe { Domain::from_maybe_borrowed_unchecked(bytes) })
            }
            Self::Address(ip) => Host::Address(ip),
        }
    }
}

/// Borrowed view into a domain-name byte slice.
///
/// The slice is contractually a validated [`Domain`](crate::address::Domain)
/// in presentation form (ASCII A-label) — invariants are enforced wherever
/// `DomainRef` is constructed. Methods always treat the bytes as ASCII (and
/// therefore valid UTF-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> DomainRef<'a> {
    /// Returns the raw bytes (always ASCII).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the domain as a `&str`. ASCII bytes are valid UTF-8 by
    /// construction.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: `DomainRef` is only ever constructed from a validated
        // Domain buffer, whose validator only accepts ASCII bytes.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }
}
