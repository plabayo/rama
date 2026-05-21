//! Host bytes that aren't a DNS-shaped [`Domain`] or recognized IP
//! address — preserved verbatim per RFC 3986 §3.2.2.
//!
//! Two grammar shapes land here, distinguished by [`UninterpretedHost::is_bracketed`]:
//!
//! - **Non-bracketed `reg-name`**: bytes outside the strict DNS-label
//!   shape — pct-encoded segments (`exa%6Dple.com`), sub-delim characters
//!   (`tag,with,commas`), or raw non-ASCII UTF-8 (`münchen.de` under
//!   graceful URI parsing / IRI). Stored as-received.
//! - **Bracketed IPvFuture literal**: the body of `[vN.X]`. The brackets
//!   are URI syntax, not host content — they're not stored, but
//!   [`Display`](std::fmt::Display) re-adds them.
//!
//! Wire-fidelity is the design contract: this type is **construction-
//! free from the public API** — only the URI parser builds it, by
//! preserving bytes off the wire. Callers either keep it as-is
//! (forwarding, logging) or convert into [`Domain`], [`IpAddr`],
//! [`Ipv4Addr`], or [`Ipv6Addr`] via the `TryFrom` impls, which apply
//! pct-decoding and (for `Domain`) UTS #46 IDN normalization on the way.

use std::{
    borrow::Cow,
    fmt,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr},
};

use rama_core::bytes::Bytes;

use super::Domain;
use super::domain::DomainParseError;

/// Reg-name / IP-literal host bytes preserved verbatim.
///
/// Wire-fidelity is the design contract: this type is
/// **construction-free from the public API** — only the URI parser
/// builds it, by preserving bytes off the wire. Two grammar shapes
/// land here, distinguished by [`is_bracketed`](Self::is_bracketed):
///
/// - **Non-bracketed `reg-name`**: bytes outside the strict DNS-label
///   shape — pct-encoded segments (`exa%6Dple.com`), sub-delim
///   characters (`tag,with,commas`), or raw non-ASCII UTF-8
///   (`münchen.de` under graceful URI parsing / IRI).
/// - **Bracketed IPvFuture literal** (`[vN.X]`): brackets are URI
///   syntax, not host content; they're not stored, but
///   [`Display`](std::fmt::Display) re-adds them.
///
/// Callers either keep an `UninterpretedHost` as-is (forwarding,
/// logging) or convert into [`Domain`], [`IpAddr`](std::net::IpAddr),
/// [`Ipv4Addr`](std::net::Ipv4Addr), or [`Ipv6Addr`](std::net::Ipv6Addr)
/// via the `TryFrom` impls — which apply pct-decoding and (for
/// `Domain`) UTS #46 IDN normalization on the way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UninterpretedHost {
    /// `true` when the host came from a bracketed IP-literal (`[vN.X]`).
    /// The bytes below do **not** include the surrounding brackets —
    /// those belong to URI syntax, not host content. Ordered before
    /// `bytes` so derived [`Ord`] compares bracketed forms separately.
    bracketed: bool,
    bytes: Bytes,
}

impl UninterpretedHost {
    /// Construct from already-validated bytes. **Internal** — only the
    /// URI parser, after walking the bytes against the appropriate
    /// grammar, has authority to mint one of these.
    #[inline]
    pub(crate) fn from_validated_bytes(bytes: Bytes, bracketed: bool) -> Self {
        Self { bracketed, bytes }
    }

    /// Borrow this host as an [`UninterpretedHostRef`]. The
    /// inspection / conversion API lives on the Ref type; the owned
    /// type's accessors here just delegate, so there's one
    /// implementation to maintain.
    #[must_use]
    pub fn as_ref(&self) -> UninterpretedHostRef<'_> {
        UninterpretedHostRef::from(self)
    }

    /// The raw on-the-wire bytes — **not** pct-decoded. For bracketed
    /// literals, the surrounding brackets are *not* included.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.as_ref().as_str()
    }

    /// Raw bytes view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }

    /// `true` when this came from a bracketed IP-literal (`[vN.X]`).
    /// [`Display`](std::fmt::Display) adds the brackets back; equality
    /// respects the flag.
    #[must_use]
    pub fn is_bracketed(&self) -> bool {
        self.bracketed
    }

    /// Pct-decoded view. See [`UninterpretedHostRef::as_unicode`] for
    /// the contract — this is a delegating wrapper.
    #[must_use]
    pub fn as_unicode(&self) -> Cow<'_, str> {
        self.as_ref().as_unicode()
    }
}

impl fmt::Display for UninterpretedHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        UninterpretedHostRef::from(self).fmt(f)
    }
}

// ---- Borrowed view ------------------------------------------------------

/// Borrowed view of an [`UninterpretedHost`] — a wide, [`Copy`] pointer
/// into pre-validated bytes plus the bracketed flag. Mirrors
/// [`DomainRef`](super::DomainRef)'s relationship to [`Domain`].
///
/// All inspection / conversion operations available on
/// [`UninterpretedHost`] are also available here, so callers holding a
/// `HostRef` don't need to round-trip back through an owned form just to
/// pct-decode or attempt a typed conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UninterpretedHostRef<'a> {
    /// `true` when the host is a bracketed IP-literal. See
    /// [`UninterpretedHost::is_bracketed`].
    bracketed: bool,
    /// Pre-validated bytes — not pct-decoded, brackets not included.
    bytes: &'a [u8],
}

impl<'a> UninterpretedHostRef<'a> {
    /// Raw on-the-wire bytes — **not** pct-decoded. Brackets (for
    /// IP-literals) are not included.
    #[must_use]
    pub fn as_str(&self) -> &'a str {
        // Safety: parser-validated to be UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Raw bytes view.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// `true` when this came from a bracketed IP-literal (`[vN.X]`).
    #[must_use]
    pub fn is_bracketed(&self) -> bool {
        self.bracketed
    }

    /// Pct-decoded view. Borrows when no `%` is present, allocates a
    /// new `String` when decoding actually occurred. See
    /// [`UninterpretedHost::as_unicode`] for the full contract.
    #[must_use]
    pub fn as_unicode(&self) -> Cow<'a, str> {
        if !self.bytes.contains(&b'%') {
            return Cow::Borrowed(self.as_str());
        }
        let mut out = Vec::with_capacity(self.bytes.len());
        let mut i = 0;
        while i < self.bytes.len() {
            let b = self.bytes[i];
            if b == b'%'
                && i + 2 < self.bytes.len()
                && let Some(decoded) =
                    rama_utils::hex::decode_pair(self.bytes[i + 1], self.bytes[i + 2])
            {
                out.push(decoded);
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        }
        match String::from_utf8(out) {
            Ok(s) => Cow::Owned(s),
            Err(_) => Cow::Borrowed(self.as_str()),
        }
    }

    /// Returns an owned [`UninterpretedHost`] by copying the underlying
    /// bytes.
    #[must_use]
    pub fn to_owned(&self) -> UninterpretedHost {
        UninterpretedHost::from_validated_bytes(Bytes::copy_from_slice(self.bytes), self.bracketed)
    }
}

impl fmt::Display for UninterpretedHostRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.bracketed {
            write!(f, "[{}]", self.as_str())
        } else {
            f.write_str(self.as_str())
        }
    }
}

impl<'a> From<&'a UninterpretedHost> for UninterpretedHostRef<'a> {
    fn from(host: &'a UninterpretedHost) -> Self {
        Self {
            bracketed: host.bracketed,
            bytes: &host.bytes,
        }
    }
}

// ---- Typed conversions --------------------------------------------------
//
// The borrowed [`UninterpretedHostRef`] is the primary surface — read-
// only conversions don't need ownership. The `&UninterpretedHost` and
// owned [`UninterpretedHost`] variants delegate through the Ref impl so
// the conversion logic lives in one place.

impl<'a> TryFrom<UninterpretedHostRef<'a>> for Domain {
    type Error = DomainParseError;

    /// Pct-decodes the bytes and, with the `idna` feature, applies UTS
    /// #46 normalization to ACE. Returns a [`DomainParseError`] tagged
    /// with the "bracketed IP-literal" kind for bracketed inputs —
    /// IP-literals are a different grammatical category and have no
    /// domain interpretation.
    fn try_from(host: UninterpretedHostRef<'a>) -> Result<Self, Self::Error> {
        if host.bracketed {
            return Err(DomainParseError::bracketed_ip_literal());
        }
        match host.as_unicode() {
            Cow::Borrowed(s) => Self::try_from(s),
            Cow::Owned(s) => Self::try_from(s),
        }
    }
}

impl<'a> TryFrom<UninterpretedHostRef<'a>> for IpAddr {
    type Error = AddrParseError;

    /// Pct-decodes the bytes and parses as an IPv4 or IPv6 address.
    /// Bracketed IPvFuture inputs always fail here — no `vN` form is
    /// registered with IANA, so there's nothing to decode.
    fn try_from(host: UninterpretedHostRef<'a>) -> Result<Self, Self::Error> {
        host.as_unicode().as_ref().parse()
    }
}

impl<'a> TryFrom<UninterpretedHostRef<'a>> for Ipv4Addr {
    type Error = AddrParseError;
    fn try_from(host: UninterpretedHostRef<'a>) -> Result<Self, Self::Error> {
        host.as_unicode().as_ref().parse()
    }
}

impl<'a> TryFrom<UninterpretedHostRef<'a>> for Ipv6Addr {
    type Error = AddrParseError;
    fn try_from(host: UninterpretedHostRef<'a>) -> Result<Self, Self::Error> {
        host.as_unicode().as_ref().parse()
    }
}

// Borrowed-`UninterpretedHost` variants — borrow as `UninterpretedHostRef`
// and delegate. Same logic, one place.

impl TryFrom<&UninterpretedHost> for Domain {
    type Error = DomainParseError;
    #[inline]
    fn try_from(host: &UninterpretedHost) -> Result<Self, Self::Error> {
        UninterpretedHostRef::from(host).try_into()
    }
}

impl TryFrom<&UninterpretedHost> for IpAddr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: &UninterpretedHost) -> Result<Self, Self::Error> {
        UninterpretedHostRef::from(host).try_into()
    }
}

impl TryFrom<&UninterpretedHost> for Ipv4Addr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: &UninterpretedHost) -> Result<Self, Self::Error> {
        UninterpretedHostRef::from(host).try_into()
    }
}

impl TryFrom<&UninterpretedHost> for Ipv6Addr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: &UninterpretedHost) -> Result<Self, Self::Error> {
        UninterpretedHostRef::from(host).try_into()
    }
}

// Owned-`UninterpretedHost` variants — same pattern.

impl TryFrom<UninterpretedHost> for Domain {
    type Error = DomainParseError;
    #[inline]
    fn try_from(host: UninterpretedHost) -> Result<Self, Self::Error> {
        Self::try_from(&host)
    }
}

impl TryFrom<UninterpretedHost> for IpAddr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: UninterpretedHost) -> Result<Self, Self::Error> {
        Self::try_from(&host)
    }
}

impl TryFrom<UninterpretedHost> for Ipv4Addr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: UninterpretedHost) -> Result<Self, Self::Error> {
        Self::try_from(&host)
    }
}

impl TryFrom<UninterpretedHost> for Ipv6Addr {
    type Error = AddrParseError;
    #[inline]
    fn try_from(host: UninterpretedHost) -> Result<Self, Self::Error> {
        Self::try_from(&host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(bytes: &'static [u8]) -> UninterpretedHost {
        UninterpretedHost::from_validated_bytes(Bytes::from_static(bytes), false)
    }

    fn bracketed(bytes: &'static [u8]) -> UninterpretedHost {
        UninterpretedHost::from_validated_bytes(Bytes::from_static(bytes), true)
    }

    // -- as_unicode ---------------------------------------------------------

    #[test]
    fn as_unicode_borrows_when_no_pct() {
        let h = reg(b"example.com");
        assert!(matches!(h.as_unicode(), Cow::Borrowed(_)));
        assert_eq!(&*h.as_unicode(), "example.com");
    }

    #[test]
    fn as_unicode_decodes_pct_to_ascii() {
        let h = reg(b"exa%6Dple.com");
        assert!(matches!(h.as_unicode(), Cow::Owned(_)));
        assert_eq!(&*h.as_unicode(), "example.com");
    }

    #[test]
    fn as_unicode_decodes_pct_to_utf8() {
        // %C3%BCller.de → müller.de
        let h = reg(b"m%C3%BCller.de");
        assert_eq!(&*h.as_unicode(), "müller.de");
    }

    // -- TryFrom<&UninterpretedHost> for Domain ---------------------------

    #[test]
    fn try_into_domain_decodes_pct_encoded_ascii() {
        let h = reg(b"exa%6Dple.com");
        let d: Domain = (&h).try_into().unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[cfg(feature = "idna")]
    #[test]
    fn try_into_domain_applies_idna_on_decoded_utf8() {
        let h = reg(b"m%C3%BCnchen.de");
        let d: Domain = (&h).try_into().unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn try_into_domain_fails_on_sub_delim_chars() {
        // Sub-delim hosts (e.g. `tag,with,commas`) are RFC 3986-legal
        // reg-name but not DNS-label-shaped — Domain rejects.
        let h = reg(b"tag,with,commas");
        Domain::try_from(&h).unwrap_err();
    }

    #[test]
    fn try_into_domain_fails_on_bracketed_with_typed_error() {
        let h = bracketed(b"v1.fe80::a");
        let err = Domain::try_from(&h).unwrap_err();
        // Surfaces the proper "bracketed IP-literal isn't a domain"
        // message, not a generic label-character error.
        assert!(
            format!("{err}").contains("bracketed IP-literal"),
            "got: {err}"
        );
    }

    // -- TryFrom<&UninterpretedHost> for IpAddr / Ipv4Addr / Ipv6Addr -----

    #[test]
    fn try_into_ip_addr_decodes_pct_encoded_ipv4() {
        // %31%32%37.0.0.1 → 127.0.0.1
        let h = reg(b"%31%32%37.0.0.1");
        let ip: IpAddr = (&h).try_into().unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn try_into_ipv4_addr_works_for_dotted_quad() {
        let h = reg(b"192.0.2.1");
        let ip: Ipv4Addr = (&h).try_into().unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn try_into_ipv6_addr_works_for_colon_form() {
        // Stored without brackets — that's URI syntax, not host content.
        let h = reg(b"2001:db8::1");
        let ip: Ipv6Addr = (&h).try_into().unwrap();
        assert_eq!(ip, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn try_into_ip_addr_fails_for_ipvfuture() {
        // IPvFuture (bracketed) bytes don't parse as any IP variant.
        let h = bracketed(b"v1.fe80::a");
        IpAddr::try_from(&h).unwrap_err();
        Ipv4Addr::try_from(&h).unwrap_err();
        Ipv6Addr::try_from(&h).unwrap_err();
    }

    #[test]
    fn try_into_ip_addr_fails_for_pure_reg_name() {
        let h = reg(b"example.com");
        IpAddr::try_from(&h).unwrap_err();
    }

    // -- Owned-input TryFrom variants -------------------------------------

    #[test]
    fn try_into_domain_owned_works() {
        let h = reg(b"exa%6Dple.com");
        let d: Domain = h.try_into().unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn try_into_ip_addr_owned_works() {
        let h = reg(b"127.0.0.1");
        let ip: IpAddr = h.try_into().unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn try_into_ipv4_owned_works() {
        let h = reg(b"127.0.0.1");
        let ip: Ipv4Addr = h.try_into().unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn try_into_ipv6_owned_works() {
        let h = reg(b"::1");
        let ip: Ipv6Addr = h.try_into().unwrap();
        assert_eq!(ip, "::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn try_into_domain_owned_propagates_bracketed_error() {
        let h = bracketed(b"v1.fe80::a");
        let err: DomainParseError = Domain::try_from(h).unwrap_err();
        assert!(format!("{err}").contains("bracketed IP-literal"));
    }

    // -- Display + ordering -------------------------------------------------

    #[test]
    fn display_brackets_ip_literal() {
        let h = bracketed(b"v1.fe80::a");
        assert_eq!(h.to_string(), "[v1.fe80::a]");
    }

    #[test]
    fn display_renders_reg_name_verbatim() {
        let h = reg(b"exa%6Dple.com");
        assert_eq!(h.to_string(), "exa%6Dple.com");
    }

    #[test]
    fn eq_distinguishes_bracketed_flag() {
        let a = reg(b"v1");
        let b = bracketed(b"v1");
        assert_ne!(a, b);
    }

    #[test]
    fn ord_sorts_bracketed_after_reg_name() {
        // Derived Ord compares `bracketed` first, then `bytes`.
        // `false < true`, so reg-name comes before IP-literal.
        let mut v = [bracketed(b"v1"), reg(b"zzz"), reg(b"aaa")];
        v.sort();
        assert_eq!(v[0].as_str(), "aaa");
        assert!(!v[0].is_bracketed());
        assert_eq!(v[1].as_str(), "zzz");
        assert!(!v[1].is_bracketed());
        assert_eq!(v[2].as_str(), "v1");
        assert!(v[2].is_bracketed());
    }

    // -- UninterpretedHostRef -------------------------------------------

    #[test]
    fn ref_from_owned_borrows_bytes() {
        let h = reg(b"exa%6Dple.com");
        let r: UninterpretedHostRef<'_> = (&h).into();
        assert_eq!(r.as_bytes(), b"exa%6Dple.com");
        assert!(!r.is_bracketed());
    }

    #[test]
    fn ref_as_unicode_decodes_pct() {
        let h = reg(b"exa%6Dple.com");
        let r: UninterpretedHostRef<'_> = (&h).into();
        assert!(matches!(r.as_unicode(), Cow::Owned(_)));
        assert_eq!(&*r.as_unicode(), "example.com");
    }

    #[test]
    fn ref_to_owned_roundtrip() {
        let h = reg(b"exa%6Dple.com");
        let r: UninterpretedHostRef<'_> = (&h).into();
        let back: UninterpretedHost = r.to_owned();
        assert_eq!(back, h);
    }

    #[test]
    fn ref_display_brackets_ip_literal() {
        let h = bracketed(b"v1.fe80::a");
        let r: UninterpretedHostRef<'_> = (&h).into();
        assert_eq!(r.to_string(), "[v1.fe80::a]");
    }

    #[test]
    fn ref_try_into_domain_decodes_pct() {
        let h = reg(b"exa%6Dple.com");
        let r: UninterpretedHostRef<'_> = (&h).into();
        let d: Domain = r.try_into().unwrap();
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn ref_try_into_ipv4_decodes_pct() {
        let h = reg(b"%31%32%37.0.0.1");
        let r: UninterpretedHostRef<'_> = (&h).into();
        let ip: Ipv4Addr = r.try_into().unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));
    }
}
