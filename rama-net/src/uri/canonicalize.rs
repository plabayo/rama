//! RFC 3986 §6.2.2 syntax-based URI normalization.
//!
//! Drives [`crate::uri::Uri::canonicalize`]. Applies, in order:
//!
//! 1. **Host promotion** — [`Host::Uninterpreted`] that decodes to an IP
//!    or a typed [`Domain`] gets replaced with the typed variant.
//!    Sub-delim reg-names and IPvFuture stay `Uninterpreted` (no
//!    canonical typed form exists for them).
//! 2. **Host case + pct normalization** (§6.2.2.1 + §6.2.2.2) — host
//!    bytes are ASCII-lowercased; for un-promoted `Uninterpreted` bodies
//!    pct-encoded octets are also normalised (decode unreserved,
//!    uppercase remaining hex). `Host::Address` is already canonical
//!    via the std `Display` impls.
//! 3. **Default-port drop** — when the scheme has a registered default
//!    port and the URI's port matches it, the port is omitted.
//! 4. **Pct-encoding normalization** (§6.2.2.2) on path, query,
//!    fragment — `%XX` octets that map to an unreserved character are
//!    decoded in place; pct-encoded octets that stay encoded get their
//!    hex digits uppercased (§6.2.2.1 case normalization).
//! 5. **Empty path** (§6.2.3) — when an authority is present and the
//!    path is empty, the canonical form has the path as `/`.
//! 6. **Dot-segment removal** (§6.2.2.3) — `.` and `..` segments are
//!    collapsed. Routed through [`super::resolve`]'s graceful
//!    [`remove_dot_segments_graceful`] so this code path can't error.
//!
//! Wire-fidelity preservation at parse time is intentional (see
//! [`crate::address::UninterpretedHost`]); `canonicalize` is opt-in,
//! for callers (typically clients building URIs from user input) who
//! want a normalised form.

use std::net::IpAddr;

use rama_core::bytes::{Bytes, BytesMut};

use crate::address::{Domain, Host, UninterpretedHost, UninterpretedHostRef};
use crate::byte_sets::is_unreserved_byte;

use super::owned::OwnedUriRef;
use super::resolve::remove_dot_segments_graceful;
use super::{Uri, UriInner};

/// Top-level entry — apply RFC 3986 §6.2.2 normalization to `uri`.
///
/// Always allocates one `OwnedUriRef`. No "already canonical?"
/// pre-scan: empirically, byte-walking to detect the no-op case costs
/// more than the allocation it would avoid on typical inputs
/// (`parse_canonical(user_input)` rarely receives already-canonical
/// bytes). If a future benchmark shows the idempotent-canonicalize
/// case dominates, revisit then.
pub(super) fn canonicalize_uri(uri: Uri) -> Uri {
    // Asterisk-form has no components — never needs work.
    if matches!(uri.inner, UriInner::Asterisk) {
        return uri;
    }
    let owned = uri.as_owned_components();
    let canonical = canonicalize_owned(owned);
    Uri {
        inner: UriInner::Owned(std::sync::Arc::new(canonical)),
    }
}

/// Apply RFC 3986 §6.2.2 syntax-based normalization to `owned` in
/// place. See the module docs for the full ordering.
fn canonicalize_owned(mut owned: OwnedUriRef) -> OwnedUriRef {
    // 0. Scheme case (§6.2.2.1). Known schemes are already canonical
    // (the `Protocol` enum stores http/https/ws/wss/socks5/socks5h
    // case-insensitively at construction). Custom schemes preserve
    // input case — lowercase them here if needed. Parser-validated
    // schemes are ASCII-only, so `to_ascii_lowercase` is loss-free.
    if let Some(scheme) = &owned.scheme
        && scheme.as_str().bytes().any(|b| b.is_ascii_uppercase())
    {
        let lower = scheme.as_str().to_ascii_lowercase();
        if let Ok(lowered) = crate::Protocol::try_from(lower) {
            owned.scheme = Some(lowered);
        }
    }

    // 1. Host promotion + host case/pct normalization (§6.2.2.1).
    if let Some(authority) = &mut owned.authority {
        if let Host::Uninterpreted(h) = &authority.address.host {
            let h_ref = UninterpretedHostRef::from(h);
            // IPv4/IPv6 first — Ipv4Addr / Ipv6Addr parsing is cheaper
            // than a Domain validation pass, and pct-decoded IP literals
            // are unambiguous.
            if let Ok(ip) = IpAddr::try_from(h_ref) {
                authority.address.host = Host::Address(ip);
            } else if let Ok(d) = Domain::try_from(h_ref) {
                authority.address.host = Host::Name(d);
            }
            // else: sub-delim reg-name or IPvFuture — no typed canonical
            // form, leave as `Uninterpreted` (normalised below).
        }

        // §6.2.2.1 case-normalization for hosts: ASCII lowercase. RFC says
        // "the host is case-insensitive" — render the canonical form
        // accordingly. `Host::Address` is already canonical via the std
        // `Display` impls. `Host::Name`/`Host::Uninterpreted` carry
        // presentation-form bytes and need explicit lowercasing here.
        match &mut authority.address.host {
            Host::Name(d) => normalize_host_domain(d),
            Host::Uninterpreted(h) => normalize_host_uninterpreted(h),
            Host::Address(_) => {}
        }

        // 2. Default-port drop. Empty (`host:`) also normalises to Unset
        // since canonicalization is the explicit opt-in to dropping
        // wire trivia.
        if let Some(scheme) = &owned.scheme
            && let Some(default) = scheme.default_port()
            && authority.address.port == crate::address::OptPort::Set(default)
        {
            authority.address.port = crate::address::OptPort::Unset;
        }
        if authority.address.port == crate::address::OptPort::Empty {
            authority.address.port = crate::address::OptPort::Unset;
        }
    }

    // 3. Pct-encoding normalization on path / query / fragment.
    normalize_pct(&mut owned.path);
    if let Some(q) = &mut owned.query {
        normalize_pct(&mut q.bytes);
    }
    if let Some(f) = &mut owned.fragment {
        normalize_pct(&mut f.bytes);
    }

    // 5. Dot-segment removal (done before the empty-path fixup so
    // segments like `.` / `..` that collapse to empty still get the
    // `/` rewrite below).
    owned.path = remove_dot_segments_graceful(&owned.path);

    // 4. Empty path → `/` when authority is present (§6.2.3).
    if owned.authority.is_some() && owned.path.is_empty() {
        owned.path = BytesMut::from(&b"/"[..]);
    }

    owned
}

/// In-place pct-encoding normalization (RFC 3986 §6.2.2.1 + §6.2.2.2):
///
/// - `%XX` where the decoded byte is `unreserved` (ALPHA / DIGIT /
///   `-._~`) → replace the 3-byte sequence with the decoded byte.
/// - `%XX` where the decoded byte stays encoded → uppercase the two
///   hex digits.
///
/// Output is always `<=` input length, so the rewrite happens in
/// place; the buffer is truncated at the end. Fast-path for `%`-free
/// inputs is a single `contains` check.
fn normalize_pct(buf: &mut BytesMut) {
    if !buf.contains(&b'%') {
        return;
    }
    let bytes = buf.as_mut();
    let mut read = 0;
    let mut write = 0;
    while read < bytes.len() {
        if bytes[read] == b'%' && read + 2 < bytes.len() {
            let h1 = bytes[read + 1];
            let h2 = bytes[read + 2];
            if let Some(decoded) = rama_utils::hex::decode_pair(h1, h2) {
                if is_unreserved_byte(decoded) {
                    bytes[write] = decoded;
                    write += 1;
                    read += 3;
                    continue;
                }
                // Keep encoded — uppercase hex.
                bytes[write] = b'%';
                bytes[write + 1] = h1.to_ascii_uppercase();
                bytes[write + 2] = h2.to_ascii_uppercase();
                write += 3;
                read += 3;
                continue;
            }
            // Malformed pct-escape — the parser already rejected these,
            // but be defensive and copy verbatim.
        }
        if write != read {
            bytes[write] = bytes[read];
        }
        write += 1;
        read += 1;
    }
    buf.truncate(write);
}

/// Lowercase a [`Domain`]'s ASCII bytes in place (§6.2.2.1).
///
/// Domains have no pct-encoding (the parser routes pct-bearing bodies
/// into [`UninterpretedHost`] instead) and contain only DNS-label bytes,
/// so a plain `to_ascii_lowercase` of the underlying slice is the
/// complete canonicalization step.
fn normalize_host_domain(d: &mut Domain) {
    let s = d.as_str();
    if !s.bytes().any(|b| b.is_ascii_uppercase()) {
        return;
    }
    let lower = Bytes::from(s.to_ascii_lowercase());
    // Safety: lowercase-ASCII of a valid DNS label is itself a valid DNS
    // label — same length, same byte class, no new structural state.
    *d = unsafe { Domain::from_maybe_borrowed_unchecked(lower) };
}

/// Lowercase + pct-normalize an [`UninterpretedHost`] body (§6.2.2.1 +
/// §6.2.2.2).
///
/// Pre-lowercases every byte (folds reg-name ASCII alpha and pct-hex
/// pairs uniformly) and then runs [`normalize_pct`], which decodes any
/// `%XX` that resolves to an unreserved byte and re-uppercases the hex
/// of the rest — restoring §6.2.2.1's "pct-hex must be uppercase"
/// requirement after the lowercase pass.
///
/// The bracketed flag is preserved: IPvFuture literals stay bracketed,
/// reg-names stay un-bracketed.
fn normalize_host_uninterpreted(h: &mut UninterpretedHost) {
    let bytes = h.as_bytes();
    if !bytes.iter().any(|&b| b == b'%' || b.is_ascii_uppercase()) {
        return;
    }
    let mut buf = BytesMut::from(bytes);
    for b in buf.iter_mut() {
        *b = b.to_ascii_lowercase();
    }
    normalize_pct(&mut buf);
    *h = UninterpretedHost::from_validated_bytes(buf.freeze(), h.is_bracketed());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(input: &[u8]) -> Vec<u8> {
        let mut b = BytesMut::from(input);
        normalize_pct(&mut b);
        b.to_vec()
    }

    #[test]
    fn pct_decode_unreserved_alpha() {
        assert_eq!(norm(b"exa%6Dple"), b"example");
        // Lowercase pct-hex also decodes.
        assert_eq!(norm(b"exa%6dple"), b"example");
    }

    #[test]
    fn pct_decode_unreserved_digit_and_dash() {
        assert_eq!(norm(b"path%2D1%2E0"), b"path-1.0");
    }

    #[test]
    fn pct_keeps_reserved_uppercased() {
        // `/` (`%2F`) is reserved — must stay encoded. Hex
        // lowercased on input → uppercased on output.
        assert_eq!(norm(b"foo%2fbar"), b"foo%2Fbar");
        // Already-uppercase passes through verbatim.
        assert_eq!(norm(b"foo%2Fbar"), b"foo%2Fbar");
    }

    #[test]
    fn pct_keeps_subdelim_uppercased() {
        // `&` (`%26`) is sub-delim — stays encoded.
        assert_eq!(norm(b"a%26b"), b"a%26b");
    }

    #[test]
    fn pct_no_change_when_input_canonical() {
        assert_eq!(norm(b"plain"), b"plain");
        assert_eq!(norm(b""), b"");
        assert_eq!(norm(b"a/b?c"), b"a/b?c");
    }

    #[test]
    fn pct_mixed_decode_and_uppercase() {
        // `%6D` (m) → decode; `%2F` (/) → uppercase keep.
        assert_eq!(norm(b"exa%6dple%2fpath"), b"example%2Fpath");
    }

    #[test]
    fn pct_truncated_passthrough() {
        // `%X` truncated — parser would reject; defensive passthrough.
        assert_eq!(norm(b"x%6"), b"x%6");
    }

    // -- normalize_host_domain -------------------------------------------

    #[test]
    fn host_domain_lowercases_ascii() {
        let mut d = Domain::from_static("EXAMPLE.com");
        normalize_host_domain(&mut d);
        assert_eq!(d.as_str(), "example.com");
    }

    #[test]
    fn host_domain_noop_when_already_lower() {
        let mut d = Domain::from_static("example.com");
        normalize_host_domain(&mut d);
        assert_eq!(d.as_str(), "example.com");
    }

    // -- normalize_host_uninterpreted ------------------------------------

    fn make_uninterpreted(bytes: &'static [u8], bracketed: bool) -> UninterpretedHost {
        UninterpretedHost::from_validated_bytes(Bytes::from_static(bytes), bracketed)
    }

    #[test]
    fn host_uninterpreted_lowercases_ascii_alpha() {
        let mut h = make_uninterpreted(b"TAG,WITH,COMMAS", false);
        normalize_host_uninterpreted(&mut h);
        assert_eq!(h.as_bytes(), b"tag,with,commas");
    }

    #[test]
    fn host_uninterpreted_normalizes_pct_decode_unreserved() {
        // `exa%6Dple.com` — %6D decodes to `m` (unreserved). Host bytes
        // also case-fold; output is fully decoded lowercase.
        let mut h = make_uninterpreted(b"exa%6Dple.com", false);
        normalize_host_uninterpreted(&mut h);
        assert_eq!(h.as_bytes(), b"example.com");
    }

    #[test]
    fn host_uninterpreted_normalizes_pct_keeps_reserved_uppercased() {
        // `%21` is `!` — sub-delim, stays encoded; uppercase after norm.
        let mut h = make_uninterpreted(b"tag%21,more", false);
        normalize_host_uninterpreted(&mut h);
        assert_eq!(h.as_bytes(), b"tag%21,more");
    }

    #[test]
    fn host_uninterpreted_preserves_bracketed_flag() {
        // IPvFuture body stays in Uninterpreted (no typed form); brackets
        // are not part of the stored bytes but the flag survives.
        let mut h = make_uninterpreted(b"v1.FE80::A", true);
        normalize_host_uninterpreted(&mut h);
        assert_eq!(h.as_bytes(), b"v1.fe80::a");
        assert!(h.is_bracketed());
    }

    #[test]
    fn host_uninterpreted_noop_when_already_canonical() {
        let mut h = make_uninterpreted(b"tag,with,commas", false);
        normalize_host_uninterpreted(&mut h);
        assert_eq!(h.as_bytes(), b"tag,with,commas");
    }
}
