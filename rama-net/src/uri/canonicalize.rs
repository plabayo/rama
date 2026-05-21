//! RFC 3986 §6.2.2 syntax-based URI normalization.
//!
//! Drives [`crate::uri::Uri::canonicalize`]. Applies, in order:
//!
//! 1. **Host promotion** — [`Host::Uninterpreted`] that decodes to an IP
//!    or a typed [`Domain`] gets replaced with the typed variant.
//!    Sub-delim reg-names and IPvFuture stay `Uninterpreted` (no
//!    canonical typed form exists for them).
//! 2. **Default-port drop** — when the scheme has a registered default
//!    port and the URI's port matches it, the port is omitted.
//! 3. **Pct-encoding normalization** (§6.2.2.2) — `%XX` octets that map
//!    to an unreserved character are decoded in place; pct-encoded
//!    octets that stay encoded get their hex digits uppercased
//!    (§6.2.2.1 case normalization). Applied to path, query, fragment.
//! 4. **Empty path** (§6.2.3) — when an authority is present and the
//!    path is empty, the canonical form has the path as `/`.
//! 5. **Dot-segment removal** (§6.2.2.3) — `.` and `..` segments are
//!    collapsed. Routed through [`super::resolve`]'s graceful
//!    [`remove_dot_segments_graceful`] so this code path can't error.
//!
//! Wire-fidelity preservation at parse time is intentional (see
//! [`crate::address::UninterpretedHost`]); `canonicalize` is opt-in,
//! for callers (typically clients building URIs from user input) who
//! want a normalised form.

use std::net::IpAddr;

use rama_core::bytes::BytesMut;

use crate::address::{Domain, Host, UninterpretedHostRef};

use super::lazy::LazyUriRef;
use super::owned::OwnedUriRef;
use super::parser::is_unreserved_byte;
use super::resolve::remove_dot_segments_graceful;
use super::{Uri, UriInner};

/// Top-level entry — apply RFC 3986 §6.2.2 normalization to `uri`.
///
/// Fast-path: when [`is_already_canonical`] returns `true`, the URI is
/// already in canonical form and we return it unchanged — no
/// allocation, no Lazy→Owned copy. Cheap O(n) pre-scan over the
/// component bytes; the saving when the fast-path hits is the
/// component-bytes copy in `as_owned_components` plus the Authority
/// clone and BytesMut allocations for path/query/fragment.
pub(super) fn canonicalize_uri(uri: Uri) -> Uri {
    // Asterisk-form has no components — never needs work.
    if matches!(uri.inner, UriInner::Asterisk) {
        return uri;
    }
    if is_already_canonical(&uri) {
        return uri;
    }
    let owned = uri.as_owned_components();
    let canonical = canonicalize_owned(owned);
    Uri {
        inner: UriInner::Owned(std::sync::Arc::new(canonical)),
    }
}

/// `true` when `uri` is already in canonical form — no host promotion,
/// no pct-decode work, no default-port to drop, no empty-path fix, no
/// dot-segments to collapse.
///
/// Conservative — false positives (returning `true` when canonicalize
/// *would* be a no-op anyway) are fine; false negatives (returning
/// `false` when canonicalize would in fact change something) would
/// silently skip the normalize and are not OK. So when in doubt, we
/// return `false` and run the full algorithm.
fn is_already_canonical(uri: &Uri) -> bool {
    match &uri.inner {
        UriInner::Asterisk => true,
        UriInner::Lazy(arc) => lazy_is_canonical(arc.as_ref()),
        UriInner::Owned(arc) => owned_is_canonical(arc.as_ref()),
    }
}

fn lazy_is_canonical(l: &LazyUriRef) -> bool {
    if let Some(auth) = &l.authority {
        // Host promotion would change `Uninterpreted` to `Domain` /
        // `IpAddr` when convertible.
        if matches!(auth.host, Host::Uninterpreted(_)) {
            return false;
        }
        // Default-port drop?
        if let Some(scheme) = &l.scheme
            && let Some(default) = scheme.default_port()
            && auth.port == Some(default)
        {
            return false;
        }
        // Empty path with authority → would become `/`.
        if l.path.0 == l.path.1 {
            return false;
        }
    }
    let path = &l.bytes[l.path.0 as usize..l.path.1 as usize];
    if !path_is_canonical(path) {
        return false;
    }
    if let Some((s, e)) = l.query
        && bytes_need_pct_normalization(&l.bytes[s as usize..e as usize])
    {
        return false;
    }
    if let Some((s, e)) = l.fragment
        && bytes_need_pct_normalization(&l.bytes[s as usize..e as usize])
    {
        return false;
    }
    true
}

fn owned_is_canonical(o: &OwnedUriRef) -> bool {
    if let Some(auth) = &o.authority {
        if matches!(auth.address.host, Host::Uninterpreted(_)) {
            return false;
        }
        if let Some(scheme) = &o.scheme
            && let Some(default) = scheme.default_port()
            && auth.address.port == Some(default)
        {
            return false;
        }
        if o.path.is_empty() {
            return false;
        }
    }
    if !path_is_canonical(&o.path) {
        return false;
    }
    if let Some(q) = &o.query
        && bytes_need_pct_normalization(&q.bytes)
    {
        return false;
    }
    if let Some(f) = &o.fragment
        && bytes_need_pct_normalization(&f.bytes)
    {
        return false;
    }
    true
}

/// `true` when the path bytes are already canonical — no pct sequence
/// that needs decoding/uppercasing, no `.` / `..` segments.
fn path_is_canonical(path: &[u8]) -> bool {
    !bytes_need_pct_normalization(path) && !has_dot_segments(path)
}

/// `true` when `bytes` contains a `%XX` sequence that either decodes to
/// an unreserved character (would be inlined) or has lowercase hex
/// digits (would be uppercased).
///
/// Cheap fast-path: if no `%` appears, return `false` without further
/// work. Otherwise walk and check each `%XX`.
fn bytes_need_pct_normalization(bytes: &[u8]) -> bool {
    if !bytes.contains(&b'%') {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            // Lowercase hex → would be uppercased.
            if h1.is_ascii_lowercase() || h2.is_ascii_lowercase() {
                return true;
            }
            // Decoded byte is unreserved → would be decoded inline.
            if let Some(decoded) = rama_utils::hex::decode_pair(h1, h2)
                && is_unreserved_byte(decoded)
            {
                return true;
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    false
}

/// `true` when `path` contains `.` / `..` segments that
/// [`remove_dot_segments_graceful`] would collapse.
fn has_dot_segments(path: &[u8]) -> bool {
    // Whole-input shapes.
    if path == b"." || path == b".." || path == b"/." || path == b"/.." {
        return true;
    }
    // Leading "./" or "../".
    if path.starts_with(b"./") || path.starts_with(b"../") {
        return true;
    }
    // Trailing "/." or "/..".
    if path.ends_with(b"/.") || path.ends_with(b"/..") {
        return true;
    }
    // Mid-path "/./" or "/../". `memchr` of `/` then peek would be
    // faster on long paths, but the inline scan is fine for the
    // typical short-path case.
    let mut i = 0;
    while i + 2 < path.len() {
        if path[i] == b'/'
            && path[i + 1] == b'.'
            && (path[i + 2] == b'/' || (path[i + 2] == b'.' && path.get(i + 3) == Some(&b'/')))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Apply RFC 3986 §6.2.2 syntax-based normalization to `owned` in
/// place. See the module docs for the full ordering.
fn canonicalize_owned(mut owned: OwnedUriRef) -> OwnedUriRef {
    // 1. Host promotion.
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
            // form, leave as `Uninterpreted`.
        }

        // 2. Default-port drop.
        if let Some(scheme) = &owned.scheme
            && let Some(default) = scheme.default_port()
            && authority.address.port == Some(default)
        {
            authority.address.port = None;
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
}
