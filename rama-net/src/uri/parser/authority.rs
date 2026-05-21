//! Authority parsing — RFC 3986 §3.2: `[ userinfo "@" ] host [ ":" port ]`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rama_core::bytes::Bytes;

use crate::address::parse_utils;
use crate::address::{Authority, Domain, Host, HostWithOptPort, UserInfo};
use crate::uri::lazy::LazyAuthority;
use crate::uri::{Component, ParseError};

use super::ParserMode;
use super::byte_sets::{is_control_byte, is_userinfo_byte};
use super::check_pct_encoded;

/// Result of `parse_optional_authority`.
pub(super) struct AuthorityScan {
    pub(super) authority: Option<ParsedAuthority>,
    /// Offset where the path starts — the first byte after the authority,
    /// or `start` itself when no authority was present.
    pub(super) path_start: usize,
}

/// Parsed authority in one of two shapes.
///
/// The variant tells the top-level parser which `Uri` form to build:
/// `Lazy` keeps zero-copy projection into the original bytes; `Owned`
/// signals that the host was IDN-normalised (UTS #46 applied), so the
/// typed host view has already diverged from the raw input — there's no
/// point keeping the Lazy buffer around.
pub(super) enum ParsedAuthority {
    /// Host bytes still match the source buffer — projectable into a
    /// [`LazyUriRef`](crate::uri::lazy::LazyUriRef).
    Lazy(LazyAuthority),
    /// Host was rewritten by UTS #46. Already materialised into an
    /// [`Authority`] so the upper layer can drop straight into an
    /// [`OwnedUriRef`](crate::uri::owned::OwnedUriRef) without a Lazy
    /// detour.
    Owned(Authority),
}

/// If `bytes[start..]` begins with `//`, parse an authority. Otherwise
/// signal opaque-path form (no authority).
pub(super) fn parse_optional_authority(
    bytes: &Bytes,
    start: usize,
    mode: ParserMode,
) -> Result<AuthorityScan, ParseError> {
    if bytes.len() >= start + 2 && bytes[start] == b'/' && bytes[start + 1] == b'/' {
        let auth_start = start + 2;
        // Authority ends at the first `/`, `?`, `#`, or end of input.
        let auth_end = bytes[auth_start..]
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .map_or(bytes.len(), |p| p + auth_start);
        let auth = parse_authority(bytes, auth_start, auth_end, mode)?;
        Ok(AuthorityScan {
            authority: Some(auth),
            path_start: auth_end,
        })
    } else {
        Ok(AuthorityScan {
            authority: None,
            path_start: start,
        })
    }
}

/// Parse the bytes `[start, end)` of the parent buffer as an RFC 3986 §3.2
/// authority. Returns a [`ParsedAuthority`] whose variant signals whether
/// the host required UTS #46 rewriting.
///
/// Exposed to the parser module so [`super::parse_authority_form`] can
/// drive it directly for HTTP CONNECT's authority-form request-target,
/// which is an authority *without* the leading `//`.
pub(super) fn parse_authority(
    bytes: &Bytes,
    start: usize,
    end: usize,
    mode: ParserMode,
) -> Result<ParsedAuthority, ParseError> {
    // Reject control chars inside the authority.
    let mut k = start;
    while k < end {
        let b = bytes[k];
        if is_control_byte(b) {
            return Err(ParseError::ControlCharInUri { at: k, byte: b });
        }
        k += 1;
    }

    // Userinfo terminates at the *last* `@`. See
    // [`crate::address::parse_utils::find_userinfo_split`] for the
    // rationale (curl / browsers / `url` crate parity).
    let userinfo_range = parse_utils::find_userinfo_split(&bytes[start..end])
        .map(|rel| (start as u16, (start + rel) as u16));
    let host_start = userinfo_range.map_or(start, |(_, e)| (e as usize) + 1);

    // Strict-mode userinfo grammar check (RFC 3986 §3.2.1). The
    // last-`@` split is graceful — strict mode additionally validates
    // every userinfo byte against `USERINFO_BYTE_SET`, which excludes
    // raw `@` (it must be `%40`) and disallowed sub-delims.
    if let (ParserMode::Strict, Some((s, e))) = (mode, userinfo_range) {
        validate_userinfo_strict(&bytes[s as usize..e as usize])?;
    }

    // Parse host + optional port from bytes[host_start..end].
    let host_view = &bytes[host_start..end];
    let (host, port, idn_encoded) = parse_host_and_port(bytes, host_start, host_view, end, mode)?;

    if idn_encoded {
        // Host bytes were rewritten by UTS #46 — Lazy projection would lie.
        // Build the typed [`Authority`] directly so the upper layer can drop
        // it into an [`OwnedUriRef`] without going through a Lazy detour.
        let user_info = userinfo_range
            .map(|(s, e)| UserInfo::from_bytes_unchecked(bytes.slice(s as usize..e as usize)));
        Ok(ParsedAuthority::Owned(Authority {
            user_info,
            address: HostWithOptPort { host, port },
        }))
    } else {
        Ok(ParsedAuthority::Lazy(LazyAuthority {
            userinfo_range,
            host,
            port,
        }))
    }
}

/// RFC 3986 §3.2.1 userinfo grammar check. Each byte must be in the
/// userinfo byte set; `%XX` escapes must be well-formed hex pairs.
fn validate_userinfo_strict(bytes: &[u8]) -> Result<(), ParseError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            check_pct_encoded(bytes, i)?;
            i += 3;
            continue;
        }
        if !is_userinfo_byte(b) {
            return Err(ParseError::StrictViolation);
        }
        i += 1;
    }
    Ok(())
}

/// Parse the host and optional port. `parent` is the full URI buffer (used
/// for zero-copy slicing of Domain bytes); `host_start` is the absolute
/// offset; `view` is `&parent[host_start..end]`; `end` is the absolute
/// end-of-authority offset.
///
/// Returns `(host, port, idn_encoded)`. `idn_encoded` is `true` when the
/// host was rewritten by UTS #46 (non-ASCII input → ACE form); the caller
/// ([`parse_authority`]) uses it to pick the [`ParsedAuthority`] variant.
///
/// IDN normalisation runs only in graceful mode. Strict mode treats
/// non-ASCII host bytes as a [`ParseError::StrictViolation`] per
/// RFC 3986 §3.2.2 (the host grammar is ASCII-only — callers wanting
/// IDN under strict must pre-encode to ACE).
fn parse_host_and_port(
    parent: &Bytes,
    host_start: usize,
    view: &[u8],
    end: usize,
    mode: ParserMode,
) -> Result<(Host, Option<u16>, bool), ParseError> {
    if view.is_empty() {
        return Err(ParseError::InvalidComponent(Component::Host));
    }

    if view[0] == b'[' {
        // Bracketed IPv6 literal.
        let close_rel = view
            .iter()
            .position(|&b| b == b']')
            .ok_or(ParseError::InvalidComponent(Component::Host))?;
        let inside = &view[1..close_rel];
        if parse_utils::ipv6_bracket_has_zone(inside) {
            return Err(ParseError::IPv6ZoneNotSupported);
        }
        let Ok(s) = std::str::from_utf8(inside) else {
            return Err(ParseError::InvalidComponent(Component::Host));
        };
        let Ok(addr) = s.parse::<Ipv6Addr>() else {
            return Err(ParseError::InvalidComponent(Component::Host));
        };
        let host = Host::Address(IpAddr::V6(addr));

        // After `]`, optional `:port`.
        let after = &view[close_rel + 1..];
        let port = match after {
            [] => None,
            [b':', rest @ ..] => Some(parse_port(rest)?),
            _ => return Err(ParseError::InvalidComponent(Component::Authority)),
        };
        return Ok((host, port, false));
    }

    // Non-bracketed host: optionally followed by `:port`. The port separator
    // is the rightmost `:` (there is at most one in non-bracketed form).
    let (host_bytes_rel, port) = match view.iter().rposition(|&b| b == b':') {
        Some(colon) => {
            let port = parse_port(&view[colon + 1..])?;
            (&view[..colon], Some(port))
        }
        None => (view, None),
    };
    if host_bytes_rel.is_empty() {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    let host_bytes_len = host_bytes_rel.len();

    let Ok(host_str) = std::str::from_utf8(host_bytes_rel) else {
        return Err(ParseError::InvalidComponent(Component::Host));
    };

    let (host, idn_encoded) = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
        (Host::Address(IpAddr::V4(v4)), false)
    } else if host_bytes_rel.is_ascii() {
        // ASCII fast-path: validate cheaply, then construct the Domain
        // zero-copy by slicing the parent Bytes — no allocation.
        if Domain::try_from(host_str).is_err() {
            return Err(ParseError::InvalidComponent(Component::Host));
        }
        let domain_bytes = parent.slice(host_start..host_start + host_bytes_len);
        // Safety: validated above.
        let domain = unsafe { Domain::from_maybe_borrowed_unchecked(domain_bytes) };
        (Host::Name(domain), false)
    } else if mode == ParserMode::Strict {
        // Strict mode is the RFC 3986 grammar; the host slot is ASCII-only
        // (`unreserved / pct-encoded / sub-delims`). UTS #46 normalisation
        // is a graceful-mode convenience, not part of the spec. Callers
        // wanting strict + IDN must pre-encode to ACE.
        return Err(ParseError::StrictViolation);
    } else {
        // Graceful + non-ASCII: route through `Domain::try_from`, which
        // handles IDN (UTS #46) under the `idna` feature. Map the
        // not-enabled error to the URI-level variant so callers can
        // distinguish.
        match Domain::try_from(host_str) {
            Ok(domain) => (Host::Name(domain), true),
            #[cfg(not(feature = "idna"))]
            Err(e) if e.is_idna_not_enabled() => return Err(ParseError::IdnaNotEnabled),
            Err(_) => return Err(ParseError::InvalidComponent(Component::Host)),
        }
    };

    // `end` is unused on the non-bracketed path — bind to a no-op to silence
    // unused-variable warnings without complicating the signature.
    let _ = end;
    Ok((host, port, idn_encoded))
}

fn parse_port(bytes: &[u8]) -> Result<u16, ParseError> {
    // Empty port (`host:`) — reject. RFC 3986 §3.2.3 permits the
    // production but recommends producers omit; receivers diverge in
    // the wild, so we pick the stricter side. Note: `parse_port_bytes`
    // also returns `None` for empty input, so this explicit branch is
    // for documentation only — the behaviour is identical without it.
    if bytes.is_empty() {
        return Err(ParseError::InvalidComponent(Component::Port));
    }
    parse_utils::parse_port_bytes(bytes).ok_or(ParseError::InvalidComponent(Component::Port))
}
