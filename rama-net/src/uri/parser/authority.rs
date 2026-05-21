//! Authority parsing — RFC 3986 §3.2: `[ userinfo "@" ] host [ ":" port ]`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rama_core::bytes::Bytes;

use crate::address::parse_utils;
use crate::address::{Domain, Host, UninterpretedHost};
use crate::uri::lazy::LazyAuthority;
use crate::uri::{Component, ParseError};

use super::ParserMode;
use super::byte_sets::{
    is_control_byte, is_ipvfuture_tail_byte, is_reg_name_byte, is_userinfo_byte,
};
use super::check_pct_encoded;

/// Result of `parse_optional_authority`.
pub(super) struct AuthorityScan {
    pub(super) authority: Option<LazyAuthority>,
    /// Offset where the path starts — the first byte after the authority,
    /// or `start` itself when no authority was present.
    pub(super) path_start: usize,
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
/// authority. Returns a [`LazyAuthority`] holding a [`Host`] whose variant
/// depends on the input shape:
///
/// - `IPv4address` → [`Host::Address`].
/// - DNS-label-shaped ASCII reg-name → [`Host::Name`] (zero-copy slice of
///   the parent buffer).
/// - Bracketed IPv6 → [`Host::Address`].
/// - **Anything else legal under RFC 3986 / 3987 §3.2.2** —
///   pct-encoded reg-name, sub-delim reg-name, raw UTF-8 reg-name
///   (graceful only), bracketed IPvFuture — → [`Host::Uninterpreted`]
///   with the wire bytes preserved. Callers convert on demand via
///   `Domain::try_from` / `IpAddr::try_from` / etc.
///
/// **No parser-time canonicalization.** Wire fidelity is the design
/// contract: bytes that arrive intact survive intact. The earlier M7
/// IDN-at-parse behaviour was reversed here — graceful mode no longer
/// auto-normalises non-ASCII hosts to ACE; the caller asks
/// `Domain::try_from(uri.host().as_uninterpreted()?)` when they want it.
///
/// Exposed to the parser module so [`super::parse_authority_form`] can
/// drive it directly for HTTP CONNECT's authority-form request-target,
/// which is an authority *without* the leading `//`.
pub(super) fn parse_authority(
    bytes: &Bytes,
    start: usize,
    end: usize,
    mode: ParserMode,
) -> Result<LazyAuthority, ParseError> {
    // Walk authority bytes. Two invariants per byte:
    //   1. No control bytes (smuggling / header-injection vector).
    //   2. In graceful mode, non-ASCII bytes must form well-formed
    //      UTF-8 sequences — the `from_utf8_unchecked` derives in
    //      every userinfo / host accessor would otherwise be UB.
    //      Strict mode rejects non-ASCII outright in the host
    //      validators below, so the UTF-8 path is graceful-only.
    let mut k = start;
    while k < end {
        let b = bytes[k];
        if is_control_byte(b) {
            return Err(ParseError::ControlCharInUri { at: k, byte: b });
        }
        if mode == ParserMode::Graceful && b >= 0x80 {
            let seq_len = super::check_utf8_sequence(bytes, k)?;
            k += seq_len;
            continue;
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
    let (host, port) = parse_host_and_port(bytes, host_start, host_view, mode)?;

    Ok(LazyAuthority {
        userinfo_range,
        host,
        port,
    })
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

/// Parse the host and optional port. `parent` is the full URI buffer
/// (used for zero-copy slicing of `Domain` / `UninterpretedHost` bytes);
/// `host_start` is the absolute offset; `view` is
/// `&parent[host_start..end]`.
///
/// Returns `(host, port)`. The host's variant is chosen by the input
/// shape — see [`parse_authority`] for the full table. No parser-time
/// canonicalization happens; bytes are always preserved or zero-copy
/// sliced from `parent`.
fn parse_host_and_port(
    parent: &Bytes,
    host_start: usize,
    view: &[u8],
    mode: ParserMode,
) -> Result<(Host, Option<u16>), ParseError> {
    if view.is_empty() {
        return Err(ParseError::InvalidComponent(Component::Host));
    }

    // --- IP-literal (bracketed) -------------------------------------------
    if view[0] == b'[' {
        let close_rel = view
            .iter()
            .position(|&b| b == b']')
            .ok_or(ParseError::InvalidComponent(Component::Host))?;
        let inside = &view[1..close_rel];
        let inside_start = host_start + 1;

        let host = if matches!(inside.first(), Some(b'v' | b'V')) {
            // RFC 3986 §3.2.2 `IPvFuture = "v" 1*HEXDIG "." 1*(...)`.
            // Preserved verbatim — no `vN` form is registered with
            // IANA, so there's nothing to decode. Bytes are stored
            // without the surrounding brackets.
            validate_ipvfuture(inside)?;
            let body = parent.slice(inside_start..inside_start + inside.len());
            Host::Uninterpreted(UninterpretedHost::from_validated_bytes(body, true))
        } else {
            // Standard IPv6.
            if parse_utils::ipv6_bracket_has_zone(inside) {
                return Err(ParseError::IPv6ZoneNotSupported);
            }
            let Ok(s) = std::str::from_utf8(inside) else {
                return Err(ParseError::InvalidComponent(Component::Host));
            };
            let Ok(addr) = s.parse::<Ipv6Addr>() else {
                return Err(ParseError::InvalidComponent(Component::Host));
            };
            Host::Address(IpAddr::V6(addr))
        };

        // After `]`, optional `:port`.
        let after = &view[close_rel + 1..];
        let port = match after {
            [] => None,
            [b':', rest @ ..] => Some(parse_port(rest)?),
            _ => return Err(ParseError::InvalidComponent(Component::Authority)),
        };
        return Ok((host, port));
    }

    // --- Non-bracketed host -----------------------------------------------
    //
    // Split off the rightmost `:` as the port separator (reg-name has no
    // `:` in its grammar, so the rightmost colon is always the port).
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

    // Validate against (i)reg-name grammar. Rejects mode-incompatible
    // bytes early — strict-mode non-ASCII, illegal punctuation, malformed
    // pct-escapes, smuggling-vector pct-decoded control bytes.
    validate_reg_name(host_bytes_rel, mode)?;

    let Ok(host_str) = std::str::from_utf8(host_bytes_rel) else {
        return Err(ParseError::InvalidComponent(Component::Host));
    };

    // Try the typed-host shapes first, in priority order:
    //   1. IPv4 dotted-quad.
    //   2. DNS-label-shaped ASCII reg-name → `Host::Name` (zero-copy).
    //   3. Anything else legal under reg-name (already validated above)
    //      → `Host::Uninterpreted` (zero-copy, preserved verbatim).
    let host = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
        Host::Address(IpAddr::V4(v4))
    } else if host_bytes_rel.is_ascii() && Domain::try_from(host_str).is_ok() {
        // ASCII DNS-label-shaped fast path: zero-copy slice into Domain.
        let domain_bytes = parent.slice(host_start..host_start + host_bytes_len);
        // Safety: `Domain::try_from(host_str)` returned `Ok` above —
        // the bytes are validated DNS-label-shape.
        let domain = unsafe { Domain::from_maybe_borrowed_unchecked(domain_bytes) };
        Host::Name(domain)
    } else {
        // Reg-name with pct-encoding, sub-delims, or raw UTF-8.
        // Stored verbatim; conversion to Domain / IpAddr is opt-in
        // via `TryFrom<&UninterpretedHost>`.
        let body = parent.slice(host_start..host_start + host_bytes_len);
        Host::Uninterpreted(UninterpretedHost::from_validated_bytes(body, false))
    };

    Ok((host, port))
}

/// RFC 3986 §3.2.2 `reg-name` validation, with optional IRI extension.
///
/// - Strict mode: bytes must be `unreserved / pct-encoded / sub-delims`,
///   all ASCII.
/// - Graceful mode: same, plus non-ASCII UTF-8 (`ireg-name` per
///   RFC 3987 §2.2). Non-ASCII bytes were already UTF-8-validated by
///   the upstream authority walker, so here we just skip multi-byte
///   sequences.
///
/// Pct-escapes must be well-formed, and the decoded byte must not be a
/// control byte — pct-encoded smuggling vectors (`%00`, `%0D`, etc.)
/// are rejected at parse time.
fn validate_reg_name(bytes: &[u8], mode: ParserMode) -> Result<(), ParseError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            check_pct_encoded(bytes, i)?;
            // Defence-in-depth: a pct-escape that decodes to a control
            // byte is a smuggling vector even though the wire bytes
            // themselves are printable. Reject at parse.
            if let Some(decoded) = rama_utils::hex::decode_pair(bytes[i + 1], bytes[i + 2])
                && is_control_byte(decoded)
            {
                return Err(ParseError::ControlCharInUri {
                    at: i,
                    byte: decoded,
                });
            }
            i += 3;
            continue;
        }
        if is_reg_name_byte(b) {
            i += 1;
            continue;
        }
        if b >= 0x80 {
            // Graceful mode tolerates `ireg-name` UTF-8 (RFC 3987);
            // strict mode does not. The authority-level walker has
            // already verified UTF-8 well-formedness in graceful mode,
            // so `check_utf8_sequence` will succeed — we just need the
            // sequence length to advance the cursor.
            if mode == ParserMode::Strict {
                return Err(ParseError::StrictViolation);
            }
            i += super::check_utf8_sequence(bytes, i)?;
            continue;
        }
        // ASCII byte outside the reg-name grammar — `[`, `]`, `<`, `>`,
        // backslash, space, etc.
        return Err(if mode == ParserMode::Strict {
            ParseError::StrictViolation
        } else {
            ParseError::InvalidComponent(Component::Host)
        });
    }
    Ok(())
}

/// RFC 3986 §3.2.2 `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`.
/// `inside` is the bytes between the surrounding `[` and `]`.
fn validate_ipvfuture(inside: &[u8]) -> Result<(), ParseError> {
    // First byte: `v` / `V`.
    let Some((&v, rest)) = inside.split_first() else {
        return Err(ParseError::InvalidComponent(Component::Host));
    };
    if v != b'v' && v != b'V' {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    // One or more hex digits, terminated by `.`.
    let dot_at = rest
        .iter()
        .position(|&b| b == b'.')
        .ok_or(ParseError::InvalidComponent(Component::Host))?;
    if dot_at == 0 {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    let hex = &rest[..dot_at];
    let tail = &rest[dot_at + 1..];
    if !hex.iter().all(|&b| b.is_ascii_hexdigit()) {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    // Tail: one or more bytes from the IPvFuture-tail byte set
    // (unreserved / sub-delims / `:`). No pct-encoding inside IPvFuture
    // per RFC 3986 §3.2.2.
    if tail.is_empty() || !tail.iter().all(|&b| is_ipvfuture_tail_byte(b)) {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    Ok(())
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
