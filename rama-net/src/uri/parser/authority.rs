//! Authority parsing — RFC 3986 §3.2: `[ userinfo "@" ] host [ ":" port ]`.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ParserMode;
use super::check_pct_encoded;
use crate::address::parse_utils;
use crate::address::{Domain, Host, OptPort, UninterpretedHost};
use crate::byte_sets::{
    is_control_byte, is_ipvfuture_tail_byte, is_reg_name_byte, is_userinfo_byte,
};
use crate::uri::lazy::LazyAuthority;
use crate::uri::{Component, ParseError};

use rama_core::bytes::Bytes;

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
    if let Some((auth_start, auth_end)) = find_optional_authority(bytes, start) {
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

/// Return the authority byte range when `bytes[start..]` begins with `//`.
/// Both materializing URI parsing and borrowed request-target validation use
/// this boundary scan.
pub(super) fn find_optional_authority(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if !bytes.get(start..)?.starts_with(b"//") {
        return None;
    }
    let authority_start = start + 2;
    let authority_end = bytes[authority_start..]
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#'))
        .map_or(bytes.len(), |offset| authority_start + offset);
    Some((authority_start, authority_end))
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
    let scanned = scan_authority(bytes, start, end, mode)?;
    let host = match scanned.host {
        ScannedHost::Empty { at } => Host::Uninterpreted(UninterpretedHost::from_validated_bytes(
            bytes.slice(at..at),
            false,
        )),
        ScannedHost::Ipv6(address) => Host::Address(IpAddr::V6(address)),
        ScannedHost::IpvFuture { start, end } => Host::Uninterpreted(
            UninterpretedHost::from_validated_bytes(bytes.slice(start..end), true),
        ),
        ScannedHost::RegName { start, end } => {
            let host_bytes = &bytes[start..end];
            // Safety: `scan_host_and_port` validated this exact range as UTF-8.
            let host_str = unsafe { core::str::from_utf8_unchecked(host_bytes) };
            if let Ok(address) = host_str.parse::<Ipv4Addr>() {
                Host::Address(IpAddr::V4(address))
            } else if host_bytes.is_ascii() && Domain::try_from(host_str).is_ok() {
                let domain_bytes = bytes.slice(start..end);
                // Safety: `Domain::try_from(host_str)` returned `Ok` above.
                let domain = unsafe { Domain::from_maybe_borrowed_unchecked(domain_bytes) };
                Host::Name(domain)
            } else {
                Host::Uninterpreted(UninterpretedHost::from_validated_bytes(
                    bytes.slice(start..end),
                    false,
                ))
            }
        }
    };

    Ok(LazyAuthority {
        userinfo_range: scanned.userinfo_range,
        host,
        port: scanned.port,
    })
}

struct ScannedAuthority {
    userinfo_range: Option<(u16, u16)>,
    host: ScannedHost,
    port: OptPort,
}

enum ScannedHost {
    Empty { at: usize },
    Ipv6(Ipv6Addr),
    IpvFuture { start: usize, end: usize },
    RegName { start: usize, end: usize },
}

/// Scan and validate an authority without retaining or allocating bytes.
/// Parsing and borrowed request-target validation both use this grammar pass;
/// only the parser materializes the resulting typed host.
fn scan_authority(
    bytes: &[u8],
    start: usize,
    end: usize,
    mode: ParserMode,
) -> Result<ScannedAuthority, ParseError> {
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

    let (host, port) = scan_host_and_port(bytes, host_start, end, mode)?;
    Ok(ScannedAuthority {
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

fn scan_host_and_port(
    bytes: &[u8],
    host_start: usize,
    end: usize,
    mode: ParserMode,
) -> Result<(ScannedHost, OptPort), ParseError> {
    let view = &bytes[host_start..end];
    // RFC 3986 §3.2.2 `reg-name = *(...)` allows empty — `file:///path`,
    // `unix:///run/x`, etc. Stored as `Host::Uninterpreted(b"")`; callers
    // that need a non-empty host check `host.as_str().is_empty()`.
    if view.is_empty() {
        return Ok((ScannedHost::Empty { at: host_start }, OptPort::Unset));
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
            ScannedHost::IpvFuture {
                start: inside_start,
                end: inside_start + inside.len(),
            }
        } else {
            // Standard IPv6.
            if parse_utils::ipv6_bracket_has_zone(inside) {
                return Err(ParseError::IPv6ZoneNotSupported);
            }
            let Ok(s) = core::str::from_utf8(inside) else {
                return Err(ParseError::InvalidComponent(Component::Host));
            };
            let Ok(addr) = s.parse::<Ipv6Addr>() else {
                return Err(ParseError::InvalidComponent(Component::Host));
            };
            ScannedHost::Ipv6(addr)
        };

        // After `]`, optional `:port`.
        let after = &view[close_rel + 1..];
        let port = match after {
            [] => OptPort::Unset,
            [b':', rest @ ..] => parse_port(rest)?,
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
            (&view[..colon], port)
        }
        None => (view, OptPort::Unset),
    };
    if host_bytes_rel.is_empty() {
        return Err(ParseError::InvalidComponent(Component::Host));
    }
    // Validate against (i)reg-name grammar. Rejects mode-incompatible
    // bytes early — strict-mode non-ASCII, illegal punctuation, malformed
    // pct-escapes, smuggling-vector pct-decoded control bytes.
    validate_reg_name(host_bytes_rel, mode)?;

    if core::str::from_utf8(host_bytes_rel).is_err() {
        return Err(ParseError::InvalidComponent(Component::Host));
    }

    Ok((
        ScannedHost::RegName {
            start: host_start,
            end: host_start + host_bytes_rel.len(),
        },
        port,
    ))
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
/// Graceful-mode reg-name validation. Re-exported via [`crate::uri::parser`]
/// so address types can validate without depending on the internal
/// [`ParserMode`] enum.
pub(crate) fn validate_reg_name_graceful(bytes: &[u8]) -> Result<(), ParseError> {
    validate_reg_name(bytes, ParserMode::Graceful)
}

/// Strict-mode reg-name validation. See [`validate_reg_name_graceful`].
pub(crate) fn validate_reg_name_strict(bytes: &[u8]) -> Result<(), ParseError> {
    validate_reg_name(bytes, ParserMode::Strict)
}

/// Validate an authority without constructing its typed, owned representation.
///
/// This is the borrowed counterpart of [`parse_authority`], intended for
/// callers that only need to classify wire bytes. It deliberately follows the
/// graceful parser rules so a successful validation has the same acceptance
/// envelope as [`crate::uri::Uri::parse_authority_form`].
#[cfg(feature = "http")]
pub(super) fn validate_authority(
    bytes: &[u8],
    start: usize,
    end: usize,
    mode: ParserMode,
) -> Result<(), ParseError> {
    scan_authority(bytes, start, end, mode).map(drop)
}

fn validate_reg_name(bytes: &[u8], mode: ParserMode) -> Result<(), ParseError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            check_pct_encoded(bytes, i)?;
            // Defence-in-depth: a pct-escape that decodes to a control
            // byte is a smuggling vector even though the wire bytes
            // themselves are printable.
            if let Some(decoded) =
                crate::byte_sets::pct_decoded_control_byte(bytes[i + 1], bytes[i + 2])
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
pub(crate) fn validate_ipvfuture(inside: &[u8]) -> Result<(), ParseError> {
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

fn parse_port(bytes: &[u8]) -> Result<crate::address::OptPort, ParseError> {
    // RFC 3986 §3.2.3 `port = *DIGIT` — empty (`host:`) is grammatically
    // valid. Surfaced as `OptPort::Empty` so the trailing colon survives
    // round-trips through owned address types.
    if bytes.is_empty() {
        return Ok(crate::address::OptPort::Empty);
    }
    parse_utils::parse_port_bytes(bytes)
        .map(crate::address::OptPort::Set)
        .ok_or(ParseError::InvalidComponent(Component::Port))
}
