//! Internal parser engine for [`crate::uri::Uri`].
//!
//! `Uri` is for *any* RFC 3986 URI — http(s), ws(s), ftp, mailto:, urn:,
//! file:, custom schemes — not just HTTP. HTTP-specific shapes (e.g. the
//! asterisk request-target from RFC 9112 §3.2.4) are called out in docs
//! and tests, but the parser itself is protocol-neutral.
//!
//! Two modes, one engine:
//!
//! - **Graceful** (`Uri::parse`) — accepts what real wire traffic looks like
//!   inside the differential-parse-safe envelope. Rejects: ASCII control
//!   chars (smuggling/header-injection vectors). Accepts: every non-control
//!   byte in path/query/fragment, even bytes RFC 3986 puts outside `pchar`
//!   (`{`, `}`, `^`, `|`, raw UTF-8, etc.). Browsers and curl do the same.
//!
//! - **Strict** (`Uri::parse_strict`) — RFC 3986 grammar. Anything outside
//!   the per-component byte set is [`ParseError::StrictViolation`].
//!
//! Things never accepted in either mode:
//!
//! - Any ASCII control byte (`< 0x20` or `0x7F`) anywhere in the input
//! - Inputs longer than [`MAX_URI_LEN`] (forced by 16-bit offsets in
//!   [`LazyUriRef`])
//!
//! Per-form scanners detect control chars inline during their walk — no
//! separate pre-pass.
//!
//! ## Forms currently parsed
//!
//! - Asterisk-form `*` — HTTP-only per RFC 9112 §3.2.4
//! - Origin-form `/path?query#fragment`
//! - Absolute-form `scheme:hier-part [ "?" query ] [ "#" fragment ]`, both
//!   shapes: `scheme://authority/path` and opaque `scheme:opaque-path`
//!
//! Not yet supported: HTTP authority-form (`host:port` for CONNECT) and
//! relative refs with path-noscheme.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rama_core::bytes::Bytes;

use crate::Protocol;
use crate::address::{Domain, Host};

use super::lazy::{LazyAuthority, LazyUriRef};
use super::{Component, ParseError, Uri};

/// Maximum input length the parser accepts.
///
/// Capped because [`LazyUriRef`] stores component offsets as `u16`. The
/// `- 1` keeps `u16::MAX` available as an internal sentinel if we ever
/// need one.
pub(in crate::uri) const MAX_URI_LEN: usize = u16::MAX as usize - 1;

/// Which parser mode is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParserMode {
    /// Browser/curl-compatible. Rejects only smuggling-class inputs.
    Graceful,
    /// RFC 3986 syntax only.
    Strict,
}

/// Engine entry point. All `Uri::parse*` methods funnel through here.
pub(super) fn parse(bytes: Bytes, mode: ParserMode) -> Result<Uri, ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }
    if bytes.len() > MAX_URI_LEN {
        return Err(ParseError::TooLong { len: bytes.len() });
    }

    // Asterisk-form: the whole input is the single byte `*`. HTTP-specific
    // (RFC 9112 §3.2.4); harmless for other protocols since it's just one
    // variant.
    if bytes.as_ref() == b"*" {
        return Ok(Uri::from_asterisk());
    }

    // Origin-form: starts with `/`. No scheme, no authority.
    if bytes[0] == b'/' {
        let scan = scan_path_query_fragment(&bytes, 0, mode)?;
        return Ok(Uri::from_lazy(LazyUriRef {
            scheme: None,
            authority: None,
            path: (0, scan.path_end),
            query: scan.query,
            fragment: scan.fragment,
            bytes,
        }));
    }

    // Absolute-form: `scheme ":" hier-part [ "?" query ] [ "#" fragment ]`
    // (RFC 3986 §3). hier-part is either `//authority path-abempty` or an
    // opaque path-absolute / path-rootless (e.g. `urn:isbn:0`, `mailto:a@b`).
    if let Some(colon) = find_scheme_end(&bytes) {
        let scheme_str = bytes_to_str(&bytes[..colon]);
        let Ok(scheme) = Protocol::try_from(scheme_str) else {
            return Err(ParseError::InvalidComponent(Component::Scheme));
        };

        let after_colon = colon + 1;
        let (authority, hier_start) = parse_optional_authority(&bytes, after_colon, mode)?;
        let scan = scan_path_query_fragment(&bytes, hier_start, mode)?;

        return Ok(Uri::from_lazy(LazyUriRef {
            scheme: Some(scheme),
            authority,
            path: (hier_start as u16, scan.path_end),
            query: scan.query,
            fragment: scan.fragment,
            bytes,
        }));
    }

    // Anything else (relative refs with path-noscheme, HTTP authority-form
    // `host:port`, etc.) is not yet supported.
    Err(ParseError::InvalidComponent(Component::Scheme))
}

// --- Path / Query / Fragment scan (shared by origin-form and absolute-form)
//
// Single-pass walk from `start` to end of `bytes`:
// - reject control chars (always fatal)
// - track section transitions on `?` and `#`
// - in strict mode, validate per-section byte set + percent-escapes

#[derive(Debug)]
struct PathQueryFragment {
    path_end: u16,
    query: Option<(u16, u16)>,
    fragment: Option<(u16, u16)>,
}

#[derive(Clone, Copy)]
enum Section {
    Path,
    Query,
    Fragment,
}

fn scan_path_query_fragment(
    bytes: &Bytes,
    start: usize,
    mode: ParserMode,
) -> Result<PathQueryFragment, ParseError> {
    let len = bytes.len();
    let strict = mode == ParserMode::Strict;
    let mut section = Section::Path;
    let mut path_end = len;
    let mut query_start: Option<usize> = None;
    let mut fragment_start: Option<usize> = None;

    let mut i = start;
    while i < len {
        let b = bytes[i];
        if is_control_byte(b) {
            return Err(ParseError::ControlCharInUri { at: i, byte: b });
        }

        // Section transitions
        let transitioned = match section {
            Section::Path => match b {
                b'?' => {
                    path_end = i;
                    query_start = Some(i + 1);
                    section = Section::Query;
                    true
                }
                b'#' => {
                    path_end = i;
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    true
                }
                _ => false,
            },
            Section::Query => {
                if b == b'#' {
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    true
                } else {
                    false
                }
            }
            Section::Fragment => false,
        };
        if transitioned {
            i += 1;
            continue;
        }

        if strict {
            if b == b'%' {
                check_pct_encoded(bytes, i)?;
                i += 3;
                continue;
            }
            let ok = match section {
                Section::Path => is_path_byte(b),
                Section::Query | Section::Fragment => is_query_fragment_byte(b),
            };
            if !ok {
                return Err(ParseError::StrictViolation);
            }
        }
        i += 1;
    }

    let query_range = query_start.map(|qs| {
        let qe = fragment_start.map_or(len, |fs| fs - 1);
        (qs as u16, qe as u16)
    });
    let fragment_range = fragment_start.map(|fs| (fs as u16, len as u16));

    Ok(PathQueryFragment {
        path_end: path_end as u16,
        query: query_range,
        fragment: fragment_range,
    })
}

// --- Scheme parsing --------------------------------------------------------

/// If `bytes` starts with `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` followed
/// by `:`, return the byte index of the `:`. Otherwise `None`.
fn find_scheme_end(bytes: &[u8]) -> Option<usize> {
    let first = *bytes.first()?;
    if !is_scheme_first_byte(first) {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b':' {
            return Some(i);
        }
        if !is_scheme_rest_byte(b) {
            return None;
        }
        i += 1;
    }
    None
}

// --- Authority parsing -----------------------------------------------------

/// If `bytes[start..]` begins with `//`, parse an authority and return
/// `(Some(LazyAuthority), end_of_authority_offset)`. Otherwise return
/// `(None, start)` — the absolute URI is opaque-path form.
fn parse_optional_authority(
    bytes: &Bytes,
    start: usize,
    mode: ParserMode,
) -> Result<(Option<LazyAuthority>, usize), ParseError> {
    if bytes.len() >= start + 2 && bytes[start] == b'/' && bytes[start + 1] == b'/' {
        let auth_start = start + 2;
        // Authority ends at the first `/`, `?`, `#`, or end of input.
        let auth_end = bytes[auth_start..]
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .map_or(bytes.len(), |p| p + auth_start);
        let auth = parse_authority(bytes, auth_start, auth_end, mode)?;
        Ok((Some(auth), auth_end))
    } else {
        Ok((None, start))
    }
}

/// Parse the bytes `[start, end)` of the parent buffer as an RFC 3986 §3.2
/// authority: `[ userinfo "@" ] host [ ":" port ]`.
fn parse_authority(
    bytes: &Bytes,
    start: usize,
    end: usize,
    _mode: ParserMode,
) -> Result<LazyAuthority, ParseError> {
    // Reject control chars inside the authority.
    let mut k = start;
    while k < end {
        let b = bytes[k];
        if is_control_byte(b) {
            return Err(ParseError::ControlCharInUri { at: k, byte: b });
        }
        k += 1;
    }

    // Userinfo terminates at the first `@`. Userinfo bytes must not contain
    // `@` literally (per ABNF — `@` is not in the userinfo set), so the
    // *first* `@` is unambiguously the terminator.
    let userinfo_range = bytes[start..end]
        .iter()
        .position(|&b| b == b'@')
        .map(|rel| (start as u16, (start + rel) as u16));
    let host_start = userinfo_range.map_or(start, |(_, e)| (e as usize) + 1);

    // Parse host + optional port from bytes[host_start..end].
    let host_view = &bytes[host_start..end];
    let (host, port) = parse_host_and_port(bytes, host_start, host_view, end)?;

    Ok(LazyAuthority {
        userinfo_range,
        host,
        port,
    })
}

/// Parse the host and optional port. `parent` is the full URI buffer (used
/// for zero-copy slicing of Domain bytes); `host_start` is the absolute
/// offset; `view` is `&parent[host_start..end]`; `end` is the absolute
/// end-of-authority offset.
fn parse_host_and_port(
    parent: &Bytes,
    host_start: usize,
    view: &[u8],
    end: usize,
) -> Result<(Host, Option<u16>), ParseError> {
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
        // RFC 9844 zone identifiers are wire-encoded as `%25en0`; the bare
        // `%` byte is illegal in our policy. Reject before address parsing.
        if inside.contains(&b'%') {
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
        return Ok((host, port));
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

    let host = if let Ok(v4) = host_str.parse::<Ipv4Addr>() {
        Host::Address(IpAddr::V4(v4))
    } else {
        // Treat as DNS name. Validate via Domain::try_from on a borrowed
        // slice (validates ASCII/length), then construct the owned Domain
        // zero-copy by slicing the parent Bytes.
        if Domain::try_from(host_str).is_err() {
            return Err(ParseError::InvalidComponent(Component::Host));
        }
        let domain_bytes = parent.slice(host_start..host_start + host_bytes_len);
        // Safety: validated above.
        let domain = unsafe { Domain::from_maybe_borrowed_unchecked(domain_bytes) };
        Host::Name(domain)
    };

    // `end` is unused on the non-bracketed path — bind to a no-op to silence
    // unused-variable warnings without complicating the signature.
    let _ = end;
    Ok((host, port))
}

fn parse_port(bytes: &[u8]) -> Result<u16, ParseError> {
    if bytes.is_empty() {
        // Empty port (`host:`) — reject. RFC 3986 §3.2.3 permits the
        // production but recommends producers omit; receivers diverge in
        // the wild, so we pick the stricter side.
        return Err(ParseError::InvalidComponent(Component::Port));
    }
    let Ok(s) = std::str::from_utf8(bytes) else {
        return Err(ParseError::InvalidComponent(Component::Port));
    };
    let Ok(port) = s.parse::<u16>() else {
        return Err(ParseError::InvalidComponent(Component::Port));
    };
    Ok(port)
}

/// `bytes` is assumed to be valid UTF-8 (caller is responsible). Used for
/// scheme conversion, where the parser has already validated the byte set
/// is a subset of ASCII.
fn bytes_to_str(bytes: &[u8]) -> &str {
    // Safety: scheme bytes are validated as ASCII alpha + digit + + - .
    unsafe { std::str::from_utf8_unchecked(bytes) }
}

/// Verifies a `%XX` percent-escape at `i`. Caller has confirmed
/// `bytes[i] == b'%'`.
fn check_pct_encoded(bytes: &[u8], i: usize) -> Result<(), ParseError> {
    let h1 = bytes.get(i + 1).copied();
    let h2 = bytes.get(i + 2).copied();
    match (h1, h2) {
        (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => Ok(()),
        _ => Err(ParseError::InvalidPercentEncoding { at: i }),
    }
}

// --- Byte-set lookup tables (single-load hot path) -------------------------
//
// `matches!` and `b < 0x20 || b == 0x7F` compile to compare-chains whose
// shape is up to LLVM. The hot loop runs these on every byte of every
// parsed URI, so we precompute `[bool; 256]` tables: one byte load per
// check, no branches, no surprises across compiler versions.

// --- Table-building primitives ---------------------------------------------

/// Mark every byte in `[lo, hi_exclusive)` as `true`. const-evaluable.
const fn set_range(mut t: [bool; 256], lo: u8, hi_exclusive: u8) -> [bool; 256] {
    let mut i = lo;
    while i < hi_exclusive {
        t[i as usize] = true;
        i += 1;
    }
    t
}

/// Mark every byte present in `bytes` as `true`. const-evaluable.
const fn set_each(mut t: [bool; 256], bytes: &[u8]) -> [bool; 256] {
    let mut j = 0;
    while j < bytes.len() {
        t[bytes[j] as usize] = true;
        j += 1;
    }
    t
}

/// Convenience: ASCII alphanumerics (`0-9 A-Z a-z`) — the unreserved
/// alphabet that shows up in nearly every URI byte set.
const fn set_ascii_alphanum(t: [bool; 256]) -> [bool; 256] {
    let t = set_range(t, b'0', b'9' + 1);
    let t = set_range(t, b'A', b'Z' + 1);
    set_range(t, b'a', b'z' + 1)
}

// --- Concrete byte sets ----------------------------------------------------

/// `b < 0x20 || b == 0x7F` as a single load.
const CONTROL_BYTE_SET: [bool; 256] = set_each(set_range([false; 256], 0, 0x20), &[0x7F]);

/// Strict RFC 3986 path byte set: pchar ∪ `/`. pchar = unreserved /
/// pct-encoded / sub-delims / `:` / `@`. `%` is allowed as the lead byte
/// of a percent-escape (the `%XX` triple is checked separately).
const PATH_BYTE_SET: [bool; 256] = set_each(
    set_ascii_alphanum([false; 256]),
    // unreserved extras + sub-delims + pchar extras + path delimiter + `%`
    b"-._~!$&'()*+,;=:@/%",
);

/// Strict RFC 3986 query / fragment byte set: pchar ∪ `/` ∪ `?`.
const QUERY_FRAGMENT_BYTE_SET: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"-._~!$&'()*+,;=:@/%?");

/// RFC 3986 §3.1: a scheme's first byte must be ASCII alpha.
const SCHEME_FIRST_BYTE_SET: [bool; 256] = set_ascii_alpha([false; 256]);

/// RFC 3986 §3.1: a scheme's subsequent bytes are ALPHA / DIGIT / "+" / "-" / ".".
const SCHEME_REST_BYTE_SET: [bool; 256] = set_each(set_ascii_alphanum([false; 256]), b"+-.");

/// ASCII alpha range A-Z and a-z (no digits). Used by the scheme-first table.
const fn set_ascii_alpha(t: [bool; 256]) -> [bool; 256] {
    let t = set_range(t, b'A', b'Z' + 1);
    set_range(t, b'a', b'z' + 1)
}

#[inline(always)]
const fn is_control_byte(b: u8) -> bool {
    CONTROL_BYTE_SET[b as usize]
}

#[inline(always)]
const fn is_path_byte(b: u8) -> bool {
    PATH_BYTE_SET[b as usize]
}

#[inline(always)]
const fn is_query_fragment_byte(b: u8) -> bool {
    QUERY_FRAGMENT_BYTE_SET[b as usize]
}

#[inline(always)]
const fn is_scheme_first_byte(b: u8) -> bool {
    SCHEME_FIRST_BYTE_SET[b as usize]
}

#[inline(always)]
const fn is_scheme_rest_byte(b: u8) -> bool {
    SCHEME_REST_BYTE_SET[b as usize]
}

#[cfg(test)]
mod tests;
