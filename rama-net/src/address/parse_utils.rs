use rama_core::error::{BoxError, ErrorContext, ErrorExt, extra::OpaqueError};
use std::net::{IpAddr, Ipv6Addr};

pub(crate) fn split_port_from_str(s: &str) -> Result<(&str, u16), BoxError> {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => Ok((&s[..colon], port)),
            Err(err) => Err(err.context("parse port as u16")),
        }
    } else {
        Err(OpaqueError::from_static_str("missing port").into_box_error())
    }
}

pub(crate) fn try_to_parse_str_to_ip(value: &str) -> Option<IpAddr> {
    if value.starts_with('[') || value.ends_with(']') {
        let value = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))?;
        // Reject zone identifiers (RFC 6874) — `Ipv6Addr::parse` will fail
        // on `%25en0`-style content anyway, but `ipv6_bracket_has_zone`
        // makes the rejection explicit and consistent with the URI
        // parser's typed error.
        if ipv6_bracket_has_zone(value.as_bytes()) {
            return None;
        }
        Some(IpAddr::V6(value.parse::<Ipv6Addr>().ok()?))
    } else {
        value.parse::<IpAddr>().ok()
    }
}

// --- Shared byte-scanning helpers ----------------------------------------
//
// Used by both `Authority::try_from` (eager, BoxError-typed) and
// `uri::parser` (lazy, typed `ParseError`). Each helper does only byte
// inspection — no allocation, no opinions about error type. Callers
// translate result to their preferred error.

/// Returns the byte index of the **last** `@` in `bytes`, treating it as
/// the userinfo / host boundary. The "last `@`" convention matches curl,
/// browsers, and the Rust `url` crate — `user@name:pass@host:80` parses
/// as userinfo=`user@name:pass`, host=`host`, port=80.
///
/// (Strict RFC 3986 §3.2.1 disallows raw `@` inside userinfo, so a
/// strict-mode validator should additionally reject inputs where the
/// userinfo byte slice still contains `@` after the split. The grammar
/// requires it to be percent-encoded as `%40`.)
#[inline]
pub(crate) fn find_userinfo_split(bytes: &[u8]) -> Option<usize> {
    bytes.iter().rposition(|&b| b == b'@')
}

/// Returns `true` if the bytes between IPv6 brackets contain a `%`,
/// which indicates a zone identifier (RFC 6874 `%25en0` wire encoding).
/// We don't currently support zone IDs in either parser — `std::net::Ipv6Addr`
/// has no field for them.
#[inline]
pub(crate) fn ipv6_bracket_has_zone(inside_brackets: &[u8]) -> bool {
    inside_brackets.contains(&b'%')
}

/// Parse `bytes` as a decimal `u16` (port). Returns `None` if `bytes` is
/// empty, contains non-ASCII, isn't all digits, or overflows. Callers
/// map `None` to their preferred error type.
#[inline]
pub(crate) fn parse_port_bytes(bytes: &[u8]) -> Option<u16> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.parse::<u16>().ok()
}

/// Parse an IPv6 host that may be bracketed and may have a trailing port,
/// out of `s`, where `last_colon` is the byte index of the rightmost `:` in
/// `s`. The caller is expected to have already verified that the substring
/// `s[..last_colon]` contains at least one `:` (so this looks IPv6-shaped).
///
/// Returns `(addr, Set(port))` for `[ipv6]:port`, `(addr, Empty)` for
/// `[ipv6]:` (RFC 3986 §3.2.3 empty port), or `(addr, Unset)` when the
/// input is a bare bracket-less `ipv6` whose final colon was actually
/// part of the address.
///
/// # Errors
///
/// Returns a contextual error when the bracket-form is partial (only `[`
/// or only `]`), when the address itself fails to parse, or when the
/// port substring is non-empty but not a valid `u16`.
pub(crate) fn parse_bracketed_ipv6_with_port(
    s: &str,
    last_colon: usize,
) -> Result<(Ipv6Addr, crate::address::OptPort), BoxError> {
    use crate::address::OptPort;

    let first_part = &s[..last_colon];
    debug_assert!(
        first_part.contains(':'),
        "parse_bracketed_ipv6_with_port: caller must check ':' in s[..last_colon]"
    );

    if first_part.starts_with('[') || first_part.ends_with(']') {
        // [ipv6]:port — strip brackets, parse, then parse port.
        let value = first_part
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .context("strip brackets from ipv6 host w/ trailing port")?;
        // RFC 6874 zone identifiers (wire-encoded as `%25en0`) are not
        // currently supported — they require an `Ipv6+zone` host shape
        // we haven't built. Reject with a clear message rather than
        // letting `Ipv6Addr::parse` fail opaquely on the `%`.
        if ipv6_bracket_has_zone(value.as_bytes()) {
            return Err(OpaqueError::from_static_str(
                "ipv6 zone identifiers (RFC 6874) are not supported",
            )
            .into_box_error());
        }
        let addr = value
            .parse::<Ipv6Addr>()
            .context("parse ipv6 host inside brackets")?;
        let port_bytes = &s.as_bytes()[last_colon + 1..];
        let port = if port_bytes.is_empty() {
            OptPort::Empty
        } else {
            OptPort::Set(parse_port_bytes(port_bytes).context("parse port string as u16")?)
        };
        Ok((addr, port))
    } else {
        // No brackets — the whole `s` is a bare ipv6; `last_colon` was part of
        // the address itself, not a port separator.
        let addr = s
            .parse::<Ipv6Addr>()
            .context("parse bare ipv6 host w/o trailing port")?;
        Ok((addr, OptPort::Unset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bracketed_v6_with_port() {
        use crate::address::OptPort;
        let s = "[2001:db8::1]:443";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, OptPort::Set(443));
    }

    #[test]
    fn parse_bracketed_v6_empty_port() {
        use crate::address::OptPort;
        let s = "[2001:db8::1]:";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, OptPort::Empty);
    }

    #[test]
    fn parse_bare_v6_no_port() {
        use crate::address::OptPort;
        let s = "2001:db8::1";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, OptPort::Unset);
    }

    #[test]
    fn parse_bare_v6_loopback() {
        use crate::address::OptPort;
        let s = "::1";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
        assert_eq!(port, OptPort::Unset);
    }

    #[test]
    fn rejects_half_bracket() {
        let s = "[2001:db8::1:443";
        let last_colon = s.rfind(':').unwrap();
        parse_bracketed_ipv6_with_port(s, last_colon).unwrap_err();

        let s = "2001:db8::1]:443";
        let last_colon = s.rfind(':').unwrap();
        parse_bracketed_ipv6_with_port(s, last_colon).unwrap_err();
    }

    #[test]
    fn rejects_bad_port() {
        let s = "[::1]:notaport";
        let last_colon = s.rfind(':').unwrap();
        parse_bracketed_ipv6_with_port(s, last_colon).unwrap_err();
    }

    #[test]
    fn rejects_bad_address_inside_brackets() {
        let s = "[zz::1]:443";
        let last_colon = s.rfind(':').unwrap();
        parse_bracketed_ipv6_with_port(s, last_colon).unwrap_err();
    }
}
