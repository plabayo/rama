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
        Some(IpAddr::V6(value.parse::<Ipv6Addr>().ok()?))
    } else {
        value.parse::<IpAddr>().ok()
    }
}

/// Parse an IPv6 host that may be bracketed and may have a trailing port,
/// out of `s`, where `last_colon` is the byte index of the rightmost `:` in
/// `s`. The caller is expected to have already verified that the substring
/// `s[..last_colon]` contains at least one `:` (so this looks IPv6-shaped).
///
/// Returns `(addr, Some(port))` when the input is `[ipv6]:port`,
/// or `(addr, None)` when the input is a bare bracket-less `ipv6` whose
/// final colon was actually part of the address.
///
/// # Errors
///
/// Returns a contextual error when the bracket-form is partial (only `[`
/// or only `]`), when the address itself fails to parse, or when the
/// port substring is not a valid `u16`.
pub(crate) fn parse_bracketed_ipv6_with_port(
    s: &str,
    last_colon: usize,
) -> Result<(Ipv6Addr, Option<u16>), BoxError> {
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
        let addr = value
            .parse::<Ipv6Addr>()
            .context("parse ipv6 host inside brackets")?;
        let port = s[last_colon + 1..]
            .parse::<u16>()
            .context("parse port string as u16")?;
        Ok((addr, Some(port)))
    } else {
        // No brackets — the whole `s` is a bare ipv6; `last_colon` was part of
        // the address itself, not a port separator.
        let addr = s
            .parse::<Ipv6Addr>()
            .context("parse bare ipv6 host w/o trailing port")?;
        Ok((addr, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bracketed_v6_with_port() {
        let s = "[2001:db8::1]:443";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_bare_v6_no_port() {
        let s = "2001:db8::1";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, None);
    }

    #[test]
    fn parse_bare_v6_loopback() {
        let s = "::1";
        let last_colon = s.rfind(':').unwrap();
        let (addr, port) = parse_bracketed_ipv6_with_port(s, last_colon).unwrap();
        assert_eq!(addr, Ipv6Addr::LOCALHOST);
        assert_eq!(port, None);
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
