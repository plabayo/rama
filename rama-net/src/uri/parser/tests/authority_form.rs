//! `Uri::parse_authority_form` — the HTTP CONNECT request-target shape
//! `[userinfo@]host[:port]` (RFC 9112 §3.2.3).
//!
//! Distinct entry point because the grammar is ambiguous with
//! `scheme:opaque-path` (`example.com:443` parses validly as both, and
//! RFC 3986 prefers the scheme reading). HTTP proxies handling CONNECT
//! must route through this entry; `Uri::parse` retains the RFC 3986
//! tie-break.

use crate::uri::{ParseError, Uri};

#[test]
fn host_port_pair() {
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    assert!(u.scheme().is_none(), "authority-form has no scheme");
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), Some(443));
    assert_eq!(u.path().map(|p| p.as_raw_str()), Some(""));
}

#[test]
fn host_port_with_userinfo() {
    let u = Uri::parse_authority_form("user:pass@example.com:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), Some(443));
    assert!(u.userinfo().is_some());
}

#[test]
fn ipv4_literal() {
    let u = Uri::parse_authority_form("127.0.0.1:8080").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "127.0.0.1");
    assert_eq!(u.port(), Some(8080));
}

#[test]
fn ipv6_bracketed_literal() {
    let u = Uri::parse_authority_form("[::1]:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "::1");
    assert_eq!(u.port(), Some(443));

    let u = Uri::parse_authority_form("[2001:db8::1]:80").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "2001:db8::1");
    assert_eq!(u.port(), Some(80));
}

#[test]
fn bare_host_without_port_accepted() {
    // RFC 9112 §3.2.3 says CONNECT *requires* a port; lower-level URI
    // parsing is more permissive — HTTP-aware callers can enforce the
    // port requirement at their layer.
    let u = Uri::parse_authority_form("example.com").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), None);
}

#[test]
fn path_query_fragment_delimiters_rejected() {
    // Any of `/`, `?`, `#` means the caller has the wrong shape.
    assert!(Uri::parse_authority_form("example.com:443/foo").is_err());
    assert!(Uri::parse_authority_form("example.com:443?x=1").is_err());
    assert!(Uri::parse_authority_form("example.com:443#frag").is_err());
    assert!(Uri::parse_authority_form("https://example.com:443").is_err());
}

#[test]
fn empty_input_rejected() {
    assert!(matches!(
        Uri::parse_authority_form(""),
        Err(ParseError::Empty)
    ));
}

#[test]
fn invalid_port_rejected() {
    assert!(Uri::parse_authority_form("example.com:99999").is_err());
    assert!(Uri::parse_authority_form("example.com:abc").is_err());
    assert!(Uri::parse_authority_form("example.com:").is_err());
}

#[cfg(feature = "idna")]
#[test]
fn graceful_idn_normalises_non_ascii_host() {
    let u = Uri::parse_authority_form("münchen.de:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "xn--mnchen-3ya.de");
}

#[cfg(feature = "idna")]
#[test]
fn strict_rejects_non_ascii_host() {
    // Strict authority-form must reject non-ASCII identically to strict
    // `Uri::parse` — RFC 3986 host grammar is ASCII only.
    let r = Uri::parse_authority_form_strict("münchen.de:443");
    assert!(r.is_err(), "strict authority-form must reject non-ASCII");
}

#[test]
fn renders_without_scheme_or_path() {
    // Round-trip: parsed authority-form must render as `host:port` only.
    // If a scheme or path slips in, HTTP CONNECT proxies route wrong.
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    let s = u.to_string();
    assert!(!s.contains("://"), "rendered has scheme prefix: {s}");
    assert!(s.contains("example.com"));
    assert!(s.contains("443"));
}

#[test]
fn plain_parse_treats_host_port_as_scheme_path() {
    // Pin RFC 3986 tie-break: `Uri::parse` on a bare `host:port` reads
    // it as `scheme:opaque-path`. Callers handling CONNECT must call
    // `parse_authority_form` instead.
    let u = Uri::parse("example.com:443").unwrap();
    assert_eq!(u.scheme().map(|s| s.as_str()), Some("example.com"));
    assert!(u.host().is_none());
}
