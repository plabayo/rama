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
    Uri::parse_authority_form("example.com:443/foo").unwrap_err();
    Uri::parse_authority_form("example.com:443?x=1").unwrap_err();
    Uri::parse_authority_form("example.com:443#frag").unwrap_err();
    Uri::parse_authority_form("https://example.com:443").unwrap_err();
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
    Uri::parse_authority_form("example.com:99999").unwrap_err();
    Uri::parse_authority_form("example.com:abc").unwrap_err();
}

#[test]
fn empty_port_accepted_in_graceful_as_bare_host() {
    // RFC 3986 §3.2.3 allows empty port; graceful authority-form
    // accepts bare-host shapes, so `example.com:` parses with `None`.
    let u = Uri::parse_authority_form("example.com:").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), None);
}

#[test]
fn empty_port_rejected_in_strict_authority_form() {
    // RFC 9112 §3.2.3 requires `host ":" port` — strict mode rejects
    // the bare-host form an empty port produces.
    let r = Uri::parse_authority_form_strict("example.com:");
    assert!(matches!(r, Err(crate::uri::ParseError::StrictViolation)));
}

#[cfg(feature = "idna")]
#[test]
fn graceful_preserves_non_ascii_host_in_authority_form() {
    // Wire-fidelity preservation (M7 reversed): parser stores the bytes
    // verbatim. IDN conversion to ACE happens on demand via
    // `Domain::try_from(uri.host().as_uninterpreted())`.
    let u = Uri::parse_authority_form("münchen.de:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "münchen.de");
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

// ---- Strict RFC 9112 §3.2.3 enforcement -----------------------------------

#[test]
fn strict_accepts_host_port() {
    // The canonical CONNECT shape passes through cleanly.
    let u = Uri::parse_authority_form_strict("example.com:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), Some(443));
}

#[test]
fn strict_accepts_bracketed_ipv6_host_port() {
    let u = Uri::parse_authority_form_strict("[2001:db8::1]:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "2001:db8::1");
    assert_eq!(u.port(), Some(443));
}

#[test]
fn strict_rejects_userinfo() {
    // RFC 9112 §3.2.3: "The request-target consists of the host and port
    // number of the tunnel destination" — no userinfo permitted.
    let err = Uri::parse_authority_form_strict("user:pass@example.com:443").unwrap_err();
    assert!(
        matches!(err, ParseError::StrictViolation),
        "expected StrictViolation, got {err:?}"
    );
    // Userinfo on its own (no password) is also out.
    Uri::parse_authority_form_strict("user@example.com:443").unwrap_err();
}

#[test]
fn strict_rejects_bare_host_without_port() {
    // §3.2.3 mandates a port. Graceful accepts; strict does not.
    let err = Uri::parse_authority_form_strict("example.com").unwrap_err();
    assert!(
        matches!(err, ParseError::StrictViolation),
        "expected StrictViolation, got {err:?}"
    );
    // IPv6 bracketed without port also rejected.
    Uri::parse_authority_form_strict("[2001:db8::1]").unwrap_err();
}

#[test]
fn strict_keeps_path_query_fragment_rejection() {
    // Pre-port-check guard fires before the strict-mode shape check.
    // The error kind (InvalidComponent vs StrictViolation) doesn't matter
    // — both modes reject — but pin both still error so we don't accept
    // a CONNECT target with a path under any setting.
    Uri::parse_authority_form_strict("example.com:443/p").unwrap_err();
    Uri::parse_authority_form_strict("example.com:443?q").unwrap_err();
    Uri::parse_authority_form_strict("example.com:443#f").unwrap_err();
}
