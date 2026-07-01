//! Absolute-form `scheme:hier-part [ "?" query ] [ "#" fragment ]`.
//! Covers HTTP/HTTPS specifically; non-HTTP schemes are in
//! [`super::non_http_schemes`].

use core::net::{IpAddr, Ipv4Addr};

use super::{lazy, parse_graceful, path_str, range_str, userinfo_str};
use crate::Protocol;
use crate::address::{Domain, Host};
use crate::uri::{Component, ParseError};

// ----------------------------------------------------------------------
// Basic absolute-form: scheme + authority + path + query + fragment
// ----------------------------------------------------------------------

#[test]
fn http_basic() {
    let u = parse_graceful("http://example.com/").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme, Some(Protocol::HTTP));
    let auth = l.authority.as_ref().unwrap();
    assert!(auth.userinfo_range.is_none());
    assert_eq!(auth.host, Host::Name(Domain::from_static("example.com")));
    assert_eq!(auth.port, crate::address::OptPort::Unset);
    assert_eq!(path_str(l), "/");
    assert!(l.query.is_none());
    assert!(l.fragment.is_none());
}

#[test]
fn https_with_path_query_fragment() {
    let u = parse_graceful("https://api.example.com/v1/users?id=42#bio").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme, Some(Protocol::HTTPS));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Name(Domain::from_static("api.example.com"))
    );
    assert_eq!(auth.port, crate::address::OptPort::Unset);
    assert_eq!(path_str(l), "/v1/users");
    assert_eq!(range_str(l, l.query), Some("id=42"));
    assert_eq!(range_str(l, l.fragment), Some("bio"));
}

#[test]
fn with_port() {
    let u = parse_graceful("http://example.com:8080/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("example.com")));
    assert_eq!(auth.port, crate::address::OptPort::Set(8080));
}

#[test]
fn with_userinfo() {
    let u = parse_graceful("http://user:pass@example.com/").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some("user:pass"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("example.com")));
}

#[test]
fn with_empty_path_after_authority() {
    // `http://example.com` — path is empty (path-abempty production).
    let u = parse_graceful("http://example.com").unwrap();
    let l = lazy(&u);
    assert_eq!(path_str(l), "");
    assert!(l.authority.is_some());
}

#[test]
fn ipv4_host() {
    let u = parse_graceful("http://192.0.2.16:8080/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 16)))
    );
    assert_eq!(auth.port, crate::address::OptPort::Set(8080));
}

// ----------------------------------------------------------------------
// Schemeless
// ----------------------------------------------------------------------

#[test]
fn absolute_no_scheme_www_example_com_is_invalid_as_absolute() {
    let _ = parse_graceful("www.example.com").unwrap_err();
}

// ----------------------------------------------------------------------
// IPv6 host literals (bracketed)
// ----------------------------------------------------------------------

#[test]
fn ipv6_basic() {
    let u = parse_graceful("https://[2001:db8::1]/p").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V6("2001:db8::1".parse().unwrap()))
    );
    assert!(auth.port.is_unset());
}

#[test]
fn ipv6_with_port() {
    let u = parse_graceful("https://[2001:db8::1]:8443/p").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V6("2001:db8::1".parse().unwrap()))
    );
    assert_eq!(auth.port, crate::address::OptPort::Set(8443));
}

#[test]
fn ipv6_loopback() {
    let u = parse_graceful("http://[::1]/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Address(IpAddr::V6("::1".parse().unwrap())));
}

#[test]
fn ipv6_unspecified() {
    let u = parse_graceful("http://[::]/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Address(IpAddr::V6("::".parse().unwrap())));
}

#[test]
fn ipv6_full_form() {
    let u = parse_graceful("http://[2001:0db8:0000:0000:0000:0000:0000:0001]/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V6("2001:db8::1".parse().unwrap()))
    );
}

#[test]
fn ipv6_with_embedded_ipv4() {
    // `::ffff:192.0.2.1` is the IPv4-mapped IPv6 form.
    let u = parse_graceful("http://[::ffff:192.0.2.1]/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V6("::ffff:192.0.2.1".parse().unwrap()))
    );
}

// ----------------------------------------------------------------------
// Userinfo edge cases
// ----------------------------------------------------------------------

#[test]
fn empty_userinfo() {
    // `@host` — empty userinfo before `@`. Legal per RFC 3986 §3.2.1.
    // Distinct from "no userinfo" (None vs Some("")).
    let u = parse_graceful("http://@example.com/").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some(""));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("example.com")));
}

#[test]
fn userinfo_with_empty_password() {
    let u = parse_graceful("http://user:@example.com/").unwrap();
    assert_eq!(userinfo_str(lazy(&u)), Some("user:"));
}

#[test]
fn userinfo_without_password() {
    let u = parse_graceful("http://user@example.com/").unwrap();
    assert_eq!(userinfo_str(lazy(&u)), Some("user"));
}

#[test]
fn userinfo_with_only_password() {
    // `:pass@host` — empty user, just a password.
    let u = parse_graceful("http://:pass@example.com/").unwrap();
    assert_eq!(userinfo_str(lazy(&u)), Some(":pass"));
}

#[test]
fn userinfo_with_multiple_colons() {
    // `user:p:w@host` — multiple colons in userinfo are legal per RFC 3986
    // (userinfo = *( unreserved / pct-encoded / sub-delims / ":" )).
    // The semantic interpretation (user vs password) is convention.
    let u = parse_graceful("http://user:p:w@example.com/").unwrap();
    assert_eq!(userinfo_str(lazy(&u)), Some("user:p:w"));
}

// ----------------------------------------------------------------------
// Scheme content + case
// ----------------------------------------------------------------------

#[test]
fn scheme_uppercase_accepted() {
    // RFC 3986 §3.1 says schemes are case-insensitive. Parser accepts any
    // case; canonicalisation is a separate opt-in op.
    for s in ["HTTP://example.com/", "Http://example.com/"] {
        assert!(parse_graceful(s).is_ok(), "graceful should accept {s:?}");
    }
}

#[test]
fn scheme_with_plus_minus_dot() {
    for s in [
        "git+ssh://example.com/repo",
        "view-source://example.com/",
        "x.y://example.com/",
        "a1+b-c.d://example.com/",
    ] {
        let u = parse_graceful(s).unwrap();
        assert!(lazy(&u).scheme.is_some());
    }
}

// ----------------------------------------------------------------------
// Error paths
// ----------------------------------------------------------------------

#[test]
fn invalid_scheme_first_byte_rejected() {
    let r = parse_graceful("1http://example.com/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Scheme))
    ));
}

#[test]
fn invalid_scheme_char_rejected() {
    let r = parse_graceful("ht_tp://example.com/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Scheme))
    ));
}

#[test]
fn empty_port_preserved_as_optport_empty() {
    // RFC 3986 §3.2.3 `port = *DIGIT` — empty is grammatically valid.
    // Surfaced as `OptPort::Empty` so the trailing colon round-trips
    // losslessly through owned address types.
    let u = parse_graceful("http://example.com:/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Empty);
    assert_eq!(auth.host.to_str(), "example.com");
    // Lossless round-trip — the bare `:` survives Display.
    assert_eq!(u.to_string(), "http://example.com:/");
}

#[test]
fn empty_port_round_trips_through_authority_into_owned() {
    use crate::uri::Uri;

    // Auditor's repro: `into_owned()` must preserve the trailing `:`
    // (otherwise `OptPort::Empty` collapses to `Unset` at the
    // wire-vs-semantic boundary).
    let owned = Uri::parse_authority_form("example.com:")
        .unwrap()
        .authority()
        .unwrap()
        .into_owned();
    assert_eq!(owned.to_string(), "example.com:");
    assert_eq!(owned.address.port, crate::address::OptPort::Empty);
}

#[test]
fn overflow_port_rejected() {
    let r = parse_graceful("http://example.com:99999/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Port))
    ));
}

#[test]
fn non_numeric_port_rejected() {
    let r = parse_graceful("http://example.com:abc/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Port))
    ));
}

#[test]
fn ipv6_zone_rejected() {
    // RFC 9844 zone identifiers are wire-encoded as `%25en0`. We surface
    // a typed rejection rather than letting it slip past as an opaque
    // Ipv6Addr parse error.
    let r = parse_graceful("https://[fe80::1%25en0]/");
    assert!(matches!(r, Err(ParseError::IPv6ZoneNotSupported)));
}
