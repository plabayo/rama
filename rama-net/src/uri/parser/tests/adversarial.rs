//! Adversarial corpus: security-class inputs that must be rejected (or
//! parsed *safely*) in both graceful and strict modes.
//!
//! Every category here has a public CVE precedent if mis-handled.

use std::net::{IpAddr, Ipv4Addr};

use super::{assert_origin_form, lazy, parse_graceful, parse_strict, userinfo_str};
use crate::address::Host;
use crate::uri::parser::MAX_URI_LEN;
use crate::uri::{Component, ParseError};

// ----------------------------------------------------------------------
// Control-character rejection (smuggling / header-injection vectors)
// ----------------------------------------------------------------------

#[test]
fn crlf_anywhere_rejected() {
    for s in [
        "/foo\r/bar",
        "/foo\n/bar",
        "/foo\r\n/bar",
        "/foo?bar\rbaz",
        "/foo?bar\nbaz",
        "/foo#frag\r",
        "/foo#frag\n",
        "http://example.com\r/",
        "http://example.com\n/",
        "http://example.com/\r",
    ] {
        assert!(
            matches!(parse_graceful(s), Err(ParseError::ControlCharInUri { .. })),
            "graceful must reject {s:?}"
        );
        assert!(
            matches!(parse_strict(s), Err(ParseError::ControlCharInUri { .. })),
            "strict must reject {s:?}"
        );
    }
}

#[test]
fn nul_byte_rejected() {
    for s in ["/\0foo", "/foo\0", "/foo?\0", "/foo#\0", "http://\0/"] {
        assert!(matches!(
            parse_graceful(s),
            Err(ParseError::ControlCharInUri { byte: 0, .. })
        ));
    }
}

#[test]
fn tab_rejected() {
    // WHATWG silently strips tabs. We never strip wire bytes — silent
    // rewrite hides intent and bypasses upstream allowlists.
    for s in [
        "/foo\tbar",
        "http://example\t.com/",
        "http://example.com/foo\tbar",
    ] {
        assert!(matches!(
            parse_graceful(s),
            Err(ParseError::ControlCharInUri { byte: b'\t', .. })
        ));
    }
}

#[test]
fn del_byte_rejected() {
    for s in ["/foo\x7Fbar", "http://example.com/\x7F"] {
        assert!(matches!(
            parse_graceful(s),
            Err(ParseError::ControlCharInUri { byte: 0x7F, .. })
        ));
    }
}

// ----------------------------------------------------------------------
// Backslash NOT folded to slash (smuggling vector)
// ----------------------------------------------------------------------

#[test]
fn backslash_not_folded_to_slash() {
    // Browsers fold `\` to `/` for "special" schemes. Documented request-
    // smuggling vector against intermediaries — we never fold. Graceful
    // accepts the literal backslash; strict rejects.
    let u = parse_graceful("/path\\foo").unwrap();
    assert_origin_form(&u, "/path\\foo", None, None);
    assert!(matches!(
        parse_strict("/path\\foo"),
        Err(ParseError::StrictViolation)
    ));
}

#[test]
fn backslash_authority_spoof_rejected_in_both_modes() {
    // Classic browser-spoof input: `https://example.com\evil.com/`.
    // WHATWG-URL rewrites `\` → `/` and parses host as `evil.com`;
    // rama rejects — `\` isn't in the host byte set.
    assert!(matches!(
        parse_graceful("https://example.com\\evil.com/"),
        Err(ParseError::InvalidComponent(Component::Host))
    ));
    parse_strict("https://example.com\\evil.com/").unwrap_err();
}

// ----------------------------------------------------------------------
// Alternate IPv4 forms — must not silently decode to 127.0.0.1
// (SSRF amplifier)
// ----------------------------------------------------------------------

#[test]
fn alt_ipv4_octal_not_treated_as_ipv4() {
    let u = parse_graceful("http://0177.0.0.1/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert!(matches!(auth.host, Host::Name(_)));
    assert_ne!(
        auth.host,
        Host::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "alt-form must not silently map to 127.0.0.1"
    );
}

#[test]
fn alt_ipv4_hex_not_treated_as_ipv4() {
    let u = parse_graceful("http://0x7f.0.0.1/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert!(matches!(auth.host, Host::Name(_)));
    assert_ne!(auth.host, Host::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn alt_ipv4_single_int_not_treated_as_ipv4() {
    let u = parse_graceful("http://2130706433/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert!(matches!(auth.host, Host::Name(_)));
    assert_ne!(auth.host, Host::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

// ----------------------------------------------------------------------
// %2F preserved literally (path-traversal / auth-bypass vectors)
// ----------------------------------------------------------------------

#[test]
fn percent_2f_not_decoded_in_path() {
    let u = parse_graceful("/admin/%2F../secret").unwrap();
    assert_origin_form(&u, "/admin/%2F../secret", None, None);
}

// ----------------------------------------------------------------------
// Length / overflow boundary
// ----------------------------------------------------------------------

#[test]
fn overlong_input_rejected() {
    let big = "/".to_owned() + &"a".repeat(MAX_URI_LEN);
    assert!(matches!(
        parse_graceful(&big),
        Err(ParseError::TooLong { .. })
    ));
}

#[test]
fn max_uri_len_minus_one_accepted() {
    let just_under = "/".to_owned() + &"a".repeat(MAX_URI_LEN - 1);
    parse_graceful(&just_under).unwrap();
}

#[test]
fn exactly_max_uri_len_accepted() {
    // The cap is `MAX_URI_LEN`. Exactly `MAX_URI_LEN` bytes should still
    // parse — the rejection is `> MAX_URI_LEN`.
    let exactly = "/".to_owned() + &"a".repeat(MAX_URI_LEN - 1);
    assert_eq!(exactly.len(), MAX_URI_LEN);
    parse_graceful(&exactly).unwrap();
}

#[test]
fn public_uri_max_len_matches_internal_cap() {
    use crate::uri::Uri;
    assert_eq!(Uri::MAX_LEN, MAX_URI_LEN);
}

// ----------------------------------------------------------------------
// IPv6 edge cases
// ----------------------------------------------------------------------

#[test]
fn unbracketed_ipv6_in_authority_rejected() {
    let r = parse_graceful("http://2001:db8::1/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(
            Component::Port | Component::Host
        ))
    ));
}

#[test]
fn ipv6_zone_id_rejected() {
    // RFC 9844 `%25en0` zone-identifier wire encoding. We reject pending
    // first-class `Ipv6+zone` host support.
    let r = parse_graceful("https://[fe80::1%25en0]/");
    assert!(matches!(r, Err(ParseError::IPv6ZoneNotSupported)));
}

#[test]
fn eager_and_lazy_authority_paths_agree_on_ipv6_zone() {
    // Both `Uri::parse` (lazy) and `Authority::try_from` (eager) route
    // through the same `parse_utils::ipv6_bracket_has_zone` helper. They
    // must agree on rejection.
    use crate::address::Authority;
    let auth_str = "[fe80::1%25en0]:8080";
    let eager_err = Authority::try_from(auth_str).is_err();
    let lazy_err = parse_graceful(&format!("http://{auth_str}/")).is_err();
    assert!(eager_err && lazy_err, "both paths must reject IPv6 zone");
}

#[test]
fn unbalanced_brackets_rejected() {
    for s in [
        "http://[2001:db8::1/",      // missing closing `]`
        "http://2001:db8::1]/",      // closing `]` without opening
        "http://[2001:db8::1]:abc/", // bad port after IPv6
    ] {
        assert!(
            parse_graceful(s).is_err(),
            "must reject malformed brackets in {s:?}"
        );
    }
}

// ----------------------------------------------------------------------
// Userinfo confusion
// ----------------------------------------------------------------------

#[test]
fn userinfo_confusion_does_not_bleed_into_host() {
    // `http://trusted.com@evil.com/` — userinfo is `trusted.com`, host is
    // `evil.com`. Parser must not confuse the two.
    let u = parse_graceful("http://trusted.com@evil.com/").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some("trusted.com"));
    assert_eq!(
        l.authority.as_ref().unwrap().host,
        Host::Name(crate::address::Domain::from_static("evil.com"))
    );
}

#[test]
fn at_in_path_is_not_userinfo() {
    // `@` after `/` is part of the path, not userinfo.
    let u = parse_graceful("/foo@bar").unwrap();
    assert_origin_form(&u, "/foo@bar", None, None);
}

#[test]
fn double_at_in_authority_uses_last_at_split() {
    // `user@info@host` — multiple `@` in authority. Curl, browsers, and
    // the Rust `url` crate all split on the *last* `@`. We match that
    // for real-world parity. The byte `@` is not in RFC 3986's userinfo
    // grammar, so a strict-mode validator (M5+ work) would reject the
    // remaining `@` in the userinfo bytes — but that's separate from
    // the boundary choice.
    let u = parse_graceful("http://user@info@host/").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some("user@info"));
    assert_eq!(
        l.authority.as_ref().unwrap().host,
        Host::Name(crate::address::Domain::from_static("host"))
    );
}

// ----------------------------------------------------------------------
// Port edges
// ----------------------------------------------------------------------

#[test]
fn port_0_accepted() {
    let u = parse_graceful("http://example.com:0/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.port, Some(0));
}

#[test]
fn port_65535_accepted() {
    let u = parse_graceful("http://example.com:65535/").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.port, Some(65535));
}

#[test]
fn port_65536_overflow_rejected() {
    let r = parse_graceful("http://example.com:65536/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Port))
    ));
}

#[test]
fn port_negative_rejected() {
    let r = parse_graceful("http://example.com:-80/");
    assert!(matches!(
        r,
        Err(ParseError::InvalidComponent(Component::Port))
    ));
}

// ----------------------------------------------------------------------
// Empty authority (RFC 3986 §3.2.2 `reg-name = *(...)` — empty allowed)
// ----------------------------------------------------------------------

#[test]
fn empty_authority_accepted_as_empty_uninterpreted_host() {
    // `file:///path`, `unix:///run/x`, also `http:///path` — empty
    // reg-name parses as `Host::Uninterpreted(b"")`. Callers that need a
    // non-empty host enforce that at a higher layer.
    use crate::address::Host;
    let u = parse_graceful("file:///tmp/x").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    match &auth.host {
        Host::Uninterpreted(h) => assert!(h.as_str().is_empty()),
        other => panic!("expected empty Uninterpreted host, got {other:?}"),
    }
    assert_eq!(auth.port, None);

    // `http://` — empty authority with no path.
    let u = parse_graceful("http://").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert!(matches!(&auth.host, Host::Uninterpreted(h) if h.as_str().is_empty()));
}

#[test]
fn scheme_with_only_colon_accepted() {
    // `http:` — bare scheme + colon, no path / authority. RFC-valid
    // (degenerate) URI.
    let u = parse_graceful("http:").unwrap();
    assert!(lazy(&u).scheme.is_some());
}
