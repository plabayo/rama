use core::net::{IpAddr, Ipv4Addr};

use super::parse_graceful;
use crate::Protocol;
use crate::address::{Domain, Host, HostRef};

// ----------------------------------------------------------------------
// scheme()
// ----------------------------------------------------------------------

#[test]
fn scheme_origin_form_is_none() {
    assert!(parse_graceful("/foo").unwrap().scheme().is_none());
    assert!(parse_graceful("/foo?bar#baz").unwrap().scheme().is_none());
}

#[test]
fn scheme_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().scheme().is_none());
}

#[test]
fn scheme_http() {
    let u = parse_graceful("http://example.com/").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTP));
}

#[test]
fn scheme_https() {
    let u = parse_graceful("https://example.com/").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTPS));
}

#[test]
fn scheme_custom() {
    for (input, expected) in [
        ("urn:isbn:0", "urn"),
        ("mailto:a@b", "mailto"),
        ("ftp://h/p", "ftp"),
        ("git+ssh://h/r", "git+ssh"),
        ("ws://h/", "ws"),
        ("wss://h/", "wss"),
    ] {
        let u = parse_graceful(input).unwrap();
        assert_eq!(
            u.scheme().map(|p| p.as_str()),
            Some(expected),
            "scheme for {input:?}"
        );
    }
}

// ----------------------------------------------------------------------
// path()
// ----------------------------------------------------------------------

#[test]
fn path_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().path().is_none());
}

#[test]
fn path_origin_form() {
    let u = parse_graceful("/foo/bar").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.as_encoded_str(), "/foo/bar");
}

#[test]
fn path_root() {
    let u = parse_graceful("/").unwrap();
    assert_eq!(u.path().unwrap().as_encoded_str(), "/");
}

#[test]
fn path_strips_at_query_delimiter() {
    let u = parse_graceful("/foo?q").unwrap();
    assert_eq!(u.path().unwrap().as_encoded_str(), "/foo");
}

#[test]
fn path_strips_at_fragment_delimiter() {
    let u = parse_graceful("/foo#f").unwrap();
    assert_eq!(u.path().unwrap().as_encoded_str(), "/foo");
}

#[test]
fn path_absolute_form() {
    let u = parse_graceful("http://example.com/v1/users").unwrap();
    assert_eq!(u.path().unwrap().as_encoded_str(), "/v1/users");
}

#[test]
fn path_absolute_empty() {
    // `http://example.com` — path-abempty is empty.
    let u = parse_graceful("http://example.com").unwrap();
    let p = u.path().unwrap();
    assert_eq!(p.as_encoded_str(), "");
    assert!(p.as_encoded_str().is_empty());
}

#[test]
fn path_opaque_in_urn() {
    let u = parse_graceful("urn:isbn:0451450523").unwrap();
    assert_eq!(u.path().unwrap().as_encoded_str(), "isbn:0451450523");
}

// ----------------------------------------------------------------------
// query()
// ----------------------------------------------------------------------

#[test]
fn query_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().query().is_none());
}

#[test]
fn query_absent_is_none() {
    assert!(parse_graceful("/foo").unwrap().query().is_none());
    assert!(parse_graceful("http://x/").unwrap().query().is_none());
}

#[test]
fn query_present() {
    let u = parse_graceful("/p?key=val&x=y").unwrap();
    assert_eq!(u.query().unwrap().as_encoded_str(), "key=val&x=y");
}

#[test]
fn query_empty_distinct_from_none() {
    // `/foo?` — Some("") vs None for `/foo`.
    let with = parse_graceful("/foo?").unwrap();
    let q = with.query().unwrap();
    assert_eq!(q.as_encoded_str(), "");
    assert!(q.as_encoded_str().is_empty());

    let without = parse_graceful("/foo").unwrap();
    assert!(without.query().is_none());
}

#[test]
fn query_stops_at_fragment() {
    let u = parse_graceful("/p?q1=a#frag").unwrap();
    assert_eq!(u.query().unwrap().as_encoded_str(), "q1=a");
}

#[test]
fn query_in_absolute_form() {
    let u = parse_graceful("https://api.example.com/v1?id=42").unwrap();
    assert_eq!(u.query().unwrap().as_encoded_str(), "id=42");
}

// ----------------------------------------------------------------------
// fragment()
// ----------------------------------------------------------------------

#[test]
fn fragment_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().fragment().is_none());
}

#[test]
fn fragment_absent_is_none() {
    assert!(parse_graceful("/foo").unwrap().fragment().is_none());
    assert!(parse_graceful("/foo?q").unwrap().fragment().is_none());
}

#[test]
fn fragment_present() {
    let u = parse_graceful("/foo#section").unwrap();
    assert_eq!(u.fragment().unwrap().as_encoded_str(), "section");
}

#[test]
fn fragment_empty_distinct_from_none() {
    let with = parse_graceful("/foo#").unwrap();
    let f = with.fragment().unwrap();
    assert_eq!(f.as_encoded_str(), "");
    assert!(f.as_encoded_str().is_empty());

    let without = parse_graceful("/foo").unwrap();
    assert!(without.fragment().is_none());
}

#[test]
fn fragment_with_question_mark_byte() {
    // `?` is a legal fragment byte (RFC 3986 §3.5).
    let u = parse_graceful("/p#frag?q").unwrap();
    assert_eq!(u.fragment().unwrap().as_encoded_str(), "frag?q");
}

#[test]
fn fragment_in_absolute_form() {
    let u = parse_graceful("https://x/v#bio").unwrap();
    assert_eq!(u.fragment().unwrap().as_encoded_str(), "bio");
}

// ----------------------------------------------------------------------
// All four accessors together — single-URI roundtrip
// ----------------------------------------------------------------------

#[test]
fn full_uri_all_accessors() {
    let u = parse_graceful("https://api.example.com/v1/users?id=42&filter=x#bio").unwrap();
    assert_eq!(u.scheme(), Some(&Protocol::HTTPS));
    assert_eq!(u.path().unwrap().as_encoded_str(), "/v1/users");
    assert_eq!(u.query().unwrap().as_encoded_str(), "id=42&filter=x");
    assert_eq!(u.fragment().unwrap().as_encoded_str(), "bio");
}

#[test]
fn origin_form_all_accessors() {
    let u = parse_graceful("/p?a=b#frag").unwrap();
    assert!(u.scheme().is_none());
    assert_eq!(u.path().unwrap().as_encoded_str(), "/p");
    assert_eq!(u.query().unwrap().as_encoded_str(), "a=b");
    assert_eq!(u.fragment().unwrap().as_encoded_str(), "frag");
}

#[test]
fn asterisk_all_accessors_none() {
    let u = parse_graceful("*").unwrap();
    assert!(u.is_asterisk());
    assert!(u.scheme().is_none());
    assert!(u.path().is_none());
    assert!(u.query().is_none());
    assert!(u.fragment().is_none());
}

// ----------------------------------------------------------------------
// host() / port() shortcuts
// (Full authority() returning AuthorityRef lands in M4 (c) along with
// the userinfo accessor — these are quick-access shortcuts useful even
// without the full bundle.)
// ----------------------------------------------------------------------

#[test]
fn host_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().host().is_none());
}

#[test]
fn host_origin_form_is_none() {
    // Origin-form has no authority.
    assert!(parse_graceful("/foo").unwrap().host().is_none());
    assert!(parse_graceful("/p?q#f").unwrap().host().is_none());
}

#[test]
fn host_opaque_path_is_none() {
    // urn:, mailto:, data: etc. have a scheme but no authority.
    for s in ["urn:isbn:0", "mailto:a@b", "data:text/plain,hi"] {
        assert!(
            parse_graceful(s).unwrap().host().is_none(),
            "host should be None for {s:?}"
        );
    }
}

#[test]
fn host_domain() {
    let u = parse_graceful("http://example.com/").unwrap();
    let h = u.host().unwrap();
    assert_eq!(
        h,
        HostRef::from(&Host::Name(Domain::from_static("example.com")))
    );
}

#[test]
fn host_ipv4() {
    let u = parse_graceful("http://192.0.2.16:8080/").unwrap();
    let h = u.host().unwrap();
    let expected_host = Host::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 16)));
    assert_eq!(h, HostRef::from(&expected_host));
}

#[test]
fn host_ipv6() {
    let u = parse_graceful("https://[2001:db8::1]/p").unwrap();
    let h = u.host().unwrap();
    let expected_host = Host::Address(IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(h, HostRef::from(&expected_host));
}

#[test]
fn port_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().port().is_unset());
}

#[test]
fn port_origin_form_is_none() {
    assert!(parse_graceful("/foo").unwrap().port().is_unset());
}

#[test]
fn port_opaque_path_is_none() {
    assert!(parse_graceful("urn:isbn:0").unwrap().port().is_unset());
    assert!(parse_graceful("mailto:a@b").unwrap().port().is_unset());
}

#[test]
fn port_absent_when_authority_has_no_port() {
    // `http://example.com/` — host but no `:port`.
    assert!(
        parse_graceful("http://example.com/")
            .unwrap()
            .port()
            .is_unset()
    );
}

#[test]
fn port_explicit() {
    let u = parse_graceful("http://example.com:8080/").unwrap();
    assert_eq!(u.port_u16(), Some(8080));
}

#[test]
fn port_default_not_substituted() {
    // We deliberately do NOT substitute scheme defaults. `http://x/`
    // returns None for port, not Some(80). Canonicalisation is a
    // separate policy decision the caller makes.
    assert!(
        parse_graceful("http://example.com/")
            .unwrap()
            .port()
            .is_unset()
    );
    assert!(
        parse_graceful("https://example.com/")
            .unwrap()
            .port()
            .is_unset()
    );
}

#[test]
fn port_zero() {
    let u = parse_graceful("http://example.com:0/").unwrap();
    assert_eq!(u.port_u16(), Some(0));
}

#[test]
fn port_max() {
    let u = parse_graceful("http://example.com:65535/").unwrap();
    assert_eq!(u.port_u16(), Some(65535));
}

#[test]
fn port_ipv6_authority() {
    let u = parse_graceful("https://[2001:db8::1]:8443/").unwrap();
    assert_eq!(u.port_u16(), Some(8443));
}

// ----------------------------------------------------------------------
// userinfo()
//
// Returns Option<UserInfoRef>. None when the URI has no authority, or
// the authority has no `@`. Some("") (empty userinfo) is distinct from
// None — the `@host` form.
// ----------------------------------------------------------------------

#[test]
fn userinfo_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().userinfo().is_none());
}

#[test]
fn userinfo_origin_form_is_none() {
    assert!(parse_graceful("/foo").unwrap().userinfo().is_none());
}

#[test]
fn userinfo_opaque_path_is_none() {
    // urn:, mailto: etc. have a scheme but no authority.
    assert!(parse_graceful("urn:isbn:0").unwrap().userinfo().is_none());
    assert!(parse_graceful("mailto:a@b").unwrap().userinfo().is_none());
}

#[test]
fn userinfo_authority_without_at_is_none() {
    // `http://example.com/` — authority but no `@`.
    assert!(
        parse_graceful("http://example.com/")
            .unwrap()
            .userinfo()
            .is_none()
    );
}

#[test]
fn userinfo_user_only() {
    let u = parse_graceful("http://alice@example.com/").unwrap();
    assert_eq!(u.userinfo().unwrap().as_str(), "alice");
}

#[test]
fn userinfo_user_password() {
    let u = parse_graceful("http://alice:secret@example.com/").unwrap();
    let ui = u.userinfo().unwrap();
    assert_eq!(ui.as_str(), "alice:secret");
    assert_eq!(
        ui.split_user_password(),
        (&b"alice"[..], Some(&b"secret"[..]))
    );
}

#[test]
fn userinfo_empty_at_host() {
    // `http://@host/` — empty userinfo before `@`. Some("") vs None.
    let u = parse_graceful("http://@example.com/").unwrap();
    assert_eq!(u.userinfo().unwrap().as_str(), "");
}

#[test]
fn userinfo_only_colon() {
    // `:` alone in userinfo — empty user, empty password.
    let u = parse_graceful("http://:@example.com/").unwrap();
    let ui = u.userinfo().unwrap();
    assert_eq!(ui.as_str(), ":");
    assert_eq!(ui.split_user_password(), (&b""[..], Some(&b""[..])));
}

#[test]
fn userinfo_with_last_at_split() {
    // `user@info@host` — last-`@` split (M3-e behavior). userinfo is
    // `user@info`, host is `host`.
    let u = parse_graceful("http://user@info@example.com/").unwrap();
    assert_eq!(u.userinfo().unwrap().as_str(), "user@info");
}

// ----------------------------------------------------------------------
// authority()
//
// Returns Option<AuthorityRef>. Bundles host + port + userinfo as
// borrowed views. None when the URI has no authority component.
// ----------------------------------------------------------------------

#[test]
fn authority_asterisk_is_none() {
    assert!(parse_graceful("*").unwrap().authority().is_none());
}

#[test]
fn authority_origin_form_is_none() {
    assert!(parse_graceful("/foo").unwrap().authority().is_none());
}

#[test]
fn authority_opaque_path_is_none() {
    assert!(parse_graceful("urn:isbn:0").unwrap().authority().is_none());
    assert!(parse_graceful("mailto:a@b").unwrap().authority().is_none());
}

#[test]
fn authority_host_only() {
    let u = parse_graceful("http://example.com/").unwrap();
    let a = u.authority().unwrap();
    assert!(a.userinfo().is_none());
    assert_eq!(
        a.host(),
        HostRef::from(&Host::Name(Domain::from_static("example.com")))
    );
    assert!(a.port().is_unset());
}

#[test]
fn authority_with_port() {
    let u = parse_graceful("http://example.com:8080/").unwrap();
    let a = u.authority().unwrap();
    assert!(a.userinfo().is_none());
    assert_eq!(a.port_u16(), Some(8080));
}

#[test]
fn authority_with_userinfo_no_port() {
    let u = parse_graceful("http://alice:secret@example.com/").unwrap();
    let a = u.authority().unwrap();
    assert_eq!(a.userinfo().unwrap().as_str(), "alice:secret");
    assert_eq!(
        a.host(),
        HostRef::from(&Host::Name(Domain::from_static("example.com")))
    );
    assert!(a.port().is_unset());
}

#[test]
fn authority_with_userinfo_and_port() {
    let u = parse_graceful("https://api:tok@api.example.com:8443/v1").unwrap();
    let a = u.authority().unwrap();
    assert_eq!(a.userinfo().unwrap().as_str(), "api:tok");
    assert_eq!(
        a.host(),
        HostRef::from(&Host::Name(Domain::from_static("api.example.com")))
    );
    assert_eq!(a.port_u16(), Some(8443));
}

#[test]
fn authority_ipv6_host() {
    let u = parse_graceful("https://[2001:db8::1]:8443/").unwrap();
    let a = u.authority().unwrap();
    let expected_host = Host::Address(IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(a.host(), HostRef::from(&expected_host));
    assert_eq!(a.port_u16(), Some(8443));
}

#[test]
fn authority_empty_userinfo_distinct_from_none() {
    let with = parse_graceful("http://@example.com/").unwrap();
    assert_eq!(with.authority().unwrap().userinfo().unwrap().as_str(), "");

    let without = parse_graceful("http://example.com/").unwrap();
    assert!(without.authority().unwrap().userinfo().is_none());
}

#[test]
fn host_port_shortcuts_match_authority() {
    // Uri::host() / Uri::port() must agree with authority().host() /
    // authority().port() — they're shortcuts over the same data.
    for s in [
        "http://example.com/",
        "http://example.com:8080/",
        "http://alice:secret@example.com:8080/",
        "https://[2001:db8::1]:8443/p",
    ] {
        let u = parse_graceful(s).unwrap();
        let a = u.authority().unwrap();
        assert_eq!(u.host(), Some(a.host()), "host mismatch on {s:?}");
        assert_eq!(u.port(), a.port(), "port mismatch on {s:?}");
    }
}

// ----------------------------------------------------------------------
// path segment matching: contains_segments / PathSegment matchers
// ----------------------------------------------------------------------

#[test]
fn contains_segments_matches_whole_segment_runs() {
    let u = parse_graceful("/golang.org/x/mod/@v/list").unwrap();
    let p = u.path().unwrap();
    // present as whole segment(s), at any position
    assert!(p.contains_segments("@v"));
    assert!(p.contains_segments("mod/@v"));
    assert!(p.contains_segments("x"));
    // not a partial-segment match
    assert!(!p.contains_segments("@version"));
    assert!(!p.contains_segments("od/@v"));
    // empty needle is trivially contained
    assert!(p.contains_segments(""));
}

#[test]
fn contains_segments_is_decode_aware() {
    // `%2D` == `-`; the `/-/` registry marker must match decoded.
    let u = parse_graceful("/npm/%2D/rev").unwrap();
    assert!(u.path().unwrap().contains_segments("-"));
}

#[test]
fn segment_suffix_prefix_and_matches() {
    let u = parse_graceful("/dl/rails-7.1.0.gem").unwrap();
    let seg = u.path().unwrap().last_segment().unwrap();
    // only `.gem` is the real extension here
    for ext in [".gem", ".tgz", ".zip", ".nupkg"] {
        assert_eq!(seg.has_suffix(ext), ext == ".gem", "has_suffix({ext})");
    }
    assert!(seg.has_prefix("rails-"));
    assert!(seg.matches("rails-7.1.0.gem"));
    assert!(!seg.matches("rails-7.1.0.tgz"));
}

#[test]
fn segment_has_suffix_is_decode_aware() {
    // `%2E` == `.`; the suffix check decodes both sides.
    let u = parse_graceful("/pkg/widget%2Etgz").unwrap();
    let seg = u.path().unwrap().last_segment().unwrap();
    assert!(seg.has_suffix(".tgz"));
}
