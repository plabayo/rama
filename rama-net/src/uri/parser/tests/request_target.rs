//! Borrowed HTTP request-target validation and parser parity.

use super::super::{MAX_URI_LEN, validate_http_request_target};
use crate::uri::{Component, ParseError, Uri};

#[test]
fn borrowed_validator_accepts_each_http_request_target_form() {
    const NON_AUTHORITY: &[&[u8]] = &[
        b"*",
        b"/",
        b"/resource?q=1",
        "/café".as_bytes(),
        b"http://example.com/resource?q=1",
        b"custom+scheme://user@example.com:8443/path",
        b"urn:opaque",
        b"http:/single-slash",
        b"http://[2001:db8::1]:8080/",
        b"http://[v1.future]:8080/",
    ];
    for target in NON_AUTHORITY {
        assert!(
            validate_http_request_target(target, false).is_ok(),
            "{target:?}"
        );
    }

    const AUTHORITY: &[&[u8]] = &[
        b"example.com",
        b"example.com:443",
        b"user@example.com:443",
        b"127.0.0.1:80",
        b"[2001:db8::1]:443",
        b"[v1.future]:443",
    ];
    for target in AUTHORITY {
        assert!(
            validate_http_request_target(target, true).is_ok(),
            "{target:?}"
        );
    }
}

#[test]
fn borrowed_validator_rejects_non_http_target_shapes() {
    const NON_AUTHORITY: &[&[u8]] = &[
        b"",
        b"relative/path",
        b"http://[invalid]/",
        b"http://example.com:65536/",
        b"/path#fragment",
        b"http://example.com/path#fragment",
        b"/bad\ttarget",
    ];
    for target in NON_AUTHORITY {
        assert!(
            validate_http_request_target(target, false).is_err(),
            "{target:?}"
        );
    }

    const AUTHORITY: &[&[u8]] = &[
        b"",
        b"example.com/path",
        b"example.com?query",
        b"example.com#fragment",
        b":443",
        b"[2001:db8::1",
        b"[2001:db8::1]suffix",
        b"example.com:65536",
        b"bad host:443",
    ];
    for target in AUTHORITY {
        assert!(
            validate_http_request_target(target, true).is_err(),
            "{target:?}"
        );
    }
}

#[test]
fn borrowed_authority_validation_matches_regular_parsing() {
    const CASES: &[&[u8]] = &[
        b"example.com",
        b"example.com:",
        b"example.com:443",
        b"user@@example.com:443",
        b"127.0.0.1:80",
        b"[2001:db8::1]:443",
        b"[vF.a:b]:443",
        b"exa%6Dple.com:443",
        "café.example:443".as_bytes(),
        b":443",
        b"[2001:db8::1",
        b"[fe80::1%25eth0]:443",
        b"[v.future]:443",
        b"example.com:65536",
        b"bad\\host:443",
    ];

    for target in CASES {
        let borrowed = validate_http_request_target(target, true);
        let parsed = Uri::parse_authority_form(*target);
        assert_eq!(borrowed.is_ok(), parsed.is_ok(), "{target:?}");
    }
}

#[test]
fn borrowed_non_authority_validation_matches_regular_parsing() {
    const CASES: &[&[u8]] = &[
        b"*",
        b"/",
        b"/resource?q=1",
        "/café".as_bytes(),
        b"http://example.com/resource?q=1",
        b"custom+scheme://user@example.com:8443/path",
        b"http://[2001:db8::1]:8080/",
        b"http://[v1.future]:8080/",
        b"relative/path",
        b"urn:opaque",
        b"http:/missing-slash",
        b"http://[invalid]/",
        b"http://example.com:65536/",
        b"/bad\ttarget",
    ];

    for target in CASES {
        let borrowed = validate_http_request_target(target, false);
        let parsed = Uri::parse(*target).and_then(|uri| {
            if uri.fragment().is_some() {
                Err(ParseError::InvalidComponent(Component::Authority))
            } else {
                Ok(uri)
            }
        });
        assert_eq!(borrowed.is_ok(), parsed.is_ok(), "{target:?}");
    }
}

#[test]
fn borrowed_validator_enforces_uri_length_limit() {
    let at_limit = vec![b'/'; MAX_URI_LEN];
    validate_http_request_target(&at_limit, false).unwrap();

    let over_limit = vec![b'/'; MAX_URI_LEN + 1];
    assert!(matches!(
        validate_http_request_target(&over_limit, false),
        Err(ParseError::TooLong { len }) if len == MAX_URI_LEN + 1
    ));
}

#[test]
fn borrowed_validator_enforces_scheme_length_limit() {
    let mut at_limit = vec![b'a'; crate::proto::MAX_SCHEME_LEN];
    at_limit.extend_from_slice(b"://example.com/");
    validate_http_request_target(&at_limit, false).unwrap();

    let mut over_limit = vec![b'a'; crate::proto::MAX_SCHEME_LEN + 1];
    over_limit.extend_from_slice(b"://example.com/");
    assert!(matches!(
        validate_http_request_target(&over_limit, false),
        Err(ParseError::InvalidComponent(Component::Scheme))
    ));
}
