//! `Display` impl on [`Uri`] — round-trip from parse + format.

use rama_core::bytes::BytesMut;

use super::super::super::UriInner;
use super::super::super::owned::OwnedUriRef;
use super::parse_graceful;
use crate::Protocol;
use crate::address::{Authority, Domain, Host, HostWithOptPort, UserInfo};
use crate::uri::{Fragment, Query, Uri};

// ----------------------------------------------------------------------
// Lazy round-trip — parse then Display produces byte-identical output.
// ----------------------------------------------------------------------

#[test]
fn lazy_round_trip() {
    for input in [
        // origin-form
        "/",
        "/foo",
        "/foo/bar",
        "/foo?bar=1",
        "/foo?bar=1#section",
        "/path#frag",
        "/?",
        "/#",
        // absolute-form
        "https://example.com/",
        "https://example.com/path?q=1#f",
        "http://user:pass@example.com:8080/p",
        "https://[::1]:443/",
        // opaque
        "urn:isbn:0451450523",
        "mailto:user@example.com",
        "data:text/plain",
        // empty-path absolute
        "http://example.com",
    ] {
        let uri: Uri = parse_graceful(input).unwrap();
        assert_eq!(uri.to_string(), input, "round-trip mismatch");
    }
}

#[test]
fn asterisk_displays_as_star() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(uri.to_string(), "*");
}

// ----------------------------------------------------------------------
// Owned reassembly — construct OwnedUriRef directly and verify the
// component pieces are stitched together correctly.
// ----------------------------------------------------------------------

fn owned(o: OwnedUriRef) -> Uri {
    Uri {
        inner: UriInner::Owned(std::sync::Arc::new(o)),
    }
}

fn http_authority(host: &str, port: Option<u16>, userinfo: Option<&str>) -> Authority {
    Authority {
        user_info: userinfo.map(|s| UserInfo::try_from(s).unwrap()),
        address: HostWithOptPort {
            host: Host::Name(Domain::try_from(host).unwrap()),
            port,
        },
    }
}

#[test]
fn owned_origin_form_path_only() {
    let uri = owned(OwnedUriRef {
        path: BytesMut::from(&b"/foo"[..]),
        ..Default::default()
    });
    assert_eq!(uri.to_string(), "/foo");
}

#[test]
fn owned_origin_form_with_query_and_fragment() {
    let uri = owned(OwnedUriRef {
        path: BytesMut::from(&b"/p"[..]),
        query: Some(Query {
            bytes: BytesMut::from(&b"a=1"[..]),
        }),
        fragment: Some(Fragment {
            bytes: BytesMut::from(&b"sec"[..]),
        }),
        ..Default::default()
    });
    assert_eq!(uri.to_string(), "/p?a=1#sec");
}

#[test]
fn owned_absolute_form_full() {
    let uri = owned(OwnedUriRef {
        scheme: Some(Protocol::HTTPS),
        authority: Some(http_authority("example.com", Some(8443), Some("u:p"))),
        path: BytesMut::from(&b"/x"[..]),
        query: Some(Query {
            bytes: BytesMut::from(&b"q=1"[..]),
        }),
        fragment: None,
    });
    assert_eq!(uri.to_string(), "https://u:p@example.com:8443/x?q=1");
}

#[test]
fn owned_opaque_form_scheme_only() {
    // urn:isbn:0 — scheme + path, no authority.
    let uri = owned(OwnedUriRef {
        scheme: Some(Protocol::from_static("urn")),
        authority: None,
        path: BytesMut::from(&b"isbn:0"[..]),
        query: None,
        fragment: None,
    });
    assert_eq!(uri.to_string(), "urn:isbn:0");
}

#[test]
fn owned_empty_query_distinguished_from_no_query() {
    // ?-with-empty-content (`Some(empty)`) vs no `?` at all (`None`)
    // must produce different output — these are distinct URIs (§3.4).
    let with_q = owned(OwnedUriRef {
        path: BytesMut::from(&b"/p"[..]),
        query: Some(Query {
            bytes: BytesMut::new(),
        }),
        ..Default::default()
    });
    let no_q = owned(OwnedUriRef {
        path: BytesMut::from(&b"/p"[..]),
        query: None,
        ..Default::default()
    });
    assert_eq!(with_q.to_string(), "/p?");
    assert_eq!(no_q.to_string(), "/p");
}

#[test]
fn owned_empty_fragment_distinguished_from_no_fragment() {
    let with_f = owned(OwnedUriRef {
        path: BytesMut::from(&b"/p"[..]),
        fragment: Some(Fragment {
            bytes: BytesMut::new(),
        }),
        ..Default::default()
    });
    let no_f = owned(OwnedUriRef {
        path: BytesMut::from(&b"/p"[..]),
        fragment: None,
        ..Default::default()
    });
    assert_eq!(with_f.to_string(), "/p#");
    assert_eq!(no_f.to_string(), "/p");
}
