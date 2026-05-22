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

// ----------------------------------------------------------------------
// Debug — userinfo password redaction (audit H3)
//
// `Display` is wire-faithful (intentionally) but `Debug` MUST NOT leak
// credentials through tracing spans, panic messages, or `dbg!`. The
// password portion of any userinfo is rendered as `***`.
// ----------------------------------------------------------------------

#[test]
fn debug_redacts_lazy_uri_password() {
    let u = parse_graceful("http://alice:secret@example.com/p").unwrap();
    let s = format!("{u:?}");
    assert!(!s.contains("secret"), "debug leaked password: {s}");
    assert!(s.contains("alice"));
    assert!(s.contains("***"));
    assert!(s.contains("example.com"));
}

#[test]
fn debug_preserves_userinfo_with_no_password() {
    // Username-only userinfo carries no credential; Debug emits it raw.
    let u = parse_graceful("http://alice@example.com/p").unwrap();
    let s = format!("{u:?}");
    assert!(s.contains("alice@"), "user-only userinfo dropped: {s}");
    assert!(!s.contains("***"), "no password → no redaction marker: {s}");
}

#[test]
fn debug_omits_userinfo_section_when_absent() {
    let u = parse_graceful("http://example.com/p").unwrap();
    let s = format!("{u:?}");
    assert!(!s.contains('@'));
    assert!(!s.contains("***"));
    assert!(s.contains("example.com"));
}

#[test]
fn debug_redacts_owned_uri_password() {
    // Trigger Owned form via mutation, then verify Debug still redacts.
    let mut u = parse_graceful("http://alice:secret@example.com/p").unwrap();
    // Any mutating call upgrades to Owned.
    u.set_path("/new");
    let s = format!("{u:?}");
    assert!(!s.contains("secret"), "debug leaked password (Owned): {s}");
    assert!(s.contains("alice"));
    assert!(s.contains("***"));
}

#[test]
fn display_remains_wire_faithful_with_userinfo() {
    // Display is the wire form — userinfo is preserved verbatim. The
    // protective surface is `Debug`; the audit explicitly keeps Display
    // unchanged.
    let u = parse_graceful("http://alice:secret@example.com/p").unwrap();
    assert_eq!(u.to_string(), "http://alice:secret@example.com/p");
}

#[test]
fn debug_wraps_in_uri_marker() {
    // The `Uri("…")` wrapper is the documented Debug shape; pin it so
    // downstream log scrapers and snapshot tests can rely on the format.
    let u = parse_graceful("http://example.com/").unwrap();
    assert_eq!(format!("{u:?}"), r#"Uri("http://example.com/")"#);
}
