//! Curated corpus of non-HTTP URIs.
//!
//! `Uri` is for *any* RFC 3986 URI, not just HTTP. This file exercises the
//! parser on schemes that consumers may encounter in the wild.

use super::{lazy, parse_graceful, path_str, range_str, userinfo_str};
use crate::address::{Domain, Host};

// ----------------------------------------------------------------------
// Opaque-path schemes (no `//authority`, `urn:foo`-style)
// ----------------------------------------------------------------------

#[test]
fn urn_isbn() {
    let u = parse_graceful("urn:isbn:0451450523").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("urn"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "isbn:0451450523");
}

#[test]
fn mailto_simple() {
    let u = parse_graceful("mailto:user@example.com").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("mailto"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "user@example.com");
}

#[test]
fn mailto_with_subject_query() {
    let u = parse_graceful("mailto:user@example.com?subject=Hi&body=Hello").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("mailto"));
    assert_eq!(path_str(l), "user@example.com");
    assert_eq!(range_str(l, l.query), Some("subject=Hi&body=Hello"));
}

#[test]
fn data_text_plain() {
    let u = parse_graceful("data:text/plain,Hello").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("data"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "text/plain,Hello");
}

#[test]
fn data_base64_encoded() {
    let u = parse_graceful("data:image/png;base64,iVBORw0KGgo=").unwrap();
    let l = lazy(&u);
    assert_eq!(path_str(l), "image/png;base64,iVBORw0KGgo=");
}

#[test]
fn news_group() {
    let u = parse_graceful("news:comp.infosystems.www.servers.unix").unwrap();
    let l = lazy(&u);
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "comp.infosystems.www.servers.unix");
}

#[test]
fn tel_phone_number() {
    let u = parse_graceful("tel:+1-816-555-1212").unwrap();
    let l = lazy(&u);
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "+1-816-555-1212");
}

#[test]
fn geo_rfc5870() {
    // RFC 5870 — geo URI scheme.
    let u = parse_graceful("geo:48.198634,16.371648").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("geo"));
    assert_eq!(path_str(l), "48.198634,16.371648");
}

#[test]
fn magnet_with_query() {
    // `magnet:?xt=…` — the magnet scheme has no path, just a query.
    let u = parse_graceful("magnet:?xt=urn:btih:abc123").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("magnet"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "");
    assert_eq!(range_str(l, l.query), Some("xt=urn:btih:abc123"));
}

#[test]
fn tag_rfc4151() {
    // RFC 4151 — tag URI scheme used for stable identifiers.
    let u = parse_graceful("tag:example.com,2006:foo").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("tag"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "example.com,2006:foo");
}

#[test]
fn xmpp_user() {
    // XMPP URI — `xmpp:user@host`. Opaque path; the `@` is just a literal
    // byte in the path.
    let u = parse_graceful("xmpp:user@example.com").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("xmpp"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "user@example.com");
}

// ----------------------------------------------------------------------
// Authority-bearing non-HTTP schemes
// ----------------------------------------------------------------------

#[test]
fn ftp_with_path() {
    let u = parse_graceful("ftp://ftp.example.org:2121/pub/").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("ftp"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(2121));
    assert_eq!(path_str(l), "/pub/");
}

#[test]
fn ws_socket() {
    let u = parse_graceful("ws://chat.example.com/socket").unwrap();
    let l = lazy(&u);
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Name(Domain::from_static("chat.example.com"))
    );
    assert_eq!(path_str(l), "/socket");
}

#[test]
fn wss_with_port() {
    let u = parse_graceful("wss://chat.example.com:8443/socket").unwrap();
    let auth = lazy(&u).authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(8443));
}

#[test]
fn git_protocol() {
    // `git://` is the legacy git smart protocol scheme.
    let u = parse_graceful("git://github.com/user/repo").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("git"));
    assert_eq!(path_str(l), "/user/repo");
}

#[test]
fn git_ssh_compound_scheme() {
    let u = parse_graceful("git+ssh://git@example.com:22/repo.git").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("git+ssh"));
    assert_eq!(userinfo_str(l), Some("git"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(22));
}

#[test]
fn ssh_with_port() {
    let u = parse_graceful("ssh://user@server.example.com:22/path").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some("user"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(22));
    assert_eq!(path_str(l), "/path");
}

#[test]
fn redis_with_db() {
    let u = parse_graceful("redis://localhost:6379/0").unwrap();
    let l = lazy(&u);
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("localhost")));
    assert_eq!(auth.port, crate::address::OptPort::Set(6379));
    assert_eq!(path_str(l), "/0");
}

#[test]
fn mongodb_with_userinfo() {
    let u = parse_graceful("mongodb://user:pass@db.example.com:27017/mydb").unwrap();
    let l = lazy(&u);
    assert_eq!(userinfo_str(l), Some("user:pass"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(27017));
    assert_eq!(path_str(l), "/mydb");
}

#[test]
fn coap_ipv6_iot() {
    // CoAP — RFC 7252. Common for IoT devices on link-local IPv6.
    let u = parse_graceful("coap://[::1]:5683/.well-known/core").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("coap"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(5683));
    assert_eq!(path_str(l), "/.well-known/core");
}

#[test]
fn s3_bucket() {
    let u = parse_graceful("s3://bucket-name/object/key").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("s3"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("bucket-name")));
    assert_eq!(path_str(l), "/object/key");
}

#[test]
fn telnet_ipv4() {
    let u = parse_graceful("telnet://192.0.2.16:80/").unwrap();
    let l = lazy(&u);
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.port, crate::address::OptPort::Set(80));
    assert_eq!(path_str(l), "/");
}

#[test]
fn ldap_ipv6_with_query() {
    let u = parse_graceful("ldap://[2001:db8::7]/c=GB?objectClass?one").unwrap();
    let l = lazy(&u);
    let auth = l.authority.as_ref().unwrap();
    assert!(matches!(auth.host, Host::Address(_)));
    assert_eq!(path_str(l), "/c=GB");
    assert_eq!(range_str(l, l.query), Some("objectClass?one"));
}

#[test]
fn custom_scheme() {
    // Arbitrary scheme names are valid per RFC 3986 §3.1.
    let u = parse_graceful("myproto://host/path").unwrap();
    assert_eq!(
        lazy(&u).scheme.as_ref().map(|p| p.as_str()),
        Some("myproto")
    );
}
