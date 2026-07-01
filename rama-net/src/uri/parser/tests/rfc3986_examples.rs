//! RFC 3986 §1.1.2 — canonical example URIs straight from the spec.
//!
//! These are the worked examples shipped by RFC 3986; every URI parser
//! claiming RFC 3986 conformance must accept them and produce the
//! components shown in the spec.

use core::net::{IpAddr, Ipv4Addr};

use super::{lazy, parse_graceful, path_str, range_str};
use crate::Protocol;
use crate::address::{Domain, Host};

#[test]
fn ftp_example() {
    let u = parse_graceful("ftp://ftp.is.co.za/rfc/rfc1808.txt").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("ftp"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("ftp.is.co.za")));
    assert_eq!(path_str(l), "/rfc/rfc1808.txt");
}

#[test]
fn http_example() {
    let u = parse_graceful("http://www.ietf.org/rfc/rfc2396.txt").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme, Some(Protocol::HTTP));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(auth.host, Host::Name(Domain::from_static("www.ietf.org")));
    assert_eq!(path_str(l), "/rfc/rfc2396.txt");
}

#[test]
fn ldap_ipv6_example() {
    let u = parse_graceful("ldap://[2001:db8::7]/c=GB?objectClass?one").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("ldap"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V6("2001:db8::7".parse().unwrap()))
    );
    assert_eq!(path_str(l), "/c=GB");
    assert_eq!(range_str(l, l.query), Some("objectClass?one"));
}

#[test]
fn mailto_example() {
    let u = parse_graceful("mailto:John.Doe@example.com").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("mailto"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "John.Doe@example.com");
}

#[test]
fn news_example() {
    let u = parse_graceful("news:comp.infosystems.www.servers.unix").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("news"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "comp.infosystems.www.servers.unix");
}

#[test]
fn tel_example() {
    let u = parse_graceful("tel:+1-816-555-1212").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("tel"));
    assert!(l.authority.is_none());
    assert_eq!(path_str(l), "+1-816-555-1212");
}

#[test]
fn telnet_example() {
    let u = parse_graceful("telnet://192.0.2.16:80/").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("telnet"));
    let auth = l.authority.as_ref().unwrap();
    assert_eq!(
        auth.host,
        Host::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 16)))
    );
    assert_eq!(auth.port, crate::address::OptPort::Set(80));
    assert_eq!(path_str(l), "/");
}

#[test]
fn urn_example() {
    let u = parse_graceful("urn:oasis:names:specification:docbook:dtd:xml:4.1.2").unwrap();
    let l = lazy(&u);
    assert_eq!(l.scheme.as_ref().map(|p| p.as_str()), Some("urn"));
    assert!(l.authority.is_none());
    assert_eq!(
        path_str(l),
        "oasis:names:specification:docbook:dtd:xml:4.1.2"
    );
}
