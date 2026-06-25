//! HTTP wire-form writers on [`Uri`].

use rama_core::bytes::BytesMut;

use super::parse_graceful;
use crate::uri::{PathRef, QueryRef, Uri, WireError};

fn buf() -> BytesMut {
    BytesMut::new()
}

fn write_origin(uri: &Uri) -> Result<String, WireError> {
    let mut b = buf();
    uri.write_http_origin_form(&mut b)?;
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

fn write_absolute(uri: &Uri) -> Result<String, WireError> {
    let mut b = buf();
    uri.write_http_absolute_form(&mut b)?;
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

fn write_authority(uri: &Uri) -> Result<String, WireError> {
    let mut b = buf();
    uri.write_http_authority_form(&mut b)?;
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

fn write_h2_path(uri: &Uri) -> String {
    let mut b = buf();
    uri.write_h2_path(&mut b);
    String::from_utf8(b.to_vec()).unwrap()
}

fn write_h2_authority(uri: &Uri) -> Result<String, WireError> {
    let mut b = buf();
    uri.write_h2_authority(&mut b)?;
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

fn write_h2_scheme(uri: &Uri) -> Result<String, WireError> {
    let mut b = buf();
    uri.write_h2_scheme(&mut b)?;
    Ok(String::from_utf8(b.to_vec()).unwrap())
}

// ----------------------------------------------------------------------
// write_http_origin_form
// ----------------------------------------------------------------------

#[test]
fn origin_form_origin_uri() {
    let uri: Uri = parse_graceful("/foo?bar=1").unwrap();
    assert_eq!(write_origin(&uri).unwrap(), "/foo?bar=1");
}

#[test]
fn origin_form_strips_scheme_authority_and_fragment() {
    let uri: Uri = parse_graceful("https://user:pw@example.com:8080/p?q=1#frag").unwrap();
    assert_eq!(write_origin(&uri).unwrap(), "/p?q=1");
}

#[test]
fn origin_form_empty_path_normalises_to_slash() {
    let uri: Uri = parse_graceful("https://example.com").unwrap();
    assert_eq!(write_origin(&uri).unwrap(), "/");
}

#[test]
fn origin_form_no_query_no_question_mark() {
    let uri: Uri = parse_graceful("/foo").unwrap();
    assert_eq!(write_origin(&uri).unwrap(), "/foo");
}

#[test]
fn origin_form_asterisk_errors() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_origin(&uri), Err(WireError::AsteriskMismatch));
}

#[test]
fn origin_form_encodes_owned_raw_query_component_text() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.set_query(QueryRef::from_raw_str("a=1\r\nInjected: yes #frag").into_owned());

    assert_eq!(
        write_origin(&uri).unwrap(),
        "/p?a=1%0D%0AInjected:%20yes%20%23frag",
    );
}

#[test]
fn origin_form_direct_writers_preserve_valid_pct_and_escape_raw_text() {
    let mut uri: Uri = parse_graceful("/old").unwrap();
    uri.set_path(PathRef::from_raw_str("/raw space/%2F/%zz/%A"));
    uri.set_query(QueryRef::from_raw_str("q=%2F&bad=%zz&tail=%A").into_owned());

    assert_eq!(
        write_origin(&uri).unwrap(),
        "/raw%20space/%2F/%25zz/%25A?q=%2F&bad=%25zz&tail=%25A",
    );
}

// ----------------------------------------------------------------------
// write_http_absolute_form
// ----------------------------------------------------------------------

#[test]
fn absolute_form_strips_userinfo_and_fragment() {
    let uri: Uri = parse_graceful("https://user:pw@example.com:8080/p?q=1#frag").unwrap();
    assert_eq!(
        write_absolute(&uri).unwrap(),
        "https://example.com:8080/p?q=1",
    );
}

#[test]
fn absolute_form_no_authority_keeps_scheme_path() {
    // Opaque URI: scheme + path, no authority.
    let uri: Uri = parse_graceful("urn:isbn:0451450523").unwrap();
    assert_eq!(write_absolute(&uri).unwrap(), "urn:isbn:0451450523");
}

#[test]
fn absolute_form_empty_path_normalises_to_slash() {
    let uri: Uri = parse_graceful("https://example.com").unwrap();
    assert_eq!(write_absolute(&uri).unwrap(), "https://example.com/");
}

#[test]
fn absolute_form_origin_uri_errors_no_scheme() {
    let uri: Uri = parse_graceful("/foo").unwrap();
    assert_eq!(write_absolute(&uri), Err(WireError::NoScheme));
}

#[test]
fn absolute_form_asterisk_errors() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_absolute(&uri), Err(WireError::AsteriskMismatch));
}

#[test]
fn absolute_form_encodes_owned_raw_query_component_text() {
    let mut uri: Uri = parse_graceful("https://example.com/p").unwrap();
    uri.set_query(QueryRef::from_raw_str("a=1\r\nInjected: yes #frag").into_owned());

    assert_eq!(
        write_absolute(&uri).unwrap(),
        "https://example.com/p?a=1%0D%0AInjected:%20yes%20%23frag",
    );
}

// ----------------------------------------------------------------------
// write_http_authority_form
// ----------------------------------------------------------------------

#[test]
fn authority_form_host_only() {
    let uri: Uri = parse_graceful("https://example.com/path?q=1#frag").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "example.com");
}

#[test]
fn authority_form_host_port() {
    let uri: Uri = parse_graceful("https://example.com:8080/").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "example.com:8080");
}

#[test]
fn authority_form_strips_userinfo() {
    let uri: Uri = parse_graceful("https://user:pw@example.com:443/").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "example.com:443");
}

#[test]
fn authority_form_brackets_ipv6() {
    let uri: Uri = parse_graceful("https://[::1]:8443/").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "[::1]:8443");
}

#[test]
fn authority_form_brackets_ipv6_no_port() {
    let uri: Uri = parse_graceful("https://[2001:db8::1]/").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "[2001:db8::1]");
}

#[test]
fn authority_form_no_authority_errors() {
    let uri: Uri = parse_graceful("/foo").unwrap();
    assert_eq!(write_authority(&uri), Err(WireError::NoAuthority));
}

#[test]
fn authority_form_opaque_uri_errors() {
    // mailto: has no authority — scheme + opaque-path.
    let uri: Uri = parse_graceful("mailto:user@example.com").unwrap();
    assert_eq!(write_authority(&uri), Err(WireError::NoAuthority));
}

#[test]
fn authority_form_asterisk_errors() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_authority(&uri), Err(WireError::AsteriskMismatch));
}

// ----------------------------------------------------------------------
// write_h2_path
// ----------------------------------------------------------------------

#[test]
fn h2_path_origin_uri() {
    let uri: Uri = parse_graceful("/foo?q=1").unwrap();
    assert_eq!(write_h2_path(&uri), "/foo?q=1");
}

#[test]
fn h2_path_absolute_uri_strips_scheme_authority_fragment() {
    let uri: Uri = parse_graceful("https://example.com/p?q=1#frag").unwrap();
    assert_eq!(write_h2_path(&uri), "/p?q=1");
}

#[test]
fn h2_path_empty_path_normalises_to_slash() {
    let uri: Uri = parse_graceful("https://example.com").unwrap();
    assert_eq!(write_h2_path(&uri), "/");
}

#[test]
fn h2_path_asterisk_writes_star() {
    // RFC 9113 §8.3.1: asterisk-form requests carry `*` in :path.
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_h2_path(&uri), "*");
}

#[test]
fn h2_path_encodes_owned_raw_query_component_text() {
    let mut uri: Uri = parse_graceful("/p").unwrap();
    uri.set_query(QueryRef::from_raw_str("a=1\r\nInjected: yes #frag").into_owned());

    assert_eq!(write_h2_path(&uri), "/p?a=1%0D%0AInjected:%20yes%20%23frag",);
}

// ----------------------------------------------------------------------
// write_h2_authority
// ----------------------------------------------------------------------

#[test]
fn h2_authority_host_port() {
    let uri: Uri = parse_graceful("https://example.com:8080/path").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "example.com:8080");
}

#[test]
fn h2_authority_strips_userinfo() {
    let uri: Uri = parse_graceful("https://user:pw@example.com/").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "example.com");
}

#[test]
fn h2_authority_brackets_ipv6() {
    let uri: Uri = parse_graceful("https://[::1]:8443/").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "[::1]:8443");
}

#[test]
fn h2_authority_no_authority_errors() {
    let uri: Uri = parse_graceful("/foo").unwrap();
    assert_eq!(write_h2_authority(&uri), Err(WireError::NoAuthority));
}

#[test]
fn h2_authority_asterisk_errors() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_h2_authority(&uri), Err(WireError::AsteriskMismatch));
}

// ----------------------------------------------------------------------
// write_h2_scheme
// ----------------------------------------------------------------------

#[test]
fn h2_scheme_https() {
    let uri: Uri = parse_graceful("https://example.com/").unwrap();
    assert_eq!(write_h2_scheme(&uri).unwrap(), "https");
}

#[test]
fn h2_scheme_http() {
    let uri: Uri = parse_graceful("http://example.com/").unwrap();
    assert_eq!(write_h2_scheme(&uri).unwrap(), "http");
}

#[test]
fn h2_scheme_custom() {
    let uri: Uri = parse_graceful("ws://example.com/").unwrap();
    assert_eq!(write_h2_scheme(&uri).unwrap(), "ws");
}

#[test]
fn h2_scheme_no_scheme_errors() {
    let uri: Uri = parse_graceful("/foo").unwrap();
    assert_eq!(write_h2_scheme(&uri), Err(WireError::NoScheme));
}

#[test]
fn h2_scheme_asterisk_errors() {
    let uri: Uri = parse_graceful("*").unwrap();
    assert_eq!(write_h2_scheme(&uri), Err(WireError::AsteriskMismatch));
}

// ----------------------------------------------------------------------
// Buffer reuse — writers append, callers can build batches.
// ----------------------------------------------------------------------

#[test]
fn writers_append_not_overwrite() {
    let uri: Uri = parse_graceful("https://example.com/p").unwrap();
    let mut b = BytesMut::from(&b"prefix:"[..]);
    uri.write_http_origin_form(&mut b).unwrap();
    assert_eq!(&b[..], b"prefix:/p");
}

// ----------------------------------------------------------------------
// Host::Uninterpreted wire round-trip
//
// Bracketed IPvFuture and sub-delim reg-name hosts stay `Uninterpreted`
// through canonicalize and must round-trip through the wire writers
// byte-for-byte: the writer emits the preserved body and re-adds the
// `[...]` brackets for IP-literals.
// ----------------------------------------------------------------------

#[test]
fn authority_form_preserves_ipvfuture_brackets() {
    let uri: Uri = parse_graceful("https://[v1.fe80::a]:443/p").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "[v1.fe80::a]:443");
}

#[test]
fn authority_form_preserves_sub_delim_reg_name() {
    let uri: Uri = parse_graceful("https://tag,with,commas:8080/p").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "tag,with,commas:8080");
}

#[test]
fn h2_authority_preserves_ipvfuture_brackets() {
    let uri: Uri = parse_graceful("https://[v1.fe80::a]:443/p").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "[v1.fe80::a]:443");
}

#[test]
fn h2_authority_preserves_sub_delim_reg_name() {
    let uri: Uri = parse_graceful("https://tag,with,commas:8080/p").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "tag,with,commas:8080");
}

#[test]
fn h2_authority_brackets_ipv6_no_port() {
    // Sibling to `authority_form_brackets_ipv6_no_port` covering the
    // HTTP/2 :authority pseudo-header path.
    let uri: Uri = parse_graceful("https://[2001:db8::1]/").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "[2001:db8::1]");
}

#[test]
fn http_authority_form_preserves_empty_port_marker() {
    // Wire fidelity: `host:` (OptPort::Empty) round-trips through the
    // HTTP/1.1 authority-form writer. Call `canonicalize()` first if
    // you want the empty marker normalized away.
    let uri: Uri = parse_graceful("https://example.com:/p").unwrap();
    assert_eq!(write_authority(&uri).unwrap(), "example.com:");
}

#[test]
fn h2_authority_preserves_empty_port_marker() {
    let uri: Uri = parse_graceful("https://example.com:/p").unwrap();
    assert_eq!(write_h2_authority(&uri).unwrap(), "example.com:");
}

#[test]
fn http_authority_form_canonicalize_drops_empty_port() {
    let uri: Uri = parse_graceful("https://example.com:/p").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(write_authority(&canonical).unwrap(), "example.com");
}
