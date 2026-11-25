//! Request targets as received and as sent, shared by the HTTP/1, HTTP/2 and HTTP/3 codecs.

use std::net::IpAddr;

use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::{
    HeaderMap, HeaderValue,
    header::{self, Entry, hop_by_hop::connection_header_names},
};
use rama_net::{
    Protocol,
    address::{Authority, AuthorityRef, HostRef},
    uri::Uri,
};
use rama_utils::bytes::trim_ows;

/// A received `:authority`: the URI grammar's reg-name, raw UTF-8 included, but never an empty
/// host, which no `Host` could name.
pub(crate) fn received_authority(value: &str) -> Option<Authority> {
    Authority::try_from(value)
        .ok()
        .filter(|authority| !authority.address.host.is_empty())
}

/// Several `Host` lines leave the routed authority ambiguous, so a decoder refuses them before
/// normalizing (RFC 9112 §3.2: a request smuggling and cache poisoning vector).
pub(crate) fn several_hosts(headers: &HeaderMap) -> bool {
    headers.get_all(header::HOST).iter().nth(1).is_some()
}

/// Reconciles a received target's single `Host` with its request-target authority, so services
/// and later hops see one: HTTP-family userinfo is dropped, and `Host` names the URI authority
/// (as RFC 9112 §3.2.2 requires of HTTP/1 proxies). `Host` is read with the grammar received
/// authorities follow, raw UTF-8 included. Decoders refuse several `Host` lines first.
/// `authority_sensitive` is the never-index flag of the pseudo-header the URI authority came from.
pub(crate) fn normalize_received(
    uri: &mut Uri,
    headers: &mut HeaderMap,
    authority_sensitive: bool,
) {
    // RFC 9110 §4.2.4: the HTTP family, and scheme-less CONNECT, never carry userinfo.
    if uri.userinfo().is_some() && uri.scheme().is_none_or(Protocol::is_http_based) {
        match uri.authority().filter(|_| uri.scheme().is_none()) {
            // An authority-form target is rebuilt as one, not as a `//host` reference.
            Some(authority) => {
                let mut authority = authority.into_owned();
                authority.user_info = None;
                *uri = Uri::from_authority_form(authority);
            }
            None => {
                uri.unset_user_info();
            }
        }
    }
    if let Some(host) = replacement_host(uri.authority(), headers, authority_sensitive) {
        set_host(headers, host);
    }
}

/// Why an asterisk target's authority could not become its `Host`.
pub(crate) enum AsteriskHostError {
    InvalidAuthority,
    TooManyFields,
}

/// An asterisk target's URI cannot hold its received authority, so it becomes `Host`, winning
/// over a disagreeing one as a URI authority does: `OPTIONS *` reads alike on every version.
pub(crate) fn asterisk_host(
    authority: &[u8],
    headers: &mut HeaderMap,
    authority_sensitive: bool,
) -> Result<(), AsteriskHostError> {
    if let Ok(parsed) = AuthorityRef::parse(authority) {
        reconcile_host(parsed, headers, authority_sensitive);
    }
    // `Host` is all that carries the authority now, so it keeps its never-index flag.
    if authority_sensitive && let Some(host) = headers.get_mut(header::HOST) {
        host.set_sensitive(true);
    }
    if !headers.contains_key(header::HOST) {
        let mut host = HeaderValue::from_bytes(authority)
            .map_err(|_error| AsteriskHostError::InvalidAuthority)?;
        host.set_sensitive(authority_sensitive);
        headers
            .try_insert(header::HOST, host)
            .map_err(|_error| AsteriskHostError::TooManyFields)?;
    }
    Ok(())
}

/// [`normalize_received`]'s `Host` rule for an authority the URI cannot hold.
fn reconcile_host(authority: AuthorityRef<'_>, headers: &mut HeaderMap, authority_sensitive: bool) {
    if let Some(host) = replacement_host(Some(authority), headers, authority_sensitive) {
        set_host(headers, host);
    }
}

fn replacement_host(
    authority: Option<AuthorityRef<'_>>,
    headers: &HeaderMap,
    authority_sensitive: bool,
) -> Option<HeaderValue> {
    let values = headers.get_all(header::HOST);
    let host_sensitive = values.iter().any(HeaderValue::is_sensitive);
    // A Host derived from the authority keeps both never-index restrictions.
    let derived_sensitive = host_sensitive || authority_sensitive;
    let mut hosts = values.iter();
    // Several lines never get here: decoders refuse them.
    let (Some(host), None) = (hosts.next(), hosts.next()) else {
        return None;
    };
    let parsed = AuthorityRef::parse(host.as_bytes()).ok();
    match (authority, parsed) {
        (Some(authority), parsed)
            if parsed.is_none_or(|parsed| {
                parsed.userinfo().is_some() || !same_address(authority, parsed)
            }) =>
        {
            host_value(authority, derived_sensitive)
        }
        (None, Some(parsed)) if parsed.userinfo().is_some() => host_value(parsed, host_sensitive),
        _ => None,
    }
}

/// Replaces every Host line through the first one's entry, keeping its name spelling and position.
fn set_host(headers: &mut HeaderMap, host: HeaderValue) {
    match headers.entry(header::HOST) {
        Entry::Occupied(mut entry) => {
            entry.insert(host);
        }
        Entry::Vacant(entry) => {
            entry.insert(host);
        }
    }
}

/// The `Host` of an outgoing request, as an encoder may use it.
pub(crate) enum OutgoingHost<'a> {
    /// No Host field is present.
    Absent,
    /// One line without userinfo, parseable as a received authority once its outer
    /// whitespace is trimmed, as HTTP/2 and HTTP/3 send it.
    Usable {
        /// The trimmed value: what is parsed is what is sent.
        bytes: &'a [u8],
        /// The backing value, shared when the encoder stores its bytes separately.
        value: &'a HeaderValue,
        /// The authority parsed from the trimmed bytes.
        parsed: AuthorityRef<'a>,
    },
    /// Unparseable, carrying userinfo, or several lines: never sent next to a URI authority.
    Unusable,
}

pub(crate) fn outgoing_host(headers: &HeaderMap) -> OutgoingHost<'_> {
    let mut hosts = headers.get_all(header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (None, _) => OutgoingHost::Absent,
        (Some(host), None) => {
            let bytes = trim_ows(host.as_bytes());
            match AuthorityRef::parse(bytes) {
                Ok(parsed) if parsed.userinfo().is_none() => OutgoingHost::Usable {
                    bytes,
                    value: host,
                    parsed,
                },
                _ => OutgoingHost::Unusable,
            }
        }
        _ => OutgoingHost::Unusable,
    }
}

pub(crate) fn normalized_outgoing_host(headers: &HeaderMap) -> Option<HeaderValue> {
    let OutgoingHost::Usable {
        bytes,
        value,
        parsed,
    } = outgoing_host(headers)
    else {
        return None;
    };
    if matches!(parsed.host(), HostRef::Address(IpAddr::V6(_))) && bytes.first() != Some(&b'[') {
        return host_value(parsed, value.is_sensitive());
    }
    if bytes.len() == value.as_bytes().len() {
        return None;
    }
    let bytes = Bytes::from(value.clone()).slice_ref(bytes);
    let mut trimmed = HeaderValue::from_maybe_shared(bytes).ok()?;
    trimmed.set_sensitive(value.is_sensitive());
    Some(trimmed)
}

pub(crate) fn normalize_outgoing_host(headers: &mut HeaderMap) {
    if let Some(value) = normalized_outgoing_host(headers) {
        set_host(headers, value);
    }
}

/// The HTTP/1 form of the H2/H3 rule that one authority reaches the wire: an unusable
/// `Host` gives way to the URI authority. `false` when there is none to send instead.
pub(crate) fn repair_outgoing_h1_host(uri: &Uri, headers: &mut HeaderMap) -> bool {
    normalize_outgoing_host(headers);
    let nominated = headers.contains_key(header::CONNECTION)
        && connection_header_names(headers).any(|name| name == header::HOST);
    if nominated {
        // The next intermediary would strip a nominated `Host` (RFC 9110 §7.6.1).
        unnominate_host(headers);
    }
    let nominated = nominated && headers.contains_key(header::HOST);
    if !nominated && !matches!(outgoing_host(headers), OutgoingHost::Unusable) {
        return true;
    }
    let sensitive = headers
        .get_all(header::HOST)
        .iter()
        .any(HeaderValue::is_sensitive);
    match uri
        .authority()
        .and_then(|authority| host_value(authority, sensitive))
    {
        Some(host) => {
            set_host(headers, host);
            true
        }
        None => false,
    }
}

/// Removes the `host` option from every `Connection` line, in place, keeping the other options
/// as spelled; a line left without options is dropped, the others keep their position.
fn unnominate_host(headers: &mut HeaderMap) {
    headers.retain_values(header::CONNECTION, |value| {
        match without_host_option(value) {
            Some(kept) if kept.is_empty() => false,
            Some(kept) => {
                *value = kept;
                true
            }
            None => true,
        }
    });
}

/// `value` without its `host` members, or `None` when it has none.
fn without_host_option(value: &HeaderValue) -> Option<HeaderValue> {
    let is_host = |member: &[u8]| trim_ows(member).eq_ignore_ascii_case(b"host");
    let members = || value.as_bytes().split(|byte| *byte == b',');
    if !members().any(is_host) {
        return None;
    }
    if !members().any(|member| !is_host(member) && !trim_ows(member).is_empty()) {
        let mut empty = HeaderValue::from_static("");
        empty.set_sensitive(value.is_sensitive());
        return Some(empty);
    }
    let mut line = BytesMut::with_capacity(value.len());
    for (index, member) in members().filter(|member| !is_host(member)).enumerate() {
        if index > 0 {
            line.extend_from_slice(b",");
        }
        line.extend_from_slice(member);
    }
    let line = line.freeze();
    let line = line.slice_ref(trim_ows(&line));
    // The kept bytes come from a valid value, so they form one too.
    let mut kept =
        HeaderValue::from_maybe_shared(line).unwrap_or_else(|_| HeaderValue::from_static(""));
    kept.set_sensitive(value.is_sensitive());
    Some(kept)
}

/// Whether an outgoing `:authority` takes the `Host` bytes: a `Host` naming another host or port
/// is the wire authority (as with curl), and a matching one is sent exactly (RFC 9114 §4.3.1)
/// unless the URI adds userinfo, which `Host` cannot carry.
pub(crate) fn host_is_wire_authority(projected: AuthorityRef<'_>, host: AuthorityRef<'_>) -> bool {
    !same_address(projected, host) || projected.userinfo().is_none()
}

/// Same host and port; an empty port (`h:`) differs from none, so `:authority` and `Host` round-trip.
fn same_address(a: AuthorityRef<'_>, b: AuthorityRef<'_>) -> bool {
    a.host() == b.host() && a.port() == b.port()
}

fn host_value(authority: AuthorityRef<'_>, sensitive: bool) -> Option<HeaderValue> {
    let mut address = String::new();
    authority.write_address(&mut address).ok()?;
    // Raw UTF-8 stays raw, as received authorities and the typed `Host` header keep it.
    let mut value = HeaderValue::try_from(address.into_bytes()).ok()?;
    value.set_sensitive(sensitive);
    Some(value)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use rama_http_types::HeaderName;

    use super::*;

    /// A `Host` that is the only authority is read with the received grammar too: raw UTF-8
    /// with userinfo loses the userinfo, as an ASCII one does.
    #[test]
    fn raw_utf8_hosts_without_a_uri_authority_lose_their_userinfo() {
        let mut uri = Uri::parse("/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_bytes("user@\u{fffd}.example".as_bytes()).unwrap(),
        );
        normalize_received(&mut uri, &mut headers, false);
        assert_eq!(
            headers[header::HOST].as_bytes(),
            "\u{fffd}.example".as_bytes()
        );
    }

    fn normalized(uri: &str, hosts: &[&str]) -> (String, Vec<String>) {
        let mut uri = Uri::parse(uri).unwrap();
        let mut headers = HeaderMap::new();
        for host in hosts {
            headers.append(header::HOST, HeaderValue::from_str(host).unwrap());
        }
        normalize_received(&mut uri, &mut headers, false);
        let hosts = headers
            .get_all(header::HOST)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        (uri.to_string(), hosts)
    }

    #[test]
    fn received_targets_name_one_authority() {
        for (uri, hosts, expected_uri, expected_hosts) in [
            // Matching values are kept byte for byte.
            (
                "https://example.com/",
                &["EXAMPLE.com"][..],
                "https://example.com/",
                &["EXAMPLE.com"][..],
            ),
            (
                "https://example.com:2/",
                &["example.com:02"],
                "https://example.com:2/",
                &["example.com:02"],
            ),
            ("https://example.com/", &[], "https://example.com/", &[]),
            // HTTP-family userinfo is dropped; other schemes keep theirs.
            (
                "https://user:pw@example.com/",
                &["example.com"],
                "https://example.com/",
                &["example.com"],
            ),
            ("wss://user@example.com/", &[], "wss://example.com/", &[]),
            (
                "ftp://user@example.com/f",
                &["example.com"],
                "ftp://user@example.com/f",
                &["example.com"],
            ),
            // Host always names the routed authority.
            (
                "https://example.com/",
                &["other.example"],
                "https://example.com/",
                &["example.com"],
            ),
            (
                "https://example.com/",
                &["user@example.com"],
                "https://example.com/",
                &["example.com"],
            ),
            (
                "https://example.com/",
                &["bad host"],
                "https://example.com/",
                &["example.com"],
            ),
            (
                "https://[::1]:8443/",
                &["other"],
                "https://[::1]:8443/",
                &["[::1]:8443"],
            ),
            // Without a URI authority, Host only loses userinfo.
            ("/", &["user@example.com:8080"], "/", &["example.com:8080"]),
            ("/", &["example.com"], "/", &["example.com"]),
        ] {
            let (uri_out, hosts_out) = normalized(uri, hosts);
            assert_eq!(uri_out, expected_uri, "{uri} {hosts:?}");
            assert_eq!(hosts_out, expected_hosts, "{uri} {hosts:?}");
        }
    }

    /// `h:` and `h` differ on the wire.
    #[test]
    fn an_empty_port_is_another_authority() {
        assert_eq!(
            normalized("https://example.com/", &["example.com:"]),
            (
                "https://example.com/".to_owned(),
                vec!["example.com".to_owned()]
            )
        );
        assert_eq!(
            normalized("https://example.com:/", &["example.com"]),
            (
                "https://example.com:/".to_owned(),
                vec!["example.com:".to_owned()]
            )
        );
        let authority = |value: &'static str| AuthorityRef::try_from(value).unwrap();
        assert!(host_is_wire_authority(
            authority("user@example.com"),
            authority("example.com:")
        ));
    }

    /// Derived and collapsed Hosts never lose a never-index restriction.
    #[test]
    fn normalization_keeps_every_sensitivity() {
        let host = |value: &'static str, sensitive: bool| {
            let mut value = HeaderValue::from_static(value);
            value.set_sensitive(sensitive);
            value
        };
        let run = |uri: &str, hosts: Vec<HeaderValue>, authority_sensitive: bool| {
            let mut uri = Uri::parse(uri).unwrap();
            let mut headers = HeaderMap::new();
            for value in hosts {
                headers.append(header::HOST, value);
            }
            normalize_received(&mut uri, &mut headers, authority_sensitive);
            let hosts: Vec<_> = headers.get_all(header::HOST).iter().cloned().collect();
            assert_eq!(hosts.len(), 1);
            (
                hosts[0].to_str().unwrap().to_owned(),
                hosts[0].is_sensitive(),
            )
        };
        let https = "https://private.example/";
        // Derived from a sensitive authority, or from any sensitive Host line.
        assert_eq!(
            run(https, vec![host("public.example", false)], true),
            ("private.example".to_owned(), true)
        );
        assert_eq!(
            run(https, vec![host("public.example", true)], false),
            ("private.example".to_owned(), true)
        );
        // A matching Host is not derived: it keeps its own flag.
        assert_eq!(
            run(https, vec![host("private.example", false)], true),
            ("private.example".to_owned(), false)
        );
        // Without a URI authority, a Host losing its userinfo keeps its restriction.
        assert_eq!(
            run("/", vec![host("user@a.example", true)], false),
            ("a.example".to_owned(), true)
        );
    }

    #[test]
    fn several_host_lines_are_detected() {
        let mut headers = HeaderMap::new();
        headers.append(header::HOST, HeaderValue::from_static("a.example"));
        assert!(!several_hosts(&headers));
        headers.append(header::HOST, HeaderValue::from_static("a.example"));
        assert!(several_hosts(&headers));
    }

    #[test]
    fn replaced_hosts_keep_their_sensitivity() {
        let mut uri = Uri::parse("https://example.com/").unwrap();
        let mut headers = HeaderMap::new();
        let mut host = HeaderValue::from_static("other.example");
        host.set_sensitive(true);
        headers.insert(header::HOST, host);
        normalize_received(&mut uri, &mut headers, false);
        assert!(headers[header::HOST].is_sensitive());
        assert_eq!(headers[header::HOST], "example.com");
    }

    /// A `Host` option is dropped even without a `Host` line, and a line emptied before a kept
    /// one is dropped without moving the kept line.
    #[test]
    fn host_options_leave_every_connection_line() {
        for (lines, expected) in [
            (
                &[("Connection", "host"), ("X-End", "1")][..],
                &[("X-End", "1")][..],
            ),
            (
                &[
                    ("Connection", "Host"),
                    ("Host", "example.test"),
                    ("connection", "keep-alive"),
                ],
                &[("Host", "example.test"), ("connection", "keep-alive")],
            ),
            (
                &[("Connection", ", Host,, x-hop ,"), ("Host", "example.test")],
                &[("Connection", ",, x-hop ,"), ("Host", "example.test")],
            ),
        ] {
            let mut headers = HeaderMap::new();
            for (name, value) in lines {
                headers.append(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_static(value),
                );
            }
            let uri = Uri::parse("http://example.test/").unwrap();
            assert!(repair_outgoing_h1_host(&uri, &mut headers));
            let sent: Vec<_> = headers
                .ordered_iter()
                .map(|(name, value)| (name.as_original_str(), value.to_str().unwrap()))
                .collect();
            let expected: Vec<_> = expected
                .iter()
                .map(|(name, value)| (Cow::Borrowed(*name), *value))
                .collect();
            assert_eq!(sent, expected, "{lines:?}");
        }
    }

    #[test]
    fn a_differing_host_is_the_wire_authority() {
        let authority = |value: &'static str| AuthorityRef::try_from(value).unwrap();
        assert!(host_is_wire_authority(
            authority("example.com"),
            authority("EXAMPLE.com")
        ));
        assert!(host_is_wire_authority(
            authority("example.com"),
            authority("other.example")
        ));
        assert!(host_is_wire_authority(
            authority("user@example.com"),
            authority("other.example")
        ));
        assert!(!host_is_wire_authority(
            authority("user@example.com"),
            authority("example.com")
        ));
    }
}
