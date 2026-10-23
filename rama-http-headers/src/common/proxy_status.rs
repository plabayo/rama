//! `Proxy-Status` (RFC 9209).

use std::fmt::Write as _;

use base64::{
    Engine as _,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD},
    },
};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_http_types::structured_fields::{BareItem, ListEvent, ListMember, parse_list};
use rama_http_types::{HeaderName, HeaderValue, StatusCode};
use rama_utils::collections::smallvec::{SmallVec, smallvec};

// RFC 9651 §4.2.7: synthesize missing padding and tolerate nonzero pad bits.
static BYTE_SEQUENCE_DECODE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// How each intermediary handled a response ([RFC 9209]).
///
/// The first entry is the intermediary closest to the origin server, the last the one
/// closest to the user agent. An intermediary appends its own entry and should keep
/// the others. Origin servers must not send this field. Unknown parameters are ignored
/// when decoding.
///
/// [RFC 9209]: https://www.rfc-editor.org/rfc/rfc9209.html
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyStatus(SmallVec<[ProxyStatusEntry; 1]>);

/// One intermediary's [`ProxyStatus`] entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyStatusEntry {
    /// The service, hostname or address identifying the intermediary (not a product name).
    pub proxy: Box<str>,
    /// Why the intermediary failed, if it did.
    pub error: Option<ProxyErrorType>,
    /// The next hop: a hostname, IP address or alias.
    pub next_hop: Option<Box<str>>,
    /// The ALPN identifier of the protocol used to the next hop, as bytes: sent as a Token
    /// when it is one, as a Byte Sequence otherwise (RFC 9209 §2.1.3).
    pub next_protocol: Option<Box<[u8]>>,
    /// The status received from the next hop.
    pub received_status: Option<u16>,
    /// Further detail, for debugging; never sensitive.
    pub details: Option<Box<str>>,
    /// The DNS RCODE of a [`ProxyErrorType::DnsError`].
    pub rcode: Option<Box<str>>,
    /// The Extended DNS Error INFO-CODE of a [`ProxyErrorType::DnsError`].
    pub info_code: Option<u16>,
}

impl ProxyStatusEntry {
    /// An entry for `proxy` with no parameters.
    pub fn new(proxy: impl Into<Box<str>>) -> Self {
        Self {
            proxy: proxy.into(),
            error: None,
            next_hop: None,
            next_protocol: None,
            received_status: None,
            details: None,
            rcode: None,
            info_code: None,
        }
    }

    /// An entry for `proxy` reporting `error`.
    pub fn error(proxy: impl Into<Box<str>>, error: ProxyErrorType) -> Self {
        Self {
            error: Some(error),
            ..Self::new(proxy)
        }
    }
}

impl ProxyStatus {
    /// A field with a single entry.
    #[must_use]
    pub fn new(entry: ProxyStatusEntry) -> Self {
        // Usually only this intermediary's own entry, so it stays inline.
        Self(smallvec![entry])
    }

    /// The entries, closest to the origin first.
    #[must_use]
    pub fn entries(&self) -> &[ProxyStatusEntry] {
        &self.0
    }

    /// Append this intermediary's entry.
    pub fn push(&mut self, entry: ProxyStatusEntry) {
        self.0.push(entry);
    }
}

macro_rules! proxy_error_types {
    ($($(#[$doc:meta])* $variant:ident => $name:literal, $status:ident;)*) => {
        /// A proxy error type ([RFC 9209 §2.3]).
        ///
        /// [RFC 9209 §2.3]: https://www.rfc-editor.org/rfc/rfc9209.html#section-2.3
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum ProxyErrorType {
            $($(#[$doc])* $variant,)*
            /// An error type registered after RFC 9209 (a valid Token).
            Other(Box<str>),
        }

        impl ProxyErrorType {
            /// The registered name.
            #[must_use]
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $name,)*
                    Self::Other(name) => name,
                }
            }

            /// The status RFC 9209 recommends answering with, if any.
            #[must_use]
            pub fn recommended_status(&self) -> Option<StatusCode> {
                match self {
                    $(Self::$variant => proxy_error_types!(@status $status),)*
                    Self::Other(_) => None,
                }
            }

            fn from_token(token: &str) -> Self {
                match token {
                    $($name => Self::$variant,)*
                    other => Self::Other(other.into()),
                }
            }
        }
    };
    (@status none) => { None };
    (@status $status:ident) => { Some(StatusCode::$status) };
}

proxy_error_types! {
    /// `dns_timeout`: timeout resolving the next hop.
    DnsTimeout => "dns_timeout", GATEWAY_TIMEOUT;
    /// `dns_error`: DNS error resolving the next hop (see `rcode`, `info-code`).
    DnsError => "dns_error", BAD_GATEWAY;
    /// `destination_not_found`: no next hop could be determined.
    DestinationNotFound => "destination_not_found", INTERNAL_SERVER_ERROR;
    /// `destination_unavailable`: the next hop is considered unavailable.
    DestinationUnavailable => "destination_unavailable", SERVICE_UNAVAILABLE;
    /// `destination_ip_prohibited`: the next hop's address may not be used.
    DestinationIpProhibited => "destination_ip_prohibited", BAD_GATEWAY;
    /// `destination_ip_unroutable`: the next hop's address cannot be reached.
    DestinationIpUnroutable => "destination_ip_unroutable", BAD_GATEWAY;
    /// `connection_refused`: the next hop refused the connection.
    ConnectionRefused => "connection_refused", BAD_GATEWAY;
    /// `connection_terminated`: the next hop closed the connection.
    ConnectionTerminated => "connection_terminated", BAD_GATEWAY;
    /// `connection_timeout`: connecting to the next hop timed out.
    ConnectionTimeout => "connection_timeout", GATEWAY_TIMEOUT;
    /// `connection_read_timeout`: reading from the next hop timed out.
    ConnectionReadTimeout => "connection_read_timeout", GATEWAY_TIMEOUT;
    /// `connection_write_timeout`: writing to the next hop timed out.
    ConnectionWriteTimeout => "connection_write_timeout", GATEWAY_TIMEOUT;
    /// `connection_limit_reached`: the intermediary's connection limit was reached.
    ConnectionLimitReached => "connection_limit_reached", SERVICE_UNAVAILABLE;
    /// `tls_protocol_error`: a TLS protocol error with the next hop.
    TlsProtocolError => "tls_protocol_error", BAD_GATEWAY;
    /// `tls_certificate_error`: the next hop's certificate was rejected.
    TlsCertificateError => "tls_certificate_error", BAD_GATEWAY;
    /// `tls_alert_received`: the next hop sent a TLS alert.
    TlsAlertReceived => "tls_alert_received", BAD_GATEWAY;
    /// `http_request_error`: the request is invalid; answer with the applicable 4xx.
    HttpRequestError => "http_request_error", none;
    /// `http_request_denied`: the request was denied by policy.
    HttpRequestDenied => "http_request_denied", FORBIDDEN;
    /// `http_response_incomplete`: the next hop's response was incomplete.
    HttpResponseIncomplete => "http_response_incomplete", BAD_GATEWAY;
    /// `http_response_header_section_size`: the response header section was too large.
    HttpResponseHeaderSectionSize => "http_response_header_section_size", BAD_GATEWAY;
    /// `http_response_header_size`: a response header field line was too large.
    HttpResponseHeaderSize => "http_response_header_size", BAD_GATEWAY;
    /// `http_response_body_size`: the response body was too large.
    HttpResponseBodySize => "http_response_body_size", BAD_GATEWAY;
    /// `http_response_trailer_section_size`: the response trailer section was too large.
    HttpResponseTrailerSectionSize => "http_response_trailer_section_size", BAD_GATEWAY;
    /// `http_response_trailer_size`: a response trailer field line was too large.
    HttpResponseTrailerSize => "http_response_trailer_size", BAD_GATEWAY;
    /// `http_response_transfer_coding`: a transfer-coding error in the response.
    HttpResponseTransferCoding => "http_response_transfer_coding", BAD_GATEWAY;
    /// `http_response_content_coding`: a content-coding error in the response.
    HttpResponseContentCoding => "http_response_content_coding", BAD_GATEWAY;
    /// `http_response_timeout`: the next hop's response timed out.
    HttpResponseTimeout => "http_response_timeout", GATEWAY_TIMEOUT;
    /// `http_upgrade_failed`: the protocol upgrade failed.
    HttpUpgradeFailed => "http_upgrade_failed", BAD_GATEWAY;
    /// `http_protocol_error`: an HTTP protocol error with the next hop.
    HttpProtocolError => "http_protocol_error", BAD_GATEWAY;
    /// `proxy_internal_response`: the intermediary generated the response itself.
    ProxyInternalResponse => "proxy_internal_response", none;
    /// `proxy_internal_error`: an internal error in the intermediary.
    ProxyInternalError => "proxy_internal_error", INTERNAL_SERVER_ERROR;
    /// `proxy_configuration_error`: the intermediary is misconfigured.
    ProxyConfigurationError => "proxy_configuration_error", INTERNAL_SERVER_ERROR;
    /// `proxy_loop_detected`: the request looped through the intermediary.
    ProxyLoopDetected => "proxy_loop_detected", BAD_GATEWAY;
}

impl TypedHeader for ProxyStatus {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::PROXY_STATUS
    }
}

impl HeaderDecode for ProxyStatus {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let mut combined = Vec::new();
        for value in values {
            if !combined.is_empty() {
                combined.extend_from_slice(b", ");
            }
            combined.extend_from_slice(value.as_bytes());
        }
        let mut entries: SmallVec<[ProxyStatusEntry; 1]> = SmallVec::new();
        let mut invalid = false;
        parse_list(&combined, |event| match event {
            ListEvent::Member(ListMember::Item(BareItem::Token(name))) => {
                entries.push(ProxyStatusEntry::new(name));
            }
            ListEvent::Member(ListMember::Item(BareItem::String(name))) => {
                entries.push(ProxyStatusEntry::new(unescape(name)));
            }
            ListEvent::Member(_) => invalid = true,
            ListEvent::Parameter { key, value } => {
                if let Some(entry) = entries.last_mut() {
                    apply_parameter(entry, key, value);
                }
            }
        })
        .map_err(|_error| Error::invalid())?;
        if invalid || entries.is_empty() {
            return Err(Error::invalid());
        }
        Ok(Self(entries))
    }
}

fn apply_parameter(entry: &mut ProxyStatusEntry, key: &str, value: BareItem<'_>) {
    match (key, value) {
        ("error", BareItem::Token(token)) => entry.error = Some(ProxyErrorType::from_token(token)),
        ("next-hop", BareItem::Token(hop)) => entry.next_hop = Some(hop.into()),
        ("next-hop", BareItem::String(hop)) => entry.next_hop = Some(unescape(hop)),
        ("next-protocol", BareItem::Token(protocol)) => {
            entry.next_protocol = Some(protocol.as_bytes().into());
        }
        ("next-protocol", BareItem::ByteSequence(encoded)) => {
            entry.next_protocol = BYTE_SEQUENCE_DECODE
                .decode(encoded)
                .ok()
                .map(Vec::into_boxed_slice);
        }
        ("received-status", BareItem::Integer(status)) => {
            entry.received_status = u16::try_from(status).ok();
        }
        ("details", BareItem::String(details)) => entry.details = Some(unescape(details)),
        ("rcode", BareItem::String(rcode)) => entry.rcode = Some(unescape(rcode)),
        ("info-code", BareItem::Integer(code)) => entry.info_code = u16::try_from(code).ok(),
        // Unknown parameters and unexpected value types are ignored.
        _ => {}
    }
}

/// Decode a String's wire contents: `\"` and `\\` are its only escapes.
fn unescape(wire: &str) -> Box<str> {
    if !wire.contains('\\') {
        return wire.into();
    }
    let mut out = String::with_capacity(wire.len());
    let mut chars = wire.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(c);
        }
    }
    out.into_boxed_str()
}

impl HeaderEncode for ProxyStatus {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut out = String::new();
        for (index, entry) in self.0.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            write_token_or_string(&mut out, &entry.proxy);
            if let Some(error) = &entry.error {
                out.push_str(";error=");
                out.push_str(error.as_str());
            }
            if let Some(hop) = &entry.next_hop {
                out.push_str(";next-hop=");
                write_string(&mut out, hop);
            }
            if let Some(protocol) = &entry.next_protocol {
                out.push_str(";next-protocol=");
                match std::str::from_utf8(protocol) {
                    Ok(token) if is_token(token) => out.push_str(token),
                    _ => {
                        out.push(':');
                        out.push_str(&STANDARD.encode(protocol));
                        out.push(':');
                    }
                }
            }
            if let Some(status) = entry.received_status {
                _ = write!(out, ";received-status={status}");
            }
            if let Some(details) = &entry.details {
                out.push_str(";details=");
                write_string(&mut out, details);
            }
            if let Some(rcode) = &entry.rcode {
                out.push_str(";rcode=");
                write_string(&mut out, rcode);
            }
            if let Some(code) = entry.info_code {
                _ = write!(out, ";info-code={code}");
            }
        }
        if let Ok(value) = HeaderValue::try_from(out) {
            values.extend(std::iter::once(value));
        }
    }
}

/// RFC 9651 §3.3.4 Token.
fn is_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'*')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&b))
}

fn write_token_or_string(out: &mut String, value: &str) {
    if is_token(value) {
        out.push_str(value);
    } else {
        write_string(out, value);
    }
}

/// RFC 9651 §3.3.3 String: printable ASCII, escaping `"` and `\`; anything else is dropped.
fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars().filter(|c| (' '..='~').contains(c)) {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMapExt;
    use rama_http_types::HeaderMap;

    fn round_trip(status: &ProxyStatus) -> (String, Option<ProxyStatus>) {
        let mut headers = HeaderMap::new();
        headers.typed_insert(status.clone());
        let wire = headers[&rama_http_types::header::PROXY_STATUS]
            .to_str()
            .unwrap()
            .to_owned();
        (wire, headers.typed_get())
    }

    #[test]
    fn encodes_and_decodes_entries_with_parameters() {
        let mut dns = ProxyStatusEntry::error("masque.example", ProxyErrorType::DnsError);
        dns.next_hop = Some("target.example".into());
        dns.rcode = Some("NXDOMAIN".into());
        dns.info_code = Some(3);
        let mut denied = ProxyStatusEntry::error("edge proxy", ProxyErrorType::HttpRequestDenied);
        denied.details = Some("quote \" and backslash \\".into());
        denied.received_status = Some(403);
        denied.next_protocol = Some(b"h3".as_slice().into());
        let status = ProxyStatus(smallvec![dns, denied]);
        let (wire, decoded) = round_trip(&status);
        assert_eq!(
            wire,
            "masque.example;error=dns_error;next-hop=\"target.example\";rcode=\"NXDOMAIN\";info-code=3, \
             \"edge proxy\";error=http_request_denied;next-protocol=h3;received-status=403;\
             details=\"quote \\\" and backslash \\\\\""
        );
        assert_eq!(decoded, Some(status));
    }

    #[test]
    fn decodes_peer_fields_ignoring_unknown_parameters() {
        let mut headers = HeaderMap::new();
        headers.append(
            &rama_http_types::header::PROXY_STATUS,
            HeaderValue::from_static("origin-side;error=dns_timeout"),
        );
        headers.append(
            &rama_http_types::header::PROXY_STATUS,
            HeaderValue::from_static("\"client side\";error=future_error;future=1;next-hop=hop"),
        );
        let status: ProxyStatus = headers.typed_get().unwrap();
        assert_eq!(status.entries().len(), 2);
        assert_eq!(status.entries()[0].error, Some(ProxyErrorType::DnsTimeout));
        assert_eq!(&*status.entries()[1].proxy, "client side");
        assert_eq!(
            status.entries()[1].error,
            Some(ProxyErrorType::Other("future_error".into()))
        );
        assert_eq!(status.entries()[1].next_hop.as_deref(), Some("hop"));
    }

    #[test]
    fn rejects_invalid_fields() {
        for value in ["", "1", "(a b)", "a;error=", "a,", "\"unterminated"] {
            let mut headers = HeaderMap::new();
            headers.append(
                &rama_http_types::header::PROXY_STATUS,
                HeaderValue::from_static(value),
            );
            assert_eq!(headers.typed_get::<ProxyStatus>(), None, "{value}");
        }
    }

    #[test]
    fn recommended_statuses() {
        assert_eq!(
            ProxyErrorType::DnsError.recommended_status(),
            Some(StatusCode::BAD_GATEWAY)
        );
        assert_eq!(
            ProxyErrorType::DnsTimeout.recommended_status(),
            Some(StatusCode::GATEWAY_TIMEOUT)
        );
        assert_eq!(
            ProxyErrorType::DestinationIpProhibited.recommended_status(),
            Some(StatusCode::BAD_GATEWAY)
        );
        assert_eq!(
            ProxyErrorType::ProxyInternalResponse.recommended_status(),
            None
        );
        assert_eq!(ProxyErrorType::Other("x".into()).recommended_status(), None);
    }

    #[test]
    fn next_protocol_keeps_binary_alpn_identifiers() {
        for (alpn, wire) in [
            (&b"h2"[..], "p;next-protocol=h2"),
            (&b"\xff"[..], "p;next-protocol=:/w==:"),
            (&b"h3 draft"[..], "p;next-protocol=:aDMgZHJhZnQ=:"),
        ] {
            let mut entry = ProxyStatusEntry::new("p");
            entry.next_protocol = Some(alpn.into());
            let (encoded, decoded) = round_trip(&ProxyStatus::new(entry));
            assert_eq!(encoded, wire);
            assert_eq!(
                decoded.unwrap().entries()[0].next_protocol.as_deref(),
                Some(alpn)
            );
        }
    }

    #[test]
    fn next_protocol_decodes_lenient_byte_sequences() {
        for wire in [
            "p;next-protocol=:/w==:",
            "p;next-protocol=:/w:",
            "p;next-protocol=:/x==:",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                rama_http_types::header::PROXY_STATUS,
                HeaderValue::from_static(wire),
            );
            let decoded: ProxyStatus = headers.typed_get().unwrap();
            assert_eq!(
                decoded.entries()[0].next_protocol.as_deref(),
                Some(&b"\xff"[..]),
                "{wire}"
            );
            assert_eq!(round_trip(&decoded).0, "p;next-protocol=:/w==:");
        }
    }
}
