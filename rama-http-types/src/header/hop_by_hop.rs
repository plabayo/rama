//! Hop-by-hop HTTP header sanitation utilities.
//!
//! HTTP intermediaries consume connection-specific fields and must not copy
//! them blindly to the next hop. The context-aware sanitizers are the
//! recommended API for relays: they remove all source-hop metadata, then
//! re-originate only valid upgrade and request-trailer capabilities. The
//! `remove_*` functions remove those capabilities as well, for callers that
//! intentionally do not support them on the next hop.
//!
//! Proxy authentication fields are not removed unless they are explicitly
//! nominated by `Connection`. Whether a proxy consumes or relays credentials
//! depends on its role and is therefore a separate forwarding policy.
//!
//! A request and its response must use the same context:
//!
//! ```
//! use rama_http_types::{Request, Response, StatusCode, Version};
//! use rama_http_types::header::hop_by_hop::{
//!     HopByHopResponseDisposition, sanitize_hop_by_hop_request_headers,
//!     sanitize_hop_by_hop_response_headers,
//! };
//!
//! let mut request = Request::builder()
//!     .version(Version::HTTP_11)
//!     .header("connection", "close")
//!     .body(())?;
//! let context = sanitize_hop_by_hop_request_headers(&mut request);
//!
//! let mut response = Response::builder()
//!     .status(StatusCode::OK)
//!     .body(())?;
//! assert_eq!(
//!     sanitize_hop_by_hop_response_headers(&mut response, &context),
//!     HopByHopResponseDisposition::Forward,
//! );
//! # Ok::<(), rama_http_types::Error>(())
//! ```

use rama_core::telemetry::tracing;
use rama_utils::{
    byte_set::{set_ascii_alphanum, set_each},
    collections::smallvec::{IntoIter as SmallVecIntoIter, SmallVec},
};

use crate::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version, header};

const HOP_BY_HOP_HEADERS: [&HeaderName; 7] = [
    &header::CONNECTION,
    &header::PROXY_CONNECTION,
    &header::KEEP_ALIVE,
    &header::TE,
    &header::TRAILER,
    &header::TRANSFER_ENCODING,
    &header::UPGRADE,
];

const HTTP_TOKEN_BYTES: [bool; 256] =
    set_each(set_ascii_alphanum([false; 256]), b"!#$%&'*+-.^_`|~");

fn next_comma_separated_token(mut value: &[u8]) -> Option<(&[u8], &[u8])> {
    loop {
        let mut parts = value.splitn(2, |byte| *byte == b',');
        let token = parts.next()?.trim_ascii();
        let remaining = parts.next();
        if !token.is_empty() {
            return Some((token, remaining.unwrap_or_default()));
        }
        value = remaining?;
    }
}

fn comma_separated_tokens(value: &HeaderValue) -> impl Iterator<Item = &[u8]> {
    let mut remaining = value.as_bytes();
    std::iter::from_fn(move || {
        let (token, rest) = next_comma_separated_token(remaining)?;
        remaining = rest;
        Some(token)
    })
}

struct ConnectionHeaderNames {
    values: SmallVecIntoIter<[HeaderValue; 2]>,
    current: Option<HeaderValue>,
    offset: usize,
}

impl Iterator for ConnectionHeaderNames {
    type Item = HeaderName;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(value) = self.current.as_ref() else {
                self.current = self.values.next();
                self.offset = 0;
                self.current.as_ref()?;
                continue;
            };
            let bytes = value.as_bytes();
            let Some((token, remaining)) =
                next_comma_separated_token(bytes.get(self.offset..).unwrap_or_default())
            else {
                self.current = None;
                continue;
            };
            self.offset = bytes.len().saturating_sub(remaining.len());
            if let Ok(name) = HeaderName::from_bytes(token) {
                return Some(name);
            }
        }
    }
}

/// Return every syntactically valid field name nominated by `Connection`.
///
/// Invalid list members are ignored individually, so they cannot prevent a
/// valid sibling nomination from being removed. The returned iterator owns a
/// cheap snapshot of the `Connection` field values, so callers may mutate the
/// source map while consuming it.
pub fn connection_header_names(headers: &HeaderMap) -> impl Iterator<Item = HeaderName> + use<> {
    let values = headers
        .get_all(header::CONNECTION)
        .iter()
        .cloned()
        .collect::<SmallVec<[HeaderValue; 2]>>()
        .into_iter();
    ConnectionHeaderNames {
        values,
        current: None,
        offset: 0,
    }
}

/// Return known hop-by-hop field names and valid `Connection` nominations.
///
/// Known names are included even when absent from the map. The iterator owns
/// its nominations so callers may mutate the map while consuming it.
pub fn hop_by_hop_header_names(headers: &HeaderMap) -> impl Iterator<Item = HeaderName> + use<> {
    HOP_BY_HOP_HEADERS
        .into_iter()
        .cloned()
        .chain(connection_header_names(headers))
}

fn remove_field(headers: &mut HeaderMap, name: &HeaderName) {
    if headers.remove(name).is_some() {
        tracing::trace!("removed hop-by-hop header for name: {name}");
    }
}

fn remove_hop_by_hop_headers_with_nominations(
    headers: &mut HeaderMap,
    nominated: impl IntoIterator<Item = HeaderName>,
    known: &[&HeaderName],
) {
    for name in nominated {
        remove_field(headers, &name);
    }
    for name in known {
        remove_field(headers, name);
    }
}

/// Remove all hop-by-hop headers from an HTTP message.
///
/// In addition to the known connection-specific fields, this removes every
/// field nominated by `Connection`. Use [`HopByHopHeaderContext::take`] when
/// upgrade, trailer, or `TE: trailers` metadata has to be restored for a newly
/// originated hop.
pub fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    for name in hop_by_hop_header_names(headers) {
        remove_field(headers, &name);
    }
}

/// Remove request-side hop-by-hop fields without forwarding capabilities.
///
/// Use this when the next hop intentionally does not support upgrades or
/// request trailers.
pub fn remove_hop_by_hop_request_headers(headers: &mut HeaderMap) {
    remove_hop_by_hop_headers(headers);
}

/// Remove response-side hop-by-hop fields without forwarding capabilities.
///
/// Use this when the next hop intentionally does not support upgrades or
/// trailers.
pub fn remove_hop_by_hop_response_headers(headers: &mut HeaderMap) {
    remove_hop_by_hop_headers(headers);
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UpgradeProtocol {
    WebSocket(UpgradeProtocolVersion),
    H2c(UpgradeProtocolVersion),
    Http(UpgradeProtocolVersion),
    Tls(UpgradeProtocolVersion),
    Other { wire: Box<[u8]>, name_length: usize },
}

fn is_http_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|byte| HTTP_TOKEN_BYTES[*byte as usize])
}

fn supports_trailer_fields(version: Version) -> bool {
    matches!(
        version,
        Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UpgradeProtocolVersion {
    Unversioned,
    V1_0,
    V1_1,
    V1_2,
    V1_3,
    V2_0,
    V3_0,
    Other(Box<[u8]>),
}

impl UpgradeProtocolVersion {
    fn parse(value: Option<&[u8]>) -> Option<Self> {
        match value {
            None => Some(Self::Unversioned),
            Some(b"1.0") => Some(Self::V1_0),
            Some(b"1.1") => Some(Self::V1_1),
            Some(b"1.2") => Some(Self::V1_2),
            Some(b"1.3") => Some(Self::V1_3),
            Some(b"2.0") => Some(Self::V2_0),
            Some(b"3.0") => Some(Self::V3_0),
            Some(value) if is_http_token(value) => Some(Self::Other(value.into())),
            _ => None,
        }
    }
}

impl UpgradeProtocol {
    fn parse(value: &[u8]) -> Option<Self> {
        let name_length = value
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(value.len());
        let name = &value[..name_length];
        let version = match value.get(name_length..) {
            Some([]) => None,
            Some([b'/', version @ ..]) => Some(version),
            _ => return None,
        };
        if name.eq_ignore_ascii_case(b"websocket") {
            Some(Self::WebSocket(UpgradeProtocolVersion::parse(version)?))
        } else if name.eq_ignore_ascii_case(b"h2c") {
            Some(Self::H2c(UpgradeProtocolVersion::parse(version)?))
        } else if name.eq_ignore_ascii_case(b"http") {
            Some(Self::Http(UpgradeProtocolVersion::parse(version)?))
        } else if name.eq_ignore_ascii_case(b"tls") {
            Some(Self::Tls(UpgradeProtocolVersion::parse(version)?))
        } else if is_http_token(name) && version.is_none_or(is_http_token) {
            Some(Self::Other {
                wire: value.into(),
                name_length,
            })
        } else {
            None
        }
    }

    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::WebSocket(left), Self::WebSocket(right))
            | (Self::H2c(left), Self::H2c(right))
            | (Self::Http(left), Self::Http(right))
            | (Self::Tls(left), Self::Tls(right)) => left == right,
            (
                Self::Other {
                    wire: left,
                    name_length: left_name_length,
                },
                Self::Other {
                    wire: right,
                    name_length: right_name_length,
                },
            ) => {
                left[..*left_name_length].eq_ignore_ascii_case(&right[..*right_name_length])
                    && left.get(left_name_length + 1..) == right.get(right_name_length + 1..)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
struct Http1UpgradeIntent {
    fields: SmallVec<[(HeaderName, HeaderValue); 2]>,
    protocols: SmallVec<[UpgradeProtocol; 2]>,
}

/// Connection-specific metadata captured while sanitizing an HTTP message.
///
/// This type supports intermediaries that consume hop-by-hop fields and then
/// originate equivalent fields for the next hop. It deliberately retains only
/// valid HTTP/1.1 upgrade intent, `TE: trailers` capability, and non-nominated
/// trailer declarations.
#[derive(Clone, Debug, Default)]
pub struct HopByHopHeaderContext {
    nominated_headers: Box<[HeaderName]>,
    trailer_fields: Box<[(HeaderName, HeaderValue)]>,
    upgrade_intent: Option<Box<Http1UpgradeIntent>>,
    te_trailers: bool,
}

impl HopByHopHeaderContext {
    /// Capture connection-specific metadata without modifying the headers.
    #[must_use]
    pub fn capture(headers: &HeaderMap, version: Version) -> Self {
        let preserve_upgrade = version == Version::HTTP_11;
        let mut nominated_headers = Vec::new();
        let mut trailer_fields = Vec::new();
        let mut upgrade_fields = SmallVec::new();
        let mut upgrade_protocols = SmallVec::new();
        let mut te_trailers = false;
        let mut saw_connection_upgrade = false;
        let mut saw_connection_close = false;
        let mut saw_upgrade = false;
        let mut valid_connection = true;
        let mut valid_upgrade = true;

        for (name, value) in headers.ordered_iter() {
            if name == header::CONNECTION {
                for token in comma_separated_tokens(value) {
                    let Ok(nominated) = HeaderName::from_bytes(token) else {
                        valid_connection = false;
                        continue;
                    };
                    if nominated.as_str().eq_ignore_ascii_case("close") {
                        saw_connection_close = true;
                    }
                    if preserve_upgrade
                        && nominated == header::UPGRADE
                        && let Ok(value) = HeaderValue::from_bytes(token)
                    {
                        saw_connection_upgrade = true;
                        upgrade_fields.push((name.clone(), value));
                    }
                    nominated_headers.push(nominated);
                }
            } else if name == header::TRAILER && supports_trailer_fields(version) {
                trailer_fields.push((name.clone(), value.clone()));
            } else if name == header::TE && supports_trailer_fields(version) {
                te_trailers |= comma_separated_tokens(value)
                    .any(|token| token.eq_ignore_ascii_case(b"trailers"));
            } else if preserve_upgrade && name == header::UPGRADE {
                saw_upgrade = true;
                upgrade_fields.push((name.clone(), value.clone()));
                for protocol in comma_separated_tokens(value) {
                    match UpgradeProtocol::parse(protocol) {
                        Some(protocol) => upgrade_protocols.push(protocol),
                        None => valid_upgrade = false,
                    }
                }
            }
        }

        let upgrade_intent = if saw_connection_upgrade
            && !saw_connection_close
            && saw_upgrade
            && valid_connection
            && valid_upgrade
            && !upgrade_protocols.is_empty()
        {
            Some(Box::new(Http1UpgradeIntent {
                fields: upgrade_fields,
                protocols: upgrade_protocols,
            }))
        } else {
            None
        };
        if nominated_headers.contains(&header::TRAILER) {
            trailer_fields.clear();
        }
        Self {
            nominated_headers: nominated_headers.into_boxed_slice(),
            trailer_fields: trailer_fields.into_boxed_slice(),
            upgrade_intent,
            te_trailers,
        }
    }

    /// Capture connection-specific metadata and remove all hop-by-hop fields.
    #[must_use]
    pub fn take(headers: &mut HeaderMap, version: Version) -> Self {
        let context = Self::capture(headers, version);
        remove_hop_by_hop_headers_with_nominations(
            headers,
            context.nominated_headers.iter().cloned(),
            &HOP_BY_HOP_HEADERS,
        );
        context
    }

    /// Return the fields nominated by the original `Connection` header.
    #[must_use]
    pub fn nominated_headers(&self) -> &[HeaderName] {
        &self.nominated_headers
    }

    /// Restore captured `Trailer` fields for a target that supports trailers.
    ///
    /// An existing target field takes precedence over the captured fields.
    pub fn restore_trailer_headers(&self, headers: &mut HeaderMap, version: Version) {
        if !supports_trailer_fields(version) {
            return;
        }
        if headers.contains_key(header::TRAILER) {
            return;
        }
        for (name, value) in &self.trailer_fields {
            headers.append(name.clone(), value.clone());
        }
    }

    fn restore_request_te_header(&self, headers: &mut HeaderMap, version: Version) {
        remove_field(headers, &header::TE);
        if !self.te_trailers {
            return;
        }
        match version {
            Version::HTTP_11 => {
                headers.append(header::CONNECTION, HeaderValue::from_static("TE"));
                headers.insert(header::TE, HeaderValue::from_static("trailers"));
            }
            Version::HTTP_2 | Version::HTTP_3 => {
                headers.insert(header::TE, HeaderValue::from_static("trailers"));
            }
            _ => tracing::debug!(
                http.version = %version,
                "not restoring TE trailers for HTTP version without trailer support"
            ),
        }
    }

    fn restore_upgrade(&self, headers: &mut HeaderMap, version: Version) {
        remove_field(headers, &header::CONNECTION);
        remove_field(headers, &header::UPGRADE);
        if version != Version::HTTP_11 {
            return;
        }
        if let Some(intent) = &self.upgrade_intent {
            for (name, value) in &intent.fields {
                headers.append(name.clone(), value.clone());
            }
        }
    }

    fn restore_message_headers(
        &self,
        headers: &mut HeaderMap,
        version: Version,
        target_nominations: &[HeaderName],
    ) {
        if !target_nominations.contains(&header::TRAILER) {
            self.restore_trailer_headers(headers, version);
        }
        self.restore_upgrade(headers, version);
    }

    /// Restore response metadata needed to originate the next hop.
    ///
    /// This is intended for a transformation of the same response, such as
    /// adaptation. It does not correlate a response with its request; relays
    /// should use [`sanitize_hop_by_hop_response_headers`] for that validation.
    ///
    /// The target headers are expected to have been sanitized first. Trailer
    /// declarations remain removed when either the source or target nominated
    /// `Trailer` as connection-specific.
    pub fn restore_response(
        &self,
        headers: &mut HeaderMap,
        version: Version,
        target_nominations: &[HeaderName],
    ) {
        self.restore_message_headers(headers, version, target_nominations);
    }

    /// Restore metadata for an adapted or otherwise re-originated request.
    ///
    /// In addition to common message metadata, this restores the normalized
    /// `TE: trailers` capability required by the target HTTP version.
    pub fn restore_request(
        &self,
        headers: &mut HeaderMap,
        version: Version,
        target_nominations: &[HeaderName],
    ) {
        self.restore_message_headers(headers, version, target_nominations);
        self.restore_request_te_header(headers, version);
    }

    fn allows_upgrade_response(&self, response: &Self) -> bool {
        let (Some(request), Some(response)) = (&self.upgrade_intent, &response.upgrade_intent)
        else {
            return false;
        };
        response.protocols.iter().all(|selected| {
            request
                .protocols
                .iter()
                .any(|offered| offered.matches(selected))
        })
    }
}

/// Action a caller must take after sanitizing a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum HopByHopResponseDisposition {
    /// The response can be forwarded after sanitation.
    Forward,
    /// The invalid `101 Switching Protocols` response must be rejected.
    RejectUpgrade,
}

/// Sanitize an outbound request while preserving valid next-hop metadata.
///
/// The returned context must be supplied to
/// [`sanitize_hop_by_hop_response_headers`] so that an upgrade response is
/// retained only for a matching request.
#[must_use]
pub fn sanitize_hop_by_hop_request_headers<B>(request: &mut Request<B>) -> HopByHopHeaderContext {
    let version = request.version();
    let context = HopByHopHeaderContext::take(request.headers_mut(), version);
    context.restore_request(request.headers_mut(), version, &[]);
    context
}

/// Sanitize an outbound response using its corresponding request context.
///
/// Callers must reject the exchange when this returns
/// [`HopByHopResponseDisposition::RejectUpgrade`]; forwarding a stripped `101`
/// would violate HTTP/1.1 framing and desynchronize the connection state.
#[must_use = "a rejected upgrade must not be forwarded"]
pub fn sanitize_hop_by_hop_response_headers<B>(
    response: &mut Response<B>,
    request_context: &HopByHopHeaderContext,
) -> HopByHopResponseDisposition {
    let version = response.version();
    let status = response.status();
    let response_context = HopByHopHeaderContext::take(response.headers_mut(), version);
    response_context.restore_trailer_headers(response.headers_mut(), version);
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return HopByHopResponseDisposition::Forward;
    }
    if request_context.allows_upgrade_response(&response_context) {
        response_context.restore_upgrade(response.headers_mut(), version);
        HopByHopResponseDisposition::Forward
    } else {
        tracing::debug!(
            http.response.status = %status,
            http.version = %version,
            request.upgrade_intent = request_context.upgrade_intent.is_some(),
            request.upgrade_protocol_count = request_context
                .upgrade_intent
                .as_deref()
                .map_or(0, |intent| intent.protocols.len()),
            response.upgrade_intent = response_context.upgrade_intent.is_some(),
            response.upgrade_protocol_count = response_context
                .upgrade_intent
                .as_deref()
                .map_or(0, |intent| intent.protocols.len()),
            "rejecting invalid or uncorrelated HTTP protocol upgrade"
        );
        HopByHopResponseDisposition::RejectUpgrade
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Vec<&'a [u8]> {
        headers
            .get_all(name)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect()
    }

    #[test]
    fn connection_parser_keeps_valid_members_beside_invalid_members() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"close, \xff").unwrap(),
        );
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static(" , x-hop, keep-alive, "),
        );
        headers.append(header::CONNECTION, HeaderValue::from_static("TE"));

        assert_eq!(
            connection_header_names(&headers).collect::<Vec<_>>(),
            [
                HeaderName::from_static("close"),
                HeaderName::from_static("x-hop"),
                HeaderName::from_static("keep-alive"),
                HeaderName::from_static("te"),
            ]
        );
    }

    #[test]
    fn upgrade_protocol_token_validation_matches_http_grammar() {
        assert!(!is_http_token(b""));
        for byte in u8::MIN..=u8::MAX {
            let expected = byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte);
            assert_eq!(is_http_token(&[byte]), expected, "token byte {byte:#04x}");
        }
    }

    #[test]
    fn common_upgrade_protocols_use_inline_variants() {
        for (wire, expected) in [
            (
                b"WebSocket".as_slice(),
                UpgradeProtocol::WebSocket(UpgradeProtocolVersion::Unversioned),
            ),
            (
                b"H2C".as_slice(),
                UpgradeProtocol::H2c(UpgradeProtocolVersion::Unversioned),
            ),
            (
                b"HTTP/1.0".as_slice(),
                UpgradeProtocol::Http(UpgradeProtocolVersion::V1_0),
            ),
            (
                b"HTTP/1.1".as_slice(),
                UpgradeProtocol::Http(UpgradeProtocolVersion::V1_1),
            ),
            (
                b"TLS/1.2".as_slice(),
                UpgradeProtocol::Tls(UpgradeProtocolVersion::V1_2),
            ),
            (
                b"TLS/1.3".as_slice(),
                UpgradeProtocol::Tls(UpgradeProtocolVersion::V1_3),
            ),
            (
                b"HTTP/2.0".as_slice(),
                UpgradeProtocol::Http(UpgradeProtocolVersion::V2_0),
            ),
            (
                b"HTTP/3.0".as_slice(),
                UpgradeProtocol::Http(UpgradeProtocolVersion::V3_0),
            ),
        ] {
            assert_eq!(UpgradeProtocol::parse(wire), Some(expected));
        }
    }

    #[test]
    fn uncommon_upgrade_protocol_keeps_exact_version() {
        let protocol = UpgradeProtocol::parse(b"IRC/6.9").unwrap();
        assert!(matches!(
            protocol,
            UpgradeProtocol::Other { wire, name_length: 3 } if &*wire == b"IRC/6.9"
        ));
        assert!(matches!(
            UpgradeProtocol::parse(b"TLS/6.9"),
            Some(UpgradeProtocol::Tls(UpgradeProtocolVersion::Other(version)))
                if &*version == b"6.9"
        ));
    }

    #[test]
    fn uncommon_upgrade_protocol_requires_valid_name_and_version() {
        assert_eq!(UpgradeProtocol::parse(b"IRC/6 9"), None);
        assert_eq!(UpgradeProtocol::parse(b"IR C/6.9"), None);
    }

    #[test]
    fn directional_removal_preserves_proxy_auth() {
        let mut request = HeaderMap::new();
        request.insert(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic"),
        );
        request.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic dGVzdA=="),
        );
        request.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-request-hop"),
        );
        request.insert(
            header::PROXY_CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        request.insert(
            HeaderName::from_static("x-request-hop"),
            HeaderValue::from_static("secret"),
        );
        remove_hop_by_hop_request_headers(&mut request);
        assert!(request.contains_key(header::PROXY_AUTHENTICATE));
        assert!(request.contains_key(header::PROXY_AUTHORIZATION));
        assert!(!request.contains_key(header::CONNECTION));
        assert!(!request.contains_key(header::PROXY_CONNECTION));
        assert!(!request.contains_key("x-request-hop"));

        let mut response = HeaderMap::new();
        response.insert(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic"),
        );
        response.insert(
            header::PROXY_CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        response.insert(header::TE, HeaderValue::from_static("trailers"));
        response.insert(header::CONNECTION, HeaderValue::from_static("close"));
        remove_hop_by_hop_response_headers(&mut response);
        assert!(response.contains_key(header::PROXY_AUTHENTICATE));
        assert!(!response.contains_key(header::PROXY_CONNECTION));
        assert!(!response.contains_key(header::TE));
        assert!(!response.contains_key(header::CONNECTION));
    }

    #[test]
    fn connection_nomination_removes_proxy_auth() {
        for (name, nomination) in [
            (
                header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("proxy-authenticate"),
            ),
            (
                header::PROXY_AUTHORIZATION,
                HeaderValue::from_static("proxy-authorization"),
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONNECTION, nomination);
            headers.insert(name.clone(), HeaderValue::from_static("Basic dGVzdA=="));

            remove_hop_by_hop_headers(&mut headers);

            assert!(headers.is_empty());
        }
    }

    #[test]
    fn request_sanitizer_reoriginates_te_trailers_by_version() {
        for (version, connection) in [
            (Version::HTTP_10, None),
            (Version::HTTP_11, Some(b"TE".as_slice())),
            (Version::HTTP_2, None),
            (Version::HTTP_3, None),
        ] {
            let mut request = Request::builder()
                .version(version)
                .header("connection", "close, TE")
                .header("te", "gzip, trailers")
                .body(())
                .unwrap();

            let _context = sanitize_hop_by_hop_request_headers(&mut request);

            assert_eq!(
                request
                    .headers()
                    .get(header::CONNECTION)
                    .map(HeaderValue::as_bytes),
                connection,
                "version: {version:?}"
            );
            assert_eq!(
                request.headers().get(header::TE).map(HeaderValue::as_bytes),
                (version != Version::HTTP_10).then_some(b"trailers".as_slice()),
                "version: {version:?}"
            );
        }
    }

    #[test]
    fn request_sanitizer_does_not_preserve_weighted_trailers_token() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "TE")
            .header("te", "trailers;q=1")
            .body(())
            .unwrap();

        let _context = sanitize_hop_by_hop_request_headers(&mut request);

        assert!(request.headers().is_empty());
    }

    #[test]
    fn request_sanitizer_rejects_invalid_upgrade_version_token() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "websocket/invalid version")
            .body(())
            .unwrap();

        let _context = sanitize_hop_by_hop_request_headers(&mut request);

        assert!(request.headers().is_empty());
    }

    #[test]
    fn connection_close_invalidates_upgrade_intent() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "Close, upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();

        let context = sanitize_hop_by_hop_request_headers(&mut request);
        assert!(request.headers().is_empty());

        let mut response = Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();
        assert_eq!(
            sanitize_hop_by_hop_response_headers(&mut response, &context),
            HopByHopResponseDisposition::RejectUpgrade
        );
        assert!(response.headers().is_empty());
    }

    #[test]
    fn response_sanitizer_only_restores_correlated_upgrade() {
        let mut request = Request::builder()
            .version(Version::HTTP_11)
            .header("connection", "upgrade")
            .header("upgrade", "websocket, example/1")
            .body(())
            .unwrap();
        let context = sanitize_hop_by_hop_request_headers(&mut request);

        for (protocol, disposition) in [
            ("WebSocket", HopByHopResponseDisposition::Forward),
            ("EXAMPLE/1", HopByHopResponseDisposition::Forward),
            ("example/2", HopByHopResponseDisposition::RejectUpgrade),
        ] {
            let mut response = Response::builder()
                .version(Version::HTTP_11)
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("connection", "keep-alive, upgrade")
                .header("upgrade", protocol)
                .header("keep-alive", "timeout=5")
                .body(())
                .unwrap();

            assert_eq!(
                sanitize_hop_by_hop_response_headers(&mut response, &context),
                disposition
            );
            assert_eq!(
                response.headers().contains_key(header::UPGRADE),
                disposition == HopByHopResponseDisposition::Forward
            );
            assert!(!response.headers().contains_key(header::KEEP_ALIVE));
        }
    }

    #[test]
    fn trailer_declaration_is_not_restored_when_nominated() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("trailer"));
        headers.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));

        let context = HopByHopHeaderContext::take(&mut headers, Version::HTTP_11);
        context.restore_response(&mut headers, Version::HTTP_11, &[]);

        assert!(headers.is_empty());
    }

    #[test]
    fn context_reports_nominations_and_restores_trailer_declaration() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("secret"));
        headers.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));

        let context = HopByHopHeaderContext::take(&mut headers, Version::HTTP_11);
        assert_eq!(
            context.nominated_headers(),
            [HeaderName::from_static("x-hop")]
        );
        for (version, restored) in [
            (Version::HTTP_09, false),
            (Version::HTTP_10, false),
            (Version::HTTP_11, true),
            (Version::HTTP_2, true),
            (Version::HTTP_3, true),
        ] {
            let mut target = HeaderMap::new();
            context.restore_response(&mut target, version, &[]);
            assert_eq!(target.contains_key(header::TRAILER), restored);
            assert_eq!(target.len(), usize::from(restored));
        }
    }

    #[test]
    fn unsupported_source_version_does_not_capture_trailer_capabilities() {
        for version in [Version::HTTP_09, Version::HTTP_10] {
            let mut headers = HeaderMap::new();
            headers.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));
            headers.insert(header::TE, HeaderValue::from_static("trailers"));

            let context = HopByHopHeaderContext::take(&mut headers, version);
            context.restore_request(&mut headers, Version::HTTP_11, &[]);

            assert!(headers.is_empty());
        }
    }

    #[test]
    fn strict_removal_uses_the_same_nomination_parser() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("secret"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        remove_hop_by_hop_headers(&mut headers);

        assert_eq!(values(&headers, &header::ACCEPT), [b"application/json"]);
        assert_eq!(headers.len(), 1);
    }
}
