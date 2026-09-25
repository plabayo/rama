//! Upgrade-token handshakes for protocols that use the Capsule Protocol (RFC 9297 §3.2).
//!
//! HTTP/1.x upgrades with `GET` + `Upgrade` and succeeds with `101`; HTTP/2 and HTTP/3 use
//! Extended CONNECT (RFC 8441, RFC 9220) and succeed with any `2xx`. These helpers keep that
//! version mapping in one place so a protocol implementation does not repeat it.

use crate::utils::request_connect_protocol;
use rama_core::extensions::ExtensionsRef as _;
use rama_http_headers::{CapsuleProtocol, Connection, HeaderMapExt as _};
use rama_http_types::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
    proto::ext::Protocol,
};
use std::fmt;

/// Message fields the Capsule Protocol forbids (RFC 9297 §3.2).
const FORBIDDEN_FIELDS: [HeaderName; 3] = [
    header::CONTENT_LENGTH,
    header::CONTENT_TYPE,
    header::TRANSFER_ENCODING,
];

/// A handshake that cannot start or accept the Capsule Protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleHandshakeError {
    /// The request is neither an HTTP/1.x upgrade nor Extended CONNECT.
    NotAnUpgrade,
    /// The response refused the upgrade; its content is an ordinary HTTP message.
    Unsuccessful(StatusCode),
    /// A field the Capsule Protocol forbids: the message is malformed.
    ForbiddenField(HeaderName),
    /// A status the Capsule Protocol forbids (204, 205, 206): the message is malformed.
    ForbiddenStatus(StatusCode),
    /// The HTTP/1.x `101` response names another protocol.
    UpgradeMismatch,
}

impl fmt::Display for CapsuleHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnUpgrade => f.write_str("request is not an upgrade or extended CONNECT"),
            Self::Unsuccessful(status) => write!(f, "upgrade refused with status {status}"),
            Self::ForbiddenField(name) => write!(f, "capsule protocol forbids field {name}"),
            Self::ForbiddenStatus(status) => write!(f, "capsule protocol forbids status {status}"),
            Self::UpgradeMismatch => f.write_str("101 response upgraded to another protocol"),
        }
    }
}

impl std::error::Error for CapsuleHandshakeError {}

/// Turn `request` into a Capsule Protocol handshake for `protocol` on its HTTP version,
/// advertising `Capsule-Protocol: ?1`. The request must not carry content.
pub fn prepare_capsule_request<B>(
    request: &mut Request<B>,
    protocol: Protocol,
) -> Result<(), CapsuleHandshakeError> {
    reject_forbidden_fields(request.headers())?;
    if request.version() <= Version::HTTP_11 {
        *request.method_mut() = Method::GET;
        let upgrade = HeaderValue::from_str(protocol.as_str())
            .map_err(|_error| CapsuleHandshakeError::NotAnUpgrade)?;
        let headers = request.headers_mut();
        headers.insert(header::UPGRADE, upgrade);
        headers.typed_insert(Connection::upgrade());
    } else {
        let headers = request.headers_mut();
        headers.remove(header::UPGRADE);
        headers.remove(header::CONNECTION);
        *request.method_mut() = Method::CONNECT;
        request.extensions().insert(protocol);
    }
    request.headers_mut().typed_insert(CapsuleProtocol::ENABLED);
    Ok(())
}

/// Validate a received Capsule Protocol handshake request and return its upgrade token.
pub fn validate_capsule_request<B>(
    request: &Request<B>,
) -> Result<Protocol, CapsuleHandshakeError> {
    let protocol = request_connect_protocol(request).ok_or(CapsuleHandshakeError::NotAnUpgrade)?;
    reject_forbidden_fields(request.headers())?;
    Ok(protocol)
}

/// The status accepting a Capsule Protocol handshake on `version`.
#[must_use]
pub fn capsule_response_status(version: Version) -> StatusCode {
    if version <= Version::HTTP_11 {
        StatusCode::SWITCHING_PROTOCOLS
    } else {
        StatusCode::OK
    }
}

/// Build the response accepting a Capsule Protocol handshake for `protocol`.
#[must_use]
pub fn capsule_response<B: Default>(version: Version, protocol: &Protocol) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = capsule_response_status(version);
    if version <= Version::HTTP_11
        && let Ok(upgrade) = HeaderValue::from_str(protocol.as_str())
    {
        let headers = response.headers_mut();
        headers.insert(header::UPGRADE, upgrade);
        headers.typed_insert(Connection::upgrade());
    }
    response
        .headers_mut()
        .typed_insert(CapsuleProtocol::ENABLED);
    response
}

/// Validate the response to a Capsule Protocol handshake request.
///
/// A refused handshake is [`CapsuleHandshakeError::Unsuccessful`]; its body can still be read.
pub fn validate_capsule_response<B, R>(
    request: &Request<R>,
    response: &Response<B>,
) -> Result<(), CapsuleHandshakeError> {
    let status = response.status();
    if matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::PARTIAL_CONTENT
    ) {
        return Err(CapsuleHandshakeError::ForbiddenStatus(status));
    }
    if status != capsule_response_status(request.version())
        && !(request.version() > Version::HTTP_11 && status.is_success())
    {
        return Err(CapsuleHandshakeError::Unsuccessful(status));
    }
    reject_forbidden_fields(response.headers())?;
    if request.version() <= Version::HTTP_11 {
        let expected =
            request_connect_protocol(request).ok_or(CapsuleHandshakeError::NotAnUpgrade)?;
        let upgraded = response
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(expected.as_ref()));
        if !upgraded {
            return Err(CapsuleHandshakeError::UpgradeMismatch);
        }
    }
    Ok(())
}

fn reject_forbidden_fields(
    headers: &rama_http_types::HeaderMap,
) -> Result<(), CapsuleHandshakeError> {
    FORBIDDEN_FIELDS
        .iter()
        .find(|name| headers.contains_key(*name))
        .map_or(Ok(()), |name| {
            Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: Protocol = Protocol::from_static("connect-udp");
    const VERSIONS: [Version; 4] = [
        Version::HTTP_10,
        Version::HTTP_11,
        Version::HTTP_2,
        Version::HTTP_3,
    ];

    fn request(version: Version) -> Request<()> {
        let mut request = Request::builder()
            .version(version)
            .uri("https://proxy.example/.well-known/masque/udp/example.org/443/")
            .body(())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        request
    }

    #[test]
    fn requests_map_to_upgrade_or_extended_connect() {
        for version in VERSIONS {
            let request = request(version);
            assert_eq!(validate_capsule_request(&request), Ok(TOKEN));
            assert_eq!(
                request.headers().typed_get::<CapsuleProtocol>(),
                Some(CapsuleProtocol::ENABLED)
            );
            if version <= Version::HTTP_11 {
                assert_eq!(request.method(), Method::GET);
                assert_eq!(request.headers()[header::UPGRADE], "connect-udp");
                assert!(!request.extensions().contains::<Protocol>());
            } else {
                assert_eq!(request.method(), Method::CONNECT);
                assert!(!request.headers().contains_key(header::UPGRADE));
                assert!(!request.headers().contains_key(header::CONNECTION));
            }
        }
    }

    #[test]
    fn responses_follow_each_version_success_rule() {
        for version in VERSIONS {
            let request = request(version);
            let accepted: Response<()> = capsule_response(version, &TOKEN);
            validate_capsule_response(&request, &accepted).unwrap();
            if version > Version::HTTP_11 {
                let mut created = accepted;
                *created.status_mut() = StatusCode::CREATED;
                validate_capsule_response(&request, &created).unwrap();
            }
            for status in [StatusCode::BAD_REQUEST, StatusCode::NOT_IMPLEMENTED] {
                let mut refused = Response::new(());
                *refused.status_mut() = status;
                assert_eq!(
                    validate_capsule_response(&request, &refused),
                    Err(CapsuleHandshakeError::Unsuccessful(status))
                );
            }
            for status in [204, 205, 206] {
                let mut forbidden = Response::new(());
                *forbidden.status_mut() = StatusCode::from_u16(status).unwrap();
                assert!(matches!(
                    validate_capsule_response(&request, &forbidden),
                    Err(CapsuleHandshakeError::ForbiddenStatus(_))
                ));
            }
        }
        let request = request(Version::HTTP_11);
        let mut other: Response<()> = capsule_response(Version::HTTP_11, &TOKEN);
        other
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            validate_capsule_response(&request, &other),
            Err(CapsuleHandshakeError::UpgradeMismatch)
        );
    }

    #[test]
    fn content_framing_fields_are_forbidden_in_both_directions() {
        for name in FORBIDDEN_FIELDS {
            for version in VERSIONS {
                let mut request = request(version);
                request
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert_eq!(
                    validate_capsule_request(&request),
                    Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
                );
                let clean = self::request(version);
                let mut response: Response<()> = capsule_response(version, &TOKEN);
                response
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert_eq!(
                    validate_capsule_response(&clean, &response),
                    Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
                );
                let mut unprepared = Request::builder().version(version).body(()).unwrap();
                unprepared
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert!(prepare_capsule_request(&mut unprepared, TOKEN).is_err());
            }
        }
        assert_eq!(
            validate_capsule_request(&Request::new(())),
            Err(CapsuleHandshakeError::NotAnUpgrade)
        );
    }
}
