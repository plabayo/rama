//! Upgrade-token handshakes for protocols that use the Capsule Protocol (RFC 9297 §3.2).
//!
//! HTTP/1.1 upgrades with `Upgrade` + `Connection: upgrade` and succeeds with `101`; HTTP/2 and
//! HTTP/3 use Extended CONNECT (RFC 8441, RFC 9220) and succeed with any `2xx`. HTTP/1.0 cannot
//! upgrade (RFC 9110 §7.8). These helpers keep that version mapping in one place.
//!
//! Received messages are checked under a [`ViolationPolicy`]. `Reject` treats every field
//! RFC 9297 §3.2 forbids as malformed. `Ignore` only rejects fields that would frame request
//! content ahead of the capsules (a non-zero `Content-Length`, any `Transfer-Encoding`); on a
//! `101` or a `2xx` CONNECT response they never frame the tunnel and are left alone.

use rama_core::extensions::ExtensionsRef as _;
use rama_http_headers::{CapsuleProtocol, Connection, HeaderMapExt as _};
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header,
    proto::ext::Protocol,
};
use std::fmt;

use super::ViolationPolicy;

/// Message fields the Capsule Protocol forbids (RFC 9297 §3.2).
const FORBIDDEN_FIELDS: [HeaderName; 3] = [
    header::CONTENT_LENGTH,
    header::CONTENT_TYPE,
    header::TRANSFER_ENCODING,
];

/// A handshake that cannot start or accept the Capsule Protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleHandshakeError {
    /// The HTTP version cannot carry an upgrade token (HTTP/1.0 and earlier).
    UnsupportedVersion(Version),
    /// The request is neither an HTTP/1.1 upgrade nor Extended CONNECT.
    NotAnUpgrade,
    /// An HTTP/2 or HTTP/3 message carries a connection-specific upgrade field.
    ConnectionSpecificField(HeaderName),
    /// The response refused the upgrade; its content is an ordinary HTTP message.
    Unsuccessful(StatusCode),
    /// A field the Capsule Protocol forbids: the message is malformed.
    ForbiddenField(HeaderName),
    /// A status the Capsule Protocol forbids (204, 205, 206): the message is malformed.
    ForbiddenStatus(StatusCode),
    /// The HTTP/1.1 `101` response does not switch to the requested protocol.
    UpgradeMismatch,
}

impl fmt::Display for CapsuleHandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "{version:?} cannot upgrade to the capsule protocol")
            }
            Self::NotAnUpgrade => f.write_str("request is not an upgrade or extended CONNECT"),
            Self::ConnectionSpecificField(name) => {
                write!(f, "connection-specific field {name} in extended CONNECT")
            }
            Self::Unsuccessful(status) => write!(f, "upgrade refused with status {status}"),
            Self::ForbiddenField(name) => write!(f, "capsule protocol forbids field {name}"),
            Self::ForbiddenStatus(status) => write!(f, "capsule protocol forbids status {status}"),
            Self::UpgradeMismatch => f.write_str("101 response did not switch to the protocol"),
        }
    }
}

impl std::error::Error for CapsuleHandshakeError {}

/// How an HTTP version carries an upgrade token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Upgrade,
    ExtendedConnect,
}

fn carrier(version: Version) -> Result<Carrier, CapsuleHandshakeError> {
    match version {
        Version::HTTP_11 => Ok(Carrier::Upgrade),
        Version::HTTP_2 | Version::HTTP_3 => Ok(Carrier::ExtendedConnect),
        version => Err(CapsuleHandshakeError::UnsupportedVersion(version)),
    }
}

/// Turn `request` into a Capsule Protocol handshake for `protocol` on its HTTP version,
/// advertising `Capsule-Protocol: ?1`. The request must not carry content.
pub fn prepare_capsule_request<B>(
    request: &mut Request<B>,
    protocol: Protocol,
) -> Result<(), CapsuleHandshakeError> {
    let carrier = carrier(request.version())?;
    reject_forbidden_fields(request.headers(), ViolationPolicy::Reject, Message::Request)?;
    match carrier {
        Carrier::Upgrade => {
            let upgrade = HeaderValue::from_str(protocol.as_str())
                .map_err(|_error| CapsuleHandshakeError::NotAnUpgrade)?;
            *request.method_mut() = Method::GET;
            let headers = request.headers_mut();
            headers.insert(header::UPGRADE, upgrade);
            headers.typed_insert(Connection::upgrade());
        }
        Carrier::ExtendedConnect => {
            let headers = request.headers_mut();
            headers.remove(header::UPGRADE);
            headers.remove(header::CONNECTION);
            *request.method_mut() = Method::CONNECT;
            request.extensions().insert(protocol);
        }
    }
    request.headers_mut().typed_insert(CapsuleProtocol::ENABLED);
    Ok(())
}

/// Validate a received Capsule Protocol handshake request and return its upgrade token.
pub fn validate_capsule_request<B>(
    request: &Request<B>,
    violations: ViolationPolicy,
) -> Result<Protocol, CapsuleHandshakeError> {
    let protocol = match carrier(request.version())? {
        Carrier::Upgrade => {
            let upgrading = request
                .headers()
                .typed_get::<Connection>()
                .is_some_and(|connection| connection.contains_upgrade());
            if !upgrading {
                return Err(CapsuleHandshakeError::NotAnUpgrade);
            }
            single_token(request.headers()).ok_or(CapsuleHandshakeError::NotAnUpgrade)?
        }
        Carrier::ExtendedConnect => {
            for name in [header::UPGRADE, header::CONNECTION] {
                if request.headers().contains_key(&name) {
                    return Err(CapsuleHandshakeError::ConnectionSpecificField(name));
                }
            }
            if request.method() != Method::CONNECT {
                return Err(CapsuleHandshakeError::NotAnUpgrade);
            }
            request
                .extensions()
                .get_ref::<Protocol>()
                .cloned()
                .ok_or(CapsuleHandshakeError::NotAnUpgrade)?
        }
    };
    reject_forbidden_fields(request.headers(), violations, Message::Request)?;
    Ok(protocol)
}

/// The status accepting a Capsule Protocol handshake on `version`.
pub fn capsule_response_status(version: Version) -> Result<StatusCode, CapsuleHandshakeError> {
    Ok(match carrier(version)? {
        Carrier::Upgrade => StatusCode::SWITCHING_PROTOCOLS,
        Carrier::ExtendedConnect => StatusCode::OK,
    })
}

/// Build the response accepting a Capsule Protocol handshake for `protocol` on `version`.
pub fn capsule_response<B: Default>(
    version: Version,
    protocol: &Protocol,
) -> Result<Response<B>, CapsuleHandshakeError> {
    let mut response = Response::new(B::default());
    *response.status_mut() = capsule_response_status(version)?;
    if carrier(version)? == Carrier::Upgrade {
        let upgrade = HeaderValue::from_str(protocol.as_str())
            .map_err(|_error| CapsuleHandshakeError::NotAnUpgrade)?;
        let headers = response.headers_mut();
        headers.insert(header::UPGRADE, upgrade);
        headers.typed_insert(Connection::upgrade());
    }
    response
        .headers_mut()
        .typed_insert(CapsuleProtocol::ENABLED);
    Ok(response)
}

/// Validate the response to a Capsule Protocol handshake for `protocol` sent on `version`.
///
/// The request is the caller's own, prepared by [`prepare_capsule_request`]; only the response
/// is checked here. A refused handshake is [`CapsuleHandshakeError::Unsuccessful`]; its body can
/// still be read.
pub fn validate_capsule_response<B>(
    version: Version,
    protocol: &Protocol,
    response: &Response<B>,
    violations: ViolationPolicy,
) -> Result<(), CapsuleHandshakeError> {
    let carrier = carrier(version)?;
    let status = response.status();
    if matches!(
        status,
        StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::PARTIAL_CONTENT
    ) {
        return Err(CapsuleHandshakeError::ForbiddenStatus(status));
    }
    let accepted = match carrier {
        Carrier::Upgrade => status == StatusCode::SWITCHING_PROTOCOLS,
        Carrier::ExtendedConnect => status.is_success(),
    };
    if !accepted {
        return Err(CapsuleHandshakeError::Unsuccessful(status));
    }
    reject_forbidden_fields(response.headers(), violations, Message::Response)?;
    if carrier == Carrier::Upgrade {
        // RFC 9110 §7.8: the switched-to protocol in `Upgrade`, listed in `Connection`.
        let switched = single_token(response.headers())
            .is_some_and(|token| token.as_str().eq_ignore_ascii_case(protocol.as_str()))
            && response
                .headers()
                .typed_get::<Connection>()
                .is_some_and(|connection| connection.contains_upgrade());
        if !switched {
            return Err(CapsuleHandshakeError::UpgradeMismatch);
        }
    }
    Ok(())
}

/// The single upgrade token of an `Upgrade` field (case-insensitive, RFC 9110 §16.7).
fn single_token(headers: &HeaderMap) -> Option<Protocol> {
    let mut values = headers.get_all(header::UPGRADE).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let token = std::str::from_utf8(value.as_bytes()).ok()?.trim();
    Protocol::try_from(token).ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Message {
    Request,
    Response,
}

fn reject_forbidden_fields(
    headers: &HeaderMap,
    violations: ViolationPolicy,
    message: Message,
) -> Result<(), CapsuleHandshakeError> {
    let forbidden = |name: &HeaderName| match (violations, message) {
        (ViolationPolicy::Reject, _) => headers.contains_key(name),
        // Framing stays enforced: request content would precede the capsules.
        (_, Message::Request) if *name == header::CONTENT_LENGTH => headers
            .get_all(name)
            .iter()
            .any(|value| !is_zero_length(value)),
        (_, Message::Request) if *name == header::TRANSFER_ENCODING => headers.contains_key(name),
        _ => false,
    };
    FORBIDDEN_FIELDS
        .iter()
        .find(|name| forbidden(name))
        .map_or(Ok(()), |name| {
            Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
        })
}

/// A zero `Content-Length` in any RFC 9110 §8.6 spelling: `1*DIGIT`, or an identical list.
fn is_zero_length(value: &HeaderValue) -> bool {
    value.as_bytes().split(|&byte| byte == b',').all(|part| {
        let part = part.trim_ascii();
        !part.is_empty() && part.iter().all(|&byte| byte == b'0')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: Protocol = Protocol::from_static("connect-udp");
    const VERSIONS: [Version; 3] = [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3];

    fn request(version: Version) -> Request<()> {
        let mut request = Request::builder()
            .version(version)
            .uri("https://proxy.example/.well-known/masque/udp/example.org/443/")
            .body(())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        request
    }

    fn response(version: Version) -> Response<()> {
        capsule_response(version, &TOKEN).unwrap()
    }

    #[test]
    fn requests_map_to_upgrade_or_extended_connect() {
        for version in VERSIONS {
            let request = request(version);
            assert_eq!(
                validate_capsule_request(&request, ViolationPolicy::Ignore),
                Ok(TOKEN)
            );
            assert_eq!(
                request.headers().typed_get::<CapsuleProtocol>(),
                Some(CapsuleProtocol::ENABLED)
            );
            if version == Version::HTTP_11 {
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
    fn http_1_0_cannot_upgrade() {
        // RFC 9110 §7.8: an HTTP/1.0 recipient ignores Upgrade.
        let mut request = Request::builder()
            .version(Version::HTTP_10)
            .body(())
            .unwrap();
        assert_eq!(
            prepare_capsule_request(&mut request, TOKEN),
            Err(CapsuleHandshakeError::UnsupportedVersion(Version::HTTP_10))
        );
        let mut received = Request::builder()
            .version(Version::HTTP_10)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "connect-udp")
            .body(())
            .unwrap();
        assert_eq!(
            validate_capsule_request(&received, ViolationPolicy::Ignore),
            Err(CapsuleHandshakeError::UnsupportedVersion(Version::HTTP_10))
        );
        *received.version_mut() = Version::HTTP_09;
        validate_capsule_request(&received, ViolationPolicy::Ignore).unwrap_err();
        assert_eq!(
            capsule_response::<()>(Version::HTTP_10, &TOKEN).unwrap_err(),
            CapsuleHandshakeError::UnsupportedVersion(Version::HTTP_10)
        );
        let mut switching = response(Version::HTTP_11);
        *switching.version_mut() = Version::HTTP_10;
        validate_capsule_response(
            Version::HTTP_10,
            &TOKEN,
            &switching,
            ViolationPolicy::Ignore,
        )
        .unwrap_err();
    }

    #[test]
    fn extended_connect_requests_need_connect_and_protocol_only() {
        for version in [Version::HTTP_2, Version::HTTP_3] {
            let mut get = request(version);
            *get.method_mut() = Method::GET;
            assert_eq!(
                validate_capsule_request(&get, ViolationPolicy::Ignore),
                Err(CapsuleHandshakeError::NotAnUpgrade)
            );
            let upgrade_style = Request::builder()
                .version(version)
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "connect-udp")
                .body(())
                .unwrap();
            assert!(matches!(
                validate_capsule_request(&upgrade_style, ViolationPolicy::Ignore),
                Err(CapsuleHandshakeError::ConnectionSpecificField(_))
            ));
            let bare = Request::builder()
                .method(Method::CONNECT)
                .version(version)
                .body(())
                .unwrap();
            assert_eq!(
                validate_capsule_request(&bare, ViolationPolicy::Ignore),
                Err(CapsuleHandshakeError::NotAnUpgrade)
            );
        }
        // HTTP/1.1 needs a genuine upgrade, not a Protocol extension.
        let mut connect = request(Version::HTTP_2);
        *connect.version_mut() = Version::HTTP_11;
        assert_eq!(
            validate_capsule_request(&connect, ViolationPolicy::Ignore),
            Err(CapsuleHandshakeError::NotAnUpgrade)
        );
    }

    #[test]
    fn responses_follow_each_version_success_rule() {
        for version in VERSIONS {
            validate_capsule_response(version, &TOKEN, &response(version), ViolationPolicy::Ignore)
                .unwrap();
            if version != Version::HTTP_11 {
                let mut created = response(version);
                *created.status_mut() = StatusCode::CREATED;
                validate_capsule_response(version, &TOKEN, &created, ViolationPolicy::Ignore)
                    .unwrap();
            }
            for status in [
                StatusCode::OK,
                StatusCode::BAD_REQUEST,
                StatusCode::NOT_IMPLEMENTED,
            ] {
                if version != Version::HTTP_11 && status == StatusCode::OK {
                    continue;
                }
                let mut refused = Response::new(());
                *refused.status_mut() = status;
                assert_eq!(
                    validate_capsule_response(version, &TOKEN, &refused, ViolationPolicy::Ignore),
                    Err(CapsuleHandshakeError::Unsuccessful(status)),
                    "{version:?} {status}"
                );
            }
            for status in [204, 205, 206] {
                let mut forbidden = Response::new(());
                *forbidden.status_mut() = StatusCode::from_u16(status).unwrap();
                assert!(matches!(
                    validate_capsule_response(version, &TOKEN, &forbidden, ViolationPolicy::Ignore),
                    Err(CapsuleHandshakeError::ForbiddenStatus(_))
                ));
            }
        }
    }

    #[test]
    fn http_1_1_switching_requires_upgrade_and_connection() {
        let mut other = response(Version::HTTP_11);
        other
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            validate_capsule_response(Version::HTTP_11, &TOKEN, &other, ViolationPolicy::Ignore),
            Err(CapsuleHandshakeError::UpgradeMismatch)
        );
        let mut no_connection = response(Version::HTTP_11);
        no_connection.headers_mut().remove(header::CONNECTION);
        assert_eq!(
            validate_capsule_response(
                Version::HTTP_11,
                &TOKEN,
                &no_connection,
                ViolationPolicy::Ignore
            ),
            Err(CapsuleHandshakeError::UpgradeMismatch)
        );
        let mut repeated = response(Version::HTTP_11);
        repeated
            .headers_mut()
            .append(header::UPGRADE, HeaderValue::from_static("connect-udp"));
        assert_eq!(
            validate_capsule_response(Version::HTTP_11, &TOKEN, &repeated, ViolationPolicy::Ignore),
            Err(CapsuleHandshakeError::UpgradeMismatch)
        );
        // Upgrade tokens compare case-insensitively (RFC 9110 §16.7).
        let mut shouted = response(Version::HTTP_11);
        shouted
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("CONNECT-UDP"));
        validate_capsule_response(Version::HTTP_11, &TOKEN, &shouted, ViolationPolicy::Ignore)
            .unwrap();
    }

    #[test]
    fn rejecting_forbids_every_capsule_field_in_both_directions() {
        for name in FORBIDDEN_FIELDS {
            for version in VERSIONS {
                let mut request = request(version);
                request
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert_eq!(
                    validate_capsule_request(&request, ViolationPolicy::Reject),
                    Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
                );
                let mut response = response(version);
                response
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert_eq!(
                    validate_capsule_response(version, &TOKEN, &response, ViolationPolicy::Reject),
                    Err(CapsuleHandshakeError::ForbiddenField(name.clone()))
                );
                // Our own requests never carry them, whatever the policy.
                let mut unprepared = Request::builder().version(version).body(()).unwrap();
                unprepared
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("0"));
                assert!(prepare_capsule_request(&mut unprepared, TOKEN).is_err());
            }
        }
        assert_eq!(
            validate_capsule_request(&Request::new(()), ViolationPolicy::Reject),
            Err(CapsuleHandshakeError::NotAnUpgrade)
        );
    }

    #[test]
    fn ignoring_still_rejects_request_content_framing() {
        for version in VERSIONS {
            for (name, value, accepted) in [
                (header::CONTENT_LENGTH, "0", true),
                (header::CONTENT_LENGTH, " 0 ", true),
                (header::CONTENT_LENGTH, "00", true),
                (header::CONTENT_LENGTH, "0, 0", true),
                (header::CONTENT_LENGTH, "+0", false),
                (header::CONTENT_LENGTH, "0, 1", false),
                (header::CONTENT_LENGTH, "", false),
                (header::CONTENT_LENGTH, "5", false),
                (header::CONTENT_LENGTH, "invalid", false),
                (header::TRANSFER_ENCODING, "chunked", false),
                (header::CONTENT_TYPE, "application/octet-stream", true),
            ] {
                let mut request = request(version);
                request
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static(value));
                let result = validate_capsule_request(&request, ViolationPolicy::Ignore);
                if accepted {
                    assert_eq!(result, Ok(TOKEN), "{version:?} {name}: {value}");
                } else {
                    assert_eq!(
                        result,
                        Err(CapsuleHandshakeError::ForbiddenField(name.clone())),
                        "{version:?} {name}: {value}"
                    );
                }
            }
            // Repeated zero lengths frame nothing; one non-zero value does.
            let mut repeated = request(version);
            for value in ["0", "0"] {
                repeated
                    .headers_mut()
                    .append(header::CONTENT_LENGTH, HeaderValue::from_static(value));
            }
            validate_capsule_request(&repeated, ViolationPolicy::Ignore).unwrap();
            repeated
                .headers_mut()
                .append(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
            validate_capsule_request(&repeated, ViolationPolicy::Ignore).unwrap_err();
            // A 101 or 2xx CONNECT response never frames the tunnel with these fields.
            for name in FORBIDDEN_FIELDS {
                let mut response = response(version);
                response
                    .headers_mut()
                    .insert(name.clone(), HeaderValue::from_static("5"));
                validate_capsule_response(version, &TOKEN, &response, ViolationPolicy::Ignore)
                    .unwrap();
            }
        }
    }
}
