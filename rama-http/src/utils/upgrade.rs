use rama_core::extensions::ExtensionsRef as _;
use rama_http_headers::{Connection, HeaderMapExt as _, Upgrade};
use rama_http_types::{Method, Request, proto::ext::Protocol};

/// Application protocol requested by an HTTP upgrade or Extended CONNECT.
///
/// HTTP/2 and HTTP/3 use the [`Protocol`] extension on `CONNECT`. HTTP/1 requires
/// both `Upgrade` and `Connection: Upgrade`; an advertisement alone returns `None`.
/// This identifies intent, not peer support or a completed upgrade.
pub fn request_connect_protocol<Body>(request: &Request<Body>) -> Option<Protocol> {
    if request.method() == Method::CONNECT
        && let Some(protocol) = request.extensions().get_ref::<Protocol>()
    {
        return Some(protocol.clone());
    }

    let is_genuine_upgrade = request
        .headers()
        .typed_get::<Connection>()
        .is_some_and(|connection| connection.contains_upgrade());
    if !is_genuine_upgrade {
        return None;
    }
    let upgrade = request.headers().typed_get::<Upgrade>()?;
    // Only SP and HTAB are optional whitespace (RFC 9110 §5.6.3), never Unicode spaces.
    let token = std::str::from_utf8(upgrade.as_bytes().trim_ascii()).ok()?;
    // A non-token upgrade value cannot be a `:protocol`; treat it as a mere advertisement.
    Protocol::try_from(token).ok()
}

/// A `CONNECT` without a [`Protocol`]: its target is a `host:port` authority (RFC 9110 §9.3.6).
pub(crate) fn is_plain_connect<Body>(request: &Request<Body>) -> bool {
    request.method() == Method::CONNECT && !request.extensions().contains::<Protocol>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::{HeaderValue, header};

    #[test]
    fn distinguishes_upgrade_requests_from_advertisements() {
        for (connection, upgrade, expected) in [
            (None, &b"websocket"[..], None),
            (Some("keep-alive"), b"websocket", None),
            (Some("keep-alive, Upgrade"), b"websocket", Some("websocket")),
            (Some("upgrade"), b"websocket, h2c", None),
            (Some("upgrade"), b"custom-protocol", Some("custom-protocol")),
            (Some("upgrade"), b" websocket\t", Some("websocket")),
            (Some("upgrade"), b"\xc2\xa0websocket\xc2\xa0", None),
        ] {
            let mut request = Request::builder()
                .header(header::UPGRADE, HeaderValue::from_bytes(upgrade).unwrap());
            if let Some(connection) = connection {
                request = request.header(header::CONNECTION, connection);
            }
            let request = request.body(()).unwrap();
            let protocol = request_connect_protocol(&request);
            assert_eq!(protocol.as_ref().map(Protocol::as_str), expected);
        }
    }

    #[test]
    fn protocol_extension_requires_connect() {
        let mut request = Request::new(());
        request
            .extensions()
            .insert(Protocol::from_static("websocket"));
        assert!(request_connect_protocol(&request).is_none());
        *request.method_mut() = Method::CONNECT;
        assert_eq!(
            request_connect_protocol(&request),
            Some(Protocol::from_static("websocket")),
        );
        let plain = Request::builder().method(Method::CONNECT).body(()).unwrap();
        assert!(request_connect_protocol(&plain).is_none());
    }
}
