use rama::{
    Service,
    error::{BoxError, ErrorContext, extra::OpaqueError},
    extensions::Extensions,
    http::{
        Request, Response,
        headers::{HeaderMapExt as _, SecWebSocketExtensions, SecWebSocketProtocol},
        ws::handshake::client::{ClientWebSocket, HttpClientWebSocketExt},
    },
    utils::{collections::NonEmptySmallVec, str::NonEmptyStr},
};

pub(super) async fn connect<C>(
    req: Request,
    client: C,
    protocols: Option<NonEmptySmallVec<3, NonEmptyStr>>,
) -> Result<ClientWebSocket, BoxError>
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let extensions = req
        .headers()
        .typed_try_get::<SecWebSocketExtensions>()
        .context("invalid WebSocket extension offer")?;
    let protocols = match protocols {
        Some(protocols) => Some(SecWebSocketProtocol(protocols)),
        None => req
            .headers()
            .typed_try_get::<SecWebSocketProtocol>()
            .context("invalid WebSocket protocol offer")?,
    };
    let builder = client
        .websocket_with_request(req)
        .maybe_with_protocols(protocols);
    let builder = if extensions.is_some() {
        builder
    } else {
        builder.with_per_message_deflate_overwrite_extensions()
    };
    builder
        .handshake(Extensions::default())
        .await
        .context("establish WS(S) connection")
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use rama::{
        ServiceInput,
        bytes::Bytes,
        extensions::ExtensionsRef as _,
        http::{
            Body, HeaderMap, StatusCode,
            headers::{Connection, SecWebSocketAccept, SecWebSocketKey, Upgrade},
        },
        service::service_fn,
    };
    use std::sync::Arc;

    async fn offered(
        extensions: Option<&str>,
        protocol: Option<&str>,
        explicit_protocol: bool,
    ) -> (HeaderMap, bool) {
        let seen = Arc::new(Mutex::new(None));
        let observed = seen.clone();
        let response_extension = extensions.map(|value| {
            if value == "permessage-deflate; client_max_window_bits" {
                "permessage-deflate; client_max_window_bits=15".to_owned()
            } else {
                value.to_owned()
            }
        });
        let client = service_fn(move |req: Request| {
            *observed.lock() = Some(req.headers().clone());
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            response.headers_mut().typed_insert(Connection::upgrade());
            response.headers_mut().typed_insert(Upgrade::websocket());
            let key = req.headers().typed_get::<SecWebSocketKey>().unwrap();
            response
                .headers_mut()
                .typed_insert(SecWebSocketAccept::try_from(key).unwrap());
            if let Some(extension) = &response_extension {
                response
                    .headers_mut()
                    .insert("sec-websocket-extensions", extension.parse().unwrap());
            }
            if let Some(protocol) = req.headers().get("sec-websocket-protocol") {
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", protocol.clone());
            }
            let (client_io, _server_io) = tokio::io::duplex(1024);
            let (pending, on_upgrade) = rama::http::io::upgrade::pending();
            pending.fulfill(rama::http::io::upgrade::Upgraded::new(
                ServiceInput::new(client_io),
                Bytes::new(),
            ));
            response.extensions().insert(on_upgrade);
            async { Ok::<_, OpaqueError>(response) }
        });
        let mut req = Request::builder()
            .uri("ws://example.test/socket")
            .body(Body::empty())
            .unwrap();
        if let Some(value) = extensions {
            req.headers_mut()
                .insert("sec-websocket-extensions", value.parse().unwrap());
        }
        if let Some(value) = protocol {
            req.headers_mut()
                .insert("sec-websocket-protocol", value.parse().unwrap());
        }
        let protocols =
            explicit_protocol.then(|| NonEmptySmallVec::new("override".parse().unwrap()));
        let result = connect(req, client, protocols).await;
        let accepted = result.is_ok();
        let result = seen.lock().take();
        (result.unwrap_or_default(), accepted)
    }

    #[tokio::test]
    async fn cli_websocket_explicit_negotiation_headers_survive_defaults() {
        for extension in [
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_no_context_takeover",
        ] {
            let (headers, accepted) = offered(Some(extension), Some("chat"), false).await;
            assert!(
                accepted,
                "valid response to explicit offer was rejected: {extension}"
            );
            assert_eq!(
                headers.get_all("sec-websocket-extensions").iter().count(),
                1
            );
            assert_eq!(headers["sec-websocket-extensions"], extension);
            assert_eq!(headers["sec-websocket-protocol"], "chat");
        }
        let (defaults, accepted) = offered(None, None, false).await;
        assert!(accepted);
        assert_eq!(defaults["sec-websocket-extensions"], "permessage-deflate");
        assert!(!defaults.contains_key("sec-websocket-protocol"));
        let (overridden, accepted) = offered(None, Some("chat"), true).await;
        assert!(accepted);
        assert_eq!(overridden["sec-websocket-protocol"], "override");
    }

    #[tokio::test]
    async fn cli_websocket_invalid_negotiation_headers_fail_before_send() {
        assert!(
            offered(
                Some("permessage-deflate; client_max_window_bits=99"),
                None,
                false
            )
            .await
            .0
            .is_empty()
        );
        assert!(offered(None, Some("not a token"), false).await.0.is_empty());
    }
}
