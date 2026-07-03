use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http_headers::{Connection, HeaderMapExt, SecWebSocketAccept, SecWebSocketKey, Upgrade};
use rama_http_types::header::SEC_WEBSOCKET_ACCEPT;
use rama_http_types::proto::h2::ext::Protocol;
use rama_http_types::{Request, Response, StatusCode, Version};

use super::request::{is_websocket_protocol, request_connect_protocol};
use crate::layer::remove_header::remove_illegal_h2_response_headers;

#[derive(Clone, Debug)]
/// [`Service`] which will adapt the response version to the original request version.
///
/// When a request passes through this [`Service`] it will store the request version,
/// and if the response has a different [`Version`] it will adapt it back the original one.
///
/// Warning: when used together with a [`RequestVersionAdapter`] make sure this is placed
/// first so it can store the info it needs from the original response in a [`ResponseVersionAdaptCtx`]
///
/// [`RequestVersionAdapter`]: super::RequestVersionAdapter
pub struct ResponseVersionAdapter<S> {
    inner: S,
}

impl<S> ResponseVersionAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Body> Service<Request<Body>> for ResponseVersionAdapter<S>
where
    S: Service<Request<Body>, Output = Response, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let request_ctx = ResponseVersionAdaptCtx::from_request(&req);

        let mut resp = self.inner.serve(req).await.into_box_error()?;
        adapt_response_version(&mut resp, &request_ctx)?;

        Ok(resp)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Default)]
/// [`Layer`] which will adapt the response version to the original request version.
///
/// When a request passes through this [`Layer`] it will store the request version,
/// and if the response has a different [`Version`] it will adapt it back the original one.
pub struct ResponseVersionAdapterLayer;

impl<S> Layer<S> for ResponseVersionAdapterLayer {
    type Service = ResponseVersionAdapter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ResponseVersionAdapter { inner }
    }
}

/// Request-derived state, captured before a request is sent, that a response may
/// need in order to be translated back to the original request [`Version`].
///
/// The motivating case is the WebSocket handshake: an HTTP/1 `101 Switching
/// Protocols` accept carries `Sec-WebSocket-Accept`, which is a signature of the
/// request's `Sec-WebSocket-Key`. That key lives only on the request, so it cannot be
/// reconstructed from an HTTP/2 `200` response alone, it must be captured here.
#[derive(Debug, Clone, Default)]
pub struct ResponseVersionAdaptCtx {
    ///  Original version the request had
    pub version: Version,
    /// The Extended CONNECT / `Upgrade` application protocol the request asked for
    /// (e.g. `websocket`), if any. Captured from the request's `:protocol` extension
    /// (HTTP/2/3 CONNECT) or `Upgrade` header (HTTP/1).
    pub connect_protocol: Option<Protocol>,
    /// The request's `Sec-WebSocket-Key`, needed to recompute `Sec-WebSocket-Accept`
    /// when reconstructing an HTTP/1 WebSocket handshake response.
    pub websocket_key: Option<SecWebSocketKey>,
}

impl ResponseVersionAdaptCtx {
    /// Capture the [`ResponseVersionAdaptCtx`] from an outgoing request.
    pub fn from_request<Body>(request: &Request<Body>) -> Self {
        Self {
            version: request.version(),
            connect_protocol: request_connect_protocol(request),
            websocket_key: request.headers().typed_get::<SecWebSocketKey>(),
        }
    }

    fn is_websocket(&self) -> bool {
        self.connect_protocol
            .as_ref()
            .is_some_and(is_websocket_protocol)
    }
}

/// Adapt response to match the provided [`Version`], using [`ResponseVersionAdaptCtx`]
/// captured from the original request to translate handshake responses.
pub fn adapt_response_version<Body>(
    response: &mut Response<Body>,
    request_ctx: &ResponseVersionAdaptCtx,
) -> Result<(), BoxError> {
    let resp_version = response.version();
    if resp_version == request_ctx.version {
        tracing::trace!(
            version = ?response.version(),
            "response version is already correct, no version switching needed",
        );
        return Ok(());
    }

    tracing::trace!(
        ?resp_version,
        target_version = ?request_ctx.version,
        "changing response version",
    );

    // HTTP/2 and HTTP/3 share the same semantic model (no connection-specific headers,
    // Extended CONNECT for upgrades), so translation keys on the h1-style (`<= HTTP_11`)
    // vs modern (`>= HTTP_2`) class transition. This makes HTTP/3 work here for free.
    let resp_is_h1 = resp_version <= Version::HTTP_11;
    let target_is_h1 = request_ctx.version <= Version::HTTP_11;

    match (resp_is_h1, target_is_h1) {
        (true, false) => upgrade_response_to_h2_or_h3(response, request_ctx)?,
        (false, true) => downgrade_response_to_h1(response, request_ctx)?,
        // same class (HTTP/1.0<->1.1 or HTTP/2<->HTTP/3): only the version field changes
        (true, true) | (false, false) => {}
    }

    *response.version_mut() = request_ctx.version;
    Ok(())
}

/// Translate an HTTP/1.x response up to HTTP/2 or HTTP/3.
///
/// For a WebSocket handshake (known from the captured request context) the HTTP/1
/// `101 Switching Protocols` accept becomes the `200 OK` form (RFC 8441 §5.1).
/// Otherwise removes the connection-specific headers that are *illegal* in HTTP/2 and
/// HTTP/3 (RFC 9113 §8.2.2 / RFC 9114 §4.2) so an ordinary response can be
/// (re)serialized over the binary-framed protocol.
///
/// A `101` whose captured request protocol is NOT websocket (h2c, WebTransport, …) has
/// no supported modern translation and is rejected with an error rather than silently
/// mishandled. (The actual byte-stream bridging of an upgrade across versions is always
/// the upgrade/relay layer's job — the adapter only translates the handshake status.)
fn upgrade_response_to_h2_or_h3<Body>(
    response: &mut Response<Body>,
    request_ctx: &ResponseVersionAdaptCtx,
) -> Result<(), BoxError> {
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        if request_ctx.is_websocket() {
            tracing::trace!("translating h1 websocket 101 response into h2/h3 200 OK");
            *response.status_mut() = StatusCode::OK;
            // `Sec-WebSocket-Accept` is unused in h2/h3; drop it (the connection-specific
            // upgrade headers are removed by the illegal-header strip below).
            response.headers_mut().remove(SEC_WEBSOCKET_ACCEPT);
        } else {
            return Err(BoxError::from(format!(
                "cannot translate a `101 Switching Protocols` response to HTTP/2+ for protocol {}: only websocket is supported",
                request_ctx
                    .connect_protocol
                    .as_ref()
                    .map_or("<unknown upgrade>", Protocol::as_str),
            )));
        }
    }

    // Remove only the connection-specific headers that are *illegal* in HTTP/2 & HTTP/3.
    // This is a protocol-legality fixup, not a proxy hop policy: headers that are legal
    // in those versions (e.g. `Trailer`, `Proxy-Authenticate`) are left untouched.
    remove_illegal_h2_response_headers(response.headers_mut());
    Ok(())
}

/// Translate an HTTP/2 or HTTP/3 response down to HTTP/1.x.
///
/// For a WebSocket handshake (known from the captured request context) the Extended
/// CONNECT `200 OK` becomes the HTTP/1 `101 Switching Protocols` accept, re-deriving
/// `Sec-WebSocket-Accept` from the request's `Sec-WebSocket-Key`. Ordinary responses
/// (no captured Extended CONNECT protocol) carry no connection-specific headers and
/// need only the version swap. A non-WebSocket Extended CONNECT is rejected.
fn downgrade_response_to_h1<Body>(
    response: &mut Response<Body>,
    request_ctx: &ResponseVersionAdaptCtx,
) -> Result<(), BoxError> {
    let Some(protocol) = request_ctx.connect_protocol.as_ref() else {
        // Not an Extended CONNECT request: an ordinary response needs only the version swap.
        return Ok(());
    };
    if !is_websocket_protocol(protocol) {
        return Err(BoxError::from(format!(
            "cannot translate an Extended CONNECT `{}` response to HTTP/1: only websocket is supported",
            protocol.as_str(),
        )));
    }

    // A WebSocket success (`200`) becomes the HTTP/1 `101` accept; a non-success
    // response (handshake rejected upstream) passes through apart from the version.
    if response.status() == StatusCode::OK {
        tracing::trace!("translating h2/h3 websocket 200 response into h1 101 Switching Protocols");
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

        let headers = response.headers_mut();
        headers.typed_insert(Upgrade::websocket());
        headers.typed_insert(Connection::upgrade());
        if let Some(key) = request_ctx.websocket_key.clone() {
            let accept = SecWebSocketAccept::try_from(key)
                .context("derive Sec-WebSocket-Accept for h1 websocket handshake response")?;
            headers.typed_insert(accept);
        } else {
            tracing::debug!(
                "no Sec-WebSocket-Key captured; emitting h1 websocket 101 without Sec-WebSocket-Accept",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::ExtensionsRef;
    use rama_http_types::Method;
    use rama_http_types::header::{CONNECTION, SEC_WEBSOCKET_KEY, TRANSFER_ENCODING, UPGRADE};

    const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    // RFC 6455 §1.3 worked example: accept for the key above.
    const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn ctx_with_version(version: Version) -> ResponseVersionAdaptCtx {
        ResponseVersionAdaptCtx {
            version,
            ..Default::default()
        }
    }

    fn websocket_ctx(version: Version) -> ResponseVersionAdaptCtx {
        let req = Request::builder()
            .version(version)
            .uri("https://example.com/chat")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header(SEC_WEBSOCKET_KEY, SAMPLE_KEY)
            .body(())
            .unwrap();
        ResponseVersionAdaptCtx::from_request(&req)
    }

    fn connect_udp_ctx(version: Version) -> ResponseVersionAdaptCtx {
        let req = Request::builder()
            .version(version)
            .method(Method::CONNECT)
            .uri("https://example.com/.well-known/masque/udp/1.2.3.4/443/")
            .body(())
            .unwrap();
        req.extensions()
            .insert(Protocol::from_static("connect-udp"));
        ResponseVersionAdaptCtx::from_request(&req)
    }

    #[test]
    fn test_h1_to_h2_strips_hop_by_hop_headers() {
        let mut resp = Response::builder()
            .version(Version::HTTP_11)
            .header(CONNECTION, "keep-alive")
            .header("keep-alive", "timeout=5")
            .header(TRANSFER_ENCODING, "chunked")
            .header("content-type", "text/plain")
            // legal in HTTP/2 — must be preserved (not a protocol-illegal header)
            .header("trailer", "expires")
            .header("proxy-authenticate", "Basic")
            .body(())
            .unwrap();

        adapt_response_version(&mut resp, &ctx_with_version(Version::HTTP_2)).unwrap();

        assert_eq!(resp.version(), Version::HTTP_2);
        assert!(!resp.headers().contains_key(CONNECTION));
        assert!(!resp.headers().contains_key("keep-alive"));
        assert!(!resp.headers().contains_key(TRANSFER_ENCODING));
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
        // legal-in-HTTP/2 headers survive a pure version change
        assert_eq!(resp.headers().get("trailer").unwrap(), "expires");
        assert_eq!(resp.headers().get("proxy-authenticate").unwrap(), "Basic");
    }

    #[test]
    fn test_h1_to_h2_non_websocket_101_errors() {
        let mut resp = Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(UPGRADE, "h2c")
            .header(CONNECTION, "Upgrade")
            .body(())
            .unwrap();

        // a non-websocket 101 has no supported HTTP/2 translation -> explicit error,
        // not a silent passthrough.
        let err =
            adapt_response_version(&mut resp, &ctx_with_version(Version::HTTP_2)).unwrap_err();
        assert!(
            err.to_string().contains("only websocket is supported"),
            "{err}"
        );
    }

    #[test]
    fn test_h2_to_h1_unsupported_extended_connect_errors() {
        let mut resp = Response::builder()
            .version(Version::HTTP_2)
            .status(StatusCode::OK)
            .body(())
            .unwrap();

        // a non-websocket Extended CONNECT (e.g. connect-udp) cannot be downgraded to
        // an HTTP/1 handshake -> explicit error.
        let err =
            adapt_response_version(&mut resp, &connect_udp_ctx(Version::HTTP_11)).unwrap_err();
        assert!(
            err.to_string().contains("only websocket is supported"),
            "{err}"
        );
    }

    #[test]
    fn test_h1_to_h2_websocket_101_becomes_200() {
        let mut resp = Response::builder()
            .version(Version::HTTP_11)
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header("sec-websocket-accept", SAMPLE_ACCEPT)
            .body(())
            .unwrap();

        adapt_response_version(&mut resp, &websocket_ctx(Version::HTTP_2)).unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_2);
        // h1 handshake / connection-specific headers are gone in h2
        assert!(!resp.headers().contains_key(UPGRADE));
        assert!(!resp.headers().contains_key(CONNECTION));
        assert!(!resp.headers().contains_key("sec-websocket-accept"));
    }

    #[test]
    fn test_h2_to_h1_websocket_200_becomes_101() {
        let mut resp = Response::builder()
            .version(Version::HTTP_2)
            .status(StatusCode::OK)
            .body(())
            .unwrap();

        adapt_response_version(&mut resp, &websocket_ctx(Version::HTTP_11)).unwrap();

        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(
            resp.headers()
                .typed_get::<Upgrade>()
                .is_some_and(|u| u.is_websocket())
        );
        assert!(
            resp.headers()
                .typed_get::<Connection>()
                .is_some_and(|c| c.contains_upgrade())
        );
        // the accept is recomputed from the original request key (RFC 6455 example)
        assert_eq!(
            resp.headers().get("sec-websocket-accept").unwrap(),
            SAMPLE_ACCEPT,
        );
    }

    #[test]
    fn test_h2_to_h1_non_websocket_only_changes_version() {
        let mut resp = Response::builder()
            .version(Version::HTTP_2)
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();

        adapt_response_version(&mut resp, &ctx_with_version(Version::HTTP_11)).unwrap();

        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/plain");
    }
}
