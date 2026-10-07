//! WebSocket client types and utilities

#![expect(
    clippy::unreachable,
    reason = "vendored from upstream `tungstenite-rs`: arms gated on caller-validated WebSocket protocol state that the type system can't enforce"
)]

use std::{
    fmt,
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rama_core::Service;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::futures::{Sink, SinkExt as _, Stream, StreamExt as _};
use rama_core::rt::blocking::Io as BlockingIo;
use rama_core::telemetry::tracing;
use rama_http::conn::TargetHttpVersion;
use rama_http::headers::sec_websocket_extensions::{Extension, PerMessageDeflateConfig};
use rama_http::headers::sec_websocket_protocol::AcceptedWebSocketProtocol;
use rama_http::headers::{
    HeaderMapExt, HttpRequestBuilderExt as _, SecWebSocketExtensions, SecWebSocketKey,
    SecWebSocketProtocol,
};
use rama_http::proto::ext::Protocol;
use rama_http::service::client::blocking::Client as BlockingHttpClient;
use rama_http::service::client::ext::{IntoHeaderName, IntoHeaderValue};
use rama_http::service::client::{HttpClientExt, IntoUrl, RequestBuilder};
use rama_http::{Body, HeaderMap, Method, Request, Response, StatusCode, Version, header, headers};
use rama_http::{request, response};
use rama_net::extensions::StreamTransformed;
use rama_utils::str::NonEmptyStr;

use crate::protocol::{CloseFrame, Message, ProtocolError, Role, WebSocket, WebSocketConfig};
use crate::runtime::AsyncWebSocket;

/// Builder that can be used by clients to initiate the WebSocket handshake.
#[derive(Debug, Clone)]
pub struct WebSocketRequestBuilder<B> {
    inner: B,
    protocols: Option<SecWebSocketProtocol>,
    extensions: Option<SecWebSocketExtensions>,
    key: Option<SecWebSocketKey>,
}

#[derive(Debug)]
/// Request data to be used by an http client to initiate an http request.
pub struct HandshakeRequest {
    pub request: Request,
    pub protocols: Option<SecWebSocketProtocol>,
    pub extensions: Option<SecWebSocketExtensions>,
    pub key: Option<SecWebSocketKey>,
}

struct PreparedHandshakeRequest {
    request: Request,
    protocols: Option<SecWebSocketProtocol>,
    extensions: Option<SecWebSocketExtensions>,
    config: Option<WebSocketConfig>,
    key: Option<SecWebSocketKey>,
}

impl PreparedHandshakeRequest {
    async fn send<S, Body>(
        self,
        service: &S,
    ) -> Result<NegotiatedHandshakeRequest<Body>, HandshakeError>
    where
        S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
    {
        let uri = self.request.uri().clone();
        let response = service.serve(self.request).await.map_err(|err| {
            let err: BoxError = err.into();
            HandshakeError::HttpRequestError(
                err.context(uri)
                    .context("send initial websocket handshake request (upgrade)"),
            )
        })?;

        Ok(NegotiatedHandshakeRequest {
            protocols: self.protocols,
            extensions: self.extensions,
            config: self.config,
            key: self.key,
            response,
        })
    }
}

/// [`WebSocketRequestBuilder`] inner wrapper type used for a builder,
/// which includes a service, and thus is there to actually send the request as well and
/// even follow up.
pub struct WithService<'a, S, Body, Mode = websocket_builder_mode::Async> {
    service: &'a S,
    builder: RequestBuilder<'a, S, Response<Body>>,
    config: Option<WebSocketConfig>,
    version: Version,
    mode: Mode,
}

impl<S: fmt::Debug, Body, Mode: fmt::Debug> fmt::Debug for WithService<'_, S, Body, Mode> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithService")
            .field("builder", &self.builder)
            .field("config", &self.config)
            .field("version", &self.version)
            .field("mode", &self.mode)
            .finish()
    }
}

/// WebSocket request-builder execution modes.
pub mod websocket_builder_mode {
    use std::sync::Arc;

    use rama_core::rt::blocking::Runtime;

    /// Asynchronous terminal handshake operations.
    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Async;

    /// Blocking terminal handshake operations.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct Blocking<S> {
        pub(crate) runtime: Runtime,
        pub(crate) service: Arc<S>,
    }
}

/// A WebSocket request builder whose terminal handshake operations block the
/// calling thread.
pub type BlockingWebSocketRequestBuilder<'a, S, Body> =
    WebSocketRequestBuilder<WithService<'a, S, Body, websocket_builder_mode::Blocking<S>>>;

/// HTTP/2 and HTTP/3 bootstrap WebSockets with Extended CONNECT instead of an upgrade.
fn is_extended_connect(version: Version) -> bool {
    matches!(version, Version::HTTP_2 | Version::HTTP_3)
}

fn new_ws_request_builder_from_uri<T>(uri: T, version: Version) -> request::Builder
where
    T: TryInto<rama_net::uri::Uri, Error: Into<rama_http::HttpError>>,
{
    let builder = Request::builder()
        .version(version)
        .uri(uri)
        .typed_header(headers::SecWebSocketVersion::V13);

    match version {
        version @ (Version::HTTP_10 | Version::HTTP_11) => builder
            .method(Method::GET)
            .version(version)
            .typed_header(headers::Upgrade::websocket())
            .typed_header(headers::Connection::upgrade()),
        // RFC 8441 (HTTP/2) and RFC 9220 (HTTP/3) Extended CONNECT.
        version @ (Version::HTTP_2 | Version::HTTP_3) => {
            builder.method(Method::CONNECT).version(version)
        }
        _ => unreachable!("bug"),
    }
}

fn new_ws_request_builder_from_uri_with_service<'a, S, Body, T>(
    service: &'a S,
    uri: T,
    version: Version,
) -> RequestBuilder<'a, S, Response<Body>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
    T: IntoUrl,
{
    let builder = match version {
        version @ (Version::HTTP_10 | Version::HTTP_11) => service
            .get(uri)
            .version(version)
            .typed_header(headers::Upgrade::websocket())
            .typed_header(headers::Connection::upgrade()),
        version @ (Version::HTTP_2 | Version::HTTP_3) => service.connect(uri).version(version),
        _ => unreachable!("bug"),
    };

    builder.typed_header(headers::SecWebSocketVersion::V13)
}

fn new_ws_request_builder_from_request<'a, S, Body, RequestBody>(
    service: &'a S,
    mut request: Request<RequestBody>,
) -> RequestBuilder<'a, S, Response<Body>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
    RequestBody: Into<rama_http::Body>,
{
    if !request
        .headers()
        .contains_key(header::SEC_WEBSOCKET_VERSION)
    {
        request
            .headers_mut()
            .typed_insert(headers::SecWebSocketVersion::V13);
    }

    match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => {
            if request.headers().get(header::UPGRADE).is_none() {
                request
                    .headers_mut()
                    .typed_insert(headers::Upgrade::websocket());
            }
            if request.headers().get(header::CONNECTION).is_none() {
                request
                    .headers_mut()
                    .typed_insert(headers::Connection::upgrade());
            }
        }
        // - for h2 and h3: nothing to do
        // - else: this will error downstream due to invalid version
        _ => (),
    }
    service.build_from_request(request)
}

#[derive(Debug)]
/// Client error which can be triggered in case the response validation failed
pub enum ResponseValidateError {
    UnexpectedStatusCode(StatusCode),
    UnexpectedHttpVersion(Version),
    MissingUpgradeWebSocketHeader,
    MissingConnectionUpgradeHeader,
    SecWebSocketAcceptKeyMismatch,
    ProtocolMismatch(Option<NonEmptyStr>),
    ExtensionMismatch(Option<Extension>),
}

#[derive(Debug)]
/// Client error which can be triggered in case the handshake phase failed.
pub enum HandshakeError {
    ValidationError(ResponseValidateError),
    HttpRequestError(BoxError),
    HttpUpgradeError(BoxError),
}

impl fmt::Display for ResponseValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedStatusCode(status_code) => {
                write!(f, "unexpected HTTP status code: {status_code}")
            }
            Self::UnexpectedHttpVersion(version) => {
                write!(f, "unexpected HTTP version: {version:?}")
            }
            Self::MissingUpgradeWebSocketHeader => {
                write!(f, "missing upgrade WebSocket header")
            }
            Self::MissingConnectionUpgradeHeader => {
                write!(f, "missing connection upgrade header")
            }
            Self::SecWebSocketAcceptKeyMismatch => {
                write!(f, "key mismatch for sec-websocket-accept header")
            }
            Self::ProtocolMismatch(protocol) => {
                write!(f, "protocol mismatch: {protocol:?}")
            }
            Self::ExtensionMismatch(extension) => {
                write!(f, "extension mismatch: {extension:?}")
            }
        }
    }
}

impl std::error::Error for ResponseValidateError {}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationError(error) => {
                write!(f, "response validation failed: {error}")
            }
            Self::HttpRequestError(error) => {
                write!(f, "http request error: {error}")
            }
            Self::HttpUpgradeError(error) => {
                write!(f, "http upgrade error: {error}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ValidationError(error) => Some(error as &dyn std::error::Error),
            Self::HttpRequestError(error) | Self::HttpUpgradeError(error) => error.source(),
        }
    }
}

#[derive(Default, Debug)]
pub struct AcceptedWebSocketData {
    pub protocol: Option<AcceptedWebSocketProtocol>,
    pub extension: Option<Extension>,
}

/// The configuration a permessage-deflate response accepts for `offer`, if it answers it
/// (RFC 7692 §§3, 7): under the same extension name; a server constraint the offer makes
/// must be echoed, `server_max_window_bits` at most the offered value; `client_max_window_bits`
/// may only answer an offer naming it, whose value is a hint; the server may impose no
/// context takeover on the client.
fn accept_pmd(
    offer: &PerMessageDeflateConfig,
    response: &PerMessageDeflateConfig,
) -> Option<PerMessageDeflateConfig> {
    if offer.identifier != response.identifier {
        return None;
    }
    let client_max_window_bits = match response.client_max_window_bits {
        None => None,
        // zlib cannot compress within an 8-bit window
        Some(bits) if offer.client_max_window_bits.is_some() && (9..=15).contains(&bits) => {
            Some(bits)
        }
        Some(_) => return None,
    };
    let offered_server_bits = offer.server_max_window_bits.filter(|bits| *bits != 0);
    let server_max_window_bits = match (response.server_max_window_bits, offered_server_bits) {
        (None, None) => None,
        (Some(bits), limit)
            if (8..=15).contains(&bits) && limit.is_none_or(|limit| bits <= limit) =>
        {
            Some(bits)
        }
        // an offered limit unanswered, out of range or exceeded
        _ => return None,
    };
    if offer.server_no_context_takeover && !response.server_no_context_takeover {
        return None;
    }
    Some(PerMessageDeflateConfig {
        identifier: response.identifier.clone(),
        server_no_context_takeover: response.server_no_context_takeover,
        client_no_context_takeover: response.client_no_context_takeover
            || offer.client_no_context_takeover,
        server_max_window_bits,
        client_max_window_bits,
    })
}

/// The extension and subprotocol a server response selects: at most one of each
/// (RFC 6455 §4.2.2, RFC 7692 §5), and a value that does not parse fails.
fn server_selection(
    headers: &HeaderMap,
) -> Result<(Option<Extension>, Option<NonEmptyStr>), ResponseValidateError> {
    let extension = match headers.typed_try_get::<SecWebSocketExtensions>() {
        Ok(None) => None,
        Ok(Some(SecWebSocketExtensions(mut selected))) => {
            if !selected.tail.is_empty() {
                return Err(ResponseValidateError::ExtensionMismatch(Some(
                    selected.tail.swap_remove(0),
                )));
            }
            Some(selected.head)
        }
        // RFC 7692 §7.1: an extension response that does not parse fails the connection
        Err(_) => return Err(ResponseValidateError::ExtensionMismatch(None)),
    };
    let protocol = match headers.typed_try_get::<SecWebSocketProtocol>() {
        Ok(None) => None,
        Ok(Some(SecWebSocketProtocol(mut selected))) => {
            if !selected.tail.is_empty() {
                return Err(ResponseValidateError::ProtocolMismatch(Some(
                    selected.tail.swap_remove(0),
                )));
            }
            Some(selected.head)
        }
        Err(_) => return Err(ResponseValidateError::ProtocolMismatch(None)),
    };
    Ok((extension, protocol))
}

/// Validate the "accept" response from the http server
/// with whom the client is trying to establish a WebSocket connection.
pub fn validate_http_server_response<Body>(
    response: &Response<Body>,
    key: Option<headers::SecWebSocketKey>,
    protocols: Option<SecWebSocketProtocol>,
    extensions: Option<SecWebSocketExtensions>,
) -> Result<AcceptedWebSocketData, ResponseValidateError> {
    tracing::trace!(
        http.version = ?response.version(),
        http.response.status = ?response.status(),
        ws.protocols = ?protocols,
        ws.extensions = ?extensions,
        "validate http server response"
    );

    match response.version() {
        Version::HTTP_10 | Version::HTTP_11 => {
            // If the status code received from the server is not 101, the
            // client handles the response per HTTP [RFC2616] procedures. (RFC 6455)
            let response_status = response.status();
            if response_status != StatusCode::SWITCHING_PROTOCOLS {
                return Err(ResponseValidateError::UnexpectedStatusCode(response_status));
            }

            // If the response lacks an |Upgrade| header field or the |Upgrade|
            // header field contains a value that is not an ASCII case-
            // insensitive match for the value "websocket", the client MUST
            // _Fail the WebSocket Connection_. (RFC 6455)
            if !response
                .headers()
                .typed_get::<headers::Upgrade>()
                .map(|u| u.is_websocket())
                .unwrap_or_default()
            {
                return Err(ResponseValidateError::MissingUpgradeWebSocketHeader);
            }

            // If the response lacks a |Connection| header field or the
            // |Connection| header field doesn't contain a token that is an
            // ASCII case-insensitive match for the value "Upgrade", the client
            // MUST _Fail the WebSocket Connection_. (RFC 6455)
            if !response
                .headers()
                .typed_get::<headers::Connection>()
                .map(|c| c.contains_upgrade())
                .unwrap_or_default()
            {
                return Err(ResponseValidateError::MissingConnectionUpgradeHeader);
            }

            // Sec-WebSocket-Key / Accept is only used in h1 responses.
            //
            // If the response lacks a |Sec-WebSocket-Accept| header field or
            // the |Sec-WebSocket-Accept| contains a value other than the
            // base64-encoded SHA-1 of ... the client MUST _Fail the WebSocket
            // Connection_. (RFC 6455)
            if let Some(key) = key {
                let sec_websocket_accept_header = response
                    .headers()
                    .typed_get::<headers::SecWebSocketAccept>();
                let expected_accept =
                    headers::SecWebSocketAccept::try_from(key).map_err(|err| {
                        tracing::debug!("failed to create WS accept header from key: {err}");
                        ResponseValidateError::SecWebSocketAcceptKeyMismatch
                    })?;
                if sec_websocket_accept_header != Some(expected_accept) {
                    tracing::trace!(
                        "unexpected websocket accept key: {sec_websocket_accept_header:?}"
                    );
                    return Err(ResponseValidateError::SecWebSocketAcceptKeyMismatch);
                }
            }
        }
        // Extended CONNECT succeeds with any 2xx (RFC 8441 §5, RFC 9220 §3).
        Version::HTTP_2 | Version::HTTP_3 => {
            let response_status = response.status();
            if !response.status().is_success() {
                return Err(ResponseValidateError::UnexpectedStatusCode(response_status));
            }
        }
        version => {
            return Err(ResponseValidateError::UnexpectedHttpVersion(version));
        }
    }

    // If the response includes a |Sec-WebSocket-Extensions| header
    // field and this header field indicates the use of an extension
    // that was not present in the client's handshake (the server has
    // indicated an extension not requested by the client), the client
    // MUST _Fail the WebSocket Connection_. (RFC 6455)
    let mut accepted_extension = None;
    let (response_extension, response_protocol) = server_selection(response.headers())?;
    match (response_extension, extensions) {
        (None, Some(allowed_extensions)) => {
            tracing::trace!(
                ws.extensions = ?allowed_extensions,
                "server selected no WS extensions despite client supporting some (valid, move on without)",
            );
        }
        (Some(Extension::PerMessageDeflate(server_cfg)), Some(client_extensions)) => {
            let accepted = client_extensions.0.iter().find_map(|offer| match offer {
                Extension::PerMessageDeflate(offer) => accept_pmd(offer, &server_cfg),
                _ => None,
            });
            let Some(accepted) = accepted else {
                tracing::debug!("server's permessage-deflate answers none of our offers");
                return Err(ResponseValidateError::ExtensionMismatch(Some(
                    Extension::PerMessageDeflate(server_cfg),
                )));
            };
            accepted_extension = Some(Extension::PerMessageDeflate(accepted));
        }
        (Some(server_ext), _) => {
            tracing::debug!("server offered ext, but client (we) not!");
            return Err(ResponseValidateError::ExtensionMismatch(Some(server_ext)));
        }
        (None, None) => (),
    }

    // If the response includes a |Sec-WebSocket-Protocol| header field
    // and this header field indicates the use of a subprotocol that was
    // not present in the client's handshake (the server has indicated a
    // subprotocol not requested by the client), the client MUST _Fail
    // the WebSocket Connection_. (RFC 6455)
    let mut accepted_protocol = None;
    match (response_protocol, protocols) {
        (None, None) => (),
        (None, Some(allowed_protocols)) => {
            // RFC 6455 only mandates failure when the server selects a protocol
            // not in the client's offer — a server may legitimately decline to
            // select any subprotocol even when the client proposed one.
            tracing::trace!(
                ws.protocols = ?allowed_protocols,
                "server selected no WS subprotocol despite client proposing some (valid, proceed without)",
            );
        }
        (Some(selected), None) => {
            return Err(ResponseValidateError::ProtocolMismatch(Some(selected)));
        }
        (Some(selected), Some(sub_protocols)) => {
            match sub_protocols.contains(&selected) {
                Some(protocol) => accepted_protocol = Some(protocol),
                None => {
                    return Err(ResponseValidateError::ProtocolMismatch(Some(selected)));
                }
            };
        }
    }

    Ok(AcceptedWebSocketData {
        protocol: accepted_protocol,
        extension: accepted_extension,
    })
}

impl WebSocketRequestBuilder<request::Builder> {
    /// Create a new `http/1.1` WebSocket [`Request`] builder.
    pub fn new<T>(uri: T) -> Self
    where
        T: TryInto<rama_net::uri::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self::new_with_version(uri, Version::HTTP_11)
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2<T>(uri: T) -> Self
    where
        T: TryInto<rama_net::uri::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self::new_with_version(uri, Version::HTTP_2)
    }

    /// Create a new `h3` WebSocket [`Request`] builder (RFC 9220).
    pub fn new_h3<T>(uri: T) -> Self
    where
        T: TryInto<rama_net::uri::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self::new_with_version(uri, Version::HTTP_3)
    }

    fn new_with_version<T>(uri: T, version: Version) -> Self
    where
        T: TryInto<rama_net::uri::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self {
            inner: new_ws_request_builder_from_uri(uri, version),
            protocols: Default::default(),
            extensions: Default::default(),
            key: Default::default(),
        }
    }

    /// Set a custom http header
    #[must_use]
    pub fn with_header<K, V>(self, name: K, value: V) -> Self
    where
        K: TryInto<rama_http::HeaderName, Error: Into<rama_http::HttpError>>,
        V: TryInto<rama_http::HeaderValue, Error: Into<rama_http::HttpError>>,
    {
        Self {
            inner: self.inner.header(name, value),
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    /// Set a custom typed http header
    #[must_use]
    pub fn with_typed_header<H>(self, header: H) -> Self
    where
        H: headers::HeaderEncode,
    {
        Self {
            inner: self.inner.typed_header(header),
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    /// Build the handshake data
    /// to be used to initiate the WebSocket handshake using an http client.
    pub fn build_handshake(self) -> Result<HandshakeRequest, BoxError> {
        let builder = match self.protocols.as_ref() {
            Some(protocols) => self.inner.typed_header(protocols),
            None => self.inner,
        };

        let builder = match self.extensions.as_ref() {
            Some(extensions) => builder.typed_header(extensions),
            None => builder,
        };

        let mut request = builder
            .body(Body::empty())
            .context("request failed to build (invalid custom header?)")?;

        let mut key = None;
        if !is_extended_connect(request.version()) {
            let k = self.key.unwrap_or_else(headers::SecWebSocketKey::random);
            request.headers_mut().typed_insert(&k);
            key = Some(k);
        }

        // only required for h2, but we might upgrade from h1 to h2 based on layers such as tls
        request
            .extensions()
            .insert(Protocol::from_static("websocket"));

        Ok(HandshakeRequest {
            request,
            protocols: self.protocols,
            extensions: self.extensions,
            key,
        })
    }
}

impl<'a, S, Body> WebSocketRequestBuilder<WithService<'a, S, Body, websocket_builder_mode::Async>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    /// Create a new `http/1.1` WebSocket [`Request`] builder.
    pub fn new_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version_and_mode(
            service,
            Version::HTTP_11,
            uri,
            websocket_builder_mode::Async,
        )
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version_and_mode(
            service,
            Version::HTTP_2,
            uri,
            websocket_builder_mode::Async,
        )
    }

    /// Create a new `h3` WebSocket [`Request`] builder (RFC 9220).
    pub fn new_h3_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version_and_mode(
            service,
            Version::HTTP_3,
            uri,
            websocket_builder_mode::Async,
        )
    }

    /// Create a new WebSocket [`Request`] builder for the given [`Request`]
    pub fn new_with_service_and_request<RequestBody>(
        service: &'a S,
        request: Request<RequestBody>,
    ) -> Self
    where
        RequestBody: Into<rama_http::Body>,
    {
        Self::new_with_service_request_and_mode(service, request, websocket_builder_mode::Async)
    }
}

impl<'a, S, Body, Mode> WebSocketRequestBuilder<WithService<'a, S, Body, Mode>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    fn new_with_service_and_version_and_mode<T>(
        service: &'a S,
        version: Version,
        uri: T,
        mode: Mode,
    ) -> Self
    where
        T: IntoUrl,
    {
        Self {
            inner: WithService {
                service,
                builder: new_ws_request_builder_from_uri_with_service(service, uri, version),
                config: Default::default(),
                version,
                mode,
            },
            protocols: Default::default(),
            extensions: Default::default(),
            key: Default::default(),
        }
    }

    fn new_with_service_request_and_mode<RequestBody>(
        service: &'a S,
        request: Request<RequestBody>,
        mode: Mode,
    ) -> Self
    where
        RequestBody: Into<rama_http::Body>,
    {
        let key = request.headers().typed_get();
        let version = request.version();
        let protocols = request.headers().typed_get();
        let extensions = request.headers().typed_get();

        Self {
            inner: WithService {
                service,
                builder: new_ws_request_builder_from_request(service, request),
                config: Default::default(),
                version,
                mode,
            },
            protocols,
            extensions,
            key,
        }
    }

    /// Set a custom http header
    #[must_use]
    pub fn with_header<K, V>(self, name: K, value: V) -> Self
    where
        K: IntoHeaderName,
        V: IntoHeaderValue,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.header(name, value),
                ..self.inner
            },
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    /// Overwrite a custom http header
    #[must_use]
    pub fn with_header_overwrite<K, V>(self, name: K, value: V) -> Self
    where
        K: IntoHeaderName,
        V: IntoHeaderValue,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.overwrite_header(name, value),
                ..self.inner
            },
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    /// Set a custom typed http header
    #[must_use]
    pub fn with_typed_header<H>(self, header: H) -> Self
    where
        H: headers::HeaderEncode,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.typed_header(header),
                ..self.inner
            },
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    /// Overwrite a custom typed http header
    #[must_use]
    pub fn with_typed_header_overwrite<H>(self, header: H) -> Self
    where
        H: headers::HeaderEncode,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.overwrite_typed_header(header),
                ..self.inner
            },
            protocols: self.protocols,
            extensions: self.extensions,
            key: self.key,
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set/add deflate ext and also apply it to the [`WebSocketConfig`],
        /// using the default [`crate::protocol::PerMessageDeflateConfig`].
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate(mut self) -> Self {
            self.extensions = match self.extensions.take() {
                Some(ext) => {
                    Some(ext.with_extra_extension(Extension::PerMessageDeflate(Default::default())))
                },
                None => Some(SecWebSocketExtensions::per_message_deflate()),
            };
            self.inner.config = Some(self.inner.config.take().unwrap_or_default().with_per_message_deflate_default());
            self
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set/add deflate ext and also apply it to the [`WebSocketConfig`],
        /// using the default [`crate::protocol::PerMessageDeflateConfig`].
        ///
        /// Overwrites existing extensions if already existed.
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate_overwrite_extensions(mut self) -> Self {
            self.extensions = Some(SecWebSocketExtensions::per_message_deflate());
            self.inner.config = Some(self.inner.config.take().unwrap_or_default().with_per_message_deflate_default());
            self
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set/add deflate ext and also apply it to the [`WebSocketConfig`],
        /// using the default [`crate::protocol::PerMessageDeflateConfig`].
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate_with_config(mut self, config: impl Into<crate::protocol::PerMessageDeflateConfig>) -> Self {
            let config = config.into();
            self.extensions = match self.extensions.take() {
                Some(ext) => {
                    Some(ext.with_extra_extension(Extension::PerMessageDeflate((&config).into())))
                }
                None => Some(SecWebSocketExtensions::per_message_deflate_with_config((&config).into())),
            };
            self.inner.config = Some(
                self.inner
                    .config
                    .take()
                    .unwrap_or_default()
                    .with_per_message_deflate(config),
            );
            self
        }
    }

    #[cfg(feature = "compression")]
    rama_utils::macros::generate_set_and_with! {
        /// Set/add deflate ext and also apply it to the [`WebSocketConfig`],
        /// using the default [`crate::protocol::PerMessageDeflateConfig`].
        ///
        /// Overwrites existing extensions if already existed.
        #[must_use]
        #[cfg_attr(docsrs, doc(cfg(feature = "compression")))]
        pub fn per_message_deflate_with_config_overwrite_extensions(mut self, config: impl Into<crate::protocol::PerMessageDeflateConfig>) -> Self {
            let config = config.into();
            self.extensions = Some(SecWebSocketExtensions::per_message_deflate_with_config((&config).into()));
            self.inner.config = Some(
                self.inner
                    .config
                    .take()
                    .unwrap_or_default()
                    .with_per_message_deflate(config),
            );
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`WebSocketConfig`], overwriting the previous config if already set.
        pub fn config(mut self, cfg: Option<WebSocketConfig>) -> Self {
            self.inner.config = cfg;
            self
        }
    }

    fn prepare_handshake_inner(
        self,
        extensions: &Extensions,
    ) -> Result<PreparedHandshakeRequest, HandshakeError> {
        extensions.insert(StreamTransformed {
            by: "rama-ws::WebSocketClient",
        });

        let builder = match self.protocols.as_ref() {
            Some(protocols) => self.inner.builder.overwrite_typed_header(protocols),
            None => self.inner.builder,
        };

        let builder = match self.extensions.as_ref() {
            Some(extensions) => builder.typed_header(extensions),
            None => builder,
        };

        let mut key = None;
        let builder = if is_extended_connect(self.inner.version) {
            extensions.insert(TargetHttpVersion(self.inner.version));

            builder
        } else {
            extensions.insert(TargetHttpVersion(Version::HTTP_11));

            let k = self.key.unwrap_or_else(headers::SecWebSocketKey::random);
            let builder = builder.overwrite_typed_header(&k);
            key = Some(k);
            builder
        };

        // only required in h1, but because of layers such as tls we might anyway turn from h1 into h2
        let builder = builder.extension(Protocol::from_static("websocket"));

        if let Some(ext) = builder.extensions() {
            ext.extend(extensions);
        }

        let request = builder
            .build()
            .context("build initial websocket handshake request (upgrade)")
            .map_err(HandshakeError::HttpRequestError)?;

        Ok(PreparedHandshakeRequest {
            request,
            protocols: self.protocols,
            extensions: self.extensions,
            config: self.inner.config,
            key,
        })
    }

    async fn initiate_handshake_inner(
        self,
        extensions: Extensions,
    ) -> Result<NegotiatedHandshakeRequest<Body>, HandshakeError> {
        let service = self.inner.service;
        let prepared = self.prepare_handshake_inner(&extensions)?;
        prepared.send(service).await
    }
}

impl<'a, S, Body> WebSocketRequestBuilder<WithService<'a, S, Body, websocket_builder_mode::Async>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    /// Initiate the handshake by preparing the http request, sending it
    /// and receiving the http response.
    ///
    /// This consumes this [`WebSocketRequestBuilder`]. Fulfill
    /// the handshake by calling [`NegotiatedHandshakeRequest::complete`].
    ///
    /// In most cases you have however no need for this intermediate result,
    /// and are better of calling [`Self::handshake`] directly. Only in cases
    /// such as MITM proxies or edge-case purposes you might require access
    /// to [`NegotiatedHandshakeRequest`].
    pub async fn initiate_handshake(
        self,
        extensions: Extensions,
    ) -> Result<NegotiatedHandshakeRequest<Body>, HandshakeError> {
        self.initiate_handshake_inner(extensions).await
    }

    /// Establish a [`ClientWebSocket`], consuming this [`WebSocketRequestBuilder`],
    /// by doing the http-handshake, including validation and returning the socket if all is good.
    pub async fn handshake(self, extensions: Extensions) -> Result<ClientWebSocket, HandshakeError>
    where
        Body: Send + 'static,
    {
        let handshake = self.initiate_handshake(extensions).await?;
        handshake.complete().await
    }
}

impl<'a, S, Body>
    WebSocketRequestBuilder<WithService<'a, S, Body, websocket_builder_mode::Blocking<S>>>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    fn new_blocking_with_service<T>(client: &'a BlockingHttpClient<S>, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version_and_mode(
            client.get_ref(),
            Version::HTTP_11,
            uri,
            websocket_builder_mode::Blocking {
                runtime: client.runtime().clone(),
                service: client.clone_service(),
            },
        )
    }

    fn new_blocking_h2_with_service<T>(client: &'a BlockingHttpClient<S>, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_blocking_with_service_and_version(client, Version::HTTP_2, uri)
    }

    fn new_blocking_h3_with_service<T>(client: &'a BlockingHttpClient<S>, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_blocking_with_service_and_version(client, Version::HTTP_3, uri)
    }

    fn new_blocking_with_service_and_version<T>(
        client: &'a BlockingHttpClient<S>,
        version: Version,
        uri: T,
    ) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version_and_mode(
            client.get_ref(),
            version,
            uri,
            websocket_builder_mode::Blocking {
                runtime: client.runtime().clone(),
                service: client.clone_service(),
            },
        )
    }

    fn new_blocking_with_service_and_request<RequestBody>(
        client: &'a BlockingHttpClient<S>,
        request: Request<RequestBody>,
    ) -> Self
    where
        RequestBody: Into<rama_http::Body>,
    {
        Self::new_with_service_request_and_mode(
            client.get_ref(),
            request,
            websocket_builder_mode::Blocking {
                runtime: client.runtime().clone(),
                service: client.clone_service(),
            },
        )
    }

    /// Establish a blocking [`BlockingClientWebSocket`] using empty request
    /// extensions.
    pub fn try_handshake(self) -> Result<BlockingClientWebSocket, HandshakeError> {
        self.try_handshake_with_extensions(Extensions::new())
    }

    /// Establish a blocking [`BlockingClientWebSocket`] using the supplied
    /// request extensions.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "matches the async handshake API and transfers the extension set"
    )]
    pub fn try_handshake_with_extensions(
        self,
        extensions: Extensions,
    ) -> Result<BlockingClientWebSocket, HandshakeError> {
        let runtime = self.inner.mode.runtime.clone();
        let service = Arc::clone(&self.inner.mode.service);
        let prepared = self.prepare_handshake_inner(&extensions)?;
        let completed = runtime.block_on_task(async move {
            let handshake = prepared.send(service.as_ref()).await?;
            handshake.complete_upgrade().await
        })?;
        let socket = WebSocket::from_raw_socket(
            runtime.io(completed.stream),
            Role::Client,
            completed.config,
        );

        Ok(BlockingClientWebSocket {
            socket,
            response: completed.response,
            accepted_protocol: completed.accepted_protocol,
        })
    }
}

impl<B> WebSocketRequestBuilder<B> {
    rama_utils::macros::generate_set_and_with! {
        /// Define the WebSocket protocols to be used.
        pub fn protocols(mut self, protocols: Option<SecWebSocketProtocol>) -> Self {
            self.protocols = protocols;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket key (a random one will be generated if not defined).
        ///
        /// Only touch this property if you have a good reason to do so.
        pub fn key(mut self, key: Option<headers::SecWebSocketKey>) -> Self {
            self.key = key;
            self
        }
    }
}

/// Utility which can be used my Mitm proxies to
/// update the base config of a client websocket config.
///
/// Fails for a response a client must refuse: several or unparsable
/// extensions or subprotocols.
pub fn apply_response_data_to_base_websocket_config<Body>(
    base_cfg: Option<WebSocketConfig>,
    res: &mut Response<Body>,
) -> Result<Option<WebSocketConfig>, ResponseValidateError> {
    let (extension, protocol) = server_selection(res.headers())?;
    let accepted_pmd_cfg = match extension {
        Some(Extension::PerMessageDeflate(cfg)) => Some(cfg),
        _ => None,
    };

    if let Some(protocol) = protocol {
        res.extensions().insert(AcceptedWebSocketProtocol(protocol));
    }

    #[cfg(feature = "compression")]
    {
        Ok(if let Some(pmd_cfg) = accepted_pmd_cfg {
            let mut ws_cfg = base_cfg.unwrap_or_default();
            ws_cfg.per_message_deflate = Some(pmd_cfg.into());
            Some(ws_cfg)
        } else if let Some(mut ws_cfg) = base_cfg {
            ws_cfg.per_message_deflate = None;
            Some(ws_cfg)
        } else {
            base_cfg
        })
    }

    #[cfg(not(feature = "compression"))]
    {
        if accepted_pmd_cfg.is_some() {
            tracing::error!(
                "per-message-deflate is used but compression feature is disabled. Enable it if you wish to use this extension."
            );
        }

        Ok(base_cfg)
    }
}

/// Intermediate websocket handshake created by
/// [`WebSocketRequestBuilder::initiate_handshake`].
///
/// Useful in case you require access to some of the data
/// prior to validation and WS upgrading.
pub struct NegotiatedHandshakeRequest<Body> {
    pub protocols: Option<SecWebSocketProtocol>,
    pub extensions: Option<SecWebSocketExtensions>,
    pub config: Option<WebSocketConfig>,
    pub key: Option<SecWebSocketKey>,
    pub response: Response<Body>,
}

struct CompletedClientHandshake {
    stream: rama_http::io::upgrade::Upgraded,
    response: response::Parts,
    accepted_protocol: Option<AcceptedWebSocketProtocol>,
    config: Option<WebSocketConfig>,
}

impl<Body> NegotiatedHandshakeRequest<Body> {
    /// Fulfill the websocket handshake and return the upgraded [`ClientWebSocket`].
    pub async fn complete(self) -> Result<ClientWebSocket, HandshakeError>
    where
        Body: Send + 'static,
    {
        let completed = self.complete_upgrade().await?;
        let socket =
            AsyncWebSocket::from_raw_socket(completed.stream, Role::Client, completed.config).await;

        Ok(ClientWebSocket {
            socket,
            response: completed.response,
            accepted_protocol: completed.accepted_protocol,
        })
    }

    async fn complete_upgrade(self) -> Result<CompletedClientHandshake, HandshakeError>
    where
        Body: Send + 'static,
    {
        let accepted_data = validate_http_server_response(
            &self.response,
            self.key,
            self.protocols,
            self.extensions,
        )
        .map_err(HandshakeError::ValidationError)?;

        tracing::trace!(
            websocket.protocol = ?accepted_data.protocol,
            websocket.extension = ?accepted_data.extension,
            "websocket handshake http response is valid",
        );

        #[cfg(feature = "compression")]
        let maybe_ws_cfg = {
            let mut ws_cfg = self.config.unwrap_or_default();

            if let Some(Extension::PerMessageDeflate(pmd_cfg)) = accepted_data.extension {
                tracing::trace!(
                    "apply accepted per-message-deflate cfg into WS client config: {pmd_cfg:?}"
                );
                ws_cfg.per_message_deflate = Some(pmd_cfg.into());
            } else {
                ws_cfg.per_message_deflate = None;
            }

            Some(ws_cfg)
        };

        #[cfg(not(feature = "compression"))]
        let maybe_ws_cfg = {
            if let Some(Extension::PerMessageDeflate(pmd_cfg)) = accepted_data.extension {
                tracing::error!(
                    "per-message-deflate is used but compression feature is disabled. Enable it if you wish to use this extension."
                );
                return Err(HandshakeError::ValidationError(
                    ResponseValidateError::ExtensionMismatch(Some(Extension::PerMessageDeflate(
                        pmd_cfg,
                    ))),
                ));
            }
            self.config
        };

        let on_upgrade = rama_http::io::upgrade::handle_upgrade(&self.response);
        let (parts, body) = self.response.into_parts();
        let stream = on_upgrade
            .await
            .context("upgrade http connection into a raw web socket")
            .map_err(HandshakeError::HttpUpgradeError)?
            .with_guard(body);
        Ok(CompletedClientHandshake {
            stream,
            response: parts,
            accepted_protocol: accepted_data.protocol,
            config: maybe_ws_cfg,
        })
    }
}

#[derive(Debug)]
/// [`ClientWebSocket`], used as input-output stream.
///
/// Utility type created via [`WebSocketRequestBuilder::handshake`].
pub struct ClientWebSocket<S = AsyncWebSocket> {
    /// Established WebSocket message transport.
    pub socket: S,
    /// Original HTTP handshake response metadata.
    pub response: response::Parts,
    /// Subprotocol accepted during the HTTP handshake, when any.
    pub accepted_protocol: Option<AcceptedWebSocketProtocol>,
}

impl<S> Deref for ClientWebSocket<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<S> DerefMut for ClientWebSocket<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl<S> Stream for ClientWebSocket<S>
where
    S: Stream<Item = Result<Message, ProtocolError>> + Unpin,
{
    type Item = Result<Message, ProtocolError>;

    fn poll_next(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.get_mut().socket), ctx)
    }
}

impl<S> Sink<Message> for ClientWebSocket<S>
where
    S: Sink<Message, Error = ProtocolError> + Unpin,
{
    type Error = ProtocolError;

    fn poll_ready(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_ready(Pin::new(&mut self.get_mut().socket), ctx)
    }

    fn start_send(self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        Sink::start_send(Pin::new(&mut self.get_mut().socket), message)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_flush(Pin::new(&mut self.get_mut().socket), ctx)
    }

    fn poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_close(Pin::new(&mut self.get_mut().socket), ctx)
    }
}

impl<S> ExtensionsRef for ClientWebSocket<S>
where
    S: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        self.socket.extensions()
    }
}

impl<S> ClientWebSocket<S> {
    /// Transform the message transport while preserving handshake metadata.
    #[must_use]
    pub fn map_socket<T>(self, map: impl FnOnce(S) -> T) -> ClientWebSocket<T> {
        ClientWebSocket {
            socket: map(self.socket),
            response: self.response,
            accepted_protocol: self.accepted_protocol,
        }
    }

    /// Write and flush one message.
    pub fn send_message(
        &mut self,
        message: Message,
    ) -> impl Future<Output = Result<(), ProtocolError>> + Send + '_
    where
        S: Sink<Message, Error = ProtocolError> + Send + Unpin,
    {
        self.socket.send(message)
    }

    /// Receive one complete message.
    pub async fn recv_message(&mut self) -> Result<Message, ProtocolError>
    where
        S: Stream<Item = Result<Message, ProtocolError>> + Unpin,
    {
        self.socket.next().await.ok_or_else(|| {
            ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Connection closed: no messages to receive",
            ))
        })?
    }

    /// Start the close handshake by sending a Close frame.
    ///
    /// The handshake completes once the peer's Close is read: keep receiving until the
    /// stream ends. Dropping the socket before that aborts the connection.
    pub async fn close(&mut self, message: Option<CloseFrame>) -> Result<(), ProtocolError>
    where
        S: Sink<Message, Error = ProtocolError> + Send + Unpin,
    {
        self.socket.send(Message::Close(message)).await
    }

    /// View the original response data, from which this client web socket was created.
    pub fn response(&self) -> &response::Parts {
        &self.response
    }

    /// Return the accepted protocol (during the http handshake) of the [`ClientWebSocket`], if any.
    pub fn accepted_protocol(&self) -> Option<&str> {
        self.accepted_protocol.as_ref().map(|p| p.0.as_ref())
    }

    /// Consume `self` and return its message transport.
    pub fn into_inner(self) -> S {
        self.socket
    }
}

/// A synchronous WebSocket over an upgraded HTTP transport driven by a Rama
/// blocking runtime.
pub type BlockingWebSocket = WebSocket<BlockingIo<rama_http::io::upgrade::Upgraded>>;

/// A connected blocking client WebSocket and its HTTP handshake metadata.
#[derive(Debug)]
pub struct BlockingClientWebSocket {
    /// Established blocking WebSocket transport.
    pub socket: BlockingWebSocket,
    /// Original HTTP handshake response metadata.
    pub response: response::Parts,
    /// Subprotocol accepted during the HTTP handshake, when any.
    pub accepted_protocol: Option<AcceptedWebSocketProtocol>,
}

impl Deref for BlockingClientWebSocket {
    type Target = BlockingWebSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for BlockingClientWebSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl BlockingClientWebSocket {
    /// View the original response data from which this WebSocket was created.
    pub fn response(&self) -> &response::Parts {
        &self.response
    }

    /// Return the subprotocol accepted during the HTTP handshake, if any.
    pub fn accepted_protocol(&self) -> Option<&str> {
        self.accepted_protocol.as_ref().map(|p| p.0.as_ref())
    }

    /// Write and immediately flush a message.
    pub fn send_message(&mut self, message: Message) -> Result<(), ProtocolError> {
        self.socket.send(message)
    }

    /// Read the next message.
    pub fn recv_message(&mut self) -> Result<Message, ProtocolError> {
        self.socket.read()
    }

    /// Consume this wrapper and return the blocking WebSocket.
    pub fn into_inner(self) -> BlockingWebSocket {
        self.socket
    }
}

/// Extends an Http Client with high level features WebSocket features.
pub trait HttpClientWebSocketExt<Body>:
    private::HttpClientWebSocketExtSealed<Body> + Sized + Send + Sync + 'static
{
    /// Create a new [`WebSocketRequestBuilder`]] to be used to establish a WebSocket connection over http/1.1.
    fn websocket(&self, url: impl IntoUrl) -> WebSocketRequestBuilder<WithService<'_, Self, Body>>;

    /// Create a new [`WebSocketRequestBuilder`] to be used to establish a WebSocket connection over h2.
    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>>;

    /// Create a new [`WebSocketRequestBuilder`] to be used to establish a WebSocket connection over h3.
    fn websocket_h3(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>>;

    /// Create a new [`WebSocketRequestBuilder`] starting from the given request.
    ///
    /// This is useful in cases where you already have a request that you wish to use,
    /// for example in the case of a proxied reuqest.
    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        req: Request<RequestBody>,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>>;
}

impl<S, Body> HttpClientWebSocketExt<Body> for S
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
{
    fn websocket(&self, url: impl IntoUrl) -> WebSocketRequestBuilder<WithService<'_, Self, Body>> {
        WebSocketRequestBuilder::new_with_service(self, url)
    }

    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>> {
        WebSocketRequestBuilder::new_h2_with_service(self, url)
    }

    fn websocket_h3(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>> {
        WebSocketRequestBuilder::new_h3_with_service(self, url)
    }

    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        req: Request<RequestBody>,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>> {
        WebSocketRequestBuilder::new_with_service_and_request(self, req)
    }
}

/// Extends a blocking HTTP client with WebSocket handshake builders.
///
/// The HTTP client remains reusable after the handshake. Each successful
/// handshake returns one independent, connected [`BlockingClientWebSocket`].
///
/// # Panics
///
/// Blocking handshakes and socket I/O must not run directly on an asynchronous
/// executor thread.
///
/// ```no_run
/// use rama_core::{Service, error::BoxError};
/// use rama_http::{
///     Body, Request, Response,
///     service::client::blocking::Client,
/// };
/// use rama_ws::handshake::client::BlockingHttpClientWebSocketExt as _;
///
/// fn exchange<S>(client: &Client<S>) -> Result<(), BoxError>
/// where
///     S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
/// {
///     let mut socket = client
///         .websocket("wss://example.com/chat")
///         .with_header("authorization", "Bearer secret")
///         .try_handshake()?;
///
///     socket.send_message("hello".into())?;
///     let _reply = socket.recv_message()?;
///     Ok(())
/// }
/// ```
pub trait BlockingHttpClientWebSocketExt<Body>:
    private::BlockingHttpClientWebSocketExtSealed<Body>
{
    /// The asynchronous service wrapped by this blocking HTTP client.
    type AsyncService: Service<Request, Output = Response<Body>, Error: Into<BoxError>>;

    /// Create a WebSocket request builder for an HTTP/1.1 upgrade.
    fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body>;

    /// Create a WebSocket request builder for HTTP/2 Extended CONNECT.
    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body>;

    /// Create a WebSocket request builder for HTTP/3 Extended CONNECT.
    fn websocket_h3(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body>;

    /// Create a WebSocket request builder from an existing request.
    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        request: Request<RequestBody>,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body>;
}

impl<S, Body> BlockingHttpClientWebSocketExt<Body> for BlockingHttpClient<S>
where
    S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type AsyncService = S;

    fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body> {
        BlockingWebSocketRequestBuilder::new_blocking_with_service(self, url)
    }

    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body> {
        BlockingWebSocketRequestBuilder::new_blocking_h2_with_service(self, url)
    }

    fn websocket_h3(
        &self,
        url: impl IntoUrl,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body> {
        BlockingWebSocketRequestBuilder::new_blocking_h3_with_service(self, url)
    }

    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        request: Request<RequestBody>,
    ) -> BlockingWebSocketRequestBuilder<'_, Self::AsyncService, Body> {
        BlockingWebSocketRequestBuilder::new_blocking_with_service_and_request(self, request)
    }
}

mod private {
    use super::*;

    pub trait HttpClientWebSocketExtSealed<Body> {}

    impl<S, Body> HttpClientWebSocketExtSealed<Body> for S where
        S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>
    {
    }

    pub trait BlockingHttpClientWebSocketExtSealed<Body> {}

    impl<S, Body> BlockingHttpClientWebSocketExtSealed<Body> for BlockingHttpClient<S>
    where
        S: Service<Request, Output = Response<Body>, Error: Into<BoxError>>,
        Body: Send + 'static,
    {
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{ServiceInput, bytes::Bytes, service::service_fn};
    use rama_http::HeaderMap;
    use std::assert_matches;
    #[cfg(feature = "compression")]
    use std::io::Cursor;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[cfg(feature = "compression")]
    #[test]
    fn relay_config_from_upstream_window_bits_does_not_panic() {
        for raw in [
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=8; client_max_window_bits=8",
        ] {
            let mut res = Response::new(());
            res.headers_mut()
                .insert(header::SEC_WEBSOCKET_EXTENSIONS, raw.parse().unwrap());
            // a response that does not parse is refused, not relayed
            let Ok(cfg) = apply_response_data_to_base_websocket_config(None, &mut res) else {
                continue;
            };
            for role in [Role::Client, Role::Server] {
                drop(WebSocket::from_raw_socket(
                    Cursor::new(Vec::<u8>::new()),
                    role,
                    cfg,
                ));
            }
        }
    }

    struct ResponseLease(Arc<AtomicUsize>);

    impl Drop for ResponseLease {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    #[test]
    fn blocking_client_websocket_roundtrip_and_lifetimes() {
        fn assert_send<T: Send>() {}
        assert_send::<BlockingClientWebSocket>();

        let leases_dropped = Arc::new(AtomicUsize::new(0));
        let service_leases_dropped = leases_dropped.clone();
        let service = service_fn(move |request: Request| {
            let leases_dropped = service_leases_dropped.clone();
            async move {
                let is_h2 = request.version() == Version::HTTP_2;
                let accept = if is_h2 {
                    assert_eq!(request.method(), Method::CONNECT);
                    assert!(request.headers().typed_get::<SecWebSocketKey>().is_none());
                    None
                } else {
                    assert_eq!(request.method(), Method::GET);
                    let key = request
                        .headers()
                        .typed_get::<SecWebSocketKey>()
                        .expect("HTTP/1.1 client handshake request to contain a key");
                    Some(
                        headers::SecWebSocketAccept::try_from(key)
                            .expect("client handshake key to produce an accept value"),
                    )
                };

                if request.uri().path().is_some_and(|path| path == "/custom") {
                    assert_eq!(
                        request.headers().get("x-rama-test"),
                        Some(&rama_http::HeaderValue::from_static("custom")),
                    );
                }

                let (client_io, server_io) = tokio::io::duplex(4 * 1024);
                let (pending, on_upgrade) = rama_http::io::upgrade::pending();
                pending.fulfill(rama_http::io::upgrade::Upgraded::new(
                    ServiceInput::new(client_io),
                    Bytes::new(),
                ));

                tokio::spawn(async move {
                    let mut socket = AsyncWebSocket::from_raw_socket(
                        ServiceInput::new(server_io),
                        Role::Server,
                        None,
                    )
                    .await;
                    let message = socket.recv_message().await.unwrap();
                    socket.send_message(message).await.unwrap();
                });

                let mut response = Response::new(ResponseLease(leases_dropped));
                if let Some(accept) = accept {
                    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    *response.version_mut() = Version::HTTP_11;
                    response
                        .headers_mut()
                        .typed_insert(headers::Upgrade::websocket());
                    response
                        .headers_mut()
                        .typed_insert(headers::Connection::upgrade());
                    response.headers_mut().typed_insert(accept);
                } else {
                    *response.status_mut() = StatusCode::OK;
                    *response.version_mut() = Version::HTTP_2;
                }
                response.extensions().insert(on_upgrade);
                Ok::<_, BoxError>(response)
            }
        });

        let client = BlockingHttpClient::try_new(service).unwrap();
        let client_clone = client.clone();
        drop(client);

        let config = WebSocketConfig::default().with_read_buffer_size(4 * 1024);
        let mut from_url = client_clone
            .websocket("ws://example.test/echo")
            .with_config(config)
            .try_handshake()
            .unwrap();
        assert_eq!(from_url.response().status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(from_url.get_config().read_buffer_size, 4 * 1024);
        assert_eq!(
            from_url
                .extensions()
                .get_ref::<StreamTransformed>()
                .unwrap()
                .by,
            "rama-http::Upgraded",
        );

        let request = Request::builder()
            .version(Version::HTTP_11)
            .uri("ws://example.test/custom")
            .header("x-rama-test", "custom")
            .body(Body::empty())
            .unwrap();
        let mut from_request = client_clone
            .websocket_with_request(request)
            .try_handshake()
            .unwrap();
        let mut from_h2 = client_clone
            .websocket_h2("wss://example.test/h2")
            .try_handshake()
            .unwrap();

        drop(client_clone);
        assert_eq!(leases_dropped.load(Ordering::Acquire), 0);

        from_url.send_message("from url".into()).unwrap();
        assert_eq!(
            from_url
                .recv_message()
                .unwrap()
                .into_text()
                .unwrap()
                .as_str(),
            "from url",
        );

        from_request.send_message("from request".into()).unwrap();
        assert_eq!(
            from_request
                .recv_message()
                .unwrap()
                .into_text()
                .unwrap()
                .as_str(),
            "from request",
        );

        from_h2.send_message("from h2".into()).unwrap();
        assert_eq!(
            from_h2
                .recv_message()
                .unwrap()
                .into_text()
                .unwrap()
                .as_str(),
            "from h2",
        );

        let BlockingClientWebSocket {
            socket: from_url,
            response,
            accepted_protocol: protocol,
        } = from_url;
        assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
        assert!(protocol.is_none());
        assert_eq!(leases_dropped.load(Ordering::Acquire), 0);
        drop(from_url);
        assert_eq!(leases_dropped.load(Ordering::Acquire), 1);
        drop(from_request);
        assert_eq!(leases_dropped.load(Ordering::Acquire), 2);
        drop(from_h2);
        assert_eq!(leases_dropped.load(Ordering::Acquire), 3);
    }

    /// RFC 6455 §4.1 and §11.3.3, over HTTP/1.0 and HTTP/1.1: every `Upgrade` line counts and
    /// `Sec-WebSocket-Accept` appears once, while `Connection` stays a list over its lines.
    #[test]
    fn repeated_handshake_fields_are_validated_in_full() {
        let key = headers::SecWebSocketKey::random();
        let mut scratch = HeaderMap::new();
        scratch.typed_insert(headers::SecWebSocketAccept::try_from(key.clone()).unwrap());
        let accept = scratch[header::SEC_WEBSOCKET_ACCEPT].clone();
        for version in [Version::HTTP_10, Version::HTTP_11] {
            for (upgrade, connection, accepts, valid) in [
                (&["websocket"][..], &["Upgrade"][..], 1, true),
                (&["websocket"], &["keep-alive", "Upgrade"], 1, true),
                (&["websocket", "h2c"], &["Upgrade"], 1, false),
                (&["h2c", "websocket"], &["Upgrade"], 1, false),
                (&["websocket"], &["Upgrade"], 2, false),
            ] {
                let mut response = Response::builder()
                    .version(version)
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .body(())
                    .unwrap();
                let headers = response.headers_mut();
                for line in upgrade {
                    headers.append(header::UPGRADE, header::HeaderValue::from_static(line));
                }
                for line in connection {
                    headers.append(header::CONNECTION, header::HeaderValue::from_static(line));
                }
                for _ in 0..accepts {
                    headers.append(header::SEC_WEBSOCKET_ACCEPT, accept.clone());
                }
                let result =
                    validate_http_server_response(&response, Some(key.clone()), None, None);
                assert_eq!(
                    result.is_ok(),
                    valid,
                    "{version:?} {upgrade:?} {connection:?} accepts={accepts}: {result:?}"
                );
            }
        }
    }

    /// RFC 6455 §4.1 and RFC 7692 §5, on every version: the server selects at most one
    /// subprotocol and one extension, each among those offered, and every line counts.
    #[test]
    fn the_server_selects_one_offered_protocol_and_extension() {
        const PMD: &str = "permessage-deflate";
        let mut scratch = HeaderMap::new();
        scratch.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            header::HeaderValue::from_static("chat, superchat"),
        );
        let offered_protocols = scratch.typed_get::<SecWebSocketProtocol>().unwrap();
        let key = headers::SecWebSocketKey::random();
        scratch.typed_insert(headers::SecWebSocketAccept::try_from(key.clone()).unwrap());
        let accept = scratch[header::SEC_WEBSOCKET_ACCEPT].clone();
        // (protocol lines, extension lines, protocols offered, extensions offered, outcome)
        let cases: &[(
            &[&str],
            &[&str],
            bool,
            Option<&str>,
            Result<Option<&str>, &str>,
        )] = &[
            (&[], &[], true, Some(PMD), Ok(None)),
            (&["chat"], &[PMD], true, Some(PMD), Ok(Some("chat"))),
            (&["superchat"], &[], true, None, Ok(Some("superchat"))),
            (&["other"], &[], true, None, Err("protocol")),
            (&["chat", "superchat"], &[], true, None, Err("protocol")),
            (&["chat, superchat"], &[], true, None, Err("protocol")),
            (&["chat", "chat"], &[], true, None, Err("protocol")),
            (&["chat"], &[], false, None, Err("protocol")),
            (&["bad protocol"], &[], true, None, Err("protocol")),
            (&[], &[PMD, PMD], false, Some(PMD), Err("extension")),
            (
                &[],
                &["permessage-deflate, x-foo"],
                false,
                Some(PMD),
                Err("extension"),
            ),
            (&[], &["x-foo"], false, Some(PMD), Err("extension")),
            (&[], &[PMD], false, Some("x-foo"), Err("extension")),
            (&[], &[PMD], false, None, Err("extension")),
        ];
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for (protocols, extensions, offer_protocols, offer_extensions, outcome) in cases {
                let mut response = Response::builder().version(version).body(()).unwrap();
                if version == Version::HTTP_11 {
                    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    let headers = response.headers_mut();
                    headers.insert(
                        header::UPGRADE,
                        header::HeaderValue::from_static("websocket"),
                    );
                    headers.insert(
                        header::CONNECTION,
                        header::HeaderValue::from_static("Upgrade"),
                    );
                    headers.insert(header::SEC_WEBSOCKET_ACCEPT, accept.clone());
                }
                let headers = response.headers_mut();
                for line in *protocols {
                    headers.append(
                        header::SEC_WEBSOCKET_PROTOCOL,
                        header::HeaderValue::from_static(line),
                    );
                }
                for line in *extensions {
                    headers.append(
                        header::SEC_WEBSOCKET_EXTENSIONS,
                        header::HeaderValue::from_static(line),
                    );
                }
                let result = validate_http_server_response(
                    &response,
                    (version == Version::HTTP_11).then(|| key.clone()),
                    offer_protocols.then(|| offered_protocols.clone()),
                    offer_extensions.and_then(offered_pmd),
                );
                let context = format!("{version:?} {protocols:?} {extensions:?}: {result:?}");
                match (outcome, result) {
                    (Ok(protocol), Ok(accepted)) => {
                        assert_eq!(
                            accepted.protocol.as_ref().map(|p| p.0.as_ref()),
                            *protocol,
                            "{context}"
                        );
                        assert_eq!(
                            accepted.extension.is_some(),
                            !extensions.is_empty(),
                            "{context}"
                        );
                    }
                    (Err("protocol"), Err(ResponseValidateError::ProtocolMismatch(_)))
                    | (Err("extension"), Err(ResponseValidateError::ExtensionMismatch(_))) => {}
                    _ => panic!("{context}"),
                }
            }
        }
    }

    #[cfg(feature = "dial9")]
    #[test]
    fn blocking_handshake_runs_inside_dial9_session() {
        let temp_dir = rama_utils::fs::tempdir().unwrap();
        let writer = rama_core::telemetry::dial9::DiskBuffer::builder()
            .base_path(temp_dir.path())
            .max_file_size(rama_utils::octets::mib_u64(1))
            .max_total_size(rama_utils::octets::mib_u64(4))
            .build();
        let recorder = rama_core::telemetry::dial9::recorder_or_disabled(writer).build();
        let runtime = rama_core::rt::blocking::Runtime::builder()
            .with_dial9_recorder(recorder)
            .try_build()
            .unwrap();
        let service = service_fn(|request: Request| async move {
            assert!(rama_core::telemetry::dial9::Dial9Handle::current().is_enabled());
            let key = request
                .headers()
                .typed_get::<SecWebSocketKey>()
                .expect("handshake request to contain a key");
            let (client_io, _server_io) = tokio::io::duplex(1024);
            let (pending, on_upgrade) = rama_http::io::upgrade::pending();
            pending.fulfill(rama_http::io::upgrade::Upgraded::new(
                ServiceInput::new(client_io),
                Bytes::new(),
            ));

            let mut response = Response::new(());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            *response.version_mut() = Version::HTTP_11;
            response
                .headers_mut()
                .typed_insert(headers::Upgrade::websocket());
            response
                .headers_mut()
                .typed_insert(headers::Connection::upgrade());
            response.headers_mut().typed_insert(
                headers::SecWebSocketAccept::try_from(key)
                    .expect("client handshake key to produce an accept value"),
            );
            response.extensions().insert(on_upgrade);
            Ok::<_, BoxError>(response)
        });
        let client = BlockingHttpClient::with_runtime(service, &runtime);

        let socket = client
            .websocket("wss://example.test/socket")
            .try_handshake()
            .unwrap();
        assert_eq!(socket.response().status, StatusCode::SWITCHING_PROTOCOLS);
    }

    fn offered_pmd(raw: &str) -> Option<SecWebSocketExtensions> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            raw.parse().expect("valid sec-websocket-extensions header"),
        );
        headers.typed_get::<SecWebSocketExtensions>()
    }

    fn h2_response_with_pmd(raw: &str) -> Response<()> {
        let mut response = Response::new(());
        *response.version_mut() = Version::HTTP_2;
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            raw.parse().expect("valid sec-websocket-extensions header"),
        );
        response
    }

    #[test]
    fn extended_connect_handshakes_accept_any_successful_connect_status() {
        for version in [Version::HTTP_2, Version::HTTP_3] {
            let mut response = Response::new(());
            *response.version_mut() = version;
            *response.status_mut() = StatusCode::CREATED;

            validate_http_server_response(&response, None, None, None)
                .expect("successful CONNECT response");

            *response.status_mut() = StatusCode::BAD_REQUEST;
            assert_matches!(
                validate_http_server_response(&response, None, None, None),
                Err(ResponseValidateError::UnexpectedStatusCode(
                    StatusCode::BAD_REQUEST
                ))
            );
        }
    }

    #[test]
    fn h3_requests_use_extended_connect_without_a_key() {
        let handshake = WebSocketRequestBuilder::new_h3("wss://example.test/chat")
            .build_handshake()
            .unwrap();
        assert_eq!(handshake.request.method(), Method::CONNECT);
        assert_eq!(handshake.request.version(), Version::HTTP_3);
        assert!(handshake.key.is_none());
        assert!(!handshake.request.headers().contains_key(header::UPGRADE));
        assert_eq!(
            handshake.request.extensions().get_ref::<Protocol>(),
            Some(&Protocol::WEBSOCKET)
        );
    }

    /// Validate an (h2) server handshake response carrying `server_raw` against
    /// a client that offered `offered_raw`, returning the negotiated
    /// `client_max_window_bits`.
    fn validate_pmd(
        server_raw: &str,
        offered_raw: &str,
    ) -> Result<Option<u8>, ResponseValidateError> {
        let response = h2_response_with_pmd(server_raw);
        let accepted =
            validate_http_server_response(&response, None, None, offered_pmd(offered_raw))?;
        match accepted.extension {
            Some(Extension::PerMessageDeflate(cfg)) => Ok(cfg.client_max_window_bits),
            other => panic!("expected per-message-deflate extension, got {other:?}"),
        }
    }

    #[test]
    fn eight_bit_client_window_fails_the_handshake() {
        let result = validate_pmd(
            "permessage-deflate; client_max_window_bits=8",
            "permessage-deflate; client_max_window_bits",
        );
        assert_matches!(
            result,
            Err(ResponseValidateError::ExtensionMismatch(Some(_))),
            "{result:?}",
        );
    }

    #[test]
    fn invalid_extension_response_fails_the_handshake() {
        for server_raw in [
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=20",
            "permessage-deflate; server_max_window_bits=10; server_max_window_bits=10",
            "",
        ] {
            let response = h2_response_with_pmd(server_raw);
            let result = validate_http_server_response(
                &response,
                None,
                None,
                offered_pmd("permessage-deflate; client_max_window_bits"),
            );
            assert_matches!(
                result,
                Err(ResponseValidateError::ExtensionMismatch(None)),
                "{server_raw:?}: {result:?}",
            );
        }
    }

    // Regression: a valueless `client_max_window_bits` offer is parsed as the
    // sentinel `Some(0)` ("server may pick any value <= 15"). A server response
    // of `client_max_window_bits=15` must be accepted, not rejected as an
    // extension mismatch. Previously the `srv > offered` check evaluated
    // `15 > 0` and falsely failed the handshake (intermittent WS-over-h2 502s).
    #[test]
    fn valueless_client_max_window_bits_accepts_server_choice() {
        assert_eq!(
            Some(15),
            validate_pmd(
                "permessage-deflate; client_max_window_bits=15",
                "permessage-deflate; client_max_window_bits",
            )
            .expect("valueless offer should accept the server's window bits"),
        );
    }

    #[test]
    fn explicit_client_max_window_bits_is_only_a_hint() {
        // RFC 7692 §7.1.2.2: the offered value hints what the client will use; it does not cap
        // the server's answer
        assert_eq!(
            Some(15),
            validate_pmd(
                "permessage-deflate; client_max_window_bits=15",
                "permessage-deflate; client_max_window_bits=10",
            )
            .unwrap(),
        );
    }

    /// RFC 7692 §§3, 7, on every HTTP version: a response answers one compatible offer under
    /// the same name, whichever it is; server constraints of that offer are echoed, client
    /// window bits only answer an offer naming them, and a server may impose more than asked.
    #[test]
    fn a_pmd_response_answers_one_compatible_offer() {
        const PMD: &str = "permessage-deflate";
        // (offers, response, accepted (server bits, client bits, server nct, client nct))
        type Accepted = Option<(Option<u8>, Option<u8>, bool, bool)>;
        let cases: &[(&str, &str, Accepted)] = &[
            (PMD, PMD, Some((None, None, false, false))),
            (PMD, "permessage-deflate; client_max_window_bits=15", None),
            (
                "permessage-deflate; client_max_window_bits",
                "permessage-deflate; client_max_window_bits=15",
                Some((None, Some(15), false, false)),
            ),
            (
                "permessage-deflate; client_max_window_bits=10",
                "permessage-deflate; client_max_window_bits=15",
                Some((None, Some(15), false, false)),
            ),
            (
                "permessage-deflate; client_max_window_bits",
                "permessage-deflate; client_max_window_bits=8",
                None,
            ),
            ("permessage-deflate; server_max_window_bits=10", PMD, None),
            (
                "permessage-deflate; server_max_window_bits=10",
                "permessage-deflate; server_max_window_bits=12",
                None,
            ),
            (
                "permessage-deflate; server_max_window_bits=10",
                "permessage-deflate; server_max_window_bits=9",
                Some((Some(9), None, false, false)),
            ),
            (
                "permessage-deflate; server_max_window_bits=10, permessage-deflate; server_max_window_bits=15",
                "permessage-deflate; server_max_window_bits=15",
                Some((Some(15), None, false, false)),
            ),
            ("permessage-deflate; server_no_context_takeover", PMD, None),
            (
                "permessage-deflate; server_no_context_takeover",
                "permessage-deflate; server_no_context_takeover",
                Some((None, None, true, false)),
            ),
            (
                PMD,
                "permessage-deflate; server_no_context_takeover",
                Some((None, None, true, false)),
            ),
            (
                PMD,
                "permessage-deflate; server_max_window_bits=12",
                Some((Some(12), None, false, false)),
            ),
            (
                PMD,
                "permessage-deflate; client_no_context_takeover",
                Some((None, None, false, true)),
            ),
            (
                "permessage-deflate; client_no_context_takeover",
                PMD,
                Some((None, None, false, true)),
            ),
            (
                "permessage-deflate",
                "permessage-deflate",
                Some((None, None, false, false)),
            ),
            ("permessage-deflate", "perframe-deflate", None),
            ("permessage-deflate", "x-webkit-deflate-frame", None),
            ("perframe-deflate", "permessage-deflate", None),
            (
                "perframe-deflate",
                "perframe-deflate",
                Some((None, None, false, false)),
            ),
            ("perframe-deflate", "x-webkit-deflate-frame", None),
            ("x-webkit-deflate-frame", "permessage-deflate", None),
            ("x-webkit-deflate-frame", "perframe-deflate", None),
            (
                "x-webkit-deflate-frame",
                "x-webkit-deflate-frame",
                Some((None, None, false, false)),
            ),
            // parameters of an offer under another name never answer the selected one
            (
                "perframe-deflate; server_max_window_bits=15, permessage-deflate; server_max_window_bits=10",
                "permessage-deflate; server_max_window_bits=15",
                None,
            ),
            (
                "x-webkit-deflate-frame; client_max_window_bits, permessage-deflate",
                "permessage-deflate; client_max_window_bits=15",
                None,
            ),
            (
                "x-webkit-deflate-frame, permessage-deflate; server_no_context_takeover",
                "permessage-deflate; server_no_context_takeover",
                Some((None, None, true, false)),
            ),
        ];
        let key = headers::SecWebSocketKey::random();
        let mut scratch = HeaderMap::new();
        scratch.typed_insert(headers::SecWebSocketAccept::try_from(key.clone()).unwrap());
        let accept = scratch[header::SEC_WEBSOCKET_ACCEPT].clone();
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for (offers, response_raw, expected) in cases {
                let mut response = Response::builder().version(version).body(()).unwrap();
                if version == Version::HTTP_11 {
                    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                    let headers = response.headers_mut();
                    headers.insert(
                        header::UPGRADE,
                        header::HeaderValue::from_static("websocket"),
                    );
                    headers.insert(
                        header::CONNECTION,
                        header::HeaderValue::from_static("Upgrade"),
                    );
                    headers.insert(header::SEC_WEBSOCKET_ACCEPT, accept.clone());
                }
                response.headers_mut().insert(
                    header::SEC_WEBSOCKET_EXTENSIONS,
                    header::HeaderValue::from_static(response_raw),
                );
                let result = validate_http_server_response(
                    &response,
                    (version == Version::HTTP_11).then(|| key.clone()),
                    None,
                    offered_pmd(offers),
                );
                let accepted = match result {
                    Ok(AcceptedWebSocketData {
                        extension: Some(Extension::PerMessageDeflate(cfg)),
                        ..
                    }) => Some((
                        cfg.server_max_window_bits,
                        cfg.client_max_window_bits,
                        cfg.server_no_context_takeover,
                        cfg.client_no_context_takeover,
                    )),
                    Err(ResponseValidateError::ExtensionMismatch(_)) => None,
                    other => panic!("{version:?} {offers} / {response_raw}: {other:?}"),
                };
                assert_eq!(&accepted, expected, "{version:?} {offers} / {response_raw}");
            }
        }
    }

    #[test]
    fn explicit_client_max_window_bits_accepts_smaller_server_choice() {
        assert_eq!(
            Some(10),
            validate_pmd(
                "permessage-deflate; client_max_window_bits=10",
                "permessage-deflate; client_max_window_bits=12",
            )
            .expect("server choosing a smaller window should validate"),
        );
    }
}
