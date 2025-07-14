//! WebSocket client types and utilities

use std::fmt;
use std::ops::{Deref, DerefMut};

use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::telemetry::tracing;
use rama_core::{Context, Service};
use rama_http::conn::TargetHttpVersion;
use rama_http::dep::http::{self, request, response};
use rama_http::headers::{HeaderMapExt, HttpRequestBuilderExt as _, SecWebsocketKey};
use rama_http::proto::h2::ext::Protocol;
use rama_http::service::client::ext::{IntoHeaderName, IntoHeaderValue};
use rama_http::service::client::{HttpClientExt, IntoUrl, RequestBuilder};
use rama_http::{
    Body, HeaderValue, Method, Request, Response, StatusCode, Version, header, headers,
};

use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::handshake::{AcceptedSubProtocol, SubProtocols};
use crate::protocol::{Role, WebSocketConfig};
use crate::runtime::AsyncWebSocket;

/// Builder that can be used by clients to initiate the WebSocket handshake.
pub struct WebsocketRequestBuilder<B> {
    inner: B,
    sub_protocols: Option<SubProtocols>,
    key: Option<SecWebsocketKey>,
}

#[derive(Debug)]
/// Request data to be used by an http client to initiate an http request.
pub struct HandshakeRequest {
    pub request: Request,
    pub sub_protocols: Option<SubProtocols>,
    pub key: Option<SecWebsocketKey>,
}

impl<B: fmt::Debug> fmt::Debug for WebsocketRequestBuilder<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebsocketRequestBuilder")
            .field("inner", &self.inner)
            .field("protocols", &self.sub_protocols)
            .field("key", &self.key)
            .finish()
    }
}

impl<B: Clone> Clone for WebsocketRequestBuilder<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sub_protocols: self.sub_protocols.clone(),
            key: self.key.clone(),
        }
    }
}

/// [`WebsocketRequestBuilder`] inner wrapper type used for a builder,
/// which includes a service, and thus is there to actually send the request as well and
/// even follow up.
pub struct WithService<'a, S, Body, State> {
    builder: RequestBuilder<'a, S, State, Response<Body>>,
    config: Option<WebSocketConfig>,
    is_h2: bool,
}

impl<S: fmt::Debug, Body, State> fmt::Debug for WithService<'_, S, Body, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithService")
            .field("builder", &self.builder)
            .field("config", &self.config)
            .field("is_h2", &self.is_h2)
            .finish()
    }
}

fn new_ws_request_builder_from_uri<T>(uri: T, version: Version) -> request::Builder
where
    T: TryInto<http::Uri, Error: Into<http::Error>>,
{
    let builder = Request::builder()
        .version(version)
        .uri(uri)
        .typed_header(headers::SecWebsocketVersion::V13);

    match version {
        version @ (Version::HTTP_10 | Version::HTTP_11) => builder
            .method(Method::GET)
            .version(version)
            .typed_header(headers::Upgrade::websocket())
            .typed_header(headers::Connection::upgrade()),
        Version::HTTP_2 => builder.method(Method::CONNECT).version(Version::HTTP_2),
        _ => unreachable!("bug"),
    }
}

fn new_ws_request_builder_from_uri_with_service<'a, S, Body, State, T>(
    service: &'a S,
    uri: T,
    version: Version,
) -> RequestBuilder<'a, S, State, Response<Body>>
where
    S: Service<State, Request, Response = Response<Body>, Error: Into<BoxError>>,
    T: IntoUrl,
{
    let builder = match version {
        version @ (Version::HTTP_10 | Version::HTTP_11) => service
            .get(uri)
            .version(version)
            .typed_header(headers::Upgrade::websocket())
            .typed_header(headers::Connection::upgrade()),
        Version::HTTP_2 => service.connect(uri).version(Version::HTTP_2),
        _ => unreachable!("bug"),
    };

    builder.typed_header(headers::SecWebsocketVersion::V13)
}

fn new_ws_request_builder_from_request<'a, S, Body, State, RequestBody>(
    service: &'a S,
    mut request: Request<RequestBody>,
) -> RequestBuilder<'a, S, State, Response<Body>>
where
    S: Service<State, Request, Response = Response<Body>, Error: Into<BoxError>>,
    RequestBody: Into<rama_http::Body>,
{
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
        Version::HTTP_2 => (), // NOTHING TO DO
        _ => (),               // this will error downstream due to invalid version
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
    SubProtocolMismatch(Option<HeaderValue>),
}

#[derive(Debug)]
/// Client error which can be triggered in case the handshake phase failed.
pub enum HandshakeError {
    ValidationError(ResponseValidateError),
    HttpRequestError(OpaqueError),
    HttpUpgradeError(OpaqueError),
}

impl fmt::Display for ResponseValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseValidateError::UnexpectedStatusCode(status_code) => {
                write!(f, "unexpected HTTP status code: {status_code}")
            }
            ResponseValidateError::UnexpectedHttpVersion(version) => {
                write!(f, "unexpected HTTP version: {version:?}")
            }
            ResponseValidateError::MissingUpgradeWebSocketHeader => {
                write!(f, "missing upgrade WebSocket header")
            }
            ResponseValidateError::MissingConnectionUpgradeHeader => {
                write!(f, "missing connection upgrade header")
            }
            ResponseValidateError::SecWebSocketAcceptKeyMismatch => {
                write!(f, "key mismatch for sec-websocket-accept header")
            }
            ResponseValidateError::SubProtocolMismatch(header_value) => {
                write!(f, "sub protocol mismatch: {header_value:?}")
            }
        }
    }
}

impl std::error::Error for ResponseValidateError {}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::ValidationError(error) => {
                write!(f, "response validation failed: {error}")
            }
            HandshakeError::HttpRequestError(error) => {
                write!(f, "http request error: {error}")
            }
            HandshakeError::HttpUpgradeError(error) => {
                write!(f, "http upgrade error: {error}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::ValidationError(error) => Some(error as &dyn std::error::Error),
            HandshakeError::HttpRequestError(error) | HandshakeError::HttpUpgradeError(error) => {
                error.source()
            }
        }
    }
}

/// Validate the "accept" response from the http server
/// with whom the client is trying to establish a WebSocket connection.
pub fn validate_http_server_response<Body>(
    response: &Response<Body>,
    key: Option<headers::SecWebsocketKey>,
    sub_protocols: Option<SubProtocols>,
) -> Result<Option<AcceptedSubProtocol>, ResponseValidateError> {
    tracing::trace!(
        http.version = ?response.version(),
        http.response.status = ?response.status(),
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

            // Sec-WebSocket-Key / Accept is only used in h2 responses
            //
            // ...
            //
            // if the response lacks a |Sec-WebSocket-Accept| header field or
            // the |Sec-WebSocket-Accept| contains a value other than the
            // base64-encoded SHA-1 of ... the client MUST _Fail the WebSocket
            // Connection_. (RFC 6455)
            if let Some(key) = key {
                let sec_websocket_accept_header = response
                    .headers()
                    .typed_get::<headers::SecWebsocketAccept>();
                let expected_accept = Some(headers::SecWebsocketAccept::from(key));
                if sec_websocket_accept_header != expected_accept {
                    tracing::trace!(
                        "unexpected websocket accept key: {sec_websocket_accept_header:?} (expected: {expected_accept:?})"
                    );
                    return Err(ResponseValidateError::SecWebSocketAcceptKeyMismatch);
                }
            }
        }
        Version::HTTP_2 => {
            let response_status = response.status();
            if response.status() != StatusCode::OK {
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
    // TODO

    // If the response includes a |Sec-WebSocket-Protocol| header field
    // and this header field indicates the use of a subprotocol that was
    // not present in the client's handshake (the server has indicated a
    // subprotocol not requested by the client), the client MUST _Fail
    // the WebSocket Connection_. (RFC 6455)
    let mut accepted_protocol = None;
    match (
        response.headers().get(header::SEC_WEBSOCKET_PROTOCOL),
        sub_protocols,
    ) {
        (None, None) => (),
        (None, Some(_)) => {
            return Err(ResponseValidateError::SubProtocolMismatch(None));
        }
        (Some(header), None) => {
            return Err(ResponseValidateError::SubProtocolMismatch(Some(
                header.clone(),
            )));
        }
        (Some(protocol_header), Some(sub_protocols)) => {
            let accepted_protocol_str = protocol_header
                .to_str()
                .map_err(|_| ResponseValidateError::SubProtocolMismatch(None))?;
            match sub_protocols.contains(accepted_protocol_str) {
                Some(protocol) => accepted_protocol = Some(protocol),
                None => {
                    return Err(ResponseValidateError::SubProtocolMismatch(Some(
                        protocol_header.clone(),
                    )));
                }
            };
        }
    }

    Ok(accepted_protocol)
}

impl WebsocketRequestBuilder<request::Builder> {
    /// Create a new `http/1.1` WebSocket [`Request`] builder.
    pub fn new<T>(uri: T) -> Self
    where
        T: TryInto<http::Uri, Error: Into<http::Error>>,
    {
        Self {
            inner: new_ws_request_builder_from_uri(uri, Version::HTTP_11),
            sub_protocols: Default::default(),
            key: Default::default(),
        }
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2<T>(uri: T) -> Self
    where
        T: TryInto<http::Uri, Error: Into<http::Error>>,
    {
        Self {
            inner: new_ws_request_builder_from_uri(uri, Version::HTTP_2),
            sub_protocols: Default::default(),
            key: Default::default(),
        }
    }

    /// Set a custom http header
    pub fn with_header<K, V>(self, name: K, value: V) -> Self
    where
        K: TryInto<http::HeaderName, Error: Into<http::Error>>,
        V: TryInto<http::HeaderValue, Error: Into<http::Error>>,
    {
        Self {
            inner: self.inner.header(name, value),
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    /// Set a custom typed http header
    pub fn with_typed_header<H>(self, header: H) -> Self
    where
        H: headers::Header,
    {
        Self {
            inner: self.inner.typed_header(header),
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    /// Build the handshake data
    /// to be used to initiate the WebSocket handshake using an http client.
    pub fn build_handshake(self) -> Result<HandshakeRequest, OpaqueError> {
        let builder = match self.sub_protocols.as_ref() {
            Some(protocols) => {
                let s = protocols.to_string();
                self.inner.header(header::SEC_WEBSOCKET_PROTOCOL, s)
            }
            None => self.inner,
        };

        let mut request = builder
            .body(Body::empty())
            .context("request failed to build (invalid custom header?)")?;

        let mut key = None;
        if request.version() != Version::HTTP_2 {
            let k = self.key.unwrap_or_else(headers::SecWebsocketKey::random);
            key = Some(k.clone());
            request.headers_mut().typed_insert(k);
        }

        // only required for h2, but we might upgrade from h1 to h2 based on layers such as tls
        request
            .extensions_mut()
            .insert(Protocol::from_static("websocket"));

        Ok(HandshakeRequest {
            request,
            sub_protocols: self.sub_protocols,
            key,
        })
    }
}

impl<'a, S, State, Body> WebsocketRequestBuilder<WithService<'a, S, Body, State>>
where
    S: Service<State, Request, Response = Response<Body>, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
{
    /// Create a new `http/1.1` WebSocket [`Request`] builder.
    pub fn new_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self {
            inner: WithService {
                builder: new_ws_request_builder_from_uri_with_service(
                    service,
                    uri,
                    Version::HTTP_11,
                ),
                config: Default::default(),
                is_h2: false,
            },
            sub_protocols: Default::default(),
            key: Default::default(),
        }
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self {
            inner: WithService {
                builder: new_ws_request_builder_from_uri_with_service(
                    service,
                    uri,
                    Version::HTTP_2,
                ),
                config: Default::default(),
                is_h2: true,
            },
            sub_protocols: Default::default(),
            key: Default::default(),
        }
    }

    /// Create a new WebSocket [`Request`] builder for the given [`Request`]
    pub fn new_with_service_and_request<RequestBody>(
        service: &'a S,
        request: Request<RequestBody>,
    ) -> Self
    where
        RequestBody: Into<rama_http::Body>,
    {
        let key = request.headers().typed_get();
        let is_h2 = request.version() == Version::HTTP_2;

        let mut sub_protocols = None;
        if let Some(header) = request.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
            sub_protocols = header.to_str().ok().and_then(|v| v.parse().ok());
        }

        Self {
            inner: WithService {
                builder: new_ws_request_builder_from_request(service, request),
                config: Default::default(),
                is_h2,
            },
            sub_protocols,
            key,
        }
    }

    /// Set a custom http header
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
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    /// Overwrite a custom http header
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
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    /// Set a custom typed http header
    pub fn with_typed_header<H>(self, header: H) -> Self
    where
        H: headers::Header,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.typed_header(header),
                ..self.inner
            },
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    /// Overwrite a custom typed http header
    pub fn with_typed_header_overwrite<H>(self, header: H) -> Self
    where
        H: headers::Header,
    {
        Self {
            inner: WithService {
                builder: self.inner.builder.overwrite_typed_header(header),
                ..self.inner
            },
            sub_protocols: self.sub_protocols,
            key: self.key,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`WebSocketConfig`], overwriting the previous config if already set.
        pub fn config(mut self, cfg: Option<WebSocketConfig>) -> Self {
            self.inner.config = cfg;
            self
        }
    }

    /// Establish a client [`WebSocket`], consuming this [`WebsocketRequestBuilder`],
    /// by doing the http-handshake, including validation and returning the socket if all is good.
    pub async fn handshake(
        self,
        mut ctx: Context<State>,
    ) -> Result<ClientWebSocket, HandshakeError> {
        let builder = match self.sub_protocols.as_ref() {
            Some(protocols) => {
                let s = protocols.to_string();
                self.inner
                    .builder
                    .overwrite_header(header::SEC_WEBSOCKET_PROTOCOL, s)
            }
            None => self.inner.builder,
        };

        let mut key = None;
        let builder = if !self.inner.is_h2 {
            ctx.insert(TargetHttpVersion(Version::HTTP_11));

            let k = self.key.unwrap_or_else(headers::SecWebsocketKey::random);
            key = Some(k.clone());
            builder.overwrite_typed_header(k)
        } else {
            ctx.insert(TargetHttpVersion(Version::HTTP_2));

            builder
        };

        // only required in h1, but because of layers such as tls we might anyway turn from h1 into h2
        let builder = builder.extension(Protocol::from_static("websocket"));

        let mut response = builder
            .send(ctx)
            .await
            .context("send initial websocket handshake request (upgrade)")
            .map_err(HandshakeError::HttpRequestError)?;

        let accepted_protocol = validate_http_server_response(&response, key, self.sub_protocols)
            .map_err(HandshakeError::ValidationError)?;

        tracing::trace!(
            websocket.protocol = ?accepted_protocol,
            "websocket handshake http response is valid",
        );

        let stream = rama_http::io::upgrade::on(&mut response)
            .await
            .context("upgrade http connection into a raw web socket")
            .map_err(HandshakeError::HttpUpgradeError)?;

        let (parts, _) = response.into_parts();

        let socket = AsyncWebSocket::from_raw_socket(stream, Role::Client, self.inner.config).await;

        Ok(ClientWebSocket {
            socket,
            response: parts,
            accepted_protocol,
        })
    }
}

impl<B> WebsocketRequestBuilder<B> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket sub protocol, overwriting any existing sub protocol.
        pub fn sub_protocol(mut self, protocol: impl Into<SmolStr>) -> Self {
            self.sub_protocols = Some(SubProtocols::new(protocol));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocol, appending it to any existing sub protocol(s).
        pub fn additional_sub_protocol(mut self, protocol: impl Into<SmolStr>) -> Self {
            self.sub_protocols = Some(match self.sub_protocols.take() {
                Some(protocols) => protocols.with_additional_sub_protocol(protocol),
                None => SubProtocols::new(protocol),
            });
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket sub protocols, overwriting any existing sub protocol.
        pub fn sub_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
            let protocols: SmallVec<_> = protocols.into_iter().map(Into::into).collect();
            self.sub_protocols = (!protocols.is_empty()).then_some(SubProtocols(protocols));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocols, appending it to any existing sub protocol(s).
        pub fn additional_sub_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
            let protocols = protocols.into_iter();
            self.sub_protocols = match self.sub_protocols.take() {
                Some(existing_protocols) => Some(existing_protocols.with_additional_sub_protocols(protocols)),
                None => {
                    let protocols: SmallVec<_> = protocols.into_iter().map(Into::into).collect();
                    (!protocols.is_empty()).then_some(SubProtocols(protocols))
                }
            };
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket key (a random one will be generated if not defined).
        ///
        /// Only touch this property if you have a good reason to do so.
        pub fn key(mut self, key: Option<headers::SecWebsocketKey>) -> Self {
            self.key = key;
            self
        }
    }
}

#[derive(Debug)]
/// Client [`WebSocket`], used as input-output stream.
///
/// Utility type created via [`WebsocketRequestBuilder::handshake`].
pub struct ClientWebSocket {
    socket: AsyncWebSocket,
    response: response::Parts,
    accepted_protocol: Option<AcceptedSubProtocol>,
}

impl Deref for ClientWebSocket {
    type Target = AsyncWebSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for ClientWebSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl ClientWebSocket {
    /// View the original response data, from which this client web socket was created.
    pub fn response(&self) -> &response::Parts {
        &self.response
    }

    /// Return the accepted protocol (during the http handshake) of the [`ClientWebSocket`], if any.
    pub fn accepted_protocol(&self) -> Option<&str> {
        self.accepted_protocol.as_ref().map(|p| p.as_str())
    }

    /// Consume `self` as an [`AsyncWebSocket`]
    pub fn into_inner(self) -> AsyncWebSocket {
        self.socket
    }

    /// Consume `self` into its parts.
    pub fn into_parts(self) -> (AsyncWebSocket, response::Parts, Option<AcceptedSubProtocol>) {
        (self.socket, self.response, self.accepted_protocol)
    }
}

/// Extends an Http Client with high level features WebSocket features.
pub trait HttpClientWebSocketExt<Body, State>:
    private::HttpClientWebSocketExtSealed<Body, State> + Sized + Send + Sync + 'static
{
    /// Create a new [`WebsocketRequestBuilder`]] to be used to establish a WebSocket connection over http/1.1.
    fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>>;

    /// Create a new [`WebsocketRequestBuilder`] to be used to establish a WebSocket connection over h2.
    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>>;

    /// Create a new [`WebsocketRequestBuilder`] starting from the given request.
    ///
    /// This is useful in cases where you already have a request that you wish to use,
    /// for example in the case of a proxied reuqest.
    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        req: Request<RequestBody>,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>>;
}

impl<State, S, Body> HttpClientWebSocketExt<Body, State> for S
where
    S: Service<State, Request, Response = Response<Body>, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
{
    fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>> {
        WebsocketRequestBuilder::new_with_service(self, url)
    }

    fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>> {
        WebsocketRequestBuilder::new_h2_with_service(self, url)
    }

    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        req: Request<RequestBody>,
    ) -> WebsocketRequestBuilder<WithService<'_, Self, Body, State>> {
        WebsocketRequestBuilder::new_with_service_and_request(self, req)
    }
}

mod private {
    use super::*;

    pub trait HttpClientWebSocketExtSealed<Body, State> {}

    impl<State, S, Body> HttpClientWebSocketExtSealed<Body, State> for S where
        S: Service<State, Request, Response = Response<Body>, Error: Into<BoxError>>
    {
    }
}
