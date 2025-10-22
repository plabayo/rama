//! WebSocket client types and utilities

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use rama_core::Service;
use rama_core::error::{BoxError, ErrorContext, OpaqueError};
use rama_core::extensions::{Extensions, ExtensionsMut};
use rama_core::telemetry::tracing;
use rama_http::conn::TargetHttpVersion;
use rama_http::headers::sec_websocket_extensions::{Extension, PerMessageDeflateConfig};
use rama_http::headers::sec_websocket_protocol::AcceptedWebSocketProtocol;
use rama_http::headers::{
    HeaderMapExt, HttpRequestBuilderExt as _, SecWebSocketExtensions, SecWebSocketKey,
    SecWebSocketProtocol,
};
use rama_http::proto::h2::ext::Protocol;
use rama_http::service::client::ext::{IntoHeaderName, IntoHeaderValue};
use rama_http::service::client::{HttpClientExt, IntoUrl, RequestBuilder};
use rama_http::{Body, Method, Request, Response, StatusCode, Version, header, headers};
use rama_http::{request, response};

use crate::protocol::{Role, WebSocketConfig};
use crate::runtime::AsyncWebSocket;

/// Builder that can be used by clients to initiate the WebSocket handshake.
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

impl<B: fmt::Debug> fmt::Debug for WebSocketRequestBuilder<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketRequestBuilder")
            .field("inner", &self.inner)
            .field("protocols", &self.protocols)
            .field("extensions", &self.extensions)
            .field("key", &self.key)
            .finish()
    }
}

impl<B: Clone> Clone for WebSocketRequestBuilder<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            protocols: self.protocols.clone(),
            extensions: self.extensions.clone(),
            key: self.key.clone(),
        }
    }
}

/// [`WebSocketRequestBuilder`] inner wrapper type used for a builder,
/// which includes a service, and thus is there to actually send the request as well and
/// even follow up.
pub struct WithService<'a, S, Body> {
    builder: RequestBuilder<'a, S, Response<Body>>,
    config: Option<WebSocketConfig>,
    is_h2: bool,
}

impl<S: fmt::Debug, Body> fmt::Debug for WithService<'_, S, Body> {
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
    T: TryInto<rama_http::Uri, Error: Into<rama_http::HttpError>>,
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
        Version::HTTP_2 => builder.method(Method::CONNECT).version(Version::HTTP_2),
        _ => unreachable!("bug"),
    }
}

fn new_ws_request_builder_from_uri_with_service<'a, S, Body, T>(
    service: &'a S,
    uri: T,
    version: Version,
) -> RequestBuilder<'a, S, Response<Body>>
where
    S: Service<Request, Response = Response<Body>, Error: Into<BoxError>>,
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

    builder.typed_header(headers::SecWebSocketVersion::V13)
}

fn new_ws_request_builder_from_request<'a, S, Body, RequestBody>(
    service: &'a S,
    mut request: Request<RequestBody>,
) -> RequestBuilder<'a, S, Response<Body>>
where
    S: Service<Request, Response = Response<Body>, Error: Into<BoxError>>,
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
        // - for h2: nothing to do
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
    ProtocolMismatch(Option<Arc<str>>),
    ExtensionMismatch(Option<Extension>),
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
                    .typed_get::<headers::SecWebSocketAccept>();
                let expected_accept = Some(headers::SecWebSocketAccept::from(key));
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
    let mut accepted_extension = None;
    match (
        response
            .headers()
            .typed_get::<SecWebSocketExtensions>()
            .map(|ext| ext.into_first()),
        extensions,
    ) {
        (None, Some(allowed_extensions)) => {
            tracing::trace!(
                ws.extensions = ?allowed_extensions,
                "server selected no WS extensions despite client supporting some (valid, move on without)",
            );
        }
        (Some(Extension::PerMessageDeflate(server_cfg)), Some(client_extensions)) => {
            accepted_extension = client_extensions
                .iter()
                .find_map(|client_ext| {
                    if let Extension::PerMessageDeflate(client_cfg) = client_ext {
                        return Some(Ok(Extension::PerMessageDeflate(PerMessageDeflateConfig {
                            client_max_window_bits: match (
                                server_cfg.client_max_window_bits,
                                client_cfg.client_max_window_bits,
                            ) {
                                (None, None | Some(_)) => None,
                                (Some(srv), maybe_offered) => {
                                    if !(8..=15).contains(&srv) || maybe_offered.map(|offered| srv > offered).unwrap_or_default() {
                                        tracing::debug!("server offered invalid client_max_window_bits (pmd)... ext mismatch!");
                                        return Some(Err(
                                            ResponseValidateError::ExtensionMismatch(Some(
                                                Extension::PerMessageDeflate(server_cfg.clone()),
                                            )),
                                        ));
                                    }
                                    Some(srv)
                                }
                            },
                            server_max_window_bits: match (
                                server_cfg.server_max_window_bits,
                                client_cfg.server_max_window_bits,
                            ) {
                                (None, None | Some(_)) => None,
                                (Some(their_bits), maybe_our_bits) => {
                                    if !(8..=15).contains(&their_bits)
                                        || maybe_our_bits
                                            .map(|our_bits| our_bits != 0 && their_bits > our_bits)
                                            .unwrap_or_default()
                                    {
                                        tracing::debug!("server offered invalid server_max_window_bits (pmd)... ext mismatch!");
                                        return Some(Err(
                                            ResponseValidateError::ExtensionMismatch(Some(
                                                Extension::PerMessageDeflate(server_cfg.clone()),
                                            )),
                                        ));
                                    }
                                    Some(their_bits)
                                }
                            },
                            server_no_context_takeover: server_cfg.server_no_context_takeover,
                            client_no_context_takeover: client_cfg.client_no_context_takeover,
                            identifier: server_cfg.identifier.clone(),
                        })));
                    }
                    None
                })
                .transpose()?;
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
    match (
        response
            .headers()
            .typed_get::<SecWebSocketProtocol>()
            .map(|h| h.accept_first_protocol()),
        protocols,
    ) {
        (None, None) => (),
        (None, Some(_)) => {
            return Err(ResponseValidateError::ProtocolMismatch(None));
        }
        (Some(header), None) => {
            return Err(ResponseValidateError::ProtocolMismatch(Some(
                header.into_inner(),
            )));
        }
        (Some(protocol_header), Some(sub_protocols)) => {
            match sub_protocols.contains(&protocol_header) {
                Some(protocol) => accepted_protocol = Some(protocol),
                None => {
                    return Err(ResponseValidateError::ProtocolMismatch(Some(
                        protocol_header.into_inner(),
                    )));
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
        T: TryInto<rama_http::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self::new_with_version(uri, Version::HTTP_11)
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2<T>(uri: T) -> Self
    where
        T: TryInto<rama_http::Uri, Error: Into<rama_http::HttpError>>,
    {
        Self::new_with_version(uri, Version::HTTP_2)
    }

    fn new_with_version<T>(uri: T, version: Version) -> Self
    where
        T: TryInto<rama_http::Uri, Error: Into<rama_http::HttpError>>,
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
    pub fn build_handshake(self) -> Result<HandshakeRequest, OpaqueError> {
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
        if request.version() != Version::HTTP_2 {
            let k = self.key.unwrap_or_else(headers::SecWebSocketKey::random);
            request.headers_mut().typed_insert(&k);
            key = Some(k);
        }

        // only required for h2, but we might upgrade from h1 to h2 based on layers such as tls
        request
            .extensions_mut()
            .insert(Protocol::from_static("websocket"));

        Ok(HandshakeRequest {
            request,
            protocols: self.protocols,
            extensions: self.extensions,
            key,
        })
    }
}

impl<'a, S, Body> WebSocketRequestBuilder<WithService<'a, S, Body>>
where
    S: Service<Request, Response = Response<Body>, Error: Into<BoxError>>,
{
    /// Create a new `http/1.1` WebSocket [`Request`] builder.
    pub fn new_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version(service, Version::HTTP_11, uri)
    }

    /// Create a new `h2` WebSocket [`Request`] builder.
    pub fn new_h2_with_service<T>(service: &'a S, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self::new_with_service_and_version(service, Version::HTTP_2, uri)
    }

    fn new_with_service_and_version<T>(service: &'a S, version: Version, uri: T) -> Self
    where
        T: IntoUrl,
    {
        Self {
            inner: WithService {
                builder: new_ws_request_builder_from_uri_with_service(service, uri, version),
                config: Default::default(),
                is_h2: version == Version::HTTP_2,
            },
            protocols: Default::default(),
            extensions: Default::default(),
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
        let protocols = request.headers().typed_get();
        let extensions = request.headers().typed_get();

        Self {
            inner: WithService {
                builder: new_ws_request_builder_from_request(service, request),
                config: Default::default(),
                is_h2,
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
        mut extensions: Extensions,
    ) -> Result<NegotiatedHandshakeRequest<Body>, HandshakeError> {
        let builder = match self.protocols.as_ref() {
            Some(protocols) => self.inner.builder.overwrite_typed_header(protocols),
            None => self.inner.builder,
        };

        let builder = match self.extensions.as_ref() {
            Some(extensions) => builder.typed_header(extensions),
            None => builder,
        };

        let mut key = None;
        let builder = if !self.inner.is_h2 {
            extensions.insert(TargetHttpVersion(Version::HTTP_11));

            let k = self.key.unwrap_or_else(headers::SecWebSocketKey::random);
            let builder = builder.overwrite_typed_header(&k);
            key = Some(k);
            builder
        } else {
            extensions.insert(TargetHttpVersion(Version::HTTP_2));

            builder
        };

        // only required in h1, but because of layers such as tls we might anyway turn from h1 into h2
        let mut builder = builder.extension(Protocol::from_static("websocket"));

        if let Some(ext) = builder.extensions_mut() {
            ext.extend(extensions);
        }

        let response = builder
            .send()
            .await
            .context("send initial websocket handshake request (upgrade)")
            .map_err(HandshakeError::HttpRequestError)?;

        Ok(NegotiatedHandshakeRequest {
            protocols: self.protocols,
            extensions: self.extensions,
            config: self.inner.config,
            key,
            response,
        })
    }

    /// Establish a client [`WebSocket`], consuming this [`WebSocketRequestBuilder`],
    /// by doing the http-handshake, including validation and returning the socket if all is good.
    pub async fn handshake(
        self,
        extensions: Extensions,
    ) -> Result<ClientWebSocket, HandshakeError> {
        let handshake = self.initiate_handshake(extensions).await?;
        handshake.complete().await
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

impl<Body> NegotiatedHandshakeRequest<Body> {
    /// Fulfill the websocket handshake and return the upgraded [`ClientWebSocket`].
    pub async fn complete(self) -> Result<ClientWebSocket, HandshakeError> {
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

        let stream = rama_http::io::upgrade::handle_upgrade(&self.response)
            .await
            .context("upgrade http connection into a raw web socket")
            .map_err(HandshakeError::HttpUpgradeError)?;

        let (parts, _) = self.response.into_parts();

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
            None
        };

        let mut socket = AsyncWebSocket::from_raw_socket(stream, Role::Client, maybe_ws_cfg).await;
        *socket.extensions_mut() = parts.extensions.clone();

        Ok(ClientWebSocket {
            socket,
            response: parts,
            accepted_protocol: accepted_data.protocol,
        })
    }
}

#[derive(Debug)]
/// Client [`WebSocket`], used as input-output stream.
///
/// Utility type created via [`WebSocketRequestBuilder::handshake`].
pub struct ClientWebSocket {
    socket: AsyncWebSocket,
    response: response::Parts,
    accepted_protocol: Option<AcceptedWebSocketProtocol>,
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
    pub fn into_parts(
        self,
    ) -> (
        AsyncWebSocket,
        response::Parts,
        Option<AcceptedWebSocketProtocol>,
    ) {
        (self.socket, self.response, self.accepted_protocol)
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
    S: Service<Request, Response = Response<Body>, Error: Into<BoxError>>,
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

    fn websocket_with_request<RequestBody: Into<rama_http::Body>>(
        &self,
        req: Request<RequestBody>,
    ) -> WebSocketRequestBuilder<WithService<'_, Self, Body>> {
        WebSocketRequestBuilder::new_with_service_and_request(self, req)
    }
}

mod private {
    use super::*;

    pub trait HttpClientWebSocketExtSealed<Body> {}

    impl<S, Body> HttpClientWebSocketExtSealed<Body> for S where
        S: Service<Request, Response = Response<Body>, Error: Into<BoxError>>
    {
    }
}
