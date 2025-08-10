//! WebSocket server types and utilities

use std::{
    fmt,
    ops::{Deref, DerefMut},
};

use rama_core::{
    Context, Service,
    context::Extensions,
    error::{ErrorContext, OpaqueError},
    futures::{StreamExt, TryStreamExt},
    matcher::Matcher,
    telemetry::tracing::{self, Instrument},
};
use rama_http::{
    Method, Request, Response, StatusCode, Version,
    dep::http::request,
    headers::{self, HeaderMapExt, HttpResponseBuilderExt},
    io::upgrade,
    proto::h2::ext::Protocol,
    service::web::response::{Headers, IntoResponse},
};

use crate::{
    Message,
    protocol::{Role, WebSocketConfig},
    runtime::AsyncWebSocket,
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// WebSocket [`Matcher`] to match on incoming WebSocket requests.
///
/// The [`Default`] ws matcher does already out of the box the basic checks:
///
/// - for http/1.1: require GET method and `Upgrade: websocket` + `Connection: upgrade` headers
/// - for h2: require CONNECT method and `:protocol: websocket` pseudo header
pub struct WebSocketMatcher;

impl WebSocketMatcher {
    #[inline]
    /// Create a new default [`WebSocketMatcher`].
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl<State, Body> Matcher<State, Request<Body>> for WebSocketMatcher
where
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        _ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match req.version() {
            Version::HTTP_10 | Version::HTTP_11 => {
                match req.method() {
                    &Method::GET => (),
                    method => {
                        tracing::debug!(http.request.method = %method, "WebSocketMatcher: h1: unexpected method found: no match");
                        return false;
                    }
                }

                if !req
                    .headers()
                    .typed_get::<headers::Upgrade>()
                    .map(|u| u.is_websocket())
                    .unwrap_or_default()
                {
                    tracing::trace!(
                        "WebSocketMatcher: h1: no websocket upgrade header found: no match"
                    );
                    return false;
                }

                if !req
                    .headers()
                    .typed_get::<headers::Connection>()
                    .map(|c| c.contains_upgrade())
                    .unwrap_or_default()
                {
                    tracing::trace!(
                        "WebSocketMatcher: h1: no connection upgrade header found: no match"
                    );
                    return false;
                }
            }
            Version::HTTP_2 => {
                match req.method() {
                    &Method::CONNECT => (),
                    method => {
                        tracing::debug!(http.request.method = %method, "WebSocketMatcher: h2: unexpected method found: no match");
                        return false;
                    }
                }

                if !req
                    .extensions()
                    .get::<Protocol>()
                    .map(|p| p.as_str().trim().eq_ignore_ascii_case("websocket"))
                    .unwrap_or_default()
                {
                    tracing::trace!(
                        "WebSocketMatcher: h2: no websocket protocol (pseudo ext) found"
                    );
                    return false;
                }
            }
            version => {
                tracing::debug!(http.version = ?version, "WebSocketMatcher: unexpected http version found: no match");
                return false;
            }
        }

        true
    }
}

#[derive(Debug)]
/// Server error which can be triggered in case the request validation failed
pub enum RequestValidateError {
    UnexpectedHttpMethod(Method),
    UnexpectedHttpVersion(Version),
    UnexpectedPseudoProtocolHeader(Option<Protocol>),
    MissingUpgradeWebSocketHeader,
    MissingConnectionUpgradeHeader,
    InvalidSecWebSocketVersionHeader,
    InvalidSecWebSocketKeyHeader,
    InvalidSecWebSocketProtocolHeader(OpaqueError),
}

impl fmt::Display for RequestValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedHttpMethod(method) => {
                write!(f, "unexpected HTTP method: {method:?}")
            }
            Self::UnexpectedHttpVersion(version) => {
                write!(f, "unexpected HTTP version: {version:?}")
            }
            Self::UnexpectedPseudoProtocolHeader(maybe_protocol) => {
                write!(
                    f,
                    "missing or invalid pseudo h2 protocol header: {maybe_protocol:?}"
                )
            }
            Self::MissingUpgradeWebSocketHeader => {
                write!(f, "missing upgrade WebSocket header")
            }
            Self::MissingConnectionUpgradeHeader => {
                write!(f, "missing connection upgrade header")
            }
            Self::InvalidSecWebSocketVersionHeader => {
                write!(f, "missing or invalid sec-websocket-version header")
            }
            Self::InvalidSecWebSocketKeyHeader => {
                write!(f, "missing or invalid sec-websocket-key header")
            }
            Self::InvalidSecWebSocketProtocolHeader(err) => {
                write!(f, "invalid sec-websocket-protocol header: {err}")
            }
        }
    }
}

impl std::error::Error for RequestValidateError {}

pub fn validate_http_client_request<Body>(
    request: &Request<Body>,
) -> Result<
    (
        Option<headers::SecWebsocketAccept>,
        Option<headers::SecWebsocketProtocol>,
    ),
    RequestValidateError,
> {
    tracing::trace!(
        http.version = ?request.version(),
        "validate http client request"
    );

    let mut accept_header = None;

    match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => {
            match request.method() {
                &Method::GET => (),
                method => return Err(RequestValidateError::UnexpectedHttpMethod(method.clone())),
            }

            // If the request lacks an |Upgrade| header field or the |Upgrade|
            // header field contains a value that is not an ASCII case-
            // insensitive match for the value "websocket", the server MUST
            // _Fail the WebSocket Connection_. (RFC 6455)
            if !request
                .headers()
                .typed_get::<headers::Upgrade>()
                .map(|u| u.is_websocket())
                .unwrap_or_default()
            {
                return Err(RequestValidateError::MissingUpgradeWebSocketHeader);
            }

            // If the request lacks a |Connection| header field or the
            // |Connection| header field doesn't contain a token that is an
            // ASCII case-insensitive match for the value "Upgrade", the server
            // MUST _Fail the WebSocket Connection_. (RFC 6455)
            if !request
                .headers()
                .typed_get::<headers::Connection>()
                .map(|c| c.contains_upgrade())
                .unwrap_or_default()
            {
                return Err(RequestValidateError::MissingConnectionUpgradeHeader);
            }

            // A |Sec-WebSocket-Key| header field with a base64-encoded (see
            // Section 4 of [RFC4648]) value that, when decoded, is 16 bytes in
            // length.
            //
            // Only used for http/1.1 style WebSocket upgrade, not h2
            // as in the latter it is deprecated by the `:protocol` PSEUDO header.
            accept_header = match request.headers().typed_get::<headers::SecWebsocketKey>() {
                Some(key) => Some(headers::SecWebsocketAccept::from(key)),
                None => return Err(RequestValidateError::InvalidSecWebSocketKeyHeader),
            };
        }
        Version::HTTP_2 => {
            match request.method() {
                &Method::CONNECT => (),
                method => return Err(RequestValidateError::UnexpectedHttpMethod(method.clone())),
            }

            match request.extensions().get::<Protocol>() {
                None => return Err(RequestValidateError::UnexpectedPseudoProtocolHeader(None)),
                Some(protocol) => {
                    if !protocol.as_str().trim().eq_ignore_ascii_case("websocket") {
                        return Err(RequestValidateError::UnexpectedPseudoProtocolHeader(Some(
                            protocol.clone(),
                        )));
                    }
                }
            }
        }
        version => {
            return Err(RequestValidateError::UnexpectedHttpVersion(version));
        }
    }

    // A |Sec-WebSocket-Version| header field, with a value of 13.
    if request
        .headers()
        .typed_get::<headers::SecWebsocketVersion>()
        .is_none()
    {
        return Err(RequestValidateError::InvalidSecWebSocketVersionHeader);
    }

    // Optionally, a |Sec-WebSocket-Protocol| header field, with a list
    // of values indicating which protocols the client would like to
    // speak, ordered by preference.
    let protocols_header = request.headers().typed_get();

    Ok((accept_header, protocols_header))
}

#[derive(Debug, Clone, Default)]
/// An acceptor that can be used for upgrades os WebSockets on the server side.
pub struct WebSocketAcceptor {
    protocols: Option<headers::SecWebsocketProtocol>,
    protocols_flex: bool,
}

impl WebSocketAcceptor {
    #[inline]
    /// Create a new default [`WebSocketAcceptor`].
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define if the protocols validation and actioning is flexible.
        ///
        /// - In case no protocols are defined by server it implies that
        ///   the server will accept any incoming protocol instead of denying protocols.
        /// - Or in case server did specify a protocol allow list it will also
        ///   accept incoming requests which do not define a protocol.
        pub fn protocols_flex(mut self, flexible: bool) -> Self {
            self.protocols_flex = flexible;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define the WebSocket protocols.
        ///
        /// The protocols defined by the server (matcher) act as an allow list.
        /// You can make protocols optional in case you also wish to allow no
        /// protocols to be defined.
        pub fn protocols(mut self, protocols: Option<headers::SecWebsocketProtocol>) -> Self {
            self.protocols = protocols;
            self
        }
    }
}

impl WebSocketAcceptor {
    /// Consume `self` into an [`WebSocketAcceptorService`] ready to serve.
    ///
    /// Use the `UpgradeLayer` in case the ws upgrade is optional.
    pub fn into_service<S>(self, service: S) -> WebSocketAcceptorService<S> {
        WebSocketAcceptorService {
            acceptor: self,
            config: None,
            service,
        }
    }

    /// Turn this [`WebSocketAcceptor`] into an echo [`WebSocketAcceptorService`]].
    #[must_use]
    pub fn into_echo_service(mut self) -> WebSocketAcceptorService<WebSocketEchoService> {
        if self.protocols.is_none() {
            self.protocols_flex = true;
            self.protocols = Some(
                headers::SecWebsocketProtocol::new(ECHO_SERVICE_SUB_PROTOCOL_DEFAULT)
                    .with_additional_protocols([
                        ECHO_SERVICE_SUB_PROTOCOL_UPPER,
                        ECHO_SERVICE_SUB_PROTOCOL_LOWER,
                    ]),
            );
        }

        WebSocketAcceptorService {
            acceptor: self,
            config: None,
            service: WebSocketEchoService::new(),
        }
    }
}

impl<State, Body> Service<State, Request<Body>> for WebSocketAcceptor
where
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = (Response, Context<State>, Request<Body>);
    type Error = Response;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        match validate_http_client_request(&req) {
            Ok((accept_header, maybe_protocols)) => {
                let accepted_protocol = match (
                    self.protocols_flex,
                    maybe_protocols,
                    self.protocols.as_ref(),
                ) {
                    (false, Some(protocols), None) => {
                        tracing::debug!(
                            "WebSocketAcceptor: protocols found while none were expected: {protocols:?}"
                        );
                        return Err(StatusCode::BAD_REQUEST.into_response());
                    }
                    (false, None, Some(protocols)) => {
                        tracing::debug!(
                            "WebSocketAcceptor: no protocols found while one of following was expected: {protocols:?}"
                        );
                        return Err(StatusCode::BAD_REQUEST.into_response());
                    }
                    (_, None, None) | (true, None, Some(_)) => None,
                    (true, Some(found_protocols), None) => {
                        Some(found_protocols.accept_first_protocol())
                    }
                    (_, Some(found_protocols), Some(expected_protocols)) => {
                        if let Some(protocol) =
                            found_protocols.contains_any(expected_protocols.iter())
                        {
                            Some(protocol)
                        } else {
                            tracing::debug!(
                                "WebSocketAcceptor: no protocols from found protocol ({found_protocols:?}) matched for expected protocols: {expected_protocols:?}"
                            );
                            return Err(StatusCode::BAD_REQUEST.into_response());
                        }
                    }
                };

                let protocols_header = match accepted_protocol {
                    Some(p) => {
                        ctx.extensions_mut().insert(p.clone());
                        Some(p.into_header())
                    }
                    None => None,
                };

                match req.version() {
                    version @ (Version::HTTP_10 | Version::HTTP_11) => {
                        let accept_header = accept_header.ok_or_else(|| {
                            tracing::debug!("WebSocketAcceptor: missing accept header (no key?)");
                            StatusCode::BAD_REQUEST.into_response()
                        })?;

                        let mut response = Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .version(version)
                            .typed_header(accept_header)
                            .typed_header(headers::Upgrade::websocket())
                            .typed_header(headers::Connection::upgrade())
                            .body(rama_http::Body::empty())
                            .unwrap();
                        if let Some(protocols) = protocols_header {
                            response.headers_mut().typed_insert(protocols);
                        }
                        Ok((response, ctx, req))
                    }
                    Version::HTTP_2 => {
                        let mut response = Response::builder()
                            .status(StatusCode::OK)
                            .version(Version::HTTP_2)
                            .body(rama_http::Body::empty())
                            .unwrap();
                        if let Some(protocols) = protocols_header {
                            response.headers_mut().typed_insert(protocols);
                        }
                        Ok((response, ctx, req))
                    }
                    version => {
                        tracing::debug!(
                            http.version = ?version,
                            "WebSocketAcceptor: http client request has unexpected http version"
                        );
                        Err(StatusCode::BAD_REQUEST.into_response())
                    }
                }
            }
            Err(err) => {
                let response =
                    if matches!(err, RequestValidateError::InvalidSecWebSocketVersionHeader) {
                        (
                            Headers::single(headers::SecWebsocketVersion::V13),
                            StatusCode::BAD_REQUEST,
                        )
                            .into_response()
                    } else {
                        StatusCode::BAD_REQUEST.into_response()
                    };
                tracing::debug!("WebSocketAcceptor: http client request failed to validate: {err}");
                Err(response)
            }
        }
    }
}

/// Shortcut that can be used for endpoint WS services.
///
/// Created via [`WebSocketAcceptor::into_service`]
/// or `WebSocketAcceptor::into_echo_service`].
pub struct WebSocketAcceptorService<S> {
    acceptor: WebSocketAcceptor,
    config: Option<WebSocketConfig>,
    service: S,
}

impl<S: fmt::Debug> fmt::Debug for WebSocketAcceptorService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketAcceptorService")
            .field("acceptor", &self.acceptor)
            .field("config", &self.config)
            .field("service", &self.service)
            .finish()
    }
}

impl<S: Clone> Clone for WebSocketAcceptorService<S> {
    fn clone(&self) -> Self {
        Self {
            acceptor: self.acceptor.clone(),
            config: self.config,
            service: self.service.clone(),
        }
    }
}

impl<S> WebSocketAcceptorService<S> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the [`WebSocketConfig`], overwriting the previous config if already set.
        pub fn config(mut self, cfg: Option<WebSocketConfig>) -> Self {
            self.config = cfg;
            self
        }
    }
}

#[derive(Debug)]
/// Server WebSocket, used as input-output stream.
///
/// Utility type created via [`WebSocketAcceptorService`].
///
/// [`AcceptedSubProtocol`] can be found in the [`Context`], if any.
pub struct ServerWebSocket {
    socket: AsyncWebSocket,
    request: request::Parts,
}

impl Deref for ServerWebSocket {
    type Target = AsyncWebSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for ServerWebSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl ServerWebSocket {
    /// View the original request data, from which this server web socket was created.
    pub fn request(&self) -> &request::Parts {
        &self.request
    }

    /// Consume `self` as an [`AsyncWebSocket].
    pub fn into_inner(self) -> AsyncWebSocket {
        self.socket
    }

    /// Consume `self` into its parts.
    pub fn into_parts(self) -> (AsyncWebSocket, request::Parts) {
        (self.socket, self.request)
    }
}

impl<S, State, Body> Service<State, Request<Body>> for WebSocketAcceptorService<S>
where
    S: Clone + Service<State, ServerWebSocket, Response = ()>,
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        match self.acceptor.serve(ctx, req).await {
            Ok((resp, ctx, mut req)) => {
                let handler = self.service.clone();
                let span = tracing::trace_root_span!(
                    "ws::serve",
                    otel.kind = "server",
                    url.full = %req.uri(),
                    url.path = %req.uri().path(),
                    url.query = req.uri().query().unwrap_or_default(),
                    url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                    network.protocol.name = "ws",
                );

                let exec = ctx.executor().clone();

                exec.spawn_task(
                    async move {
                        match upgrade::on(&mut req).await {
                            Ok(upgraded) => {
                                let socket =
                                    AsyncWebSocket::from_raw_socket(upgraded, Role::Server, None)
                                        .await;
                                let (parts, _) = req.into_parts();

                                let server_socket = ServerWebSocket {
                                    socket,
                                    request: parts,
                                };

                                let _ = handler.serve(ctx, server_socket).await;
                            }
                            Err(e) => {
                                tracing::error!("ws upgrade error: {e:?}");
                            }
                        }
                    }
                    .instrument(span),
                );
                Ok(resp)
            }
            Err(resp) => Ok(resp),
        }
    }
}

/// Default protocol used by [`WebSocketEchoService`], incl when no match is found
pub const ECHO_SERVICE_SUB_PROTOCOL_DEFAULT: &str = "echo";
/// Uppercase all characters as part of the echod response in [`WebSocketEchoService`].
pub const ECHO_SERVICE_SUB_PROTOCOL_UPPER: &str = "echo-upper";
/// Lowercase all characters as part of the echod response in [`WebSocketEchoService`].
pub const ECHO_SERVICE_SUB_PROTOCOL_LOWER: &str = "echo-lower";

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Create a service which echos all incoming messages.
pub struct WebSocketEchoService;

impl WebSocketEchoService {
    /// Create a new [`EchoWebSocketService`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<State> Service<State, AsyncWebSocket> for WebSocketEchoService
where
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        socket: AsyncWebSocket,
    ) -> Result<Self::Response, Self::Error> {
        let protocol = ctx
            .get::<headers::sec_websocket_protocol::AcceptedWebsocketProtocol>()
            .map(|p| p.as_str())
            .unwrap_or(ECHO_SERVICE_SUB_PROTOCOL_DEFAULT);
        let transformer = if protocol.eq_ignore_ascii_case(ECHO_SERVICE_SUB_PROTOCOL_LOWER) {
            |msg: Message| {
                std::future::ready(Ok(match msg {
                    Message::Text(original) => Some(original.to_lowercase().into()),
                    msg @ Message::Binary(_) => Some(msg),
                    Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                        None
                    }
                }))
            }
        } else if protocol.eq_ignore_ascii_case(ECHO_SERVICE_SUB_PROTOCOL_UPPER) {
            |msg: Message| {
                std::future::ready(Ok(match msg {
                    Message::Text(original) => Some(original.to_uppercase().into()),
                    msg @ Message::Binary(_) => Some(msg),
                    Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                        None
                    }
                }))
            }
        } else {
            |msg: Message| {
                std::future::ready(Ok(match msg {
                    msg @ (Message::Text(_) | Message::Binary(_)) => Some(msg),
                    Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                        None
                    }
                }))
            }
        };

        let (write, read) = socket.split();
        // We should not forward messages other than text or binary.
        read.try_filter_map(transformer)
            .forward(write)
            .await
            .context("forward messages")
    }
}

impl<State> Service<State, ServerWebSocket> for WebSocketEchoService
where
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        socket: ServerWebSocket,
    ) -> Result<Self::Response, Self::Error> {
        let socket = socket.into_inner();
        self.serve(ctx, socket).await
    }
}

impl<State> Service<State, upgrade::Upgraded> for WebSocketEchoService
where
    State: Clone + Send + Sync + 'static,
{
    type Response = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        io: upgrade::Upgraded,
    ) -> Result<Self::Response, Self::Error> {
        let socket = AsyncWebSocket::from_raw_socket(io, Role::Server, None).await;
        self.serve(ctx, socket).await
    }
}

#[cfg(test)]
mod tests {
    use headers::sec_websocket_protocol::AcceptedWebsocketProtocol;
    use rama_http::Body;

    use super::*;

    macro_rules! request {
        (
            $method:literal $version:literal $uri:literal
            $(
                $header_name:literal: $header_value:literal
            )*
        ) => {
            request!(
                $method $version $uri
                $(
                    $header_name: $header_value
                )*
                w/ []
            )
        };
        (
            $method:literal $version:literal $uri:literal
            $(
                $header_name:literal: $header_value:literal
            )*
            w/ [$($extension:expr),* $(,)?]
        ) => {
            {
                let req = Request::builder()
                    .uri($uri)
                    .version(match $version {
                        "HTTP/1.1" => Version::HTTP_11,
                        "HTTP/2" => Version::HTTP_2,
                        _ => unreachable!(),
                    })
                    .method(match $method {
                        "GET" => Method::GET,
                        "POST" => Method::POST,
                        "CONNECT" => Method::CONNECT,
                        _ => unreachable!(),
                    });

                $(
                    let req = req.header($header_name, $header_value);
                )*

                $(
                    let req = req.extension($extension);
                )*

                req.body(Body::empty()).unwrap()
            }
        };
    }

    fn assert_websocket_no_match(request: &Request, matcher: &WebSocketMatcher) {
        assert!(
            !matcher.matches(None, &Context::default(), request),
            "!({matcher:?}).matches({request:?})"
        );
    }

    fn assert_websocket_match(request: &Request, matcher: &WebSocketMatcher) {
        assert!(
            matcher.matches(None, &Context::default(), request),
            "({matcher:?}).matches({request:?})"
        );
    }

    #[test]
    fn test_websocket_match_default_http_11() {
        let matcher = WebSocketMatcher::default();

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Upgrade": "websocket"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_default_http_2() {
        let matcher = WebSocketMatcher::default();

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/2" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    async fn assert_websocket_acceptor_ok(
        request: Request,
        acceptor: &WebSocketAcceptor,
        expected_accepted_protocol: Option<AcceptedWebsocketProtocol>,
    ) {
        let ctx = Context::default();
        let (resp, ctx, req) = acceptor.serve(ctx, request).await.unwrap();
        match req.version() {
            Version::HTTP_10 | Version::HTTP_11 => {
                assert_eq!(StatusCode::SWITCHING_PROTOCOLS, resp.status())
            }
            Version::HTTP_2 => assert_eq!(StatusCode::OK, resp.status()),
            _ => unreachable!(),
        }
        let accepted_protocol = resp
            .headers()
            .typed_get::<headers::SecWebsocketProtocol>()
            .map(|p| p.accept_first_protocol());
        if let Some(expected_accepted_protocol) = expected_accepted_protocol {
            assert_eq!(
                accepted_protocol.as_ref(),
                Some(&expected_accepted_protocol),
                "request = {req:?}"
            );
            assert_eq!(
                ctx.get::<AcceptedWebsocketProtocol>(),
                Some(&expected_accepted_protocol),
                "request = {req:?}"
            );
        } else {
            assert!(accepted_protocol.is_none());
            assert!(ctx.get::<AcceptedWebsocketProtocol>().is_none());
        }
    }

    async fn assert_websocket_acceptor_bad_request(request: Request, acceptor: &WebSocketAcceptor) {
        let resp = acceptor
            .serve(Context::default(), request)
            .await
            .unwrap_err();
        assert_eq!(StatusCode::BAD_REQUEST, resp.status());
    }

    #[tokio::test]
    async fn test_websocket_acceptor_default_http_2() {
        let acceptor = WebSocketAcceptor::default();

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/2" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &acceptor,
        )
        .await;
        assert_websocket_acceptor_bad_request(
            request! {
                "CONNECT" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;
        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            None,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "client"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;
    }

    #[tokio::test]
    async fn test_websocket_acceptor_default_http_11() {
        let acceptor = WebSocketAcceptor::default();

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "14"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "keep-alive"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn test_websocket_accept_flex_protocols() {
        let acceptor = WebSocketAcceptor::default().with_protocols_flex(true);

        // no protocols

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
            None,
        )
        .await;
        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            None,
        )
        .await;

        // with protocols

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "foo"
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("foo")),
        )
        .await;
        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "foo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("foo")),
        )
        .await;

        // with multiple protocols

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "foo, bar"
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("foo")),
        )
        .await;
        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "foo,baz, foo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("foo")),
        )
        .await;

        // without protocols, even though we have allow list, fine due to it being optional,
        // but we still only accept allowed protocols if defined

        let acceptor = acceptor.with_protocols(headers::SecWebsocketProtocol::new("foo"));

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
            None,
        )
        .await;

        assert_websocket_acceptor_bad_request(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "baz,fo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;
    }

    #[tokio::test]
    async fn test_websocket_accept_required_protocols() {
        let acceptor = WebSocketAcceptor::default().with_protocols(
            headers::SecWebsocketProtocol::new("foo").with_additional_protocols(["a", "b"]),
        );

        // no protocols, required so all bad

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
            },
            &acceptor,
        )
        .await;
        assert_websocket_acceptor_bad_request(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;

        // with allowed protocol

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "foo"
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("foo")),
        )
        .await;
        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "b"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("b")),
        )
        .await;

        // with multiple protocols (including at least one allowed one)

        assert_websocket_acceptor_ok(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "test, b"
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("b")),
        )
        .await;
        assert_websocket_acceptor_ok(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "a,test, c"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
            Some(AcceptedWebsocketProtocol::new("a")),
        )
        .await;

        // only with non-allowed protocol(s)

        assert_websocket_acceptor_bad_request(
            request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="
                "Sec-WebSocket-Protocol": "test, c"
            },
            &acceptor,
        )
        .await;
        assert_websocket_acceptor_bad_request(
            request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Protocol": "test"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &acceptor,
        )
        .await;
    }
}
