//! Tie a pooled connection's lifetime to the response body it produced.
//!
//! A connector returns its connection at response **headers** and the caller
//! drops that handle immediately, but the connection is logically still in use
//! until the response **body** has been read off the wire. For a pooled
//! connection this matters: the pool would otherwise consider the connection
//! free (reusable / idle) while a response body is still streaming.
//!
//! [`BindBodyToConn`] wraps such a connection and, on `serve`, moves it whole
//! into the returned response body (via [`GuardedBody`]). The connection's own
//! `Drop` (freeing a stream slot, returning it to the pool, …) then fires when
//! the body reaches end-of-stream or is dropped, instead of at headers.
//! [`BindBodyToConnLayer`] applies this to a connector's connection, and drains
//! HTTP/1 response bodies dropped before their end, within the bounds of an
//! [`Http1BodyDrainConfig`], so their connection can be reused.
//!
//! Warning: this means a [`BindBodyToConn`] connection can only be used to
//! serve a single request, which ties in perfects with how we expect a connector
//! stack to work, but might be surprising if you use this layer alone. This layer
//! should almost always be combined with connection pool that gives a new connection
//! per request.

use std::sync::Arc;

use parking_lot::Mutex;

use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::{Layer, Service};
use rama_http::StreamingBody;
use rama_http_types::body::GuardedBody;
use rama_http_types::{Body, Request, Response};
use rama_net::client::{ConnectionError, ConnectorService, EstablishedClientConnection};
use rama_utils::macros::generate_set_and_with;

use super::Http1BodyDrainConfig;
use super::drain::{Http1BodyDrain, Http1DrainBody, Http1DrainRuntime};

/// A connection wrapper that binds the connection to the lifetime of the
/// response body it produces.
///
/// A connector returns its connection at response **headers**, but the
/// connection is logically still in use until the response **body** has been
/// read off the wire. On `serve`, this wrapper moves the connection whole into
/// the returned response body (via [`GuardedBody`]), so the connection's `Drop`
/// (freeing a stream slot, returning it to the pool, …) fires when the body
/// reaches end-of-stream or is dropped, instead of at headers.
///
/// The connection is moved into the response body on `serve` (it is served
/// exactly once per request), so there is no shared ownership of it.
///
/// Created by a [`BindBodyToConnector`], an HTTP/1 response body dropped before
/// its end is drained as its [`Http1BodyDrainConfig`] allows; created with
/// [`Self::new`], it never is.
///
/// Warning: the connection returned by this service should only be used for a single
/// request, since it will be transferred to the response body and not be useable after that.
pub struct BindBodyToConn<C> {
    /// `Some` until the (single) `serve` moves the connection into the body.
    conn: Mutex<Option<C>>,
    /// Snapshot of the connection's extensions, taken at construction so that
    /// connector layers above us (e.g. the request version adapter) and the
    /// client can still read them after the connection has moved into the body.
    /// Extension entries are `Arc`-backed, so live-updated ones (e.g. the peer's
    /// max concurrency) are still observed through this clone.
    extensions: Extensions,
    /// The drain limits of the connector, if it drains HTTP/1 bodies.
    drain: Option<Arc<Http1BodyDrain>>,
}

impl<C: ExtensionsRef> BindBodyToConn<C> {
    /// Wrap `conn` so its lifetime extends to the response body of its serve.
    pub fn new(conn: C) -> Self {
        Self::with_drain(conn, None)
    }

    fn with_drain(conn: C, drain: Option<Arc<Http1BodyDrain>>) -> Self {
        Self {
            extensions: conn.extensions().clone(),
            conn: Mutex::new(Some(conn)),
            drain,
        }
    }
}

impl<C> std::fmt::Debug for BindBodyToConn<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindBodyToConn").finish_non_exhaustive()
    }
}

impl<C> ExtensionsRef for BindBodyToConn<C> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<C, ReqBody, RespBody> Service<Request<ReqBody>> for BindBodyToConn<C>
where
    C: Service<Request<ReqBody>, Output = Response<RespBody>, Error = BoxError>,
    ReqBody: Send + 'static,
    RespBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        // Move the connection out: it is served exactly once per request, and it
        // now lives for as long as its response body.
        let Some(conn) = self.conn.lock().take() else {
            return Err(BoxError::from_static_str(
                "BindBodyToConn: connection already served (must be served exactly once)",
            ));
        };
        let resp = conn.serve(req).await?;
        // The connection is dropped, releasing its pool slot, when the body
        // reaches end-of-stream or is dropped (or, for an HTTP/1 body dropped
        // early, once drained).
        if let Some(drain) = &self.drain
            && self.extensions.contains::<Http1DrainRuntime>()
        {
            let extensions = self.extensions.clone();
            let drain = drain.clone();
            return Ok(resp.map(|body| {
                Body::new(Http1DrainBody::new(
                    GuardedBody::new(Body::new(body), conn),
                    drain,
                    extensions,
                ))
            }));
        }
        Ok(resp.map(|body| Body::new(GuardedBody::new(body, conn))))
    }
}

/// [`Layer`] that wraps a connector's connection in [`BindBodyToConn`].
///
/// Place it directly above the connection pool (as
/// [`HttpPooledConnectorConfig::build_connector`](super::HttpPooledConnectorConfig::build_connector)
/// does), so the body holds the pool lease, and below any layer transforming
/// response bodies (e.g. decompression), so a drain reads the raw body.
///
/// By default HTTP/1 response bodies dropped before their end are drained as
/// [`Http1BodyDrainConfig::default`] allows; each connector this layer
/// creates has its own limit of concurrent drains, shared by its clones.
/// Draining needs connections established by an
/// [`HttpConnector`](super::HttpConnector); others are not drained.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BindBodyToConnLayer {
    http1_body_drain: Option<Http1BodyDrainConfig>,
}

impl Default for BindBodyToConnLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl BindBodyToConnLayer {
    /// Create a new [`BindBodyToConnLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            http1_body_drain: Some(Http1BodyDrainConfig::new()),
        }
    }

    generate_set_and_with! {
        /// Drain HTTP/1 response bodies dropped before their end within these
        /// limits; `None` closes their connection right away instead.
        pub fn http1_body_drain(mut self, config: Option<Http1BodyDrainConfig>) -> Self {
            self.http1_body_drain = config;
            self
        }
    }
}

impl<S> Layer<S> for BindBodyToConnLayer {
    type Service = BindBodyToConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BindBodyToConnector {
            inner,
            drain: self
                .http1_body_drain
                .as_ref()
                .filter(|config| config.can_drain())
                .map(|config| Arc::new(Http1BodyDrain::new(config))),
        }
    }
}

/// Connector produced by [`BindBodyToConnLayer`]: wraps each established
/// connection in [`BindBodyToConn`].
#[derive(Debug, Clone)]
pub struct BindBodyToConnector<S> {
    inner: S,
    /// Shared by the clones of this connector, not by other connectors.
    pub(super) drain: Option<Arc<Http1BodyDrain>>,
}

impl<S, Input> Service<Input> for BindBodyToConnector<S>
where
    S: ConnectorService<Input>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<BindBodyToConn<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { conn, input } = self.inner.connect(input).await?;
        Ok(EstablishedClientConnection {
            conn: BindBodyToConn::with_drain(conn, self.drain.clone()),
            input,
        })
    }
}
