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
//! [`BindBodyToConnLayer`] applies this to a connector's connection.
//!
//! Warning: this means a [`BindBodyToConn`] connection can only be used to
//! serve a single request, which ties in perfects with how we expect a connector
//! stack to work, but might be surprising if you use this layer alone. This layer
//! should almost always be combined with connection pool that gives a new connection
//! per request.

use parking_lot::Mutex;

use rama_core::bytes::Bytes;
use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::{Layer, Service};
use rama_http::StreamingBody;
use rama_http_types::body::GuardedBody;
use rama_http_types::{Body, Request, Response};
use rama_net::client::{ConnectorService, EstablishedClientConnection};

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
}

impl<C: ExtensionsRef> BindBodyToConn<C> {
    /// Wrap `conn` so its lifetime extends to the response body of its serve.
    pub fn new(conn: C) -> Self {
        Self {
            extensions: conn.extensions().clone(),
            conn: Mutex::new(Some(conn)),
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
        // reaches end-of-stream or is dropped.
        Ok(resp.map(|body| Body::new(GuardedBody::new(body, conn))))
    }
}

/// [`Layer`] that wraps a connector's connection in [`BindBodyToConn`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BindBodyToConnLayer;

impl BindBodyToConnLayer {
    /// Create a new [`BindBodyToConnLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for BindBodyToConnLayer {
    type Service = BindBodyToConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BindBodyToConnector { inner }
    }
}

/// Connector produced by [`BindBodyToConnLayer`]: wraps each established
/// connection in [`BindBodyToConn`].
#[derive(Debug, Clone)]
pub struct BindBodyToConnector<S> {
    inner: S,
}

impl<S, Input> Service<Input> for BindBodyToConnector<S>
where
    S: ConnectorService<Input>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<BindBodyToConn<S::Connection>, Input>;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { conn, input } = self.inner.connect(input).await?;
        Ok(EstablishedClientConnection {
            conn: BindBodyToConn::new(conn),
            input,
        })
    }
}
