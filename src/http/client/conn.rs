use super::{svc::SendRequest, HttpClientService};
use crate::http::executor::HyperExecutor;
use crate::utils::macros::define_inner_service_accessors;
use crate::{
    error::{BoxError, OpaqueError},
    http::{dep::http_body, Request, Version},
    net::client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
    Context, Layer, Service,
};
use hyper_util::rt::TokioIo;
use std::fmt;
use tokio::sync::Mutex;

/// A [`Service`] which establishes an HTTP Connection.
pub struct HttpConnector<S> {
    inner: S,
}

impl<S: fmt::Debug> fmt::Debug for HttpConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnector")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> HttpConnector<S> {
    /// Create a new [`HttpConnector`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> Clone for HttpConnector<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, State, Body> Service<State, Request<Body>> for HttpConnector<S>
where
    S: ConnectorService<State, Request<Body>, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Send + Sync + 'static,
    Body: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Response = EstablishedClientConnection<HttpClientService<Body>, State, Request<Body>>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection {
            ctx,
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let io = TokioIo::new(Box::pin(conn));

        match req.version() {
            Version::HTTP_2 => {
                let executor = HyperExecutor(ctx.executor().clone());
                let (sender, conn) = hyper::client::conn::http2::handshake(executor, io).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let svc = HttpClientService(SendRequest::Http2(Mutex::new(sender)));

                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: svc,
                    addr,
                })
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let svc = HttpClientService(SendRequest::Http1(Mutex::new(sender)));

                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: svc,
                    addr,
                })
            }
            version => Err(OpaqueError::from_display(format!(
                "unsupported Http version: {:?}",
                version
            ))
            .into()),
        }
    }
}

/// A [`Layer`] that produces an [`HttpConnector`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpConnectorLayer;

impl HttpConnectorLayer {
    /// Create a new [`HttpConnectorLayer`].
    pub const fn new() -> Self {
        Self
    }
}

impl Default for HttpConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for HttpConnectorLayer {
    type Service = HttpConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnector { inner }
    }
}
