use super::{svc::SendRequest, HttpClientService};
use rama_core::{
    error::{BoxError, OpaqueError},
    Context, Layer, Service,
};
use rama_http_types::{dep::http_body, Request, Version};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
};

use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use tokio::sync::Mutex;
use tracing::trace;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_net::tls::{client::NegotiatedTlsParameters, ApplicationProtocol};

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
    State: Clone + Send + Sync + 'static,
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
            #[cfg(any(feature = "rustls", feature = "boring"))]
            mut req,
            #[cfg(not(any(feature = "rustls", feature = "boring")))]
            req,
            conn,
            addr,
        } = self.inner.connect(ctx, req).await.map_err(Into::into)?;

        #[cfg(any(feature = "rustls", feature = "boring"))]
        if let Some(proto) = ctx
            .get::<NegotiatedTlsParameters>()
            .and_then(|params| params.application_layer_protocol.as_ref())
        {
            let new_version = match proto {
                ApplicationProtocol::HTTP_09 => rama_http_types::Version::HTTP_09,
                ApplicationProtocol::HTTP_10 => rama_http_types::Version::HTTP_10,
                ApplicationProtocol::HTTP_11 => rama_http_types::Version::HTTP_11,
                ApplicationProtocol::HTTP_2 => rama_http_types::Version::HTTP_2,
                ApplicationProtocol::HTTP_3 => rama_http_types::Version::HTTP_3,
                _ => {
                    return Err(OpaqueError::from_display(
                        "HttpConnector: unsupported negotiated ALPN: {proto}",
                    )
                    .into_boxed());
                }
            };
            trace!(
                "setting request version to {:?} based on negotiated APLN (was: {:?})",
                new_version,
                req.version(),
            );
            *req.version_mut() = new_version;
        }

        let io = Box::pin(conn);

        match req.version() {
            Version::HTTP_2 => {
                trace!(uri = %req.uri(), "create h2 client executor");
                let executor = ctx.executor().clone();
                let (sender, conn) =
                    rama_http_core::client::conn::http2::handshake(executor, io).await?;

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
                trace!(uri = %req.uri(), "create ~h1 client executor");
                let (sender, conn) = rama_http_core::client::conn::http1::handshake(io).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let svc = HttpClientService(SendRequest::Http1(sender));

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
