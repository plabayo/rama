use super::{HttpClientService, svc::SendRequest};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, OpaqueError},
    inspect::RequestInspector,
};
use rama_http_types::{Request, Version, conn::Http1ClientContextParams, dep::http_body};
use rama_net::{
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
};

use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use tracing::trace;

/// A [`Service`] which establishes an HTTP Connection.
pub struct HttpConnector<S, I1 = (), I2 = ()> {
    inner: S,
    http_req_inspector_jit: I1,
    http_req_inspector_svc: I2,
}

impl<S: fmt::Debug, I1: fmt::Debug, I2: fmt::Debug> fmt::Debug for HttpConnector<S, I1, I2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnector")
            .field("inner", &self.inner)
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_jit)
            .finish()
    }
}

impl<S> HttpConnector<S> {
    /// Create a new [`HttpConnector`].
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            http_req_inspector_jit: (),
            http_req_inspector_svc: (),
        }
    }
}

impl<S, I1, I2> HttpConnector<S, I1, I2> {
    pub fn with_jit_req_inspector<T>(self, http_req_inspector: T) -> HttpConnector<S, T, I2> {
        HttpConnector {
            inner: self.inner,
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
    }

    pub fn with_svc_req_inspector<T>(self, http_req_inspector: T) -> HttpConnector<S, I1, T> {
        HttpConnector {
            inner: self.inner,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
        }
    }

    define_inner_service_accessors!();
}

impl<S, I1, I2> Clone for HttpConnector<S, I1, I2>
where
    S: Clone,
    I1: Clone,
    I2: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

impl<S, I1, I2, State, BodyIn, BodyOut> Service<State, Request<BodyIn>> for HttpConnector<S, I1, I2>
where
    I1: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            StateOut = State,
            RequestOut = Request<BodyIn>,
        >,
    I2: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            RequestOut = Request<BodyOut>,
        > + Clone,
    S: ConnectorService<State, Request<BodyIn>, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    BodyIn: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    BodyOut: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Response =
        EstablishedClientConnection<HttpClientService<BodyOut, I2>, I1::StateOut, I1::RequestOut>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<BodyIn>,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { ctx, req, conn } =
            self.inner.connect(ctx, req).await.map_err(Into::into)?;

        let (ctx, req) = self
            .http_req_inspector_jit
            .inspect_request(ctx, req)
            .await
            .map_err(Into::into)?;

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

                let svc = HttpClientService {
                    sender: SendRequest::Http2(sender),
                    http_req_inspector: self.http_req_inspector_svc.clone(),
                };

                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: svc,
                })
            }
            Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09 => {
                trace!(uri = %req.uri(), "create ~h1 client executor");
                let mut builder = rama_http_core::client::conn::http1::Builder::new();
                if let Some(params) = ctx.get::<Http1ClientContextParams>() {
                    builder.title_case_headers(params.title_header_case);
                }
                let (sender, conn) = builder.handshake(io).await?;

                ctx.spawn(async move {
                    if let Err(err) = conn.await {
                        tracing::debug!("connection failed: {:?}", err);
                    }
                });

                let svc = HttpClientService {
                    sender: SendRequest::Http1(sender),
                    http_req_inspector: self.http_req_inspector_svc.clone(),
                };

                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: svc,
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
pub struct HttpConnectorLayer<I1 = (), I2 = ()> {
    http_req_inspector_jit: I1,
    http_req_inspector_svc: I2,
}

impl HttpConnectorLayer {
    /// Create a new [`HttpConnectorLayer`].
    pub const fn new() -> Self {
        Self {
            http_req_inspector_jit: (),
            http_req_inspector_svc: (),
        }
    }
}

impl<I1, I2> HttpConnectorLayer<I1, I2> {
    pub fn with_jit_req_inspector<T>(self, http_req_inspector: T) -> HttpConnectorLayer<T, I2> {
        HttpConnectorLayer {
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
    }

    pub fn with_svc_req_inspector<T>(self, http_req_inspector: T) -> HttpConnectorLayer<I1, T> {
        HttpConnectorLayer {
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
        }
    }
}

impl<I1: fmt::Debug, I2: fmt::Debug> fmt::Debug for HttpConnectorLayer<I1, I2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectorLayer")
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_svc)
            .finish()
    }
}

impl<I1, I2> Clone for HttpConnectorLayer<I1, I2>
where
    I1: Clone,
    I2: Clone,
{
    fn clone(&self) -> Self {
        Self {
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

impl Default for HttpConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<I1: Clone, I2: Clone, S> Layer<S> for HttpConnectorLayer<I1, I2> {
    type Service = HttpConnector<S, I1, I2>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}
