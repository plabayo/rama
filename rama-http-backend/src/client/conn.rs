use super::{HttpClientService, svc::SendRequest};
use rama_core::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    inspect::RequestInspector,
};
use rama_http_core::h2::frame::Priority;
use rama_http_types::{
    Request, Version,
    conn::{H2ClientContextParams, Http1ClientContextParams},
    dep::http_body,
    proto::h2::PseudoHeaderOrder,
};
use rama_net::{
    Protocol,
    address::Authority,
    client::{
        ConnStoreFiFoReuseLruDrop, ConnectorService, EstablishedClientConnection, Pool,
        PooledConnector, ReqToConnID,
    },
    http::RequestContext,
    stream::Stream,
};
use rama_utils::macros::nz;
use std::{marker::PhantomData, num::NonZero};
use tokio::sync::Mutex;

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

    pub fn with_connection_pool<Storage, R>(
        self,
        pool: Pool<Storage>,
        req_to_conn_id: R,
    ) -> PooledConnector<HttpConnector<S, I1, I2>, Storage, R> {
        PooledConnector::new(self, pool, req_to_conn_id)
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
                let mut builder = rama_http_core::client::conn::http2::Builder::new(executor);

                if let Some(params) = ctx
                    .get::<H2ClientContextParams>()
                    .or_else(|| req.extensions().get())
                {
                    if let Some(ref config) = params.setting_config {
                        builder.apply_setting_config(config);
                    }
                    if let Some(order) = params.headers_pseudo_order.clone() {
                        builder.headers_pseudo_order(order);
                    }
                    if let Some(priority) = params.headers_priority.clone() {
                        builder.headers_priority(priority.into());
                    }
                    if let Some(ref priority) = params.priority {
                        builder.priority(
                            priority
                                .iter()
                                .map(|p| Priority::from(p.clone()))
                                .collect::<Vec<_>>(),
                        );
                    }
                } else if let Some(pseudo_order) =
                    req.extensions().get::<PseudoHeaderOrder>().cloned()
                {
                    builder.headers_pseudo_order(pseudo_order);
                }

                let (sender, conn) = builder.handshake(io).await?;

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
                    sender: SendRequest::Http1(Mutex::new(sender)),
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
pub struct HttpConnectorLayer<I1 = (), I2 = (), P = ()> {
    http_req_inspector_jit: I1,
    http_req_inspector_svc: I2,
    pool_and_req_to_conn_id: P,
}

impl HttpConnectorLayer {
    /// Create a new [`HttpConnectorLayer`].
    pub const fn new() -> Self {
        Self {
            http_req_inspector_jit: (),
            http_req_inspector_svc: (),
            pool_and_req_to_conn_id: (),
        }
    }
}

impl<I1, I2, P> HttpConnectorLayer<I1, I2, P> {
    pub fn with_jit_req_inspector<T>(self, http_req_inspector: T) -> HttpConnectorLayer<T, I2, P> {
        HttpConnectorLayer {
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
            pool_and_req_to_conn_id: self.pool_and_req_to_conn_id,
        }
    }

    pub fn with_svc_req_inspector<T>(self, http_req_inspector: T) -> HttpConnectorLayer<I1, T, P> {
        HttpConnectorLayer {
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
            pool_and_req_to_conn_id: self.pool_and_req_to_conn_id,
        }
    }

    pub fn with_connection_pool<T, R>(
        self,
        pool: T,
        req_to_conn_id: R,
    ) -> HttpConnectorLayer<I1, I2, (T, R)> {
        HttpConnectorLayer {
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
            pool_and_req_to_conn_id: (pool, req_to_conn_id),
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

impl<I1, I2, P> Clone for HttpConnectorLayer<I1, I2, P>
where
    I1: Clone,
    I2: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
            pool_and_req_to_conn_id: self.pool_and_req_to_conn_id.clone(),
        }
    }
}

impl Default for HttpConnectorLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<I1: Clone, I2: Clone, S> Layer<S> for HttpConnectorLayer<I1, I2, ()> {
    type Service = HttpConnector<S, I1, I2>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HttpConnector {
            inner,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
    }
}

impl<I1: Clone, I2: Clone, S, Storage, R: Clone> Layer<S>
    for HttpConnectorLayer<I1, I2, (Pool<Storage>, R)>
{
    type Service = PooledConnector<HttpConnector<S, I1, I2>, Storage, R>;

    fn layer(&self, inner: S) -> Self::Service {
        let (pool, req_to_conn_id) = self.pool_and_req_to_conn_id.clone();
        HttpConnector {
            inner,
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
        .with_connection_pool(pool, req_to_conn_id)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        let (pool, req_to_conn_id) = self.pool_and_req_to_conn_id;
        HttpConnector {
            inner,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
        }
        .with_connection_pool(pool, req_to_conn_id)
    }
}

#[non_exhaustive]
#[derive(Clone, Debug)]
/// [`HttpConnectionPoolBuilder`] can be used to build a connection pool to be used
/// together with a [`HttpConnector`]
pub struct HttpConnectionPoolBuilder<ConnID = BasicHttpConId, R = BasicHttpConnIdentifier> {
    max_active: NonZero<u16>,
    max_total: NonZero<u16>,
    req_to_conn_id: R,
    _phantom_data: PhantomData<ConnID>,
}

impl HttpConnectionPoolBuilder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<ConnID, R> HttpConnectionPoolBuilder<ConnID, R>
where
    ConnID: Clone + Send + Sync + PartialEq + std::fmt::Debug + 'static,
{
    pub fn set_max_active(&mut self, value: NonZero<u16>) -> &mut Self {
        self.max_active = value;
        self
    }

    pub fn with_max_active(mut self, value: NonZero<u16>) -> Self {
        self.set_max_active(value);
        self
    }

    pub fn set_max_total(&mut self, value: NonZero<u16>) -> &mut Self {
        self.max_total = value;
        self
    }

    pub fn with_max_total(mut self, value: NonZero<u16>) -> Self {
        self.set_max_total(value);
        self
    }

    pub fn with_request_to_conn_id<T, State, Request>(
        self,
        value: T,
    ) -> HttpConnectionPoolBuilder<T::ConnID, T>
    where
        T: ReqToConnID<State, Request>,
    {
        HttpConnectionPoolBuilder {
            max_active: self.max_active,
            max_total: self.max_total,
            req_to_conn_id: value,
            _phantom_data: PhantomData,
        }
    }

    // TODO find way to get rid of this generic
    pub fn build<Body: Send + 'static>(
        self,
    ) -> Result<
        (
            Pool<ConnStoreFiFoReuseLruDrop<HttpClientService<Body>, ConnID>>,
            R,
        ),
        OpaqueError,
    > {
        let pool = Pool::new(self.max_active, self.max_total).context("create connection pool")?;
        Ok((pool, self.req_to_conn_id))
    }
}

impl Default for HttpConnectionPoolBuilder {
    fn default() -> Self {
        Self {
            max_active: nz!(10),
            max_total: nz!(20),
            req_to_conn_id: BasicHttpConnIdentifier,
            _phantom_data: PhantomData,
        }
    }
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BasicHttpConnIdentifier;

type BasicHttpConId = (Protocol, Authority);

impl<State, Body> ReqToConnID<State, Request<Body>> for BasicHttpConnIdentifier {
    type ConnID = BasicHttpConId;

    fn id(&self, ctx: &Context<State>, req: &Request<Body>) -> Result<Self::ConnID, OpaqueError> {
        let req_ctx = match ctx.get::<RequestContext>() {
            Some(ctx) => ctx,
            None => &RequestContext::try_from((ctx, req))?,
        };

        Ok((req_ctx.protocol.clone(), req_ctx.authority.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test() {
        let connector = HttpConnector::new(());
        // TODO find way to get rid of this generic...
        let (pool, req_to_conn_id) = HttpConnectionPoolBuilder::new().build::<u8>().unwrap();
        let connector = connector.with_connection_pool(pool, req_to_conn_id);
    }
}
