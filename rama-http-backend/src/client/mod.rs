//! Rama HTTP client module,
//! which provides the [`EasyHttpWebClient`] type to serve HTTP requests.

use std::fmt;

use proxy::layer::HttpProxyConnector;
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    inspect::RequestInspector,
};
use rama_http_types::{Request, Response, Version, dep::http_body};
use rama_net::{
    Protocol,
    address::Authority,
    client::{
        ConnectorService, EitherConn, EstablishedClientConnection, LeasedConnection, Pool,
        PoolStorage, PooledConnector, ReqToConnID,
    },
    http::RequestContext,
};
use rama_tcp::client::service::TcpConnector;

#[cfg(feature = "boring")]
use rama_net::tls::client::{ClientConfig, ProxyClientConfig, extract_client_config_from_ctx};

#[cfg(feature = "boring")]
use rama_tls::boring::client::{
    TlsConnector as BoringTlsConnector, TlsConnectorData as BoringTlsConnectorData,
};

#[cfg(feature = "rustls")]
use rama_tls_rustls::client::{
    TlsConnector as RustlsTlsConnector, TlsConnectorData as RustlsTlsConnectorData,
};

#[cfg(any(feature = "rustls", feature = "boring"))]
use http_inspector::HttpsAlpnModifier;

mod svc;
#[doc(inline)]
pub use svc::HttpClientService;

mod conn;
#[doc(inline)]
pub use conn::{HttpConnector, HttpConnectorLayer};
use tracing::trace;

pub mod http_inspector;
pub mod proxy;

/// An opiniated http client that can be used to serve HTTP requests.
///
/// You can fork this http client in case you have use cases not possible with this service example.
/// E.g. perhaps you wish to have middleware in into outbound requests, after they
/// passed through your "connector" setup. All this and more is possible by defining your own
/// http client. Rama is here to empower you, the building blocks are there, go crazy
/// with your own service fork and use the full power of Rust at your fingertips ;)
pub struct EasyHttpWebClient<I1 = (), I2 = (), P = ()> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_connector_layer: Option<TlsConnectorLayer>,
    #[cfg(any(feature = "rustls", feature = "boring"))]
    proxy_tls_connector_layer: Option<TlsConnectorLayer>,
    connection_pool: P,
    proxy_http_connect_version: Option<Version>,
    http_req_inspector_jit: I1,
    http_req_inspector_svc: I2,
}

#[derive(Debug, Clone)]
pub enum TlsConnectorLayer {
    #[cfg(feature = "boring")]
    Boring(Option<ClientConfig>),
    #[cfg(feature = "rustls")]
    Rustls(Option<RustlsTlsConnectorData>),
}

#[cfg(any(feature = "rustls", feature = "boring"))]
impl<I1: fmt::Debug, I2: fmt::Debug, P: fmt::Debug> fmt::Debug for EasyHttpWebClient<I1, I2, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient")
            .field("tls_connector_layer", &self.tls_connector_layer)
            .field("proxy_tls_connector_layer", &self.proxy_tls_connector_layer)
            .field("connection_pool", &self.connection_pool)
            .field(
                "proxy_http_connect_version",
                &self.proxy_http_connect_version,
            )
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_svc)
            .finish()
    }
}

#[cfg(not(any(feature = "rustls", feature = "boring")))]
impl<I1: fmt::Debug, I2: fmt::Debug, P: fmt::Debug> fmt::Debug for EasyHttpWebClient<I1, I2, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHttpWebClient")
            .field("connection_pool", &self.connection_pool)
            .field(
                "proxy_http_connect_version",
                &self.proxy_http_connect_version,
            )
            .field("http_req_inspector_jit", &self.http_req_inspector_jit)
            .field("http_req_inspector_svc", &self.http_req_inspector_svc)
            .finish()
    }
}

#[cfg(any(feature = "rustls", feature = "boring"))]
impl<I1: Clone, I2: Clone, P: Clone> Clone for EasyHttpWebClient<I1, I2, P> {
    fn clone(&self) -> Self {
        Self {
            tls_connector_layer: self.tls_connector_layer.clone(),
            proxy_tls_connector_layer: self.proxy_tls_connector_layer.clone(),
            connection_pool: self.connection_pool.clone(),
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

#[cfg(not(any(feature = "rustls", feature = "boring")))]
impl<I1: Clone, I2: Clone, P: Clone> Clone for EasyHttpWebClient<I1, I2, P> {
    fn clone(&self) -> Self {
        Self {
            connection_pool: self.connection_pool.clone(),
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit.clone(),
            http_req_inspector_svc: self.http_req_inspector_svc.clone(),
        }
    }
}

impl Default for EasyHttpWebClient {
    fn default() -> Self {
        Self {
            #[cfg(feature = "boring")]
            tls_connector_layer: Some(TlsConnectorLayer::Boring(None)),
            #[cfg(all(feature = "rustls", not(feature = "boring")))]
            tls_connector_layer: Some(TlsConnectorLayer::Rustls(None)),
            #[cfg(feature = "boring")]
            proxy_tls_connector_layer: Some(TlsConnectorLayer::Boring(None)),
            #[cfg(all(feature = "rustls", not(feature = "boring")))]
            proxy_tls_connector_layer: Some(TlsConnectorLayer::Rustls(None)),
            connection_pool: (),
            proxy_http_connect_version: Some(Version::HTTP_11),
            http_req_inspector_jit: (),
            http_req_inspector_svc: (),
        }
    }
}

impl EasyHttpWebClient {
    /// Create a new [`EasyHttpWebClient`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I1, I2, P> EasyHttpWebClient<I1, I2, P> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`TlsConnectorLayer`] of this [`EasyHttpWebClient`].
    pub fn set_tls_connector_layer(&mut self, layer: TlsConnectorLayer) -> &mut Self {
        self.tls_connector_layer = Some(layer);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] with the [`TlsConnectorLayer`] set.
    pub fn with_tls_connector_layer(mut self, layer: TlsConnectorLayer) -> Self {
        self.tls_connector_layer = Some(layer);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] with an option of [`TlsConfig`] set.
    pub fn maybe_with_tls_connector_layer(mut self, layer: Option<TlsConnectorLayer>) -> Self {
        self.tls_connector_layer = layer;
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Set the [`TlsConfig`] for the https proxy tunnel if needed within this [`EasyHttpWebClient`].
    pub fn set_proxy_tls_connector_layer(&mut self, layer: TlsConnectorLayer) -> &mut Self {
        self.proxy_tls_connector_layer = Some(layer);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] set for the https proxy tunnel if needed within this [`TlsConfig`].
    pub fn with_proxy_tls_connector_layer(mut self, layer: TlsConnectorLayer) -> Self {
        self.proxy_tls_connector_layer = Some(layer);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// Replace this [`EasyHttpWebClient`] set for the https proxy tunnel if needed within this [`TlsConfig`].
    pub fn maybe_proxy_with_tls_connector_layer(
        mut self,
        layer: Option<TlsConnectorLayer>,
    ) -> Self {
        self.proxy_tls_connector_layer = layer;
        self
    }

    /// Set the HTTP version to use for the Http Proxy CONNECT request.
    ///
    /// By default this is set to HTTP/1.1.
    pub fn with_proxy_http_connect_version(mut self, version: Version) -> Self {
        self.proxy_http_connect_version = Some(version);
        self
    }

    /// Set the HTTP version to use for the Http Proxy CONNECT request.
    pub fn set_proxy_http_connect_version(&mut self, version: Version) -> &mut Self {
        self.proxy_http_connect_version = Some(version);
        self
    }

    /// Set the HTTP version to auto detect for the Http Proxy CONNECT request.
    pub fn with_proxy_http_connect_auto_version(mut self) -> Self {
        self.proxy_http_connect_version = None;
        self
    }

    /// Set the HTTP version to auto detect for the Http Proxy CONNECT request.
    pub fn set_proxy_http_connect_auto_version(&mut self) -> &mut Self {
        self.proxy_http_connect_version = None;
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn with_http_conn_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<T, I2, P> {
        EasyHttpWebClient {
            tls_connector_layer: self.tls_connector_layer,
            proxy_tls_connector_layer: self.proxy_tls_connector_layer,
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: self.connection_pool,
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn with_http_conn_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<T, I2, P> {
        EasyHttpWebClient {
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: http_req_inspector,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: self.connection_pool,
        }
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn with_http_serve_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<I1, T, P> {
        EasyHttpWebClient {
            tls_connector_layer: self.tls_connector_layer,
            proxy_tls_connector_layer: self.proxy_tls_connector_layer,
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
            connection_pool: self.connection_pool,
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn with_http_serve_req_inspector<T>(
        self,
        http_req_inspector: T,
    ) -> EasyHttpWebClient<I1, T, P> {
        EasyHttpWebClient {
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: http_req_inspector,
            connection_pool: self.connection_pool,
        }
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn with_connection_pool<S>(self, pool: Pool<S>) -> EasyHttpWebClient<I1, I2, Pool<S>> {
        EasyHttpWebClient {
            tls_connector_layer: self.tls_connector_layer,
            proxy_tls_connector_layer: self.proxy_tls_connector_layer,
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: pool,
        }
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    pub fn without_connection_pool(self) -> EasyHttpWebClient<I1, I2, ()> {
        EasyHttpWebClient {
            tls_connector_layer: self.tls_connector_layer,
            proxy_tls_connector_layer: self.proxy_tls_connector_layer,
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: (),
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn with_connection_pool<S>(self, pool: Pool<S>) -> EasyHttpWebClient<I1, I2, Pool<S>> {
        EasyHttpWebClient {
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: pool,
        }
    }

    #[cfg(not(any(feature = "rustls", feature = "boring")))]
    pub fn without_connection_pool(self) -> EasyHttpWebClient<I1, I2, ()> {
        EasyHttpWebClient {
            proxy_http_connect_version: self.proxy_http_connect_version,
            http_req_inspector_jit: self.http_req_inspector_jit,
            http_req_inspector_svc: self.http_req_inspector_svc,
            connection_pool: (),
        }
    }
}

/// Map http request to unique connection id so we can use a connection pool
#[derive(Debug)]
#[non_exhaustive]
struct BasicHttpConnId;
type BasicConnID = (Protocol, Authority);

impl<State, Body> ReqToConnID<State, Request<Body>> for BasicHttpConnId {
    type ConnID = BasicConnID;

    fn id(&self, ctx: &Context<State>, req: &Request<Body>) -> Result<Self::ConnID, OpaqueError> {
        let req_ctx = match ctx.get::<RequestContext>() {
            Some(ctx) => ctx,
            None => &RequestContext::try_from((ctx, req))?,
        };

        Ok((req_ctx.protocol.clone(), req_ctx.authority.clone()))
    }
}

enum Connection<C, State, Body> {
    Direct(EstablishedClientConnection<C, State, Request<Body>>),
    Pooled(EstablishedClientConnection<LeasedConnection<C, BasicConnID>, State, Request<Body>>),
}

trait MaybePooledConnector<C, State, Body>: Send + Sync + 'static {
    fn connect<T>(
        &self,
        connector: T,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> impl Future<Output = Result<Connection<C, State, Body>, OpaqueError>> + Send
    where
        T: ConnectorService<State, Request<Body>, Connection = C>,
        T::Error: Send + 'static;
}

impl<C, State, Body, I1, I2> MaybePooledConnector<C, State, Body> for EasyHttpWebClient<I1, I2, ()>
where
    I1: Send + Sync + 'static,
    I2: Send + Sync + 'static,
    State: Send,
    Body: Send,
{
    async fn connect<T>(
        &self,
        connector: T,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Connection<C, State, Body>, OpaqueError>
    where
        T: ConnectorService<State, Request<Body>, Connection = C>,
        T::Error: Send + Into<BoxError> + 'static,
    {
        let result = connector
            .connect(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()).context("connector failed"))?;
        Ok(Connection::Direct(result))
    }
}

impl<C, State, Body, S, I1, I2> MaybePooledConnector<C, State, Body>
    for EasyHttpWebClient<I1, I2, Pool<S>>
where
    C: Send,
    S: PoolStorage<ConnID = BasicConnID, Connection = C>,
    State: Send + Sync + Clone + 'static,
    Body: Send + 'static,
    I1: Send + Sync + 'static,
    I2: Send + Sync + 'static,
{
    async fn connect<T>(
        &self,
        connector: T,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Connection<C, State, Body>, OpaqueError>
    where
        T: ConnectorService<State, Request<Body>, Connection = C>,
        T::Error: Send + 'static,
    {
        let pool = self.connection_pool.clone();
        let connector = PooledConnector::new(connector, pool, BasicHttpConnId);
        let result = connector
            .connect(ctx, req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err).context("pooled connector failed"))?;
        Ok(Connection::Pooled(result))
    }
}

impl<State, BodyIn, BodyOut, P, I1, I2> Service<State, Request<BodyIn>>
    for EasyHttpWebClient<I1, I2, P>
where
    EasyHttpWebClient<I1, I2, P>:
        MaybePooledConnector<HttpClientService<BodyOut, I2>, State, BodyIn>,
    State: Clone + Send + Sync + 'static,
    BodyIn: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    BodyOut: http_body::Body<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
    I1: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            StateOut = State,
            RequestOut = Request<BodyIn>,
        > + Clone,
    I2: RequestInspector<
            State,
            Request<BodyIn>,
            Error: Into<BoxError>,
            RequestOut = Request<BodyOut>,
        > + Clone,
{
    type Response = Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<BodyIn>,
    ) -> Result<Self::Response, Self::Error> {
        let uri = req.uri().clone();

        let tcp_connector = TcpConnector::new();

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let connector = {
            // 1 TCP
            let connector = tcp_connector;

            // 2 Maybe proxy tls

            // This syntax might look weird compared to using match statement but allows us to reuse all code for a mix of features.
            // This is a design limit of how Either works, Eg Either3 will not work if one feature is disabled as it won't be able to infer all types.
            // Solution to this is splitting everything up, and doing it this way, only requires us to do it once.

            #[cfg(feature = "boring")]
            let connector = if let Some(TlsConnectorLayer::Boring(config)) =
                &self.proxy_tls_connector_layer
            {
                let data = create_proxy_connector_data_boring(&ctx, config)?;
                EitherConn::A(BoringTlsConnector::tunnel(connector, None).with_connector_data(data))
            } else {
                EitherConn::B(connector)
            };

            #[cfg(feature = "rustls")]
            let connector = if let Some(TlsConnectorLayer::Rustls(config)) =
                &self.proxy_tls_connector_layer
            {
                let data = create_proxy_connector_data_rustls(&ctx, config)?;
                EitherConn::A(RustlsTlsConnector::tunnel(connector, None).with_connector_data(data))
            } else {
                EitherConn::B(connector)
            };

            // 3 Http proxy tunnel if needed
            let mut connector = HttpProxyConnector::optional(connector);
            match self.proxy_http_connect_version {
                Some(version) => connector.set_version(version),
                None => connector.set_auto_version(),
            };

            // 4 Tls for normal flow
            #[cfg(feature = "boring")]
            let connector =
                if let Some(TlsConnectorLayer::Boring(config)) = &self.tls_connector_layer {
                    let data = create_connector_data_boring(&ctx, config)?;
                    EitherConn::A(BoringTlsConnector::auto(connector).with_connector_data(data))
                } else {
                    EitherConn::B(connector)
                };

            #[cfg(feature = "rustls")]
            let connector =
                if let Some(TlsConnectorLayer::Rustls(config)) = &self.tls_connector_layer {
                    let data = create_connector_data_rustls(&ctx, config)?;
                    EitherConn::A(RustlsTlsConnector::auto(connector).with_connector_data(data))
                } else {
                    EitherConn::B(connector)
                };

            // 4 Http normal flow
            let connector = HttpConnector::new(connector);

            connector.with_jit_req_inspector((
                HttpsAlpnModifier::default(),
                self.http_req_inspector_jit.clone(),
            ))
        };

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let connector = {
            let mut proxy_connector = HttpProxyConnector::optional(tcp_connector);
            match self.proxy_http_connect_version {
                Some(version) => proxy_connector.set_version(version),
                None => proxy_connector.set_auto_version(),
            };
            HttpConnector::new(proxy_connector)
                .with_jit_req_inspector(self.http_req_inspector_jit.clone())
        };

        // set the runtime http req inspector
        let connector = connector.with_svc_req_inspector(self.http_req_inspector_svc.clone());

        // NOTE: stack might change request version based on connector data,
        let connection = self.connect(connector, ctx, req).await?;
        trace!(uri = %uri, "send http req to connector stack");

        let result = match connection {
            Connection::Direct(EstablishedClientConnection { ctx, req, conn }) => {
                conn.serve(ctx, req).await
            }
            Connection::Pooled(EstablishedClientConnection { ctx, req, conn }) => {
                conn.serve(ctx, req).await
            }
        };

        let resp = result
            .map_err(OpaqueError::from_boxed)
            .with_context(|| format!("http request failure for uri: {uri}"))?;

        trace!(uri = %uri, "response received from connector stack");

        Ok(resp)
    }
}

#[cfg(feature = "boring")]
fn create_connector_data_boring<State>(
    ctx: &Context<State>,
    tls_config: &Option<ClientConfig>,
) -> Result<BoringTlsConnectorData, OpaqueError> {
    match extract_client_config_from_ctx(ctx) {
        Some(mut chain_ref) => {
            trace!(
                "create tls connector using rama tls client config(s) from context and/or the predefined one if defined"
            );
            if let Some(tls_config) = tls_config {
                chain_ref.prepend(tls_config.clone());
            }
            BoringTlsConnectorData::try_from_multiple_client_configs(chain_ref.iter()).context(
                "EasyHttpWebClient: create tls connector data from tls client config(s) from context and/or the predefined one if defined",
            )
        }
        None => match tls_config {
            Some(tls_config) => {
                trace!("create tls connector using pre-defined rama tls client config");
                tls_config.clone().try_into().context(
                    "EasyHttpWebClient: create tls connector data from pre-defined tls config",
                )
            }
            None => {
                trace!("create tls connector using the 'new_http_auto' constructor");
                BoringTlsConnectorData::new_http_auto()
                    .context("EasyHttpWebClient: create tls connector data for http (auto)")
            }
        },
    }
}

#[cfg(feature = "boring")]
fn create_proxy_connector_data_boring<State>(
    ctx: &Context<State>,
    tls_config: &Option<ClientConfig>,
) -> Result<BoringTlsConnectorData, OpaqueError> {
    let data = match (ctx.get::<ProxyClientConfig>(), tls_config) {
        (Some(proxy_tls_config), _) => {
            trace!("create proxy tls connector using rama tls client config from context");
            proxy_tls_config
                .0
                .as_ref()
                .clone()
                .try_into()
                .context(
                "EasyHttpWebClient: create proxy tls connector data from tls config found in context",
            )?
        }
        (None, Some(proxy_tls_config)) => {
            trace!("create proxy tls connector using pre-defined rama tls client config");
            proxy_tls_config
                .clone()
                .try_into()
                .context("EasyHttpWebClient: create proxy tls connector data from tls config")?
        }
        (None, None) => {
            trace!("create proxy tls connector using the 'new_http_auto' constructor");
            BoringTlsConnectorData::new().context(
                "EasyHttpWebClient: create proxy tls connector data with no application presets",
            )?
        }
    };
    Ok(data)
}

#[cfg(feature = "rustls")]
fn create_connector_data_rustls<State>(
    _ctx: &Context<State>,
    tls_config: &Option<RustlsTlsConnectorData>,
) -> Result<RustlsTlsConnectorData, OpaqueError> {
    // TODO do we also want to support getting this from ctx?
    match tls_config {
        Some(tls_config) => {
            trace!("create tls connector using pre-defined rustls tls client config");
            Ok(tls_config.clone())
        }
        None => {
            trace!("create tls connector using the 'new_http_auto' constructor");
            RustlsTlsConnectorData::new_http_auto()
                .context("EasyHttpWebClient: create tls connector data for http (auto)")
        }
    }
}

#[cfg(feature = "rustls")]
fn create_proxy_connector_data_rustls<State>(
    _ctx: &Context<State>,
    tls_config: &Option<RustlsTlsConnectorData>,
) -> Result<RustlsTlsConnectorData, OpaqueError> {
    // TODO do we also want to support getting this from ctx?
    match tls_config {
        Some(tls_config) => {
            trace!("create tls connector using pre-defined rustls tls client config");
            Ok(tls_config.clone())
        }
        None => {
            trace!("create tls connector using the 'new_http_auto' constructor");
            RustlsTlsConnectorData::new_http_auto()
                .context("EasyHttpWebClient: create tls connector data for http (auto)")
        }
    }
}
