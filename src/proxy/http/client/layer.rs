use crate::error::{BoxError, ErrorExt, OpaqueError};
use crate::http::client::{ClientConnection, EstablishedClientConnection};
use crate::http::headers::HeaderMapExt;
use crate::http::headers::{Authorization, ProxyAuthorization};
use crate::http::Uri;
use crate::http::{Request, RequestContext};
use crate::proxy::{ProxyCredentials, ProxySocketAddr};
use crate::service::{Context, Layer, Service};
use crate::stream::Stream;
use crate::tls::HttpsTunnel;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;

use super::HttpProxyConnector;

// TODO: rework provider
// - make it perhaps public?!
// - allow providers to be stacked so they can be combined
//   Logic would be:
//   - on first error: return err
//   - if returned None, try next
//   - first that return Ok(Some(..)) gets returned

/// A [`Layer`] which wraps the given service with a [`HttpProxyConnectorService`].
///
/// See [`HttpProxyConnectorService`] for more information.
pub struct HttpProxyConnectorLayer<P> {
    provider: P,
}

impl<P: std::fmt::Debug> std::fmt::Debug for HttpProxyConnectorLayer<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProxyConnectorLayer")
            .field("provider", &self.provider)
            .finish()
    }
}

impl<P: Clone> Clone for HttpProxyConnectorLayer<P> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
        }
    }
}

#[derive(Debug, Clone)]
/// Minimal information required to establish a connection over an HTTP Proxy.
///
/// TODO: remove this or rework this once we also support SOCKS5(h) Proxies
pub struct HttpProxyInfo {
    /// The proxy address to connect to.
    pub proxy: SocketAddr,
    /// Indicates if the proxy requires a Tls connection.
    /// TODO: what about custom configs?!
    pub secure: bool,
    /// The credentials to use for the proxy connection.
    pub credentials: Option<ProxyCredentials>,
}

impl FromStr for HttpProxyInfo {
    type Err = OpaqueError;

    // TODO: test this function...

    fn from_str(raw_uri: &str) -> Result<Self, Self::Err> {
        let uri: Uri = raw_uri.parse().map_err(|err| {
            OpaqueError::from_std(err)
                .with_context(|| format!("parse http proxy address '{}'", raw_uri))
        })?;

        let secure = match uri.scheme().map(|s| s.as_str()).unwrap_or("http") {
            "http" => false,
            "https" => true,
            _ => {
                return Err(OpaqueError::from_display(format!(
                    "only http proxies are supported: '{}'",
                    raw_uri
                )));
            }
        };

        // TODO: allow for dns address (proxy routers?);
        // see: https://github.com/plabayo/rama/issues/202
        let mut proxy = match uri.host().and_then(|host| host.parse::<SocketAddr>().ok()) {
            Some(proxy) => proxy,
            None => {
                return Err(OpaqueError::from_display(format!(
                    "invalid http proxy address's authority '{}'",
                    raw_uri
                )));
            }
        };
        if let Some(port) = uri.port_u16() {
            proxy.set_port(port);
        }

        // TODO: support credentials (this would probably mean we cannot pigy back on the Uri type for our logic here)

        Ok(Self {
            proxy,
            secure,
            credentials: None,
        })
    }
}

impl HttpProxyConnectorLayer<HttpProxyInfo> {
    /// Creates a new [`HttpProxyConnectorLayer`].
    pub fn hardcoded(info: HttpProxyInfo) -> Self {
        Self { provider: info }
    }
}

impl HttpProxyConnectorLayer<private::FromEnv> {
    /// Creates a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection over the environment variable `HTTP_PROXY`.
    pub fn from_env_default() -> Self {
        Self::from_env("HTTP_PROXY".to_owned())
    }

    /// Creates a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn from_env(key: String) -> Self {
        Self {
            provider: private::FromEnv(key),
        }
    }
}

impl HttpProxyConnectorLayer<private::FromContext> {
    /// Creates a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection in case the context contains a [`HttpProxyInfo`].
    pub fn from_context() -> Self {
        Self {
            provider: private::FromContext,
        }
    }
}

impl<S, P: Clone> Layer<S> for HttpProxyConnectorLayer<P> {
    type Service = HttpProxyConnectorService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpProxyConnectorService::new(self.provider.clone(), inner)
    }
}

/// A connector which can be used to establish a connection over an HTTP Proxy.
pub struct HttpProxyConnectorService<S, P> {
    inner: S,
    provider: P,
}

impl<S: fmt::Debug, P: fmt::Debug> fmt::Debug for HttpProxyConnectorService<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxyConnectorService")
            .field("inner", &self.inner)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<S: Clone, P: Clone> Clone for HttpProxyConnectorService<S, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            provider: self.provider.clone(),
        }
    }
}

impl<S, P> HttpProxyConnectorService<S, P> {
    /// Creates a new [`HttpProxyConnectorService`].
    fn new(provider: P, inner: S) -> Self {
        Self { inner, provider }
    }
}

impl<S> HttpProxyConnectorService<S, HttpProxyInfo> {
    /// Creates a new [`HttpProxyConnectorService`] which will establish
    /// a proxied connection over the given proxy info.
    pub fn hardcoded(info: HttpProxyInfo, inner: S) -> Self {
        Self::new(info, inner)
    }
}

impl<S> HttpProxyConnectorService<S, private::FromContext> {
    /// Creates a new [`HttpProxyConnectorService`] which will establish
    /// a proxied connection if the context contains the info,
    /// otherwise it will establish a direct connection.
    pub fn from_context(inner: S) -> Self {
        Self::new(private::FromContext, inner)
    }
}

impl<S> HttpProxyConnectorService<S, private::FromEnv> {
    /// create a new [`HttpProxyConnectorService`] from an environment variable.
    pub fn from_env(key: String, inner: S) -> Result<Self, OpaqueError> {
        Ok(Self::new(private::FromEnv(key), inner))
    }

    /// Creates a new [`HttpProxyConnectorService`] from the environment variable `HTTP_PROXY`.
    pub fn from_env_default(inner: S) -> Result<Self, OpaqueError> {
        Self::from_env("HTTP_PROXY".to_owned(), inner)
    }
}

impl<S, State, Body, T, P> Service<State, Request<Body>> for HttpProxyConnectorService<S, P>
where
    S: Service<State, Request<Body>, Response = EstablishedClientConnection<T, Body, State>>,
    T: Stream + Unpin,
    P: HttpProxyProvider<State>,
    P::Error: Into<BoxError>,
    S::Error: Into<BoxError>,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = EstablishedClientConnection<T, Body, State>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let private::HttpProxyOutput { info, mut ctx } =
            self.provider.info(ctx).await.map_err(|err| {
                OpaqueError::from_boxed(err.into()).context("fetch proxy info from provider")
            })?;

        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(info) = info.as_ref() {
            ctx.insert(ProxySocketAddr::new(info.proxy));
            if info.secure {
                ctx.insert(HttpsTunnel {
                    server_name: info.proxy.ip().to_string(),
                });
            }
        }

        let established_conn =
            self.inner.serve(ctx, req).await.map_err(|err| {
                OpaqueError::from_boxed(err.into()).context("establish inner stream")
            })?;

        // return early in case we did not use a proxy
        let info = match info {
            Some(info) => info,
            None => {
                return Ok(established_conn);
            }
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection {
            mut ctx,
            mut req,
            conn,
        } = established_conn;

        let (addr, stream) = conn.into_parts();

        let request_context = ctx.get_or_insert_with(|| RequestContext::new(&req));

        if !request_context.scheme.secure() {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            if let Some(credentials) = info.credentials.as_ref() {
                match credentials {
                    ProxyCredentials::Basic { username, password } => {
                        let c = Authorization::basic(
                            username.as_str(),
                            password.as_deref().unwrap_or_default(),
                        )
                        .0;
                        req.headers_mut().typed_insert(ProxyAuthorization(c));
                    }
                    ProxyCredentials::Bearer(token) => {
                        let c = Authorization::bearer(token.as_str())
                            .map_err(|err| {
                                OpaqueError::from_std(err).context("define http proxy bearer token")
                            })?
                            .0;
                        req.headers_mut().typed_insert(ProxyAuthorization(c));
                    }
                }
            }
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(addr, stream),
            });
        }

        let authority = match request_context.authority() {
            Some(authority) => authority,
            None => {
                return Err("missing http authority".into());
            }
        };

        let mut connector = HttpProxyConnector::new(authority);
        if let Some(credentials) = info.credentials.as_ref() {
            match credentials {
                ProxyCredentials::Basic { username, password } => {
                    let c = Authorization::basic(
                        username.as_str(),
                        password.as_deref().unwrap_or_default(),
                    )
                    .0;
                    connector.with_typed_header(ProxyAuthorization(c));
                }
                ProxyCredentials::Bearer(token) => {
                    let c = Authorization::bearer(token.as_str())
                        .map_err(|err| {
                            OpaqueError::from_std(err).context("define http proxy bearer token")
                        })?
                        .0;
                    connector.with_typed_header(ProxyAuthorization(c));
                }
            }
        }

        let stream = connector
            .handshake(stream)
            .await
            .map_err(|err| OpaqueError::from_std(err).context("http proxy handshake"))?;

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: ClientConnection::new(addr, stream),
        })
    }
}

pub trait HttpProxyProvider<S>: private::Sealed<S> {}

impl<S, T> HttpProxyProvider<S> for T where T: private::Sealed<S> {}

mod private {
    use std::{convert::Infallible, sync::Arc};

    use super::*;

    #[derive(Debug)]
    pub struct HttpProxyOutput<S> {
        pub info: Option<HttpProxyInfo>,
        pub ctx: Context<S>,
    }

    #[derive(Debug, Clone)]
    pub struct FromContext;

    #[derive(Debug, Clone)]
    pub struct FromEnv(pub(crate) String);

    pub trait Sealed<S>: Clone + Send + Sync + 'static {
        type Error;

        fn info(
            &self,
            ctx: Context<S>,
        ) -> impl Future<Output = Result<HttpProxyOutput<S>, Self::Error>> + Send + '_;
    }

    impl<S, T> Sealed<S> for Arc<T>
    where
        T: Sealed<S>,
    {
        type Error = T::Error;

        fn info(
            &self,
            ctx: Context<S>,
        ) -> impl Future<Output = Result<HttpProxyOutput<S>, Self::Error>> + Send + '_ {
            (**self).info(ctx)
        }
    }

    impl<S> Sealed<S> for HttpProxyInfo
    where
        S: Send + Sync + 'static,
    {
        type Error = Infallible;

        async fn info(&self, ctx: Context<S>) -> Result<HttpProxyOutput<S>, Self::Error> {
            Ok(HttpProxyOutput {
                info: Some(self.clone()),
                ctx,
            })
        }
    }

    impl<S> Sealed<S> for FromContext
    where
        S: Send + Sync + 'static,
    {
        type Error = Infallible;

        async fn info(&self, ctx: Context<S>) -> Result<HttpProxyOutput<S>, Self::Error> {
            let info = ctx.get::<HttpProxyInfo>().cloned();
            Ok(HttpProxyOutput { info, ctx })
        }
    }

    impl<S> Sealed<S> for FromEnv
    where
        S: Send + Sync + 'static,
    {
        type Error = Infallible;

        async fn info(&self, ctx: Context<S>) -> Result<HttpProxyOutput<S>, Self::Error> {
            match std::env::var(&self.0).ok() {
                Some(raw_uri) => {
                    let info = raw_uri.parse().ok();
                    Ok(HttpProxyOutput { info, ctx })
                }
                None => Ok(HttpProxyOutput { info: None, ctx }),
            }
        }
    }
}
