use crate::error::{BoxError, ErrorContext, ErrorExt, OpaqueError};
use crate::http::client::{ClientConnection, EstablishedClientConnection};
use crate::http::headers::HeaderMapExt;
use crate::http::headers::ProxyAuthorization;
use crate::http::{Request, RequestContext};
use crate::net::address::ProxyAddress;
use crate::net::stream::Stream;
use crate::net::user::ProxyCredential;
use crate::service::{Context, Layer, Service};
use crate::tls::HttpsTunnel;
use std::fmt;
use std::future::Future;

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

impl HttpProxyConnectorLayer<ProxyAddress> {
    /// Creates a new [`HttpProxyConnectorLayer`],
    /// using the hardcoded [`ProxyAddress`].
    pub fn hardcoded(info: ProxyAddress) -> Self {
        Self { provider: info }
    }
}

impl HttpProxyConnectorLayer<Option<ProxyAddress>> {
    /// Creates a new [`HttpProxyConnectorLayer`],
    /// using the hardcoded [`ProxyAddress`] if defined, None otherwise.
    pub fn maybe_hardcoded(info: Option<ProxyAddress>) -> Self {
        Self { provider: info }
    }

    /// Try to create a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection over the environment variable `PROXY`.
    pub fn try_from_env_default() -> Result<Self, OpaqueError> {
        Self::try_from_env("PROXY")
    }

    /// Try to create a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(key: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let env_result = std::env::var(key.as_ref()).ok();
        let env_result_mapped = env_result.as_ref().and_then(|v| {
            let v = v.trim();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        });

        let provider = match env_result_mapped {
            Some(value) => Some(value.try_into().context("parse std env proxy info")?),
            None => None,
        };

        Ok(Self { provider })
    }
}

impl HttpProxyConnectorLayer<private::FromContext> {
    /// Creates a new [`HttpProxyConnectorLayer`] which will establish
    /// a proxy connection in case the context contains a [`ProxyAddress`].
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

    define_inner_service_accessors!();
}

impl<S> HttpProxyConnectorService<S, ProxyAddress> {
    /// Creates a new [`HttpProxyConnectorService`] which will establish
    /// a proxied connection over the given [`ProxyAddress`].
    pub fn hardcoded(info: ProxyAddress, inner: S) -> Self {
        Self::new(info, inner)
    }

    /// Try to create a new [`HttpProxyConnectorService`] which will establish
    /// a proxy connection over the environment variable `PROXY`.
    pub fn try_from_env_default(inner: S) -> Result<Self, OpaqueError> {
        Self::try_from_env("PROXY", inner)
    }

    /// Try to create a new [`HttpProxyConnectorService`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(key: impl AsRef<str>, inner: S) -> Result<Self, OpaqueError> {
        let value = std::env::var(key.as_ref()).context("retrieve proxy info from std env")?;
        let info = value.try_into().context("parse std env proxy info")?;
        Ok(Self {
            provider: info,
            inner,
        })
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
        let private::HttpProxyOutput { address, mut ctx } =
            self.provider.info(ctx).await.map_err(|err| {
                OpaqueError::from_boxed(err.into()).context("fetch proxy info from provider")
            })?;

        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(address) = address.as_ref() {
            ctx.insert(address.clone());
            if address.protocol().secure() {
                ctx.insert(HttpsTunnel {
                    server_name: address.authority().host().to_string(),
                });
            }
        }

        let established_conn =
            self.inner
                .serve(ctx, req)
                .await
                .map_err(|err| match address.as_ref() {
                    Some(address) => OpaqueError::from_boxed(err.into())
                        .context(format!("establish connection to proxy {}", address)),
                    None => {
                        OpaqueError::from_boxed(err.into()).context("establish connection target")
                    }
                })?;

        // return early in case we did not use a proxy
        let address = match address {
            Some(address) => address,
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

        let request_context: &RequestContext = ctx.get_or_insert_from(&req);

        if !request_context.protocol.secure() {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            if let Some(credential) = address.credential().cloned() {
                match credential {
                    ProxyCredential::Basic(basic) => {
                        req.headers_mut().typed_insert(ProxyAuthorization(basic))
                    }
                    ProxyCredential::Bearer(bearer) => {
                        req.headers_mut().typed_insert(ProxyAuthorization(bearer))
                    }
                }
            }
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(addr, stream),
            });
        }

        let authority = match request_context.authority.clone() {
            Some(authority) => authority,
            None => {
                return Err("missing http authority".into());
            }
        };

        let mut connector = HttpProxyConnector::new(authority);
        if let Some(credential) = address.credential().cloned() {
            match credential {
                ProxyCredential::Basic(basic) => {
                    connector.with_typed_header(ProxyAuthorization(basic));
                }
                ProxyCredential::Bearer(bearer) => {
                    connector.with_typed_header(ProxyAuthorization(bearer));
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
        pub address: Option<ProxyAddress>,
        pub ctx: Context<S>,
    }

    #[derive(Debug, Clone)]
    pub struct FromContext;

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

    impl<S, T> Sealed<S> for Option<T>
    where
        T: Sealed<S>,
        S: Send + Sync + 'static,
    {
        type Error = T::Error;

        async fn info(&self, ctx: Context<S>) -> Result<HttpProxyOutput<S>, Self::Error> {
            match self {
                Some(s) => s.info(ctx).await,
                None => Ok(HttpProxyOutput { address: None, ctx }),
            }
        }
    }

    impl<S> Sealed<S> for ProxyAddress
    where
        S: Send + Sync + 'static,
    {
        type Error = Infallible;

        async fn info(&self, ctx: Context<S>) -> Result<HttpProxyOutput<S>, Self::Error> {
            Ok(HttpProxyOutput {
                address: Some(self.clone()),
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
            let address = ctx.get::<ProxyAddress>().cloned();
            Ok(HttpProxyOutput { address, ctx })
        }
    }
}
