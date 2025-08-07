use std::sync::Arc;

use crate::{
    Layer, Service,
    combinators::Either3,
    error::{BoxError, OpaqueError},
    http::client::proxy::layer::{HttpProxyConnector, HttpProxyConnectorLayer},
    net::{
        address::ProxyAddress,
        client::{ConnectorService, EstablishedClientConnection},
        stream::Stream,
        transport::TryRefIntoTransportContext,
    },
    proxy::socks5::{Socks5ProxyConnector, Socks5ProxyConnectorLayer},
};

/// Proxy connector which supports http(s) and socks5(h) proxy address
///
/// Connector will look at [`ProxyAddress`] to determine which proxy
/// connector to use if one is configured
pub struct ProxyConnector<S> {
    inner: S,
    socks: Socks5ProxyConnector<S>,
    http: HttpProxyConnector<S>,
    required: bool,
}

impl<S> ProxyConnector<S> {
    /// Creates a new [`ProxyConnector`].
    fn new(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
        required: bool,
    ) -> ProxyConnector<Arc<S>> {
        let inner = Arc::new(inner);
        ProxyConnector {
            socks: socks_proxy_layer.into_layer(inner.clone()),
            http: http_proxy_layer.into_layer(inner.clone()),
            inner,
            required,
        }
    }

    #[inline]
    /// Creates a new required [`ProxyConnector`].
    ///
    /// This connector will fail if no [`ProxyAddress`] is configured
    pub fn required(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> ProxyConnector<Arc<S>> {
        Self::new(inner, socks_proxy_layer, http_proxy_layer, true)
    }

    #[inline]
    /// Creates a new optional [`ProxyConnector`].
    ///
    /// This connector will forward to the inner connector if no [`ProxyAddress`] is configured
    pub fn optional(
        inner: S,
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> ProxyConnector<Arc<S>> {
        Self::new(inner, socks_proxy_layer, http_proxy_layer, false)
    }
}

impl<State, Request, S> Service<State, Request> for ProxyConnector<S>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    Request:
        TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + 'static> + Send + 'static,
{
    type Response = EstablishedClientConnection<
        Either3<
            S::Connection,
            <Socks5ProxyConnector<S> as ConnectorService<State, Request>>::Connection,
            <HttpProxyConnector<S> as ConnectorService<State, Request>>::Connection,
        >,
        State,
        Request,
    >;

    type Error = BoxError;

    async fn serve(
        &self,
        ctx: rama_core::Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let proxy = ctx
            .get::<ProxyAddress>()
            .and_then(|proxy| proxy.protocol.as_ref());

        match proxy {
            None => {
                if self.required {
                    return Err("proxy required but none is defined".into());
                }
                let EstablishedClientConnection { ctx, req, conn } =
                    self.inner.connect(ctx, req).await.map_err(Into::into)?;
                Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: Either3::A(conn),
                })
            }
            Some(proto) => {
                if proto.is_socks5() {
                    let EstablishedClientConnection { ctx, req, conn } =
                        self.socks.connect(ctx, req).await?;
                    Ok(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: Either3::B(conn),
                    })
                } else if proto.is_http() {
                    let EstablishedClientConnection { ctx, req, conn } =
                        self.http.connect(ctx, req).await?;
                    Ok(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: Either3::C(conn),
                    })
                } else {
                    Err(OpaqueError::from_display("diplay not").into())
                }
            }
        }
    }
}

/// Proxy connector layer which supports http(s) and socks5(h) proxy address
///
/// Connector will look at [`ProxyAddress`] to determine which proxy
/// connector to use if one is configured
pub struct ProxyConnectorLayer {
    socks_layer: Socks5ProxyConnectorLayer,
    http_layer: HttpProxyConnectorLayer,
    required: bool,
}

impl ProxyConnectorLayer {
    #[must_use]
    /// Creates a new required [`ProxyConnectorLayer`].
    ///
    /// This connector will fail if no [`ProxyAddress`] is configured
    pub fn required(
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self {
            socks_layer: socks_proxy_layer,
            http_layer: http_proxy_layer,
            required: true,
        }
    }

    #[must_use]
    /// Creates a new optional [`ProxyConnectorLayer`].
    ///
    /// This connector will forward to the inner connector if no [`ProxyAddress`] is configured
    pub fn optional(
        socks_proxy_layer: Socks5ProxyConnectorLayer,
        http_proxy_layer: HttpProxyConnectorLayer,
    ) -> Self {
        Self {
            socks_layer: socks_proxy_layer,
            http_layer: http_proxy_layer,
            required: false,
        }
    }
}

impl<S> Layer<S> for ProxyConnectorLayer {
    type Service = ProxyConnector<Arc<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyConnector::new(
            inner,
            self.socks_layer.clone(),
            self.http_layer.clone(),
            self.required,
        )
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyConnector::new(inner, self.socks_layer, self.http_layer, self.required)
    }
}
