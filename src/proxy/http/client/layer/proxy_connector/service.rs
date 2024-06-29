use super::HttpProxyConnector;
use crate::{
    error::{BoxError, ErrorExt, OpaqueError},
    http::{
        client::{ClientConnection, EstablishedClientConnection},
        headers::{HeaderMapExt, ProxyAuthorization},
        Request,
    },
    net::{
        address::{Authority, Host, ProxyAddress},
        stream::Stream,
        user::ProxyCredential,
        Protocol,
    },
    service::{Context, Service},
    tls::HttpsTunnel,
};
use std::fmt;

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a [`ProxyAddress`] found in the [`Context`].
pub struct HttpProxyConnectorService<S> {
    inner: S,
    required: bool,
}

impl<S: fmt::Debug> fmt::Debug for HttpProxyConnectorService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxyConnectorService")
            .field("inner", &self.inner)
            .field("required", &self.required)
            .finish()
    }
}

impl<S: Clone> Clone for HttpProxyConnectorService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            required: self.required,
        }
    }
}

impl<S> HttpProxyConnectorService<S> {
    /// Creates a new [`HttpProxyConnectorService`].
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self { inner, required }
    }

    /// Create a new [`HttpProxyConnectorService`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Create a new [`HttpProxyConnectorService`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

impl<S, State, Body, T> Service<State, Request<Body>> for HttpProxyConnectorService<S>
where
    S: Service<State, Request<Body>, Response = EstablishedClientConnection<T, Body, State>>,
    T: Stream + Unpin,
    S::Error: Into<BoxError>,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = EstablishedClientConnection<T, Body, State>;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let address = ctx.get::<ProxyAddress>().cloned();

        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(address) = &address {
            ctx.insert(address.clone());
            if address.protocol().is_secure() {
                tracing::trace!(uri = %req.uri(), "http proxy connector: preparing proxy connection for tls tunnel");
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
                return if self.required {
                    Err("http proxy required but none is defined".into())
                } else {
                    tracing::trace!("http proxy connector: no proxy required or set: proceed with direct connection");
                    Ok(established_conn)
                };
            }
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection { ctx, mut req, conn } = established_conn;

        let (addr, stream) = conn.into_parts();

        tracing::trace!(uri = %req.uri(), proxy_addr = %addr, "http proxy connector: connected to proxy");

        let uri = req.uri();
        let protocol: Protocol = uri.scheme().map(Into::into).ok_or_else(|| {
            OpaqueError::from_display("http proxy connect failed: request uri contains no scheme")
        })?;
        let host = uri
            .host()
            .and_then(|h| Host::try_from(h).ok())
            .ok_or_else(|| {
                OpaqueError::from_display("http proxy connect failed: request uri contains no host")
            })?;
        let port = uri.port_u16().unwrap_or_else(|| protocol.default_port());
        let authority: Authority = (host, port).into();

        if !protocol.is_secure() {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            if let Some(credential) = address.credential().cloned() {
                match credential {
                    ProxyCredential::Basic(basic) => {
                        tracing::trace!(uri = %req.uri(), proxy_addr = %addr, "http proxy connector: inserted proxy Basic credentials into plain-text (http) request");
                        req.headers_mut().typed_insert(ProxyAuthorization(basic))
                    }
                    ProxyCredential::Bearer(bearer) => {
                        tracing::trace!(uri = %req.uri(), proxy_addr = %addr, "http proxy connector: inserted proxy Bearer credentials into plain-text (http) request");
                        req.headers_mut().typed_insert(ProxyAuthorization(bearer))
                    }
                }
            }
            tracing::trace!(uri = %req.uri(), proxy_addr = %addr, "http proxy connector: connected to proxy: ready for plain text request");
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(addr, stream),
            });
        }

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

        tracing::trace!(uri = %req.uri(), proxy_addr = %addr, "http proxy connector: connected to proxy: ready secure request");
        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: ClientConnection::new(addr, stream),
        })
    }
}
