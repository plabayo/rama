use crate::client::proxy::layer::HttpProxyError;

use super::InnerHttpProxyConnector;
use rama_core::{
    Context, Service,
    combinators::Either,
    error::{BoxError, ErrorExt, OpaqueError},
    telemetry::tracing,
};
use rama_http::{HeaderMap, io::upgrade};
use rama_http_headers::ProxyAuthorization;
use rama_http_types::Version;
use rama_net::{
    address::ProxyAddress,
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
    transport::TryRefIntoTransportContext,
    user::ProxyCredential,
};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, ops, sync::Arc};

#[cfg(feature = "tls")]
use rama_net::tls::TlsTunnel;

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a [`ProxyAddress`] found in the [`Context`].
pub struct HttpProxyConnector<S> {
    inner: S,
    required: bool,
    version: Option<Version>,
}

impl<S: fmt::Debug> fmt::Debug for HttpProxyConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxyConnector")
            .field("inner", &self.inner)
            .field("required", &self.required)
            .field("version", &self.version)
            .finish()
    }
}

impl<S: Clone> Clone for HttpProxyConnector<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            required: self.required,
            version: self.version,
        }
    }
}

impl<S> HttpProxyConnector<S> {
    /// Creates a new [`HttpProxyConnector`].
    ///
    /// Protocol version is set to HTTP/1.1 by default.
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self {
            inner,
            required,
            version: Some(Version::HTTP_11),
        }
    }

    /// Set the HTTP version to use for the CONNECT request.
    ///
    /// By default this is set to HTTP/1.1.
    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the HTTP version to use for the CONNECT request.
    pub fn set_version(&mut self, version: Version) -> &mut Self {
        self.version = Some(version);
        self
    }

    /// Set the HTTP version to auto detect for the CONNECT request.
    #[must_use]
    pub fn with_auto_version(mut self) -> Self {
        self.version = None;
        self
    }

    /// Set the HTTP version to auto detect for the CONNECT request.
    pub fn set_auto_version(&mut self) -> &mut Self {
        self.version = None;
        self
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    #[must_use]
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    #[must_use]
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

impl<S, State, Request> Service<State, Request> for HttpProxyConnector<S>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    Request:
        TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + 'static> + Send + 'static,
{
    type Response =
        EstablishedClientConnection<Either<S::Connection, upgrade::Upgraded>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let address = ctx.get::<ProxyAddress>().cloned();
        if !address
            .as_ref()
            .and_then(|addr| addr.protocol.as_ref())
            .map(|p| p.is_http())
            .unwrap_or(true)
        {
            return Err(OpaqueError::from_display(
                "http proxy connector can only serve http protocol",
            )
            .into_boxed());
        }

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("http proxy connector: get transport context")
            })?
            .clone();

        #[cfg(feature = "tls")]
        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(address) = &address
            && address
                .protocol
                .as_ref()
                .map(|p| p.is_secure())
                .unwrap_or_default()
        {
            tracing::trace!(
                server.address = %transport_ctx.authority.host(),
                server.port = %transport_ctx.authority.port(),
                "http proxy connector: preparing proxy connection for tls tunnel",
            );
            ctx.insert(TlsTunnel {
                server_host: address.authority.host().clone(),
            });
        }

        let established_conn =
            self.inner
                .connect(ctx, req)
                .await
                .map_err(|err| match address.as_ref() {
                    Some(address) => OpaqueError::from_std(HttpProxyError::Transport(
                        OpaqueError::from_boxed(err.into())
                            .context(format!(
                                "establish connection to proxy {} (protocol: {:?})",
                                address.authority, address.protocol,
                            ))
                            .into_boxed(),
                    )),
                    None => {
                        OpaqueError::from_boxed(err.into()).context("establish connection target")
                    }
                })?;

        // return early in case we did not use a proxy
        let Some(address) = address else {
            return if self.required {
                Err("http proxy required but none is defined".into())
            } else {
                tracing::trace!(
                    "http proxy connector: no proxy required or set: proceed with direct connection"
                );
                let EstablishedClientConnection { ctx, req, conn } = established_conn;
                return Ok(EstablishedClientConnection {
                    ctx,
                    req,
                    conn: Either::A(conn),
                });
            };
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection { mut ctx, req, conn } = established_conn;

        tracing::trace!(
            server.address = %transport_ctx.authority.host(),
            server.port = %transport_ctx.authority.port(),
            "http proxy connector: connected to proxy",
        );

        if !transport_ctx
            .app_protocol
            .map(|p| p.is_secure())
            // TODO: re-evaluate this fallback at some point... seems pretty flawed to me
            .unwrap_or_else(|| transport_ctx.authority.port() == 443)
        {
            // unless the scheme is not secure, in such a case no handshake is required...
            // we do however need to add authorization headers if credentials are present
            // => for this the user has to use another middleware as we do not have access to that here
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: Either::A(conn),
            });
        }

        let mut connector = InnerHttpProxyConnector::new(&transport_ctx.authority)?;
        match self.version {
            Some(version) => connector.set_version(version),
            None => connector.set_auto_version(),
        };

        if let Some(credential) = address.credential.clone() {
            match credential {
                ProxyCredential::Basic(basic) => {
                    connector.with_typed_header(ProxyAuthorization(basic));
                }
                ProxyCredential::Bearer(bearer) => {
                    connector.with_typed_header(ProxyAuthorization(bearer));
                }
            }
        }

        let (headers, conn) = connector
            .handshake(conn)
            .await
            .map_err(|err| OpaqueError::from_std(err).context("http proxy handshake"))?;

        tracing::trace!("inserting HttpProxyHeaders in context");
        ctx.insert(HttpProxyConnectResponseHeaders::new(headers));

        tracing::trace!(
            server.address = %transport_ctx.authority.host(),
            server.port = %transport_ctx.authority.port(),
            "http proxy connector: connected to proxy: ready secure request",
        );
        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: Either::B(conn),
        })
    }
}

#[derive(Clone, Debug)]
/// Extension added to the [`Context`] by [`HttpProxyConnector`] to record the
/// headers from a successful CONNECT response.
///
/// This can be useful, for example, when the upstream proxy provider exposes
/// information in these headers about the connection to the final destination.
pub struct HttpProxyConnectResponseHeaders(Arc<HeaderMap>);

impl HttpProxyConnectResponseHeaders {
    fn new(headers: HeaderMap) -> Self {
        Self(Arc::new(headers))
    }
}

impl AsRef<HeaderMap> for HttpProxyConnectResponseHeaders {
    fn as_ref(&self) -> &HeaderMap {
        &self.0
    }
}

impl ops::Deref for HttpProxyConnectResponseHeaders {
    type Target = HeaderMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
