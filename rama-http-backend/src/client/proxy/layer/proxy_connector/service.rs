use crate::client::proxy::layer::HttpProxyError;

use super::InnerHttpProxyConnector;
use rama_core::{
    Context, Service,
    combinators::Either,
    error::{BoxError, ErrorExt, OpaqueError},
};
use rama_http_core::upgrade;
use rama_http_types::headers::ProxyAuthorization;
use rama_net::{
    address::ProxyAddress,
    client::{ConnectorService, EstablishedClientConnection},
    stream::Stream,
    transport::TryRefIntoTransportContext,
    user::ProxyCredential,
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

#[cfg(feature = "tls")]
use rama_net::tls::TlsTunnel;

/// A connector which can be used to establish a connection over an HTTP Proxy.
///
/// This behaviour is optional and only triggered in case there
/// is a [`ProxyAddress`] found in the [`Context`].
pub struct HttpProxyConnector<S> {
    inner: S,
    required: bool,
}

impl<S: fmt::Debug> fmt::Debug for HttpProxyConnector<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxyConnector")
            .field("inner", &self.inner)
            .field("required", &self.required)
            .finish()
    }
}

impl<S: Clone> Clone for HttpProxyConnector<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            required: self.required,
        }
    }
}

impl<S> HttpProxyConnector<S> {
    /// Creates a new [`HttpProxyConnector`].
    pub(super) fn new(inner: S, required: bool) -> Self {
        Self { inner, required }
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will only connect via an http proxy in case the [`ProxyAddress`] is available
    /// in the [`Context`].
    pub fn optional(inner: S) -> Self {
        Self::new(inner, false)
    }

    /// Create a new [`HttpProxyConnector`]
    /// which will always connect via an http proxy, but fail in case the [`ProxyAddress`] is
    /// not available in the [`Context`].
    pub fn required(inner: S) -> Self {
        Self::new(inner, true)
    }

    define_inner_service_accessors!();
}

impl<S, State, Request> Service<State, Request> for HttpProxyConnector<S>
where
    S: ConnectorService<State, Request, Connection: Stream + Unpin, Error: Into<BoxError>>,
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
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

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("http proxy connector: get transport context")
            })?
            .clone();

        // in case the provider gave us a proxy info, we insert it into the context
        if let Some(address) = &address {
            ctx.insert(address.clone());

            #[cfg(feature = "tls")]
            if address
                .protocol
                .as_ref()
                .map(|p| p.is_secure())
                .unwrap_or_default()
            {
                tracing::trace!(
                    authority = %transport_ctx.authority,
                    "http proxy connector: preparing proxy connection for tls tunnel"
                );
                ctx.insert(TlsTunnel {
                    server_host: address.authority.host().clone(),
                });
            }
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
        let address = match address {
            Some(address) => address,
            None => {
                return if self.required {
                    Err("http proxy required but none is defined".into())
                } else {
                    tracing::trace!(
                        "http proxy connector: no proxy required or set: proceed with direct connection"
                    );
                    let EstablishedClientConnection {
                        ctx,
                        req,
                        conn,
                        addr,
                    } = established_conn;
                    return Ok(EstablishedClientConnection {
                        ctx,
                        req,
                        conn: Either::A(conn),
                        addr,
                    });
                };
            }
        };
        // and do the handshake otherwise...

        let EstablishedClientConnection {
            ctx,
            req,
            conn,
            addr,
        } = established_conn;

        tracing::trace!(
            authority = %transport_ctx.authority,
            proxy_addr = %addr,
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
                addr,
            });
        }

        let mut connector = InnerHttpProxyConnector::new(transport_ctx.authority.clone())?;

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

        let conn = connector
            .handshake(conn)
            .await
            .map_err(|err| OpaqueError::from_std(err).context("http proxy handshake"))?;

        tracing::trace!(
            authority = %transport_ctx.authority,
            proxy_addr = %addr,
            "http proxy connector: connected to proxy: ready secure request",
        );
        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: Either::B(conn),
            addr,
        })
    }
}
