use crate::{
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    net::{
        address::ProxyAddress,
        client::{ClientConnection, EstablishedClientConnection},
        transport::{TransportProtocol, TryRefIntoTransportContext},
    },
    service::{Context, Service},
    tcp,
};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A connector which can be used to establish a TCP connection to a server.
///
/// [`Request`]: crate::http::Request
/// [`Uri`]: crate::http::Uri
/// [`Context`]: crate::service::Context
pub struct HttpConnector;

impl HttpConnector {
    /// Create a new [`HttpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`HttpConnector`]
    /// or add connection pools, retry logic and more.
    pub fn new() -> Self {
        HttpConnector
    }
}

impl Default for HttpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Request> Service<State, Request> for HttpConnector
where
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proxy) = ctx.get::<ProxyAddress>() {
            let (stream, addr) = tcp::client::connect_trusted(&ctx, proxy.authority.clone())
                .await
                .context("tcp connector: conncept to proxy")?;
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(addr, stream),
            });
        }

        let transport_ctx = ctx
            .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("tcp connecter: compute transport context to get authority")
            })?;

        match transport_ctx.protocol {
            TransportProtocol::Tcp => (), // a-ok :)
            TransportProtocol::Udp => {
                // sanity check, shouldn't happen, but in case someone makes a weird stack, it can
                return Err(OpaqueError::from_display(
                    "Tcp Connector Service cannot establish a UDP transport",
                )
                .into());
            }
        }

        let authority = transport_ctx.authority.clone();
        let (stream, addr) = tcp::client::connect(&ctx, authority)
            .await
            .context("tcp connector: connect to server")?;

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: ClientConnection::new(addr, stream),
        })
    }
}
