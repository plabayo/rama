use crate::{
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    net::{address::ProxyAddress, client::EstablishedClientConnection},
    stream::transport::{TransportProtocol, TryRefIntoTransportContext},
    tcp, Context, Service,
};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A connector which can be used to establish a TCP connection to a server.
pub struct TcpConnector;

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    pub const fn new() -> Self {
        TcpConnector
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Request> Service<State, Request> for TcpConnector
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
            let (conn, addr) = tcp::client::connect_trusted(&ctx, proxy.authority.clone())
                .await
                .context("tcp connector: conncept to proxy")?;
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn,
                addr,
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
        let (conn, addr) = tcp::client::connect(&ctx, authority)
            .await
            .context("tcp connector: connect to server")?;

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn,
            addr,
        })
    }
}
