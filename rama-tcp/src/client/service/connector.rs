use rama_core::{
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    Context, Service,
};
use rama_dns::{DnsResolver, HickoryDns};
use rama_net::{
    address::ProxyAddress,
    client::EstablishedClientConnection,
    transport::{TransportProtocol, TryRefIntoTransportContext},
};
use tokio::net::TcpStream;

use crate::client::connect::TcpStreamConnector;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// A connector which can be used to establish a TCP connection to a server.
pub struct TcpConnector<Dns = HickoryDns, Connector = ()> {
    dns: Dns,
    connector: Connector,
}

impl<Dns, Connector> TcpConnector<Dns, Connector> {}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    pub fn new() -> Self {
        Self {
            dns: HickoryDns::default(),
            connector: (),
        }
    }
}

impl<Dns, Connector> TcpConnector<Dns, Connector> {
    /// Consume `self` to attach the given `dns` (a [`DnsResolver`]) as a new [`TcpConnector`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> TcpConnector<OtherDns, Connector>
    where
        OtherDns: DnsResolver<Error: Into<BoxError>> + Clone,
    {
        TcpConnector {
            dns,
            connector: self.connector,
        }
    }
}

impl<Dns> TcpConnector<Dns, ()> {
    /// Consume `self` to attach the given `Connector` (a [`TcpStreamConnector`]) as a new [`TcpConnector`].
    pub fn with_connector<Connector>(self, connector: Connector) -> TcpConnector<Dns, Connector>
    where
        Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
    {
        TcpConnector {
            dns: self.dns,
            connector,
        }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Request, Dns, Connector> Service<State, Request> for TcpConnector<Dns, Connector>
where
    State: Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
    Dns: DnsResolver<Error: Into<BoxError>> + Clone,
    Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static> + Clone,
{
    type Response = EstablishedClientConnection<TcpStream, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proxy) = ctx.get::<ProxyAddress>() {
            let (conn, addr) = crate::client::tcp_connect(
                &ctx,
                proxy.authority.clone(),
                true,
                self.dns.clone(),
                self.connector.clone(),
            )
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
        let (conn, addr) = crate::client::tcp_connect(
            &ctx,
            authority,
            false,
            self.dns.clone(),
            self.connector.clone(),
        )
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
