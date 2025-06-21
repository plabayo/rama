use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    telemetry::tracing,
};
use rama_dns::{DnsResolver, GlobalDnsResolver};
use rama_net::{
    address::ProxyAddress,
    client::EstablishedClientConnection,
    stream::{ClientSocketInfo, SocketInfo},
    transport::{TransportProtocol, TryRefIntoTransportContext},
};

use crate::TcpStream;
use crate::client::connect::TcpStreamConnector;

use super::{CreatedTcpStreamConnector, TcpStreamConnectorCloneFactory, TcpStreamConnectorFactory};

/// A connector which can be used to establish a TCP connection to a server.
pub struct TcpConnector<Dns = GlobalDnsResolver, ConnectorFactory = ()> {
    dns: Dns,
    connector_factory: ConnectorFactory,
}

impl<Dns: std::fmt::Debug, ConnectorFactory: std::fmt::Debug> std::fmt::Debug
    for TcpConnector<Dns, ConnectorFactory>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnector")
            .field("dns", &self.dns)
            .field("connector_factory", &self.connector_factory)
            .finish()
    }
}

impl<Dns: Clone, ConnectorFactory: Clone> Clone for TcpConnector<Dns, ConnectorFactory> {
    fn clone(&self) -> Self {
        Self {
            dns: self.dns.clone(),
            connector_factory: self.connector_factory.clone(),
        }
    }
}

impl<Dns, Connector> TcpConnector<Dns, Connector> {}

impl TcpConnector {
    /// Create a new [`TcpConnector`], which is used to establish a connection to a server.
    ///
    /// You can use middleware around the [`TcpConnector`]
    /// or add connection pools, retry logic and more.
    pub fn new() -> Self {
        Self {
            dns: GlobalDnsResolver::new(),
            connector_factory: (),
        }
    }
}

impl<Dns, ConnectorFactory> TcpConnector<Dns, ConnectorFactory> {
    /// Consume `self` to attach the given `dns` (a [`DnsResolver`]) as a new [`TcpConnector`].
    pub fn with_dns<OtherDns>(self, dns: OtherDns) -> TcpConnector<OtherDns, ConnectorFactory>
    where
        OtherDns: DnsResolver + Clone,
    {
        TcpConnector {
            dns,
            connector_factory: self.connector_factory,
        }
    }
}

impl<Dns> TcpConnector<Dns, ()> {
    /// Consume `self` to attach the given `Connector` (a [`TcpStreamConnector`]) as a new [`TcpConnector`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> TcpConnector<Dns, TcpStreamConnectorCloneFactory<Connector>>
where {
        TcpConnector {
            dns: self.dns,
            connector_factory: TcpStreamConnectorCloneFactory(connector),
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`TcpStreamConnectorFactory`]) as a new [`TcpConnector`].
    pub fn with_connector_factory<Factory>(self, factory: Factory) -> TcpConnector<Dns, Factory>
where {
        TcpConnector {
            dns: self.dns,
            connector_factory: factory,
        }
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl<State, Request, Dns, ConnectorFactory> Service<State, Request>
    for TcpConnector<Dns, ConnectorFactory>
where
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
    Dns: DnsResolver + Clone,
    ConnectorFactory: TcpStreamConnectorFactory<
            State,
            Connector: TcpStreamConnector<Error: Into<BoxError> + Send + 'static>,
            Error: Into<BoxError> + Send + 'static,
        > + Clone,
{
    type Response = EstablishedClientConnection<TcpStream, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let CreatedTcpStreamConnector { mut ctx, connector } = self
            .connector_factory
            .make_connector(ctx)
            .await
            .map_err(Into::into)?;

        if let Some(proxy) = ctx.get::<ProxyAddress>() {
            let (conn, addr) = crate::client::tcp_connect(
                &ctx,
                proxy.authority.clone(),
                self.dns.clone(),
                connector,
            )
            .await
            .context("tcp connector: conncept to proxy")?;

            ctx.insert(ClientSocketInfo(SocketInfo::new(
                conn.local_addr()
                    .inspect_err(|err| {
                        tracing::debug!(
                            "failed to receive local addr of established connection to proxy: {err:?}"
                        )
                    })
                    .ok(),
                addr,
            )));

            return Ok(EstablishedClientConnection { ctx, req, conn });
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
        let (conn, addr) = crate::client::tcp_connect(&ctx, authority, self.dns.clone(), connector)
            .await
            .context("tcp connector: connect to server")?;

        ctx.insert(ClientSocketInfo(SocketInfo::new(
            conn.local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            addr,
        )));

        Ok(EstablishedClientConnection { ctx, req, conn })
    }
}
