use super::{DatagramBridgeInput, DatagramToProxyBridge};
use crate::DatagramSocket;
use crate::proxy::{DatagramForwardService, DatagramRecovery, Peer};
use rama_core::{
    Service,
    error::{BoxError, ErrorContext as _},
    io::BridgeIo,
};
use rama_net::client::{ConnectRequest, ConnectorService};
use std::{future::Future, pin::Pin};

/// An opt-in forwarding bridge which prepares replacement egress sockets through the same
/// connector and original request. Network observations never select a new destination.
#[derive(Debug, Clone)]
pub struct DatagramForwardRecovery<C> {
    bridge: DatagramToProxyBridge<DatagramForwardService, C>,
    recovery: DatagramRecovery,
}

impl<C> DatagramToProxyBridge<DatagramForwardService, C> {
    /// Opt this forwarding bridge into recovery through its original connector and request.
    pub fn with_egress_recovery(self, recovery: DatagramRecovery) -> DatagramForwardRecovery<C> {
        DatagramForwardRecovery {
            bridge: self,
            recovery,
        }
    }
}

impl<Input, C> Service<Input> for DatagramForwardRecovery<C>
where
    Input: DatagramBridgeInput,
    Input::Bridged<C::Connection>: Into<BridgeIo<Input::Ingress, C::Connection>>,
    C: ConnectorService<ConnectRequest, Connection: DatagramSocket> + Clone,
{
    type Output = ();
    type Error = BoxError;

    fn serve(&self, input: Input) -> impl Future<Output = Result<(), BoxError>> + Send {
        // Erase the association future so closure-based connector projections remain Send
        // on supported compilers; allocate once per association, never per packet.
        let future: Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + '_>> =
            Box::pin(async move {
                // Subscribe before connecting so a routing change during initial preparation is retained.
                let changes = self.recovery.signal.subscribe();
                let request = self.bridge.connect_request(input.ingress())?;
                let mut initial = request.clone();
                initial.extensions = request.extensions.fork();
                let connected = self
                    .bridge
                    .connector
                    .connect(initial)
                    .await
                    .into_box_error()?;
                let factory = ReplacementConnector {
                    connector: self.bridge.connector.clone(),
                    request,
                };
                let BridgeIo(ingress, egress) = input.bridge(connected.conn).into();
                self.bridge
                    .inner
                    .forward_recovering(
                        BridgeIo(Peer::connected(ingress)?, Peer::connected(egress)?),
                        &self.recovery,
                        factory,
                        changes,
                    )
                    .await
            });
        future
    }
}

struct ReplacementConnector<C> {
    connector: C,
    request: ConnectRequest,
}

impl<C> Service<()> for ReplacementConnector<C>
where
    C: ConnectorService<ConnectRequest, Connection: DatagramSocket>,
{
    type Output = C::Connection;
    type Error = BoxError;

    async fn serve(&self, (): ()) -> Result<Self::Output, BoxError> {
        let mut request = self.request.clone();
        request.extensions = self.request.extensions.fork();
        Ok(self.connector.connect(request).await.into_box_error()?.conn)
    }
}
