use rama::{error::BoxError, Service};
use rama_dns::DnsResolver;
use rama_net::{client::EstablishedClientConnection, transport::TryRefIntoTransportContext};
use rama_tcp::client::service::TcpStreamConnectorFactory;

use turmoil::net::TcpStream;

struct TurmoilTcpConnector;

impl<State, Request> Service<State, Request> for TurmoilTcpConnector
where
    State: Clone + Send + Sync + 'static,
    Request: TryRefIntoTransportContext<State> + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, State, Request>;
    type Error = BoxError;

    fn serve(
        &self,
        ctx: rama::Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        todo!()
    }
}
