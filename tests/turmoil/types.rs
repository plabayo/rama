use super::stream::TcpStream;
use rama::{Service, error::BoxError, extensions::ExtensionsMut, telemetry::tracing};
use rama_net::{
    client::EstablishedClientConnection,
    stream::{ClientSocketInfo, SocketInfo},
    transport::TryRefIntoTransportContext,
};

/// A newtype for managing a `[turmoil::net::TcpStream]` 'connector' implementing `[rama::Service]`
#[derive(Debug, Clone)]
pub struct TurmoilTcpConnector;

impl<Request> Service<Request> for TurmoilTcpConnector
where
    Request: TryRefIntoTransportContext + Send + 'static,
    Request::Error: Into<BoxError> + Send + Sync + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, Request>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let transport_context = req.try_ref_into_transport_ctx().map_err(Into::into)?;
        let authority = &transport_context.authority;
        let host = authority.host();
        let port = authority.port();
        let address = format!("{host}:{port}");

        // TODO: proxy support

        let conn = turmoil::net::TcpStream::connect(address)
            .await
            .map_err(BoxError::from)?;

        let addr = conn.local_addr()?;
        let info = ClientSocketInfo(SocketInfo::new(
            conn.local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            addr,
        ));

        let mut conn = TcpStream::new(conn);
        conn.extensions_mut().insert(info);

        Ok(EstablishedClientConnection {
            req,
            conn, // Raw turmoil::net::TcpStream
        })
    }
}
