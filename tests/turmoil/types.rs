use rama::{Context, Service, error::BoxError, telemetry::tracing};
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
    type Response = EstablishedClientConnection<turmoil::net::TcpStream, Request>;
    type Error = BoxError;

    async fn serve(&self, ctx: Context, req: Request) -> Result<Self::Response, Self::Error> {
        let transport_context = req.try_ref_into_transport_ctx(&ctx).map_err(Into::into)?;
        let authority = &transport_context.authority;
        let host = authority.host();
        let port = authority.port();
        let address = format!("{host}:{port}");

        // TODO: proxy support

        let conn = turmoil::net::TcpStream::connect(address)
            .await
            .map_err(BoxError::from)?;

        let ctx = {
            let mut ctx = ctx;
            // TODO: better handling for this error?
            let addr = conn.local_addr()?;
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
            ctx
        };

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn, // Raw turmoil::net::TcpStream
        })
    }
}
