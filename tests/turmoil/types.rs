use super::stream::TcpStream;
use rama::{Service, error::BoxError, extensions::ExtensionsRef, telemetry::tracing};
use rama::{
    error::ErrorContext as _,
    net::{TransportAddressInputExt, client::EstablishedClientConnection, stream::SocketInfo},
};

/// A newtype for managing a `[turmoil::net::TcpStream]` 'connector' implementing `[rama::Service]`
#[derive(Debug, Clone)]
pub struct TurmoilTcpConnector;

impl<Input> Service<Input> for TurmoilTcpConnector
where
    Input: TransportAddressInputExt + Send + 'static,
{
    type Output = EstablishedClientConnection<TcpStream, Input>;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let address = input
            .host_with_port()
            .context("convert to host with port")?
            .to_string();

        // TODO: proxy support

        let conn = turmoil::net::TcpStream::connect(address)
            .await
            .map_err(BoxError::from)?;

        let addr = conn.local_addr()?;
        let info = SocketInfo::new(
            conn.local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok()
                .map(Into::into),
            addr.into(),
        );

        let conn = TcpStream::new(conn);
        conn.extensions().insert(info);

        Ok(EstablishedClientConnection {
            input,
            conn, // Raw turmoil::net::TcpStream
        })
    }
}
