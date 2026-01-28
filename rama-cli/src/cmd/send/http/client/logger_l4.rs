use rama::{
    Service,
    extensions::ExtensionsRef,
    net::{
        client::{ConnectorService, EstablishedClientConnection},
        stream::Socket,
    },
};

use std::net::IpAddr;

use super::VerboseLogs;

#[derive(Debug, Clone)]
pub(super) struct TransportConnInfoLogger<C>(pub(super) C);

impl<Input, C> Service<Input> for TransportConnInfoLogger<C>
where
    Input: Send + ExtensionsRef + 'static,
    C: ConnectorService<Input, Connection: Socket>,
{
    type Error = C::Error;
    type Output = EstablishedClientConnection<C::Connection, Input>;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let ec = self.0.connect(input).await?;
        if ec.input.extensions().contains::<VerboseLogs>() {
            match ec.conn.peer_addr() {
                Ok(addr) => match addr.ip_addr {
                    IpAddr::V4(addr) => {
                        eprintln!("* Connection established to peer with IPv4: {addr}")
                    }
                    IpAddr::V6(addr) => {
                        eprintln!("* Connection established to peer with IPv6: {addr}")
                    }
                },
                Err(err) => {
                    eprintln!("* Connection established to peer on unknown addr (error: {err})")
                }
            }
        }
        Ok(ec)
    }
}
