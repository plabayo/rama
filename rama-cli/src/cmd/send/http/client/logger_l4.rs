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

#[derive(Debug)]
pub(super) struct TransportConnInfoLogger<C>(pub(super) C);

impl<R, C> Service<R> for TransportConnInfoLogger<C>
where
    R: Send + ExtensionsRef + 'static,
    C: ConnectorService<R, Connection: Socket>,
{
    type Error = C::Error;
    type Response = EstablishedClientConnection<C::Connection, R>;

    async fn serve(&self, request: R) -> Result<Self::Response, Self::Error> {
        let ec = self.0.connect(request).await?;
        if ec.req.extensions().contains::<VerboseLogs>() {
            match ec.conn.peer_addr() {
                Ok(addr) => match addr.ip() {
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
