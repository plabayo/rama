use rama::{
    Service,
    extensions::ExtensionsRef,
    http::client::HttpClientService,
    net::{
        client::{ConnectionError, ConnectorService, EstablishedClientConnection},
        stream::SocketInfo,
    },
    quic::QuicConnectionInfo,
};

use std::net::IpAddr;

use super::VerboseLogs;

#[derive(Debug, Clone)]
pub(super) struct TransportConnInfoLogger<C>(pub(super) C);

impl<Input, C, Body> Service<Input> for TransportConnInfoLogger<C>
where
    Input: Send + ExtensionsRef + 'static,
    Body: Send + 'static,
    C: ConnectorService<Input, Connection = HttpClientService<Body>>,
{
    type Error = ConnectionError;
    type Output = EstablishedClientConnection<C::Connection, Input>;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let ec = self.0.connect(input).await?;
        if ec.input.extensions().contains::<VerboseLogs>()
            && let Some(socket) = ec.conn.extensions().get_ref::<SocketInfo>()
        {
            let quic = ec.conn.extensions().get_ref::<QuicConnectionInfo>();
            let transport = if quic.is_some() { "QUIC/UDP" } else { "TCP" };
            match socket.peer_addr().ip_addr {
                IpAddr::V4(addr) => {
                    eprintln!("* Connection established over {transport} to peer with IPv4: {addr}")
                }
                IpAddr::V6(addr) => {
                    eprintln!("* Connection established over {transport} to peer with IPv6: {addr}")
                }
            }
            if let Some(quic) = quic {
                let version = quic.version;
                eprintln!("* QUIC version: {version} ({:#010x})", version.as_u32());
                let initial = quic.original_version;
                if initial != version {
                    eprintln!(
                        "* QUIC initial version: {initial} ({:#010x})",
                        initial.as_u32()
                    );
                }
                eprintln!(
                    "* QUIC path at establishment: RTT {:.3} ms, UDP payload MTU {} bytes",
                    quic.handshake_rtt.as_secs_f64() * 1000.,
                    quic.handshake_mtu,
                );
            }
        }
        Ok(ec)
    }
}
