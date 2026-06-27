use std::time::Duration;

use rama_core::{
    error::{BoxError, ErrorContext as _},
    extensions::{self},
    io::Io,
    telemetry::tracing,
};
#[cfg(feature = "dns")]
use rama_dns::client::DnsConnector;
use rama_net::{
    address::HostWithPort,
    client::{ConnectorService, EstablishedClientConnection, Request},
    transport::TransportProtocol,
    user::{ProxyCredential, credentials::DpiProxyCredential},
};
use rama_tcp::client::service::TcpConnector;
use rama_utils::macros::generate_set_and_with;

use crate::proto;

mod service;
pub use self::service::Socks5MitmRelayService;

#[cfg(feature = "dns")]
pub type DefaultEgressConnector = DnsConnector<TcpConnector>;

#[cfg(not(feature = "dns"))]
pub type DefaultEgressConnector = TcpConnector;

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay a socks5 proxy connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct Socks5MitmRelay<Connector = DefaultEgressConnector> {
    egress_connector: Connector,
    connect_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Outcome of [`Socks5MitmRelay::handshake`].
pub enum Socks5MitmHandshakeOutcome {
    /// Flow is not supported, skip traffic inspection and
    /// resort to proxying bytes...
    UnsupportedFlow,
    /// Socks5 handshake complete, continue to inspect.
    /// In case there were credentials negotiated in the flow,
    /// they will also have been inserted in the input flow via
    /// [`DpiProxyCredential`] in its extensions.
    ContinueInspection,
}

impl Socks5MitmRelay<DefaultEgressConnector> {
    #[inline(always)]
    /// Create a new [`Socks5MitmRelay`].
    pub fn new() -> Self {
        #[cfg(feature = "dns")]
        let egress_connector = DnsConnector::new(TcpConnector::default());
        #[cfg(not(feature = "dns"))]
        let egress_connector = TcpConnector::default();

        Self {
            egress_connector,
            connect_timeout: Duration::from_mins(2),
        }
    }
}

impl Default for Socks5MitmRelay<DefaultEgressConnector> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<Connector> Socks5MitmRelay<Connector> {
    #[inline(always)]
    /// Set the egress connector used to connect to the intended SOCKS5 server.
    pub fn egress_connector<OtherConnector>(
        self,
        connector: OtherConnector,
    ) -> Socks5MitmRelay<OtherConnector> {
        Socks5MitmRelay {
            egress_connector: connector,
            connect_timeout: self.connect_timeout,
        }
    }
}

impl<Connector> Socks5MitmRelay<Connector> {
    generate_set_and_with! {
        /// Overwrite the timeout to be used for egress connections
        /// to the actual intended SOCKS5 servers.
        pub fn connect_timeout(mut self, timeout: Duration) -> Self {
            self.connect_timeout = if timeout.is_zero() {
                Duration::from_mins(2)
            } else {
                timeout
            };
            self
        }
    }
}

impl<Connector> Socks5MitmRelay<Connector>
where
    Connector: ConnectorService<Request>,
    Connector::Connection: Io + Unpin,
{
    /// Establish and MITM an handshake between the client and server.
    pub async fn handshake<S>(
        &self,
        ingress_stream: &mut S,
        socks5_proxy_address: HostWithPort,
    ) -> Result<(Connector::Connection, Socks5MitmHandshakeOutcome), BoxError>
    where
        S: Io + Unpin + extensions::ExtensionsRef,
    {
        let mut req = Request::new_with_extensions(
            socks5_proxy_address.clone(),
            ingress_stream.extensions().clone(),
        );
        req.transport_protocol = Some(TransportProtocol::Tcp);
        let EstablishedClientConnection {
            conn: mut egress_stream,
            ..
        } = tokio::time::timeout(self.connect_timeout, self.egress_connector.connect(req))
            .await
            .context("connection to egress socks5 proxy server timed out")?
            .map_err(Into::<BoxError>::into)
            .context("connection to egress socks5 proxy server failed")?;

        let outcome = socks5_mitm_relay_handshake(ingress_stream, &mut egress_stream).await?;
        Ok((egress_stream, outcome))
    }
}

pub async fn socks5_mitm_relay_handshake<Ingress, Egress>(
    ingress_stream: &mut Ingress,
    egress_stream: &mut Egress,
) -> Result<Socks5MitmHandshakeOutcome, BoxError>
where
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    let client_header = proto::client::Header::read_from(ingress_stream)
        .await
        .context("read client header")?;

    client_header
        .write_to(egress_stream)
        .await
        .context("write client header: with ingress provided method")?;

    let server_header = proto::server::Header::read_from(egress_stream)
        .await
        .context("read egress socks5 proxy server header")?;

    server_header
        .write_to(ingress_stream)
        .await
        .context("write server header: received from egress stream")?;

    match server_header.method {
        proto::SocksMethod::NoAuthenticationRequired => {
            proxy_socks5_handshake_request_response(
                ingress_stream,
                egress_stream,
                server_header.method,
            )
            .await
        }
        proto::SocksMethod::UsernamePassword => {
            let client_auth_req = proto::client::UsernamePasswordRequest::read_from(ingress_stream)
                .await
                .context(
                    "read client auth sub-negotiation request from ingress: username-password",
                )?;

            client_auth_req.write_to(egress_stream).await.context(
                "write client auth-sub-negotation request to egress: received from egress stream",
            )?;

            let server_auth_reply =
                proto::server::UsernamePasswordResponse::read_from(egress_stream)
                    .await
                    .context(
                        "read server sub-negotiation response from egress: username-password auth",
                    )?;

            server_auth_reply.write_to(ingress_stream).await.context(
                "write server auth-sub-negotation response to ingress: received from egress stream",
            )?;

            if !server_auth_reply.success() {
                // continue regular flow even if not succesfull as it is up to the
                // conversing pair to decide when to stop, not the proxy... if client
                // and server continue regardless of socks5 semantics, we should support that
                tracing::debug!(
                    "server auth flow did not succeed: attempt to continue socks5 proxy relay flow regardless..."
                );
            }

            ingress_stream
                .extensions()
                .insert(DpiProxyCredential(ProxyCredential::Basic(
                    client_auth_req.basic,
                )));

            proxy_socks5_handshake_request_response(
                ingress_stream,
                egress_stream,
                server_header.method,
            )
            .await
        }
        method @ (proto::SocksMethod::GSSAPI
        | proto::SocksMethod::ChallengeHandshakeAuthenticationProtocol
        | proto::SocksMethod::ChallengeResponseAuthenticationMethod
        | proto::SocksMethod::SecureSocksLayer
        | proto::SocksMethod::NDSAuthentication
        | proto::SocksMethod::MultiAuthenticationFramework
        | proto::SocksMethod::JSONParameterBlock
        | proto::SocksMethod::NoAcceptableMethods
        | proto::SocksMethod::Unknown(_)) => {
            tracing::debug!(
                "supported SOCKS5 method {method:?}: forward bytes as is without further inspection..."
            );

            Ok(Socks5MitmHandshakeOutcome::UnsupportedFlow)
        }
    }
}

async fn proxy_socks5_handshake_request_response<Ingress, Egress>(
    ingress_stream: &mut Ingress,
    egress_stream: &mut Egress,
    negotiated_method: proto::SocksMethod,
) -> Result<Socks5MitmHandshakeOutcome, BoxError>
where
    Ingress: Io + Unpin + extensions::ExtensionsRef,
    Egress: Io + Unpin + extensions::ExtensionsRef,
{
    let client_request = proto::client::Request::read_from(ingress_stream)
        .await
        .context("read client Socks5 request from ingress stream")?;

    tracing::trace!(
        "socks5 client request w/ destination {} and negotiated method {:?}: client request received cmd {:?} from ingress stream",
        client_request.destination,
        negotiated_method,
        client_request.command,
    );

    client_request
        .write_to(egress_stream)
        .await
        .context("write client request: with ingress provided data")?;

    match client_request.command {
        proto::Command::Connect => {
            let server_reply = proto::server::Reply::read_from(egress_stream)
                .await
                .context("read server socks5 reply from egress stream")?;

            server_reply
                .write_to(ingress_stream)
                .await
                .context("write server reply to ingress: received from egress stream")?;

            if server_reply.reply != proto::ReplyKind::Succeeded {
                // continue regular flow even if not succesfull as it is up to the
                // conversing pair to decide when to stop, not the proxy... if client
                // and server continue regardless of socks5 semantics, we should support that
                tracing::debug!(
                    "server req-resp flow did not succeed: attempt to continue socks5 proxy relay flow regardless..."
                );
            }

            tracing::trace!(
                bind_addr = %server_reply.bind_address,
                "socks5 proxy relay connector: handshake (socks5_client <-> proxy <-> socks5_server) complete",
            );

            Ok(Socks5MitmHandshakeOutcome::ContinueInspection)
        }
        cmd
        @ (proto::Command::Bind | proto::Command::UdpAssociate | proto::Command::Unknown(_)) => {
            // Note that except for the unknown cmd,
            // this unsupported flow for Bind and Udp-Associate is fine,
            // given both are anyway about new sidechannel flows, which can
            // be intercepted by the transparent proxy separately just fine without requiring
            // further support here.
            //
            // It is only for the Connect flow that we need to actually relay in-place as there's
            // no sidechannel for the data... the stream for the socks5 handshake is in that case
            // also the data channel...
            tracing::debug!(
                "unsupported SOCKS5 method {cmd:?}: forward bytes as is without further inspection..."
            );

            Ok(Socks5MitmHandshakeOutcome::UnsupportedFlow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dns")]
    use parking_lot::Mutex;
    use rama_core::{ServiceInput, extensions::ExtensionsRef as _};
    #[cfg(feature = "dns")]
    use rama_dns::client::DnsConnector;
    #[cfg(feature = "dns")]
    use rama_net::address::{Domain, Host};
    use rama_net::user::credentials::Basic;
    #[cfg(feature = "dns")]
    use rama_tcp::client::{TcpStreamConnector, service::TcpConnector};
    #[cfg(feature = "dns")]
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[cfg(feature = "dns")]
    #[derive(Debug, Clone, Default)]
    struct RecordingTcpConnector {
        seen: Arc<Mutex<Vec<SocketAddr>>>,
    }

    #[cfg(feature = "dns")]
    impl RecordingTcpConnector {
        fn seen_addrs(&self) -> Vec<SocketAddr> {
            self.seen.lock().clone()
        }
    }

    #[cfg(feature = "dns")]
    impl TcpStreamConnector for RecordingTcpConnector {
        type Error = std::io::Error;

        async fn connect(&self, addr: SocketAddr) -> Result<rama_tcp::TcpStream, Self::Error> {
            self.seen.lock().push(addr);
            Err(std::io::Error::other(
                "recording connector denies connection",
            ))
        }
    }

    #[cfg(feature = "dns")]
    fn new_socks_proxy_address(port: u16) -> HostWithPort {
        HostWithPort::new(Host::Name(Domain::from_static("socks5.relay.test")), port)
    }

    #[cfg(feature = "dns")]
    #[tokio::test]
    async fn test_mitm_relay_handshake_uses_injected_egress_connector() {
        // Egress connect fails before any socks5 bytes are consumed from ingress.
        let mut ingress_stream = ServiceInput::new(tokio_test::io::Builder::new().build());

        let connector = RecordingTcpConnector::default();
        // No tight connect_timeout: a short real-time bound races the spawned connect
        // attempt (Windows' ~15.6ms timer tick) and can cancel it before connect() runs.
        // The mock connector errors instantly, so the egress stack completes on its own.
        let tcp = TcpConnector::default().with_connector(connector.clone());
        let egress = DnsConnector::with_resolver(tcp, Ipv4Addr::new(203, 0, 113, 10));
        let relay = Socks5MitmRelay::new().egress_connector(egress);

        let outcome = tokio::time::timeout(
            // generous safety net to catch a true hang, never races normal completion
            Duration::from_secs(5),
            relay.handshake(&mut ingress_stream, new_socks_proxy_address(1080)),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(_)) | Err(_)),
            "connect should not succeed in in-memory connector test",
        );

        let seen = connector.seen_addrs();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 1080)
        );
    }

    #[tokio::test]
    async fn test_proxy_method_and_request_connect_no_auth_continue_inspection() {
        let mut ingress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .read(b"\x05\x01\x00")
                .write(b"\x05\x00")
                .read(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
                .write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64")
                .build(),
        );

        let mut egress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .write(b"\x05\x01\x00")
                .read(b"\x05\x00")
                .write(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
                .read(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64")
                .build(),
        );

        let outcome = socks5_mitm_relay_handshake(&mut ingress_stream, &mut egress_stream)
            .await
            .expect("negotiate socks5 connect");
        assert_eq!(outcome, Socks5MitmHandshakeOutcome::ContinueInspection);
    }

    #[tokio::test]
    async fn test_proxy_connect_flow_supports_post_handshake_data_relay() {
        let (ingress_proxy, mut ingress_client) = tokio::io::duplex(1024);
        let (egress_proxy, mut egress_server) = tokio::io::duplex(1024);

        let mut ingress_stream = ServiceInput::new(ingress_proxy);
        let mut egress_stream = ServiceInput::new(egress_proxy);

        let client_task = tokio::spawn(async move {
            ingress_client
                .write_all(b"\x05\x01\x00")
                .await
                .expect("client write socks header");
            let mut server_method = [0u8; 2];
            ingress_client
                .read_exact(&mut server_method)
                .await
                .expect("client read server method");
            assert_eq!(&server_method, b"\x05\x00");

            ingress_client
                .write_all(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
                .await
                .expect("client write connect request");
            let mut server_reply = [0u8; 10];
            ingress_client
                .read_exact(&mut server_reply)
                .await
                .expect("client read connect reply");
            assert_eq!(&server_reply, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64");

            ingress_client
                .write_all(b"PING")
                .await
                .expect("client write application data");
            let mut app_reply = [0u8; 4];
            ingress_client
                .read_exact(&mut app_reply)
                .await
                .expect("client read application reply");
            assert_eq!(&app_reply, b"PONG");
        });

        let server_task = tokio::spawn(async move {
            let mut client_header = [0u8; 3];
            egress_server
                .read_exact(&mut client_header)
                .await
                .expect("server read client header");
            assert_eq!(&client_header, b"\x05\x01\x00");
            egress_server
                .write_all(b"\x05\x00")
                .await
                .expect("server write selected method");

            let mut connect_request = [0u8; 10];
            egress_server
                .read_exact(&mut connect_request)
                .await
                .expect("server read connect request");
            assert_eq!(
                &connect_request,
                b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb"
            );
            egress_server
                .write_all(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64")
                .await
                .expect("server write connect reply");

            let mut app_data = [0u8; 4];
            egress_server
                .read_exact(&mut app_data)
                .await
                .expect("server read application data");
            assert_eq!(&app_data, b"PING");
            egress_server
                .write_all(b"PONG")
                .await
                .expect("server write application reply");
        });

        let outcome = socks5_mitm_relay_handshake(&mut ingress_stream, &mut egress_stream)
            .await
            .expect("negotiate socks5 connect");
        assert_eq!(outcome, Socks5MitmHandshakeOutcome::ContinueInspection);

        tokio::io::copy_bidirectional(&mut ingress_stream, &mut egress_stream)
            .await
            .expect("post-handshake relay bytes");

        client_task.await.expect("client task");
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn test_proxy_method_and_request_connect_auth_sets_proxy_credential_extension() {
        let mut ingress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .read(b"\x05\x01\x02")
                .write(b"\x05\x02")
                .read(b"\x01\x04john\x06secret")
                .write(b"\x01\x00")
                .read(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
                .write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64")
                .build(),
        );

        let mut egress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .write(b"\x05\x01\x02")
                .read(b"\x05\x02")
                .write(b"\x01\x04john\x06secret")
                .read(b"\x01\x00")
                .write(b"\x05\x01\x00\x01\x01\x02\x03\x04\x01\xbb")
                .read(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x19\x64")
                .build(),
        );

        let outcome = socks5_mitm_relay_handshake(&mut ingress_stream, &mut egress_stream)
            .await
            .expect("negotiate socks5 connect with auth");
        assert_eq!(outcome, Socks5MitmHandshakeOutcome::ContinueInspection);

        let credential = ingress_stream
            .extensions()
            .get_ref::<DpiProxyCredential>()
            .expect("DPI proxy credential extension");
        assert_eq!(
            credential.0,
            ProxyCredential::Basic(Basic::new(
                "john".try_into().expect("non-empty username"),
                "secret".try_into().expect("non-empty password"),
            ))
        );
    }

    #[tokio::test]
    async fn test_proxy_method_and_request_bind_returns_unsupported_and_keeps_stream() {
        assert_unsupported_flow_roundtrip(
            b"\x05\x00",
            b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00",
            [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        )
        .await;
    }

    #[tokio::test]
    async fn test_proxy_method_and_request_udp_associate_returns_unsupported_and_keeps_stream() {
        assert_unsupported_flow_roundtrip(
            b"\x05\x00",
            b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00",
            [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        )
        .await;
    }

    async fn assert_unsupported_flow_roundtrip(
        server_header: &[u8],
        client_request: &[u8],
        expected_request: [u8; 10],
    ) {
        let mut ingress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .read(b"\x05\x01\x00")
                .write(server_header)
                .read(client_request)
                .build(),
        );

        let mut egress_stream = ServiceInput::new(
            tokio_test::io::Builder::new()
                .write(b"\x05\x01\x00")
                .read(server_header)
                .write(client_request)
                .build(),
        );

        let outcome = socks5_mitm_relay_handshake(&mut ingress_stream, &mut egress_stream)
            .await
            .expect("negotiate unsupported command");
        assert_eq!(outcome, Socks5MitmHandshakeOutcome::UnsupportedFlow);

        assert_eq!(
            expected_request,
            [
                0x05,
                client_request[1],
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00
            ]
        );
    }
}
