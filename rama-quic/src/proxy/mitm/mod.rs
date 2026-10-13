//! Terminate a peeked QUIC association and the matching origin connection.

use std::{sync::Arc, time::Duration};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    io::BridgeIo,
    rt::Executor,
};
use rama_crypto::{
    dep::boring::x509::X509,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rama_net::{
    address::Host,
    client::ConnectorTarget,
    http::{TargetHttpVersion, Version},
};
use rama_quic_proto::VarInt;
use rama_tls::{
    client::TlsClientConfig,
    server::{ServerAuthData, TlsServerConfig},
};
use rama_tls_boring::proxy::cert_issuer::BoringMitmCertIssuer;
use rama_udp::DatagramSocket;
use rama_utils::guard::DropGuard;
use tokio::time::{Instant, timeout_at};

use super::InputWithQuicClientHello;
use crate::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};

/// The default for [`QuicMitmRelay::with_handshake_timeout`].
pub const DEFAULT_QUIC_MITM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Terminates a QUIC association whose ClientHello was peeked, using the egress socket the
/// producer prepared for its origin: the QUIC counterpart of the TLS MITM relay.
///
/// The origin handshake runs first, over the egress socket, with the client's QUIC version,
/// server name and the offered protocols the egress TLS configuration allows. Its certificate
/// is mirrored by the [`BoringMitmCertIssuer`], and the client is then accepted on the ingress
/// socket with that certificate and the protocol the origin selected. The inner service owns
/// both established connections; this service closes them only when establishment fails.
/// Early data is disabled on both hops. All of it shares one deadline, fixed when `serve` is
/// called.
///
/// Destination selection is the producer's: this service dials nothing but the egress socket's
/// peer, and the received server name never changes where traffic goes.
#[derive(Debug, Clone)]
pub struct QuicMitmRelay<Issuer> {
    issuer: Issuer,
    exec: Executor,
    egress_tls: TlsClientConfig,
    ingress_transport: Arc<TransportConfig>,
    egress_transport: Arc<TransportConfig>,
    handshake_timeout: Duration,
    failure_code: VarInt,
}

impl<Issuer> QuicMitmRelay<Issuer> {
    /// Verify origins with `egress_tls`, whose ALPN list (when set) bounds what is offered
    /// upstream, and close failed associations with application error `failure_code`.
    /// Datagrams are disabled on both hops until both transports enable them.
    pub fn new(
        issuer: Issuer,
        exec: Executor,
        egress_tls: TlsClientConfig,
        failure_code: VarInt,
    ) -> Self {
        // Datagrams stay off until both hops are configured for them: advertising them on one
        // hop only would promise what the relay cannot carry.
        let transport =
            Arc::new(TransportConfig::default().maybe_with_datagram_receive_buffer_size(None));
        Self {
            issuer,
            exec,
            egress_tls,
            ingress_transport: transport.clone(),
            egress_transport: transport,
            handshake_timeout: DEFAULT_QUIC_MITM_HANDSHAKE_TIMEOUT,
            failure_code,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Transport limits advertised to the client.
        pub fn ingress_transport(mut self, transport: Arc<TransportConfig>) -> Self {
            self.ingress_transport = transport;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Transport limits advertised to the origin.
        pub fn egress_transport(mut self, transport: Arc<TransportConfig>) -> Self {
            self.egress_transport = transport;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The budget for both handshakes and certificate issuance, from `serve`. Defaults to
        /// [`DEFAULT_QUIC_MITM_HANDSHAKE_TIMEOUT`].
        pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
            self.handshake_timeout = timeout;
            self
        }
    }
}

impl<Issuer: Clone, S> Layer<S> for QuicMitmRelay<Issuer> {
    type Service = QuicMitmRelayService<Issuer, S>;

    fn layer(&self, inner: S) -> Self::Service {
        QuicMitmRelayService {
            relay: self.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        QuicMitmRelayService { relay: self, inner }
    }
}

/// The service a [`QuicMitmRelay`] layer produces.
#[derive(Debug, Clone)]
pub struct QuicMitmRelayService<Issuer, S> {
    relay: QuicMitmRelay<Issuer>,
    inner: S,
}

impl<Issuer, S, Ingress, Egress> Service<InputWithQuicClientHello<BridgeIo<Ingress, Egress>>>
    for QuicMitmRelayService<Issuer, S>
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>>,
    S: Service<BridgeIo<Connection, Connection>, Error: Into<BoxError>>,
    Ingress: DatagramSocket + ExtensionsRef,
    Egress: DatagramSocket,
{
    type Output = S::Output;
    type Error = BoxError;

    fn serve(
        &self,
        input: InputWithQuicClientHello<BridgeIo<Ingress, Egress>>,
    ) -> impl Future<Output = Result<S::Output, BoxError>> + Send + '_ {
        // Fixed at hand-over, so a late first poll cannot renew the budget.
        let deadline = Instant::now() + self.relay.handshake_timeout;
        async move {
            let established = timeout_at(deadline, self.relay.establish(input))
                .await
                .map_err(|_elapsed| {
                    BoxError::from_static_str("QUIC MITM handshake deadline exceeded")
                })??;
            let Established {
                ingress,
                egress,
                endpoints,
            } = established;
            let result = self.inner.serve(BridgeIo(ingress, egress)).await;
            // The endpoints drive both connections until the inner service is done with them.
            drop(endpoints);
            result.map_err(Into::into)
        }
    }
}

struct Established {
    ingress: Connection,
    egress: Connection,
    endpoints: [Endpoint; 2],
}

impl<Issuer: BoringMitmCertIssuer<Error: Into<BoxError>>> QuicMitmRelay<Issuer> {
    async fn establish<Ingress, Egress>(
        &self,
        InputWithQuicClientHello {
            input: BridgeIo(ingress, egress),
            client_hello,
        }: InputWithQuicClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<Established, BoxError>
    where
        Ingress: DatagramSocket + ExtensionsRef,
        Egress: DatagramSocket,
    {
        let hello = &client_hello.client_hello;
        let offered = hello
            .ext_alpn()
            .ok_or_else(|| BoxError::from_static_str("QUIC ClientHello offers no ALPN"))?;
        let server_name = match hello.ext_server_name() {
            Some(name) => Host::Name(name.clone()),
            None => ingress
                .extensions()
                .get_ref::<ConnectorTarget>()
                .map(|target| target.0.host.clone())
                .ok_or_else(|| {
                    BoxError::from_static_str("QUIC MITM needs a server name or a target")
                })?,
        };

        let mut tls = self.egress_tls.clone();
        let allowed = match tls.alpn() {
            Some(configured) => configured
                .0
                .into_iter()
                .filter(|protocol| offered.contains(protocol))
                .collect(),
            None => offered.iter().cloned().collect(),
        };
        tls.set_alpn(allowed);
        let mut client = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
        client.set_transport_config(self.egress_transport.clone());
        client.set_version(client_hello.version)?;

        let origin = egress.peer_addr()?;
        let egress_endpoint = Endpoint::build(self.exec.clone()).with_datagram_socket(egress)?;
        let egress_connection = egress_endpoint
            .connect_with(client, origin.into(), &server_name.to_string())?
            .await?;
        let mut close_egress = close_on_drop(&egress_connection, self.failure_code);
        let negotiated = egress_connection
            .handshake_data()
            .and_then(|data| data.application_layer_protocol)
            .ok_or_else(|| BoxError::from_static_str("QUIC origin negotiated no ALPN"))?;
        let origin_leaf = egress_connection
            .peer_identity()
            .and_then(|chain| chain.into_iter().next())
            .ok_or_else(|| BoxError::from_static_str("QUIC origin presented no certificate"))?;

        let issued = self
            .issuer
            .issue_mitm_x509_cert(X509::from_der(&origin_leaf)?)
            .await
            .map_err(Into::into)?;
        let mut identity = ServerAuthData::new(
            issued
                .crt_chain
                .iter()
                .map(|cert| cert.to_der().map(CertificateDer::from))
                .collect::<Result<_, _>>()?,
            PrivateKeyDer::try_from(issued.key.private_key_to_der()?)
                .map_err(BoxError::from_static_str)?,
        );
        identity.ocsp = issued.ocsp_staple.map(|bytes| bytes.to_vec());
        let server_tls = TlsServerConfig::new()
            .with_server_auth(identity)
            .with_alpn([negotiated.clone()].into_iter().collect());
        let mut server = ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())?;
        server.set_transport_config(self.ingress_transport.clone());

        let ingress_endpoint = Endpoint::build(self.exec.clone())
            .with_server_config(server)
            .with_datagram_socket(ingress)?;
        let incoming = ingress_endpoint
            .accept()
            .await
            .ok_or_else(|| BoxError::from_static_str("QUIC MITM ingress closed before accept"))?;
        let ingress_connection = incoming.await?;
        let mut close_ingress = close_on_drop(&ingress_connection, self.failure_code);
        if ingress_connection
            .handshake_data()
            .and_then(|data| data.application_layer_protocol)
            .as_ref()
            != Some(&negotiated)
        {
            return Err(BoxError::from_static_str(
                "QUIC MITM ingress ALPN differs from the origin's",
            ));
        }

        // As the TLS relay does: the HTTP version the origin agreed to, for the inner service.
        if let Ok(version) = Version::try_from(&negotiated) {
            egress_connection
                .extensions()
                .insert(TargetHttpVersion(version));
        }
        close_ingress.disarm();
        close_egress.disarm();
        Ok(Established {
            ingress: ingress_connection,
            egress: egress_connection,
            endpoints: [ingress_endpoint, egress_endpoint],
        })
    }
}

/// Close `connection` with `failure_code` unless the guard is disarmed on hand-over.
fn close_on_drop(
    connection: &Connection,
    failure_code: VarInt,
) -> DropGuard<impl FnOnce() + use<>> {
    let connection = connection.clone();
    DropGuard::new(move || {
        connection.close(failure_code, b"QUIC MITM establishment failed");
    })
}

#[cfg(test)]
mod tests;
