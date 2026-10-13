//! Terminate a peeked QUIC association and the matching origin connection.

use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
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
    tls::ApplicationProtocol,
};
use rama_quic_proto::{ConnectionId, VarInt, crypto::CryptoError, peek::PeekedClientHello};
use rama_tls::{
    client::TlsClientConfig,
    server::{ServerAuthData, TlsServerConfig},
};
use rama_tls_boring::proxy::cert_issuer::BoringMitmCertIssuer;
use rama_udp::DatagramSocket;
use rama_utils::guard::DropGuard;
use tokio::time::{Instant, timeout_at};

use super::InputWithQuicClientHello;
use crate::{
    ClientConfig, Connection, Endpoint, IncomingOutcome, ServerConfig, TransportConfig,
    proto::ServerCrypto,
    proto::crypto::{
        self,
        boring::{retry_tag, server_config_from_rama, server_initial_keys},
    },
    tls::TlsOptions,
};

/// The default for [`QuicMitmRelay::with_handshake_timeout`].
pub const DEFAULT_QUIC_MITM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Terminates a QUIC association whose ClientHello was peeked, using the egress socket the
/// producer prepared for its origin: the QUIC counterpart of the TLS MITM relay.
///
/// The client's attempt is admitted on the ingress socket first, by default only once a Retry
/// validated its address, and only if it carries the ClientHello that was peeked. Then the
/// origin handshake runs over the egress socket, with the client's QUIC version, server name
/// and the offered protocols the egress TLS configuration allows, in the client's order. The
/// origin's certificate is mirrored by the [`BoringMitmCertIssuer`], and the client is accepted
/// with it and the protocol the origin selected; a failure refuses the client. No origin
/// handshake or issuance runs for an unvalidated address. The inner service owns both
/// established connections; this service closes them only when establishment fails. Early
/// data is disabled on both hops. All of it shares one deadline, fixed when `serve` is called.
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
    validate_address: bool,
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
            validate_address: true,
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

    rama_utils::macros::generate_set_and_with! {
        /// Whether a Retry validates the client's address before any origin work runs (the
        /// default). Without it, a spoofed first flight costs an origin handshake and issuance.
        pub fn validate_address(mut self, validate: bool) -> Self {
            self.validate_address = validate;
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
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
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

impl<Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone> QuicMitmRelay<Issuer> {
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
        if hello.ext_alpn().is_none() {
            return Err(BoxError::from_static_str("QUIC ClientHello offers no ALPN"));
        }
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

        let origin = Arc::new(Mutex::new(None::<Origin>));
        let failure_code = self.failure_code;
        // An origin reached for a client that is not accepted after all learns why.
        let mut close_origin = DropGuard::new({
            let origin = origin.clone();
            move || {
                if let Some(origin) = origin.lock().take() {
                    origin
                        .connection
                        .close(failure_code, b"QUIC MITM establishment failed");
                }
            }
        });
        let mut server = ServerConfig::with_resolver(Arc::new(OriginResolver {
            relay: self.clone(),
            peeked: client_hello,
            server_name,
            egress: Mutex::new(Some(egress)),
            origin: origin.clone(),
        }));
        server.set_transport_config(self.ingress_transport.clone());
        let ingress_endpoint = Endpoint::build(self.exec.clone())
            .with_server_config(server)
            .with_datagram_socket(ingress)?;
        let ingress_connection = loop {
            let incoming = ingress_endpoint.accept().await.ok_or_else(|| {
                BoxError::from_static_str("QUIC MITM ingress closed before accept")
            })?;
            if !self.validate_address {
                break incoming.await?;
            }
            match incoming.accept_or_retry().await? {
                IncomingOutcome::Accepted(connection) => break connection,
                IncomingOutcome::Retried => {}
            }
        };
        let mut close_ingress = close_on_drop(&ingress_connection, failure_code);
        let Origin {
            connection: egress_connection,
            endpoint: egress_endpoint,
            negotiated,
        } = origin.lock().take().ok_or_else(|| {
            BoxError::from_static_str("QUIC MITM accepted a client without its origin")
        })?;
        close_origin.disarm();
        let negotiated = negotiated
            .ok_or_else(|| BoxError::from_static_str("QUIC origin negotiated no ALPN"))?;
        let mut close_egress = close_on_drop(&egress_connection, failure_code);
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

/// The origin of one association, reached for the client attempt its ingress admitted.
struct Origin {
    connection: Connection,
    endpoint: Endpoint,
    negotiated: Option<ApplicationProtocol>,
}

/// Resolves the ingress configuration of one association. The endpoint asks only for the
/// attempt it admits, and runs the work (the origin handshake and certificate issuance) only
/// after any Retry validated the client's address.
struct OriginResolver<Issuer, Egress> {
    relay: QuicMitmRelay<Issuer>,
    peeked: PeekedClientHello,
    server_name: Host,
    egress: Mutex<Option<Egress>>,
    origin: Arc<Mutex<Option<Origin>>>,
}

impl<Issuer, Egress> OriginResolver<Issuer, Egress>
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Egress: DatagramSocket,
{
    async fn reach_origin(&self) -> Result<Arc<dyn crypto::ServerConfig>, BoxError> {
        let egress = self
            .egress
            .lock()
            .take()
            .ok_or_else(|| BoxError::from_static_str("QUIC MITM origin already reached"))?;
        let offered = self.peeked.client_hello.ext_alpn().unwrap_or_default();
        let mut tls = self.relay.egress_tls.clone();
        // The client's order, bounded by what the egress configuration allows.
        let allowed = match tls.alpn() {
            Some(configured) => offered
                .iter()
                .filter(|protocol| configured.0.contains(protocol))
                .cloned()
                .collect(),
            None => offered.iter().cloned().collect(),
        };
        tls.set_alpn(allowed);
        let mut client = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
        client.set_transport_config(self.relay.egress_transport.clone());
        client.set_version(self.peeked.version)?;

        let origin = egress.peer_addr()?;
        let endpoint = Endpoint::build(self.relay.exec.clone()).with_datagram_socket(egress)?;
        let connection = endpoint
            .connect_with(client, origin.into(), &self.server_name.to_string())?
            .await?;
        let negotiated = connection
            .handshake_data()
            .and_then(|data| data.application_layer_protocol);
        let origin_leaf = connection
            .peer_identity()
            .and_then(|chain| chain.into_iter().next());
        // Held from here, so a failure closes the origin with the relay's code.
        *self.origin.lock() = Some(Origin {
            connection,
            endpoint,
            negotiated: negotiated.clone(),
        });
        let negotiated = negotiated
            .ok_or_else(|| BoxError::from_static_str("QUIC origin negotiated no ALPN"))?;
        let origin_leaf = origin_leaf
            .ok_or_else(|| BoxError::from_static_str("QUIC origin presented no certificate"))?;

        let issued = self
            .relay
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
            .with_alpn([negotiated].into_iter().collect());
        match server_config_from_rama(&server_tls, TlsOptions::default())? {
            ServerCrypto::Fixed(config) => Ok(config),
            ServerCrypto::Resolver(_) => Err(BoxError::from_static_str(
                "QUIC MITM issued identity resolves per ClientHello",
            )),
        }
    }
}

impl<Issuer, Egress> crypto::InitialServerConfig for OriginResolver<Issuer, Egress>
where
    Issuer: Send + Sync,
    Egress: Send,
{
    fn initial_keys(
        &self,
        version: rama_quic_proto::Version,
        cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::InitialKeysError> {
        server_initial_keys(version, cid)
    }

    fn retry_tag(
        &self,
        version: rama_quic_proto::Version,
        cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], CryptoError> {
        retry_tag(version, cid, packet)
    }
}

impl<Issuer, Egress> crypto::ServerConfigResolver for OriginResolver<Issuer, Egress>
where
    Issuer: BoringMitmCertIssuer<Error: Into<BoxError>> + Clone,
    Egress: DatagramSocket,
{
    fn resolve(
        self: Arc<Self>,
        client_hello: crypto::ClientHelloMessage,
    ) -> crypto::ServerConfigLookup {
        Box::pin(async move {
            // The attempt the endpoint admits must be the one the routing decision inspected.
            let attempt = client_hello.client_hello();
            let peeked = &self.peeked.client_hello;
            if attempt.ext_server_name() != peeked.ext_server_name()
                || attempt.ext_alpn() != peeked.ext_alpn()
            {
                return Err(BoxError::from_static_str(
                    "QUIC MITM attempt differs from the peeked ClientHello",
                ));
            }
            Ok(crypto::ServerConfigResolution::Pending(Box::pin(
                async move { self.reach_origin().await },
            )))
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
