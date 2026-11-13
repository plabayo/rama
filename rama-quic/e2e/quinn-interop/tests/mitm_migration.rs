//! Independent Quinn client and origin, with independent Rama MITM endpoints between them.
//! Ordinary endpoint migration tests do not exercise association admission or the MITM layer.
#![cfg(feature = "boring")]

mod common;

use parking_lot::Mutex;
use rama::{
    Layer as _, Service,
    error::BoxError,
    graceful::WeakScope,
    io::BridgeIo,
    net::{address::SocketAddress, stream::Socket as _},
    quic::{
        Connection,
        proto::VarInt,
        proxy::{
            AssociationLimits, PeekQuicClientHelloService, QuicAdmissionLayer,
            QuicAssociationAdmission, QuicMitmIngress, QuicMitmIngressConfig, QuicMitmRelay,
            QuicRelay,
        },
        tls::BoringTlsProvider,
    },
    tls::{
        boring::{
            core::{pkey::PKey, x509::X509},
            proxy::cert_issuer::StaticBoringMitmCertIssuer,
        },
        client::TlsClientConfig,
    },
    udp::{
        DatagramDemux, DemuxConfig, UdpPacketSocket,
        proxy::{
            DatagramForwardService, DatagramRecovery, DatagramRecoveryConfig,
            DatagramRecoveryFailureAction, DatagramRecoverySignal, DatagramToProxyBridge,
            EcnPolicy,
        },
    },
    utils::collections::NonEmptyVec,
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

#[derive(Clone)]
struct Observe(Arc<Mutex<Option<Connection>>>);

impl Service<BridgeIo<Connection, Connection>> for Observe {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: BridgeIo<Connection, Connection>) -> Result<(), BoxError> {
        *self.0.lock() = Some(input.0.clone());
        QuicRelay::new(VarInt::from_u32(1)).serve(input).await
    }
}

#[tokio::test]
async fn independent_client_keeps_streams_across_mitm_path_eviction() {
    common::step("independent MITM migration", async {
        let auth = common::identity();
        let mitm = common::identity_from_a_stranger("MITM migration test");
        let origin = quinn::Endpoint::server(
            common::quinn_server_config(&auth),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let issuer = StaticBoringMitmCertIssuer::new(
            NonEmptyVec::new(X509::from_der(&mitm.cert_chain[0]).unwrap()),
            PKey::private_key_from_der(mitm.private_key.secret_der()).unwrap(),
        );
        let tls = TlsClientConfig::new()
            .with_alpn([common::ALPN.into()].into_iter().collect())
            .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
            .unwrap();
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let observed = Arc::new(Mutex::new(None));
        let relay = QuicMitmRelay::new(issuer, WeakScope::detached(), tls, VarInt::from_u32(1))
            .with_migration_ingress(ingress.clone())
            .into_layer(Observe(observed.clone()));
        let inspect = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            DatagramToProxyBridge::new(relay, origin_address),
        )
        .with_router(ingress);
        let admission = QuicAssociationAdmission::try_new(AssociationLimits {
            active: n(16),
            active_per_source: n(8),
            sources: n(128),
            tuples: n(128),
            starts_per_window: n(32),
            starts_per_source_window: n(16),
            window: Duration::from_secs(1),
            quarantine: Duration::from_millis(10),
        })
        .unwrap();
        let service = QuicAdmissionLayer::new(admission).into_layer(inspect);
        let listener = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let demux = DatagramDemux::new(
            listener,
            DemuxConfig {
                associations: n(16),
                queue: n(64),
                idle_timeout: Duration::from_secs(10),
                receive_bytes: n(65536),
                queued_bytes: n(1024 * 1024),
            },
        );
        let proxy = common::Peer::spawn(async move {
            demux.serve(WeakScope::detached(), service).await.unwrap();
        });
        let accepting = origin.clone();
        let echo = common::Peer::spawn(async move {
            let connection = accepting.accept().await.unwrap().await.unwrap();
            let (mut persistent_send, mut persistent_recv) = connection.accept_bi().await.unwrap();
            for _ in 0..4 {
                let mut bytes = [0; 16];
                persistent_recv.read_exact(&mut bytes).await.unwrap();
                persistent_send.write_all(&bytes).await.unwrap();

                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let bytes = recv.read_to_end(1024).await.unwrap();
                send.write_all(&bytes).await.unwrap();
                send.finish().unwrap();
            }
            connection.closed().await;
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(common::quinn_client_config(
            mitm.cert_chain.last().unwrap().clone(),
        ));
        let connection = client
            .connect(address.into(), "localhost")
            .unwrap()
            .await
            .unwrap();
        // Keep an existing stream across each move, while opening new streams as well.
        // Four addresses with a two-path bound force obsolete transport eviction.
        let (mut persistent_send, mut persistent_recv) = connection.open_bi().await.unwrap();
        for round in 0..4 {
            if round > 0 {
                client
                    .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap();
            }
            let bytes = [round as u8; 16];
            persistent_send.write_all(&bytes).await.unwrap();
            let mut echoed = [0; 16];
            persistent_recv.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, bytes);

            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let payload = format!("independent migration {round}");
            send.write_all(payload.as_bytes()).await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), payload.as_bytes());
            while observed.lock().as_ref().unwrap().remote_address() != client.local_addr().unwrap()
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        connection.close(0u32.into(), b"done");
        client.close(0u32.into(), b"done");
        origin.close(0u32.into(), b"done");
        drop((proxy, echo));
    })
    .await;
}

#[tokio::test]
async fn forwarded_quinn_connection_survives_repeated_egress_recovery() {
    common::step("forwarded egress recovery", async {
        let auth = common::identity();
        let origin = quinn::Endpoint::server(
            common::quinn_server_config(&auth),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let signal = DatagramRecoverySignal::new();
        let forward = DatagramToProxyBridge::new(
            DatagramForwardService::new(n(65536), EcnPolicy::Discard),
            origin_address,
        )
        .with_egress_recovery(DatagramRecovery::new(
            signal.clone(),
            DatagramRecoveryConfig {
                preparation_timeout: Duration::from_secs(5),
                unavailable_timeout: Duration::from_secs(5),
                failure_action: DatagramRecoveryFailureAction::Close,
            },
        ));
        let listener = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let demux = DatagramDemux::new(
            listener,
            DemuxConfig {
                associations: n(16),
                queue: n(64),
                idle_timeout: Duration::from_secs(10),
                receive_bytes: n(65536),
                queued_bytes: n(1024 * 1024),
            },
        );
        let proxy = common::Peer::spawn(async move {
            demux.serve(WeakScope::detached(), forward).await.unwrap();
        });
        let accepting = origin.clone();
        let (observed, observer) = tokio::sync::oneshot::channel();
        let echo = common::Peer::spawn(async move {
            let connection = accepting.accept().await.unwrap().await.unwrap();
            observed.send(connection.clone()).unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            for _ in 0..9 {
                let mut bytes = [0; 4096];
                recv.read_exact(&mut bytes).await.unwrap();
                send.write_all(&bytes).await.unwrap();
                let (mut fresh_send, mut fresh_recv) = connection.accept_bi().await.unwrap();
                let bytes = fresh_recv.read_to_end(1024).await.unwrap();
                fresh_send.write_all(&bytes).await.unwrap();
                fresh_send.finish().unwrap();
            }
            connection.closed().await;
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(common::quinn_client_config(
            auth.cert_chain.last().unwrap().clone(),
        ));
        let connection = client
            .connect(address.into(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let server = observer.await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        for round in 0..9 {
            let old = server.remote_address();
            let responses = server.stats().frame_rx.path_response;
            if round > 0 {
                signal.request_recovery();
            }
            let bytes = [round as u8; 4096];
            send.write_all(&bytes).await.unwrap();
            let mut echoed = [0; 4096];
            recv.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, bytes);
            let (mut fresh_send, mut fresh_recv) = connection.open_bi().await.unwrap();
            fresh_send.write_all(b"new stream").await.unwrap();
            fresh_send.finish().unwrap();
            assert_eq!(fresh_recv.read_to_end(1024).await.unwrap(), b"new stream");
            if round > 0 {
                // Confirm the independent server exercised path validation, not just echo delivery.
                while server.remote_address() == old
                    || server.stats().frame_rx.path_response <= responses
                {
                    connection
                        .send_datagram(rama::bytes::Bytes::from_static(b"path probe"))
                        .unwrap();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        connection.close(0u32.into(), b"done");
        client.close(0u32.into(), b"done");
        origin.close(0u32.into(), b"done");
        drop((proxy, echo));
    })
    .await;
}
