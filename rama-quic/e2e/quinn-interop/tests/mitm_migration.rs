//! Independent Quinn client and origin, with Rama's shared MITM between them.
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
    udp::{DatagramDemux, DemuxConfig, UdpPacketSocket, proxy::DatagramToProxyBridge},
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
async fn independent_client_migrates_repeatedly_through_shared_mitm() {
    common::step("shared MITM migration", async {
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
                max_paths_per_connection: n(8),
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
            for _ in 0..4 {
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
        for round in 0..4 {
            if round > 0 {
                client
                    .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap();
            }
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let payload = format!("independent migration {round}");
            send.write_all(payload.as_bytes()).await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(1024).await.unwrap(), payload.as_bytes());
            while observed.lock().as_ref().unwrap().remote_address().port()
                != client.local_addr().unwrap().port()
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
