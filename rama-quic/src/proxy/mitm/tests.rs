use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{Service, error::BoxError, io::BridgeIo, rt::Executor, service::service_fn};
use rama_crypto::dep::boring::{pkey::PKey, x509::X509};
use rama_net::{
    http::{TargetHttpVersion, Version},
    tls::ApplicationProtocol,
};
use rama_tls::{alpn::AlpnRouter, client::TlsClientConfig, server::ServerAuthData};
use rama_tls_boring::proxy::cert_issuer::{BoringMitmCertIssuer, StaticBoringMitmCertIssuer};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::collections::NonEmptyVec;
use tokio::time::timeout;

use super::*;
use crate::{
    ClientConfig, Endpoint, ServerConfig,
    proxy::{PeekQuicClientHelloService, QuicRelay},
    test_helpers::{identity, untrusted_identity},
    tls::{BoringTlsProvider, TlsOptions},
};

const ALPN: &[u8] = b"rama-quic-test";
const LIMIT: Duration = Duration::from_secs(20);

fn issuer(identity: &ServerAuthData) -> StaticBoringMitmCertIssuer {
    StaticBoringMitmCertIssuer::new(
        NonEmptyVec::new(X509::from_der(&identity.cert_chain[0]).unwrap()),
        PKey::private_key_from_der(identity.private_key.secret_der()).unwrap(),
    )
}

fn trusting(identity: &ServerAuthData) -> TlsClientConfig {
    trusting_with_alpn(identity, ALPN)
}

fn trusting_with_alpn(identity: &ServerAuthData, alpn: &[u8]) -> TlsClientConfig {
    TlsClientConfig::new()
        .with_alpn([alpn.into()].into_iter().collect())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap()
}

/// Client ⇄ ingress socket, egress socket ⇄ origin, as a producer would prepare them.
struct Sockets {
    client: Endpoint,
    ingress: MemoryDatagramSocket,
    ingress_address: SocketAddr,
    egress: MemoryDatagramSocket,
    origin: Endpoint,
}

fn sockets(origin_identity: &ServerAuthData, port: u16) -> Sockets {
    sockets_with_alpn(origin_identity, port, ALPN)
}

fn sockets_with_alpn(origin_identity: &ServerAuthData, port: u16, alpn: &[u8]) -> Sockets {
    let address = |offset| SocketAddr::from(([127, 0, 0, 1], port + offset));
    let capacity = NonZeroUsize::new(64).unwrap();
    let (client_socket, ingress) = MemoryDatagramSocket::pair(address(0), address(1), capacity);
    let (egress, origin_socket) = MemoryDatagramSocket::pair(address(2), address(3), capacity);
    let tls = rama_tls::server::TlsServerConfig::new()
        .with_alpn([alpn.into()].into_iter().collect())
        .with_server_auth(origin_identity.clone());
    let origin = Endpoint::build(Executor::new())
        .with_server_config(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap())
        .with_datagram_socket(origin_socket)
        .unwrap();
    let client = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .unwrap();
    Sockets {
        client,
        ingress,
        ingress_address: address(1),
        egress,
        origin,
    }
}

fn relay<I>(issuer: I, origin_identity: &ServerAuthData) -> QuicMitmRelay<I> {
    QuicMitmRelay::new(
        issuer,
        Executor::new(),
        trusting(origin_identity),
        VarInt::from_u32(0x0101),
    )
}

#[tokio::test]
async fn a_terminated_association_relays_streams_to_the_verified_origin() {
    timeout(LIMIT, async {
        let mitm_identity = identity();
        let origin_identity = untrusted_identity();
        let Sockets {
            client,
            ingress,
            ingress_address,
            egress,
            origin,
        } = sockets(&origin_identity, 24500);
        let service = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            relay(issuer(&mitm_identity), &origin_identity)
                .into_layer(QuicRelay::new(VarInt::from_u32(0x0101))),
        );
        let relaying = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });

        let origin_task = tokio::spawn(async move {
            let connection = origin.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let request = recv.read_to_end(64).await.unwrap();
            send.write_all(&[b"pong:", request.as_slice()].concat())
                .await
                .unwrap();
            send.finish().unwrap();
            connection.closed().await;
            origin
        });

        let config =
            ClientConfig::try_from_rama_tls(&trusting(&mitm_identity), TlsOptions::default())
                .unwrap();
        let connection = client
            .connect_with(config, ingress_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        // The client authenticated the relay's certificate, not the origin's.
        assert_eq!(
            connection.peer_identity().unwrap()[0],
            mitm_identity.cert_chain[0]
        );
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"pong:ping");
        connection.close(VarInt::from_u32(0), b"done");
        relaying.await.unwrap().unwrap();
        drop(origin_task.await.unwrap());
    })
    .await
    .unwrap();
}

/// Counts issuance, which must not happen for an origin that failed verification.
#[derive(Clone)]
struct CountingIssuer {
    inner: StaticBoringMitmCertIssuer,
    issued: Arc<AtomicUsize>,
}

impl BoringMitmCertIssuer for CountingIssuer {
    type Error = BoxError;

    async fn issue_mitm_x509_cert(
        &self,
        original: X509,
    ) -> Result<rama_tls_boring::proxy::cert_issuer::MitmIssuedCert, BoxError> {
        self.issued.fetch_add(1, Ordering::Relaxed);
        self.inner
            .issue_mitm_x509_cert(original)
            .await
            .map_err(Into::into)
    }
}

#[tokio::test]
async fn an_unverified_origin_is_never_mirrored_to_the_client() {
    timeout(LIMIT, async {
        let mitm_identity = identity();
        let origin_identity = untrusted_identity();
        let Sockets {
            client,
            ingress,
            ingress_address,
            egress,
            origin,
        } = sockets(&origin_identity, 24510);
        let issued = Arc::new(AtomicUsize::new(0));
        let issuer = CountingIssuer {
            inner: issuer(&mitm_identity),
            issued: issued.clone(),
        };
        // Egress trusts some other identity, so the origin fails verification.
        let service = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            relay(issuer, &mitm_identity).into_layer(service_fn(
                async |_: BridgeIo<Connection, Connection>| Ok::<_, BoxError>(()),
            )),
        );
        let relaying = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });
        let origin_task = tokio::spawn(async move {
            // The origin's handshake fails on the relay's side; nothing reaches it after.
            let _refused = origin.accept().await.unwrap().await;
            origin
        });
        let config =
            ClientConfig::try_from_rama_tls(&trusting(&mitm_identity), TlsOptions::default())
                .unwrap()
                .with_transport_config(Arc::new(
                    crate::TransportConfig::default()
                        .with_max_idle_timeout(Duration::from_secs(1).try_into().unwrap()),
                ));
        let connecting = client
            .connect_with(config, ingress_address, "localhost")
            .unwrap();
        relaying.await.unwrap().unwrap_err();
        connecting.await.unwrap_err();
        assert_eq!(issued.load(Ordering::Relaxed), 0);
        drop(origin_task.await.unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_alpn_router_dispatches_on_the_negotiated_protocol() {
    timeout(LIMIT, async {
        let mitm_identity = identity();
        let origin_identity = untrusted_identity();
        let Sockets {
            client,
            ingress,
            ingress_address,
            egress,
            origin,
        } = sockets(&origin_identity, 24520);
        let routed = Arc::new(AtomicUsize::new(0));
        let counted = routed.clone();
        let service = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            relay(issuer(&mitm_identity), &origin_identity).into_layer(AlpnRouter::new(
                ApplicationProtocol::from(ALPN),
                service_fn(
                    move |BridgeIo(ingress, egress): BridgeIo<Connection, Connection>| {
                        let counted = counted.clone();
                        async move {
                            counted.fetch_add(1, Ordering::Relaxed);
                            ingress.close(VarInt::from_u32(0), b"routed");
                            egress.close(VarInt::from_u32(0), b"routed");
                            Ok::<_, BoxError>(())
                        }
                    },
                ),
            )),
        );
        let relaying = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });
        let origin_task = tokio::spawn(async move {
            let _connection = origin.accept().await.unwrap().await;
            origin
        });
        let config =
            ClientConfig::try_from_rama_tls(&trusting(&mitm_identity), TlsOptions::default())
                .unwrap();
        let connection = client
            .connect_with(config, ingress_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        relaying.await.unwrap().unwrap();
        connection.closed().await;
        assert_eq!(routed.load(Ordering::Relaxed), 1);
        drop(origin_task.await.unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_handshake_budget_is_fixed_when_the_association_is_handed_over() {
    timeout(LIMIT, async {
        let mitm_identity = identity();
        let origin_identity = untrusted_identity();
        let Sockets {
            client,
            ingress,
            ingress_address,
            egress,
            origin,
        } = sockets(&origin_identity, 24530);
        let origin_task = tokio::spawn(async move {
            if let Some(incoming) = origin.accept().await {
                let _connection = incoming.await;
            }
            origin
        });
        let config =
            ClientConfig::try_from_rama_tls(&trusting(&mitm_identity), TlsOptions::default())
                .unwrap();
        let connecting = client
            .connect_with(config, ingress_address, "localhost")
            .unwrap();
        // Peek first, keeping its output, so the relay itself is what is handed over late.
        let peeked = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            service_fn(async |input: InputWithQuicClientHello<_>| Ok::<_, BoxError>(input)),
        )
        .with_fallback(service_fn(async |_: BridgeIo<_, _>| {
            Err::<InputWithQuicClientHello<_>, _>(BoxError::from_static_str("no ClientHello"))
        }))
        .serve(BridgeIo(ingress, egress))
        .await
        .unwrap();
        // Plenty for an in-memory handshake, but spent before the relay is first polled.
        let mitm = relay(issuer(&mitm_identity), &origin_identity)
            .with_handshake_timeout(Duration::from_millis(200))
            .into_layer(QuicRelay::new(VarInt::from_u32(0x0101)));
        let serving = mitm.serve(peeked);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let error = serving.await.unwrap_err();
        assert!(error.to_string().contains("deadline"), "{error}");
        drop(connecting);
        origin_task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_http3_origin_marks_the_egress_http_version() {
    timeout(LIMIT, async {
        let mitm_identity = identity();
        let origin_identity = untrusted_identity();
        let Sockets {
            client,
            ingress,
            ingress_address,
            egress,
            origin,
        } = sockets_with_alpn(&origin_identity, 24540, b"h3");
        let marked = Arc::new(AtomicUsize::new(0));
        let counted = marked.clone();
        let service = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            QuicMitmRelay::new(
                issuer(&mitm_identity),
                Executor::new(),
                trusting_with_alpn(&origin_identity, b"h3"),
                VarInt::from_u32(0x0101),
            )
            .into_layer(service_fn(
                move |BridgeIo(ingress, egress): BridgeIo<Connection, Connection>| {
                    let counted = counted.clone();
                    async move {
                        if egress.extensions().get_ref::<TargetHttpVersion>()
                            == Some(&TargetHttpVersion(Version::HTTP_3))
                        {
                            counted.fetch_add(1, Ordering::Relaxed);
                        }
                        ingress.close(VarInt::from_u32(0), b"checked");
                        egress.close(VarInt::from_u32(0), b"checked");
                        Ok::<_, BoxError>(())
                    }
                },
            )),
        );
        let relaying = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });
        let origin_task = tokio::spawn(async move {
            let _connection = origin.accept().await.unwrap().await;
            origin
        });
        let config = ClientConfig::try_from_rama_tls(
            &trusting_with_alpn(&mitm_identity, b"h3"),
            TlsOptions::default(),
        )
        .unwrap();
        let connection = client
            .connect_with(config, ingress_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        relaying.await.unwrap().unwrap();
        connection.closed().await;
        assert_eq!(marked.load(Ordering::Relaxed), 1);
        drop(origin_task.await.unwrap());
    })
    .await
    .unwrap();
}
