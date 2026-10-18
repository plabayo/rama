//! Loopback native TLS/QUIC/HTTP relay fixture for independent packet comparisons.
//!
//! Build this target with `--no-default-features --features http-full,boring`.
//! The external driver supplies an origin, a local CA and an owned readiness
//! file through RAMA_NATIVE_RELAY_FIXTURE_CONFIG. SSLKEYLOGFILE records both
//! terminated legs. No user-agent profile layer or dependency is needed.

use rama::{
    Layer,
    combinators::Either,
    crypto::pki_types::CertificateDer,
    error::BoxError,
    graceful::Shutdown,
    http::{
        layer::upgrade::mitm::HttpUpgradeMitmRelayLayer,
        proto::h3::Code,
        proxy::{
            h3::Http3MitmRelay,
            mitm::{DefaultErrorResponse, HttpMitmRelay},
        },
        ws::handshake::matcher::HttpWebSocketRelayServiceRequestMatcher,
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::stream::Socket as _,
    quic::{
        proto::VarInt,
        proxy::{PeekQuicClientHelloService, QuicMitmRelay},
        tls::BoringTlsProvider,
    },
    rt::Executor,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    tls::{
        boring::{
            core::{pkey::PKey, x509::X509},
            proxy::{
                TlsMitmRelay,
                cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
            },
        },
        client::TlsClientConfig,
        server::PeekTlsClientHelloService,
    },
    udp::{DatagramDemux, DemuxConfig, UdpPacketSocket, proxy::DatagramToProxyBridge},
};
use serde::Deserialize;
use std::{fs, net::SocketAddr, num::NonZeroUsize, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    H1,
    H2,
    H3,
}

#[derive(Deserialize)]
struct Config {
    protocol: Protocol,
    origin: SocketAddr,
    ca: PathBuf,
    key: PathBuf,
    ready: PathBuf,
    mirror: bool,
    validate_address: bool,
}

#[tokio::test]
#[ignore = "long-lived fixture driven by the external native relay runner"]
async fn relay_fixture() -> Result<(), BoxError> {
    let path = std::env::var("RAMA_NATIVE_RELAY_FIXTURE_CONFIG")?;
    let config: Config = serde_json::from_slice(&fs::read(path)?)?;
    let certificate = X509::from_pem(&fs::read(config.ca)?)?;
    let key = PKey::private_key_from_pem(&fs::read(config.key)?)?;

    let shutdown = Shutdown::default();
    let executor = Executor::graceful(shutdown.guard());
    let address = match config.protocol {
        Protocol::H1 | Protocol::H2 => {
            let listener = TcpListener::bind_address("127.0.0.1:0", executor.clone()).await?;
            let address = listener.local_addr()?;
            // Upgrade/Extended CONNECT metadata selects the existing byte relay. No
            // WebSocket messages are decoded or rewritten by this transparent fixture.
            let http = HttpMitmRelay::new(executor.clone()).with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                HttpUpgradeMitmRelayLayer::new(
                    executor.clone(),
                    HttpWebSocketRelayServiceRequestMatcher::default_with_exec(executor),
                ),
                ArcLayer::new(),
            ));
            let tls = TlsMitmRelay::new_cached_in_memory(certificate, key).into_layer(http);

            // The negative control omits only ingress-derived ClientHello mirroring.
            // Both branches still terminate TLS and use the same native HTTP relay.
            let application = if config.mirror {
                Either::A(
                    ConsumeErrLayer::default().into_layer(PeekTlsClientHelloService::new(tls)),
                )
            } else {
                Either::B(ConsumeErrLayer::default().into_layer(tls))
            };
            let service = IoToProxyBridgeIoLayer::new(config.origin).into_layer(application);
            shutdown.spawn_task_fn(move |_guard| async move {
                listener.serve(service).await;
            });

            address
        }
        Protocol::H3 => {
            let anchors = vec![CertificateDer::from(certificate.to_der()?)];
            let egress_tls = TlsClientConfig::new().try_with_server_trust_anchors(anchors)?;
            let issuer = CachedBoringMitmCertIssuer::new(InMemoryBoringMitmCertIssuer::new(
                certificate,
                key,
            ));
            let terminate = QuicMitmRelay::new(
                issuer,
                executor.clone(),
                egress_tls,
                VarInt::try_from(Code::H3_INTERNAL_ERROR.value())?,
            )
            // This fixture measures one Initial flight; Retry has a separate negative control.
            .with_validate_address(config.validate_address)
            .with_mirror_client(config.mirror)
            .into_layer(Http3MitmRelay::new(executor.clone()));
            let peek = PeekQuicClientHelloService::new(BoringTlsProvider, terminate);
            let association = DatagramToProxyBridge::new(peek, config.origin);
            let listener = UdpPacketSocket::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?.into_std();
            // A failed local probe cannot retain unbounded associations or queues.
            let demux = DatagramDemux::new(
                listener,
                DemuxConfig {
                    associations: NonZeroUsize::new(16).expect("nonzero association budget"),
                    queue: NonZeroUsize::new(64).expect("nonzero datagram budget"),
                    idle_timeout: Duration::from_secs(15),
                    receive_bytes: NonZeroUsize::new(65536).expect("nonzero receive budget"),
                    queued_bytes: NonZeroUsize::new(262144).expect("nonzero queue budget"),
                },
            );
            shutdown.spawn_task_fn(move |_guard| async move {
                demux
                    .serve(executor, association)
                    .await
                    .expect("native fixture datagram demux");
            });
            address
        }
    };

    let pending = config.ready.with_extension("pending");
    fs::write(
        &pending,
        serde_json::to_vec(
            &serde_json::json!({ "listen": address, "ua_enabled": cfg!(feature = "ua") }),
        )?,
    )?;
    fs::rename(pending, config.ready)?;
    shutdown.shutdown_with_limit(Duration::from_secs(5)).await?;
    Ok(())
}
