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
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    graceful::Shutdown,
    http::{
        conn::{H2ClientContextParams, H2ServerContextParams},
        core::h3::connection::Config as H3Config,
        layer::upgrade::mitm::HttpUpgradeMitmRelayLayer,
        proto::{h2::frame::DEFAULT_INITIAL_WINDOW_SIZE, h3::Code},
        proxy::{
            h3::Http3MitmRelay,
            mitm::{DefaultErrorResponse, H2InitialCreditLimits, HttpMitmRelay},
        },
        ws::handshake::matcher::HttpWebSocketRelayServiceRequestMatcher,
    },
    io::BridgeIo,
    layer::{ArcLayer, ConsumeErrLayer, MapInputLayer},
    net::stream::Socket as _,
    quic::{
        TransportConfig,
        proto::VarInt,
        proxy::{PeekQuicClientHelloService, QuicMitmRelay},
        tls::BoringTlsProvider,
    },
    rt::Executor,
    tcp::{TcpStream, proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing::{self, subscriber},
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
use std::{fs, net::SocketAddr, num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};

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
    // Caller-owned budgets, required together; absent preserves the old fixture.
    #[serde(default)]
    h2_ingress_initial_credit_max: Option<u32>,
    #[serde(default)]
    h2_egress_initial_credit_max: Option<u32>,
}

#[tokio::test]
#[ignore = "long-lived fixture driven by the external native relay runner"]
async fn relay_fixture() -> Result<(), BoxError> {
    // Keep connection failures visible in the retained fixture log.
    subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()?;

    let path = std::env::var("RAMA_NATIVE_RELAY_FIXTURE_CONFIG")?;
    let config: Config = serde_json::from_slice(&fs::read(path)?)?;
    let certificate = X509::from_pem(&fs::read(config.ca)?)?;
    let key = PKey::private_key_from_pem(&fs::read(config.key)?)?;

    let shutdown = Shutdown::default();
    let executor = Executor::graceful(shutdown.guard());
    let h2_credit_limits = match (
        config.h2_ingress_initial_credit_max,
        config.h2_egress_initial_credit_max,
    ) {
        (None, None) => None,
        (Some(ingress), Some(egress)) if matches!(&config.protocol, Protocol::H2) => {
            Some(H2InitialCreditLimits::try_new(ingress, egress)?)
        }
        _ => {
            return Err(BoxError::from_static_str(
                "H2 initial credit requires both explicit directional maxima and protocol h2",
            ));
        }
    };
    let address = match config.protocol {
        Protocol::H1 | Protocol::H2 => {
            let listener = TcpListener::bind_address("127.0.0.1:0", executor.clone()).await?;
            let address = listener.local_addr()?;
            // Upgrade/Extended CONNECT metadata selects the existing byte relay. No
            // WebSocket messages are decoded or rewritten by this transparent fixture.
            let http = HttpMitmRelay::new(executor.clone())
                .maybe_with_mirror_initial_h2_credit(if config.mirror {
                    h2_credit_limits
                } else {
                    None
                })
                .with_http_middleware((
                    ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                    HttpUpgradeMitmRelayLayer::new(
                        executor.clone(),
                        HttpWebSocketRelayServiceRequestMatcher::default_with_exec(executor),
                    ),
                    ArcLayer::new(),
                ));
            let tls = TlsMitmRelay::new_cached_in_memory(certificate, key).into_layer(http);

            // The negative control omits ingress-derived TLS and initial-credit mirroring.
            // Both branches still terminate TLS and use the same native HTTP relay.
            let application = if config.mirror {
                Either::A(
                    ConsumeErrLayer::default().into_layer(PeekTlsClientHelloService::new(tls)),
                )
            } else {
                Either::B(ConsumeErrLayer::default().into_layer(tls))
            };
            // Connector request options do not become options on its returned IO.
            // Configure each established leg explicitly before either TLS handshake.
            let application = MapInputLayer::new(move |bridge: BridgeIo<TcpStream, TcpStream>| {
                if h2_credit_limits.is_some() {
                    bridge.0.extensions().insert(H2ServerContextParams {
                        initial_connection_window_size: Some(DEFAULT_INITIAL_WINDOW_SIZE),
                        adaptive_window: Some(false),
                        ..Default::default()
                    });
                    bridge.1.extensions().insert(H2ClientContextParams {
                        init_connection_window_size: Some(DEFAULT_INITIAL_WINDOW_SIZE),
                        adaptive_window: Some(false),
                        ..Default::default()
                    });
                }
                bridge
            })
            .into_layer(application);
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
            // Both native hops can carry the datagrams advertised by the independent peer.
            // The mirror still retains the peer's exact frame-size limit on egress.
            let datagrams = Arc::new(
                TransportConfig::default().maybe_with_datagram_receive_buffer_size(Some(65_536)),
            );
            // The independent Go client advertises a finite 10 MiB field limit.
            // Reserve that budget explicitly; mirroring never raises it.
            let mut h3_egress = H3Config::default();
            h3_egress.decoder.max_field_section_size = 10 * 1024 * 1024;
            h3_egress.max_frame_size = 10 * 1024 * 1024;
            // The independent origin advertises a finite 1 MiB field limit.
            let mut h3_ingress = H3Config {
                extended_connect: true,
                ..Default::default()
            };
            h3_ingress.decoder.max_field_section_size = 1024 * 1024;
            h3_ingress.max_frame_size = 1024 * 1024;
            let relay = Http3MitmRelay::new(executor.clone())
                .with_ingress_config(h3_ingress)
                .with_egress_config(h3_egress);
            let terminate = QuicMitmRelay::new(
                issuer,
                executor.clone(),
                egress_tls,
                VarInt::try_from(Code::H3_INTERNAL_ERROR.value())?,
            )
            // This fixture measures one Initial flight; Retry has a separate negative control.
            .with_validate_address(config.validate_address)
            .with_ingress_transport(datagrams.clone())
            .with_egress_transport(datagrams)
            .with_mirror_client(config.mirror)
            .into_layer(relay);
            let peek = PeekQuicClientHelloService::new(BoringTlsProvider, terminate)
                .with_first_flight_retention(config.mirror);
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
