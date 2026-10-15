//! Conditional QUIC interception: peek each association's ClientHello, terminate HTTP/3 for
//! the server names you choose, and forward everything else untouched.
//!
//! Every client association on the UDP listener passes through, in order:
//!
//! - the demultiplexer, which gives each client its own association, bounded in number,
//!   queue and idle time;
//! - admission, which bounds associations per source (an IPv4 address or IPv6 /64) and in
//!   total, and how many start per second;
//! - the egress bridge, which connects a socket to the upstream for the association;
//! - the ClientHello peek, which reads the client's Initial flight without answering it.
//!   Datagrams that are not QUIC are forwarded; a QUIC flight that cannot be inspected is
//!   refused rather than forwarded uninspected.
//!
//! A peeked server name in `--intercept` is terminated: the client's address is validated
//! with a Retry, the upstream handshake runs with the client's version, name and offered
//! protocols, and the client gets a certificate for the upstream's identity, issued by this
//! proxy's own CA. HTTP/3 is then relayed request by request, with a response header marking
//! it; any other protocol is relayed stream by stream. Every other name is forwarded
//! datagram by datagram, never terminated.
//!
//! Note that this proxy is not production ready, and is only meant to show how the pieces
//! compose.
//!
//! # Run the example
//!
//! It needs an upstream to relay to, and the certificate that upstream presents:
//!
//! ```sh
//! cargo run -p rama-examples --bin quic_h3_mitm_proxy --features=http-full,boring -- \
//!     --upstream 127.0.0.1:4433 --upstream-ca origin-cert.pem \
//!     --intercept localhost --ca-out mitm-ca.pem
//! ```
//!
//! - `--listen <addr>`: where clients send. Default `127.0.0.1:62063`.
//! - `--upstream <addr>`: the upstream every association goes to. Required.
//! - `--upstream-ca <pem>`: the certificate the upstream presents. Required.
//! - `--intercept <name>`: a server name to terminate, in any case; repeat it for more. Default
//!   none.
//! - `--ca-out <pem>`: where to write this proxy's CA certificate, which a client must trust
//!   to talk to intercepted names.
//!
//! # Expected output
//!
//! ```text
//! INFO quic_h3_mitm_proxy: QUIC MITM proxy listening on 127.0.0.1:62063
//! ```
//!
//! An `http3_client_server` client pointed at the proxy, trusting `mitm-ca.pem`, gets the
//! upstream's response with `x-rama-mitm: h3` for an intercepted name.

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{num::NonZeroUsize, path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use rama::{
    Layer as _, Service,
    crypto::{
        cert::boring::generate_certificate_authority_x509,
        pki_types::{CertificateDer, pem::PemObject as _},
    },
    error::{BoxError, ErrorContext as _},
    graceful::Shutdown,
    http::{
        HeaderName, HeaderValue,
        layer::set_header::SetResponseHeaderLayer,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
    },
    io::BridgeIo,
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        address::{Domain, SocketAddress},
        stream::Socket as _,
        tls::ApplicationProtocol,
    },
    quic::{
        proto::VarInt,
        proxy::{
            AssociationLimits, InputWithQuicClientHello, PeekQuicClientHelloService,
            QuicAdmissionLayer, QuicAssociationAdmission, QuicMitmRelay, QuicRelay,
        },
        tls::BoringTlsProvider,
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing::{self, level_filters::LevelFilter, subscriber::EnvFilter},
    tls::{
        alpn::AlpnRouter,
        boring::proxy::cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
        client::TlsClientConfig,
        server::{CertificateSubject, SelfSignedCaConfig},
    },
    udp::{
        DatagramDemux, DemuxConfig, DemuxedSocket, PrefixedDatagramSocket, UdpPacketSender,
        UdpPacketSocket,
        proxy::{DatagramForwardService, DatagramToProxyBridge, EcnPolicy},
    },
    utils::octets::{kib, mib},
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:62063")]
    listen: SocketAddress,
    #[arg(long)]
    upstream: SocketAddress,
    #[arg(long)]
    upstream_ca: PathBuf,
    #[arg(long)]
    intercept: Vec<Domain>,
    #[arg(long)]
    ca_out: Option<PathBuf>,
}

/// A client association once its egress is connected: what the ClientHello peek reads.
type Association =
    BridgeIo<PrefixedDatagramSocket<DemuxedSocket<UdpPacketSender>>, UdpPacketSocket>;

/// An application error code closing both hops when an interception fails.
const FAILURE: u32 = 0x0101;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args = Args::parse();

    let graceful = Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let (ca_crt, ca_key) = generate_certificate_authority_x509(&SelfSignedCaConfig {
        subject: CertificateSubject {
            organisation_name: Some("QUIC H3 MITM Proxy Example".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    })
    .context("generate the MITM CA")?;
    if let Some(path) = &args.ca_out {
        tokio::fs::write(path, ca_crt.to_pem().context("encode the MITM CA")?)
            .await
            .context("write the MITM CA")?;
    }
    let issuer = CachedBoringMitmCertIssuer::new(InMemoryBoringMitmCertIssuer::new(ca_crt, ca_key));

    // Every certificate in the file is a trust anchor, so a system bundle works too.
    let upstream_anchors = CertificateDer::pem_file_iter(&args.upstream_ca)
        .context("read the upstream trust anchors")?
        .collect::<Result<Vec<_>, _>>()
        .context("parse the upstream trust anchors")?;
    let egress_tls = TlsClientConfig::new().try_with_server_trust_anchors(upstream_anchors)?;

    // HTTP/3 request by request, marking each response; anything else stream by stream.
    let h3 = Http3MitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-rama-mitm"),
            HeaderValue::from_static("h3"),
        ),
        ArcLayer::new(),
    ));
    let terminate = QuicMitmRelay::new(issuer, exec.clone(), egress_tls, VarInt::from_u32(FAILURE))
        .into_layer(
            AlpnRouter::new(ApplicationProtocol::HTTP_3, h3)
                .with_fallback(QuicRelay::new(VarInt::from_u32(FAILURE))),
        );
    let forward = DatagramForwardService::new(
        NonZeroUsize::new(65_536).expect("nonzero"),
        EcnPolicy::Discard,
    );

    let intercept: Arc<[Domain]> = args.intercept.into();
    let route = service_fn(move |input: InputWithQuicClientHello<Association>| {
        let terminate = terminate.clone();
        let intercept = intercept.clone();
        async move {
            // Domains compare case-insensitively, as DNS names do.
            let name = input.client_hello.client_hello.ext_server_name().cloned();
            if name.as_ref().is_some_and(|name| intercept.contains(name)) {
                tracing::info!(?name, "intercepting");
                terminate.serve(input).await
            } else {
                tracing::info!(?name, "forwarding");
                forward.serve(input.input).await.map_err(BoxError::from)
            }
        }
    });
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route).with_fallback(
        service_fn(move |input: Association| async move {
            forward.serve(input).await.map_err(BoxError::from)
        }),
    );

    let admission = QuicAssociationAdmission::try_new(AssociationLimits {
        active: NonZeroUsize::new(256).expect("nonzero"),
        active_per_source: NonZeroUsize::new(32).expect("nonzero"),
        sources: NonZeroUsize::new(1536).expect("nonzero"),
        tuples: NonZeroUsize::new(2048).expect("nonzero"),
        starts_per_window: NonZeroUsize::new(512).expect("nonzero"),
        starts_per_source_window: NonZeroUsize::new(64).expect("nonzero"),
        window: Duration::from_secs(1),
        quarantine: Duration::from_secs(2),
    })?;
    let association = QuicAdmissionLayer::new(admission)
        .into_layer(DatagramToProxyBridge::new(inspect, args.upstream));

    let listener = UdpPacketSocket::bind(args.listen).await?;
    tracing::info!("QUIC MITM proxy listening on {}", listener.local_addr()?);
    let demux = DatagramDemux::new(
        listener,
        DemuxConfig {
            associations: NonZeroUsize::new(1024).expect("nonzero"),
            queue: NonZeroUsize::new(64).expect("nonzero"),
            idle_timeout: Duration::from_secs(30),
            receive_bytes: NonZeroUsize::new(kib(64)).expect("nonzero"),
            queued_bytes: NonZeroUsize::new(mib(16)).expect("nonzero"),
        },
    );
    graceful.spawn_task(async move {
        if let Err(error) = demux.serve(exec, association).await {
            tracing::error!(%error, "QUIC MITM proxy listener failed");
        }
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;
    Ok(())
}
