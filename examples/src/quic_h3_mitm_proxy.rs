//! Conditional QUIC interception: peek each association's ClientHello, terminate HTTP/3 for
//! the server names you choose, and forward everything else untouched.
//!
//! See the [book’s short migration guide](https://ramaproxy.org/book/proxies/quic_migration.html)
//! for admission, migration routing, inspection and relay ordering.
//!
//! Every client association on the UDP listener passes through, in order:
//!
//! - the demultiplexer, which gives each client its own association, bounded in number,
//!   queue and idle time;
//! - admission, which bounds associations per source (an IPv4 address or IPv6 /64) and in
//!   total, and how many start per second;
//! - the ClientHello peek, whose optional migration router first returns known connection
//!   IDs to their original independent endpoint; otherwise it reads the Initial flight
//!   without answering it.
//!   Datagrams that are not QUIC are forwarded; a QUIC flight that cannot be inspected is
//!   refused rather than forwarded uninspected;
//! - interception policy, followed by the egress bridge opening the selected upstream.
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
//! - `--listen <addr>`: where clients send. Default `127.0.0.1:12063`.
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
//! INFO quic_h3_mitm_proxy: QUIC MITM proxy listening on 127.0.0.1:12063
//! ```
//!
//! An `http3_client_server` client pointed at the proxy, trusting `mitm-ca.pem`, gets the
//! upstream's response with `x-rama-mitm: h3` for an intercepted name.
//!
//! # Policy and limits
//!
//! The peek fallback forwards uninspectable associations by default, including unsupported
//! QUIC versions, malformed flights, exhausted inspection budgets and timeouts. It receives
//! `ClientHelloPeekStatus` and the QUIC rejection class. Applications requiring inspection
//! before forwarding can select `QuicPeekFallbackPolicy::NOT_QUIC` or per-class controls.
//! Once interception starts, handshake or relay failure closes that association: it cannot
//! fall back to the original encrypted connection.
//!
//! The demultiplexer allows 1024 associations, 64 queued datagrams per association and
//! 16 MiB queued overall, with a 30-second idle timeout. Admission further limits active
//! associations to 256 overall and 32 per source, and starts to 512 overall and 64 per source
//! per second. An IPv6 /64 is one source. The default peek deadline is two seconds; capture
//! allows 32 datagrams, 256 KiB input, 128 Initial packets, 2048 frame classifications,
//! 128 CRYPTO fragments, a 16 KiB ClientHello and 256 transport parameters.
//!
//! Platform association identity is the local/peer address pair. The optional migration registry
//! follows native CID ownership during the inspector's first receive: a changed tuple carrying an issued
//! CID joins the existing connection and undergoes ordinary QUIC path validation. Unknown
//! traffic retains the inspection/fallback policy. CID ownership is not authentication.
//! Connection/path limits bound the adapter; attached transports retain their own queue budgets.
//! Independent client connections retain independent endpoints and origin connections.
//! Closing the original association does not close a migrated connection.
//!
//! # Trust and preservation boundaries
//!
//! The CA private key exists in memory for this process; `--ca-out` exports only its public
//! certificate. Trust it in a disposable test client. Upstream certificates are verified
//! against `--upstream-ca`, using the inspected server name. The configured upstream socket
//! fixes the destination; an untrusted server name never chooses another target.
//!
//! The relay mirrors each client's first flight as far as its native implementation can,
//! within the egress TLS/transport limits, and traces what it lowers or drops; see
//! `QuicMitmRelay::with_mirror_client`. This does not make the encrypted connections
//! identical. Each hop creates fresh secrets, connection
//! IDs and packet numbers; QPACK state, compressed header bytes, timing, ACK behavior and
//! cross-path behavior are not preserved. Early data is disabled on both terminating hops;
//! clients resend rejected 0-RTT after the handshake. HTTP/3 server push is unsupported.
//!
//! HTTP/3 negotiates each hop's SETTINGS before advertising dependent capabilities. Request
//! and response metadata are relayed semantically, including trailers and supported tunnel
//! semantics; request-owned values are not a license to replay captured credentials. The
//! `x-rama-mitm` response field is an intentional visible difference. Generic non-H3 stream
//! relaying cannot translate arbitrary application stream-ID or datagram references.
//!
//! `just examples/tests/quic-relay-wire OUTPUT` records direct, forwarded and terminated traffic and
//! checks it with tshark. Its report proves the stated wire invariants, not full browser
//! profile equivalence. TLS session-key logs are temporary decoding inputs and are deleted;
//! retain decoded fields and ciphertext captures, never session keys in review evidence.

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
    graceful::Scope,
    http::{
        HeaderName, HeaderValue,
        layer::set_header::SetResponseHeaderLayer,
        proxy::{h3::Http3MitmRelay, mitm::DefaultErrorResponse},
    },
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
            QuicAdmissionLayer, QuicAssociationAdmission, QuicMitmIngress, QuicMitmIngressConfig,
            QuicMitmRelay, QuicRelay,
        },
        tls::BoringTlsProvider,
    },
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
    #[arg(long, default_value = "127.0.0.1:12063")]
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
type Association = PrefixedDatagramSocket<DemuxedSocket<UdpPacketSender>>;

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

    let scope = Scope::new()
        .with_default_signal()
        .with_grace(Duration::from_secs(30));
    let weak_scope = scope.clone_weak();

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
    let h3 = Http3MitmRelay::new(weak_scope.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-rama-mitm"),
            HeaderValue::from_static("h3"),
        ),
        ArcLayer::new(),
    ));
    let ingress = QuicMitmIngress::new(
        weak_scope.clone(),
        QuicMitmIngressConfig {
            max_registered_connections: rama::utils::macros::nonzero!(256),
            max_paths_per_connection: rama::utils::macros::nonzero!(4),
            path_validation_timeout: std::time::Duration::from_secs(5),
            capabilities: None,
        },
    );
    let terminate = QuicMitmRelay::new(
        issuer,
        weak_scope.clone(),
        egress_tls,
        VarInt::from_u32(FAILURE),
    )
    .with_migration_ingress(ingress.clone())
    .into_layer(
        AlpnRouter::new(ApplicationProtocol::HTTP_3, h3)
            .with_fallback(QuicRelay::new(VarInt::from_u32(FAILURE))),
    );
    let forward = DatagramForwardService::new(
        NonZeroUsize::new(65_536).expect("nonzero"),
        EcnPolicy::Discard,
    );

    let terminate = DatagramToProxyBridge::new(terminate, args.upstream);
    let forward = DatagramToProxyBridge::new(forward, args.upstream);
    let intercept: Arc<[Domain]> = args.intercept.into();
    let route_forward = forward.clone();
    let supervisor = ingress.clone();
    let route = service_fn(move |input: InputWithQuicClientHello<Association>| {
        let terminate = terminate.clone();
        let intercept = intercept.clone();
        let supervisor = supervisor.clone();
        let forward = route_forward.clone();
        async move {
            // Domains compare case-insensitively, as DNS names do.
            let name = input.peeked.client_hello.ext_server_name().cloned();
            if name.as_ref().is_some_and(|name| intercept.contains(name)) {
                tracing::info!(?name, "intercepting");
                supervisor
                    .run_connection(async move { terminate.serve(input).await })
                    .await
            } else {
                tracing::info!(?name, "forwarding");
                forward.serve(input.input).await
            }
        }
    });
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route)
        .with_router(ingress)
        .with_fallback(service_fn(move |input: Association| {
            let forward = forward.clone();
            async move { forward.serve(input).await }
        }));

    let admission = QuicAssociationAdmission::try_new(AssociationLimits {
        active: rama::utils::macros::nonzero!(256),
        active_per_source: rama::utils::macros::nonzero!(32),
        sources: rama::utils::macros::nonzero!(1536),
        tuples: rama::utils::macros::nonzero!(2048),
        starts_per_window: rama::utils::macros::nonzero!(512),
        starts_per_source_window: rama::utils::macros::nonzero!(64),
        window: Duration::from_secs(1),
        quarantine: Duration::from_secs(2),
    })?;
    // Rate and source limits apply to new migration paths too: a CID match is not proof
    // that an unauthenticated sender should consume an unbounded number of path slots.
    let association = QuicAdmissionLayer::new(admission).into_layer(inspect);

    let listener = UdpPacketSocket::bind(args.listen).await?;
    tracing::info!("QUIC MITM proxy listening on {}", listener.local_addr()?);
    let demux = DatagramDemux::new(
        listener,
        DemuxConfig {
            associations: rama::utils::macros::nonzero!(1024),
            queue: rama::utils::macros::nonzero!(64),
            idle_timeout: Duration::from_secs(30),
            receive_bytes: NonZeroUsize::new(kib(64)).expect("nonzero"),
            queued_bytes: NonZeroUsize::new(mib(16)).expect("nonzero"),
        },
    );
    scope.spawn_task(async move {
        if let Err(error) = demux.serve(weak_scope, association).await {
            tracing::error!(%error, "QUIC MITM proxy listener failed");
        }
    });

    scope.join().await.context("graceful shutdown")?;
    Ok(())
}
