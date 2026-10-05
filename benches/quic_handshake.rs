//! QUIC server handshake cost with a fixed certificate versus certificates issued per
//! ClientHello (the dynamic issuer and the in-memory CA, both with a warm cache).
//!
//! Each iteration is one client handshake on loopback against a serving endpoint, closed
//! once established. Issued cases add the ClientHello read before accepting, the cache hit
//! and a per-connection TLS context. The `split` cases offer enough ALPN protocols for the
//! ClientHello to span two Initial packets.
//!
//! ```sh
//! cargo bench --bench quic_handshake --features quic,boring,crypto
//! ```
#![expect(clippy::unwrap_used, reason = "benchmark failures must fail the run")]

use divan::AllocProfiler;
use rama::crypto::cert::CertificateAuthorityData;
use rama::{
    error::BoxError,
    net::tls::ApplicationProtocol,
    quic::{
        ClientConfig, Connection, Endpoint, ServerConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::service_fn,
    tls::{
        boring::server::{BoringServerConfigExt as _, ServerCertIssuerData, ServerCertIssuerKind},
        client::TlsClientConfig,
        server::{
            CertificateIssuanceContext, DynamicCertIssuer, LeafCertConfig, SelfSignedCaConfig,
            ServerAuthData, TlsServerConfig,
        },
    },
    utils::collections::smallvec::SmallVec,
};
use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    runtime::{Builder, Runtime},
    time::timeout,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const ALPN: &[u8] = b"rama-quic/handshake-bench";
const DEADLINE: Duration = Duration::from_secs(30);
const CASES: [&str; 6] = [
    "fixed",
    "fixed_split",
    "dynamic_issuer",
    "dynamic_issuer_split",
    "in_memory_ca",
    "in_memory_ca_split",
];

fn main() {
    divan::main();
}

/// Hands out one pre-issued certificate for every name.
struct PreIssued(ServerAuthData);

impl DynamicCertIssuer for PreIssued {
    async fn issue_cert(
        &self,
        _context: CertificateIssuanceContext,
    ) -> Result<ServerAuthData, BoxError> {
        Ok(self.0.clone())
    }
}

fn alpn(split: bool) -> SmallVec<[ApplicationProtocol; 2]> {
    let padding = if split { 24 } else { 0 };
    (0..padding)
        .map(|n: u8| ApplicationProtocol::from(vec![b'a' + n % 26; 96]))
        .chain([ApplicationProtocol::from(ALPN)])
        .collect()
}

struct Loopback {
    runtime: Runtime,
    client: Endpoint,
    client_config: ClientConfig,
    server: SocketAddr,
}

impl Loopback {
    fn new(case: &str) -> Self {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
        let leaf = ServerAuthData::new_issued_by(&ca, Default::default()).unwrap();
        let base = TlsServerConfig::new().with_alpn(alpn(false));
        let server_tls = match case.trim_end_matches("_split") {
            "fixed" => base.with_server_auth(leaf),
            "dynamic_issuer" => base.with_cert_issuer(ServerCertIssuerData::new(PreIssued(leaf))),
            _ => base.with_cert_issuer(ServerCertIssuerData::new(
                ServerCertIssuerKind::ProvidedCa {
                    ca: CertificateAuthorityData::try_new(
                        ca.certificate_chain().to_vec(),
                        ca.private_key().clone_key(),
                    )
                    .unwrap(),
                    leaf: LeafCertConfig::default(),
                },
            )),
        };
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn(case.ends_with("_split")))
            .try_with_server_trust_anchors([ca.certificate_chain()[0].clone()])
            .unwrap();
        let options = TlsOptions::default();
        let server_config =
            ServerConfig::try_from_rama_tls_with_provider(&server_tls, options, &BoringTlsProvider)
                .unwrap();
        let client_config =
            ClientConfig::try_from_rama_tls_with_provider(&client_tls, options, &BoringTlsProvider)
                .unwrap();
        let (client, server) = runtime.block_on(async {
            let server = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            let addr = server.local_addr().unwrap();
            tokio::spawn(server.serve(
                Executor::new(),
                service_fn(async |connection: Connection| {
                    _ = connection.closed().await;
                    Ok::<_, Infallible>(())
                }),
            ));
            let client = Endpoint::build(Executor::new())
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            (client, addr)
        });
        let loopback = Self {
            runtime,
            client,
            client_config,
            server,
        };
        // Warm the issuer caches, so the issued cases measure a cache hit.
        loopback.handshake();
        loopback
    }

    fn handshake(&self) {
        self.runtime.block_on(async {
            let connection = timeout(
                DEADLINE,
                self.client
                    .connect_with(self.client_config.clone(), self.server, "localhost")
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            connection.close(0u32, b"done");
        });
    }
}

#[divan::bench(args = CASES, sample_count = 200)]
fn handshake(bencher: divan::Bencher, case: &str) {
    let loopback = Loopback::new(case);
    bencher.bench_local(|| loopback.handshake());
}
