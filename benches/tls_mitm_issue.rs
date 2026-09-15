//! MITM leaf issuance cost: cold per upstream key type, a cached hit, and a
//! burst of concurrent misses for one upstream cert (which must coalesce into
//! a single issuance).
//!
//! ```sh
//! cargo bench --bench tls_mitm_issue --features boring,crypto
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::counter::ItemsCount;
use rama::{
    crypto::cert::boring::{generate_certificate_authority_x509, issue_leaf_certificate},
    futures::future::join_all,
    tls::{
        boring::{
            core::x509::X509,
            proxy::cert_issuer::{
                BoringMitmCertIssuer, CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer,
            },
        },
        server::{CertificateKeyKind, LeafCertConfig, LeafCertRequest, SelfSignedCaConfig},
    },
};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

const BURST: usize = 8;

/// An "upstream" leaf whose key type the MITM issuer mirrors.
fn upstream_cert(key_kind: CertificateKeyKind) -> X509 {
    let ca = SelfSignedCaConfig {
        key_kind,
        ..Default::default()
    };
    let (ca_cert, ca_key) = generate_certificate_authority_x509(&ca).expect("generate CA");
    let request = LeafCertRequest {
        config: LeafCertConfig {
            key_kind,
            ..Default::default()
        },
        ..Default::default()
    };
    issue_leaf_certificate(&request, &ca_cert, &ca_key)
        .expect("issue upstream leaf")
        .0
}

fn mitm_issuer() -> InMemoryBoringMitmCertIssuer {
    InMemoryBoringMitmCertIssuer::try_new_self_signed(&SelfSignedCaConfig::default())
        .expect("self-signed MITM CA")
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build")
}

/// Cold issuance: key generation + signing for a never-seen upstream cert.
#[divan::bench(
    args = [CertificateKeyKind::EcP256, CertificateKeyKind::Rsa2048],
    sample_count = 10,
    sample_size = 1
)]
fn issue_cold(bencher: divan::Bencher, key_kind: CertificateKeyKind) {
    let runtime = current_thread_runtime();
    let issuer = mitm_issuer();
    let upstream = upstream_cert(key_kind);
    bencher.bench_local(|| {
        runtime
            .block_on(issuer.issue_mitm_x509_cert(upstream.clone()))
            .expect("issue mirrored leaf")
    });
}

/// Warm cache: the per-handshake cost once the leaf exists.
#[divan::bench]
fn issue_cached_hit(bencher: divan::Bencher) {
    let runtime = current_thread_runtime();
    let issuer = CachedBoringMitmCertIssuer::new(mitm_issuer());
    let upstream = upstream_cert(CertificateKeyKind::EcP256);
    runtime
        .block_on(issuer.issue_mitm_x509_cert(upstream.clone()))
        .expect("warm cache");
    bencher.bench_local(|| {
        runtime
            .block_on(issuer.issue_mitm_x509_cert(upstream.clone()))
            .expect("cached mirrored leaf")
    });
}

/// Full relay handshake (egress connect, mirror, ingress accept) over in-memory
/// duplex pipes against a warm cert cache: the steady-state per-connection cost
/// of intercepting a host that was seen before.
#[divan::bench(args = [true, false], sample_count = 50)]
fn relay_handshake_warm(bencher: divan::Bencher, acceptor_cache: bool) {
    use rama::{
        ServiceInput,
        io::BridgeIo,
        tls::{
            boring::{
                client::TlsConnectorData,
                core::{
                    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
                    tokio as boring_tokio,
                },
                proxy::{MitmAcceptorCacheConfig, TlsMitmRelay},
            },
            client::{ServerVerifyMode, TlsClientConfig},
        },
    };
    use tokio::io::duplex;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime build");

    // Upstream server presenting an EC leaf.
    let upstream_ca = SelfSignedCaConfig::default();
    let (ca_cert, ca_key) = generate_certificate_authority_x509(&upstream_ca).expect("CA");
    let (upstream_cert, upstream_key) =
        issue_leaf_certificate(&LeafCertRequest::default(), &ca_cert, &ca_key).expect("leaf");
    let mut upstream = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    upstream.set_certificate(&upstream_cert).unwrap();
    upstream.set_private_key(&upstream_key).unwrap();
    let upstream = upstream.build();

    let (mitm_ca, mitm_key) =
        generate_certificate_authority_x509(&SelfSignedCaConfig::default()).expect("MITM CA");
    let relay = TlsMitmRelay::new_cached_in_memory(mitm_ca, mitm_key)
        .maybe_with_acceptor_cache(acceptor_cache.then(MitmAcceptorCacheConfig::default));
    let egress_config = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);

    let handshake = || async {
        let (client_io, relay_ingress) = duplex(1 << 16);
        let (relay_egress, upstream_io) = duplex(1 << 16);
        let upstream = upstream.clone();
        let server =
            tokio::spawn(async move { boring_tokio::accept(&upstream, upstream_io).await });
        // the relay service builds this per flow as well
        let egress_cd = TlsConnectorData::try_from(&egress_config).expect("egress connector data");
        let relay_task = relay.handshake(
            BridgeIo(
                ServiceInput::new(relay_ingress),
                ServiceInput::new(relay_egress),
            ),
            Some(egress_cd),
        );
        let mut conn = SslConnector::builder(SslMethod::tls_client()).unwrap();
        conn.set_verify(SslVerifyMode::NONE);
        let mut cfg = conn.build().configure().unwrap();
        cfg.set_verify_hostname(false);
        let client = boring_tokio::connect(cfg, Some("localhost"), client_io);
        let (relayed, client) = tokio::join!(relay_task, client);
        relayed.expect("relay handshake");
        client.expect("client handshake");
        server.await.unwrap().expect("upstream handshake");
    };

    // warm the cert cache
    runtime.block_on(handshake());
    bencher.bench_local(|| runtime.block_on(handshake()));
}

/// The egress connector data the relay service builds for every intercepted
/// flow (it is not clonable): a fresh `SSL_CTX` per connection.
#[divan::bench]
fn egress_connector_data_build(bencher: divan::Bencher) {
    use rama::tls::{
        boring::client::TlsConnectorData,
        client::{ServerVerifyMode, TlsClientConfig},
    };
    let egress_config = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    bencher.bench_local(|| TlsConnectorData::try_from(&egress_config).expect("connector data"));
}

/// A burst of concurrent misses for one upstream cert (a browser opening its
/// parallel sockets to a new host) against a cold cache: should cost about one
/// issuance, not `BURST` of them.
#[divan::bench(sample_count = 10, sample_size = 1)]
fn issue_cold_burst_coalesced(bencher: divan::Bencher) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .expect("runtime build");
    let inner = mitm_issuer();
    let upstream = upstream_cert(CertificateKeyKind::Rsa2048);
    bencher
        .counter(ItemsCount::new(BURST))
        .with_inputs(|| CachedBoringMitmCertIssuer::new(inner.clone()))
        .bench_local_values(|issuer| {
            runtime.block_on(async {
                let issued =
                    join_all((0..BURST).map(|_| issuer.issue_mitm_x509_cert(upstream.clone())))
                        .await;
                for issued in issued {
                    issued.expect("issue mirrored leaf");
                }
            })
        });
}
