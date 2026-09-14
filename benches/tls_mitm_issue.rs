//! MITM leaf issuance cost: cold per upstream key type, a cached hit, and a
//! burst of concurrent misses for one upstream cert (which must coalesce into
//! a single issuance).
//!
//! ```sh
//! cargo bench --bench tls_mitm_issue --features boring,crypto
//! ```

#![expect(
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
