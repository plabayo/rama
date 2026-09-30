//! Lookup cost of the host-backed DNS resolvers: a burst of concurrent A +
//! AAAA lookups for one name, as when many connections to one host open at
//! once. `cold` uses a fresh resolver per burst, `warm` reuses one.
//!
//! Resolves `RAMA_DNS_BENCH_HOST` (default `localhost`) through the real host
//! resolver, so only compare runs made on the same machine.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use divan::{Bencher, black_box};
use rama::{
    dns::client::{NativeDnsResolver, TokioDnsResolver, resolver::DnsAddressResolver},
    futures::{StreamExt as _, future::join_all},
    net::address::Domain,
};
use tokio::runtime::Runtime;

fn main() {
    divan::main();
}

static RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
});

static HOST: LazyLock<Domain> = LazyLock::new(|| {
    std::env::var("RAMA_DNS_BENCH_HOST")
        .unwrap_or_else(|_| "localhost".to_owned())
        .parse()
        .unwrap()
});

const BURSTS: &[usize] = &[1, 64, 1024];

/// Lookups that resolved no address during the current bench.
static UNRESOLVED: AtomicUsize = AtomicUsize::new(0);

/// Addresses resolved by `lookups` concurrent A + AAAA lookups; errors count as none.
async fn burst<R>(resolver: R, lookups: usize) -> usize
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    let tasks = (0..lookups).map(|_| {
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let (v6, v4) = tokio::join!(
                resolver
                    .lookup_ipv6(HOST.clone())
                    .filter(|result| std::future::ready(result.is_ok()))
                    .count(),
                resolver
                    .lookup_ipv4(HOST.clone())
                    .filter(|result| std::future::ready(result.is_ok()))
                    .count(),
            );
            if v6 + v4 == 0 {
                UNRESOLVED.fetch_add(1, Ordering::Relaxed);
            }
            v6 + v4
        })
    });
    join_all(tasks).await.into_iter().map(Result::unwrap).sum()
}

/// Fail loudly instead of timing lookups of a host that does not resolve.
fn assert_resolves<R>(resolver: R)
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    assert!(
        RT.block_on(burst(resolver, 1)) > 0,
        "{} does not resolve; set RAMA_DNS_BENCH_HOST",
        *HOST,
    );
    UNRESOLVED.store(0, Ordering::Relaxed);
}

/// A timing that includes failed lookups must not pass for a fast one.
fn report_unresolved<R>(lookups: usize) {
    let unresolved = UNRESOLVED.swap(0, Ordering::Relaxed);
    if unresolved > 0 {
        eprintln!(
            "warning: {} x{lookups}: {unresolved} lookups resolved nothing; these timings include failures",
            std::any::type_name::<R>(),
        );
    }
}

fn cold<R>(bencher: Bencher, lookups: usize, new: fn() -> R)
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    assert_resolves(new());
    bencher
        .with_inputs(new)
        .bench_local_values(|resolver| black_box(RT.block_on(burst(resolver, lookups))));
    report_unresolved::<R>(lookups);
}

fn warm<R>(bencher: Bencher, lookups: usize, new: fn() -> R)
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    let resolver = new();
    assert_resolves(resolver.clone());
    bencher.bench_local(|| black_box(RT.block_on(burst(resolver.clone(), lookups))));
    report_unresolved::<R>(lookups);
}

mod native {
    use super::*;

    #[divan::bench(args = BURSTS)]
    fn cold(bencher: Bencher, lookups: usize) {
        super::cold(bencher, lookups, NativeDnsResolver::default);
    }

    #[divan::bench(args = BURSTS)]
    fn warm(bencher: Bencher, lookups: usize) {
        super::warm(bencher, lookups, NativeDnsResolver::default);
    }
}

mod tokio_getaddrinfo {
    use super::*;

    #[divan::bench(args = BURSTS)]
    fn cold(bencher: Bencher, lookups: usize) {
        super::cold(bencher, lookups, TokioDnsResolver::new);
    }

    #[divan::bench(args = BURSTS)]
    fn warm(bencher: Bencher, lookups: usize) {
        super::warm(bencher, lookups, TokioDnsResolver::new);
    }
}
