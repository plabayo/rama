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

use std::sync::LazyLock;

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

async fn burst<R>(resolver: R, lookups: usize) -> usize
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    let tasks = (0..lookups).map(|_| {
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let (v6, v4) = tokio::join!(
                resolver.lookup_ipv6(HOST.clone()).count(),
                resolver.lookup_ipv4(HOST.clone()).count(),
            );
            v6 + v4
        })
    });
    join_all(tasks).await.into_iter().map(Result::unwrap).sum()
}

fn cold<R>(bencher: Bencher, lookups: usize, new: fn() -> R)
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    bencher
        .with_inputs(new)
        .bench_local_values(|resolver| black_box(RT.block_on(burst(resolver, lookups))));
}

fn warm<R>(bencher: Bencher, lookups: usize, new: fn() -> R)
where
    R: DnsAddressResolver + Clone + Send + Sync + 'static,
{
    let resolver = new();
    RT.block_on(burst(resolver.clone(), 1));
    bencher.bench_local(|| black_box(RT.block_on(burst(resolver.clone(), lookups))));
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
