//! Type-erased [`Extensions`] lookups on the shape of a proxied request.
//!
//! A request carries a few levels of extensions: its own, the wrapped ingress
//! and egress connections (each with the metadata the connectors published),
//! and forks of these. Most lookups of optional extensions are misses, which
//! walk all of it, and the pooled client resolves the 24-slot Boring TLS
//! config, once per pooled connection it considers, on every request.
//!
//! Which types share a slot of the lookup filters depends on their `TypeId`s,
//! so a single type can be lucky or not. Every lookup benchmark therefore
//! asks for several types, or on several differently populated shapes, and
//! reports the time of the whole round (the item counter says how many
//! lookups that is).

use divan::{black_box, counter::ItemsCount};
use rama::{
    extensions::{Egress, Extension, Extensions, Ingress},
    tls::{boring::client::BoringTlsClientConfigProvider, client::TlsClientConfigProvider as _},
};

mod bench_alloc;

fn main() {
    divan::main();
}

/// Stand-in for the many small extension types connectors and layers insert.
#[derive(Debug, Clone, Copy)]
struct Marker<const N: usize>;

impl<const N: usize> Extension for Marker<N> {}

/// Types nothing ever inserts: the miss case.
#[derive(Debug, Clone, Copy)]
struct Absent<const N: usize>;

impl<const N: usize> Extension for Absent<N> {}

/// Types only the oldest entries of the wrapped ingress connection hold.
#[derive(Debug, Clone, Copy)]
struct Deep<const N: usize>;

impl<const N: usize> Extension for Deep<N> {}

macro_rules! insert_all {
    ($ext:expr, $ty:ident, $offset:literal; $($n:literal)+) => {
        $( $ext.insert($ty::<{ $offset + $n }>); )+
    };
}

macro_rules! get_all {
    ($ext:expr, $ty:ident; $($n:literal)+) => {
        $( black_box($ext.get_ref::<$ty<$n>>()); )+
    };
}

/// The extensions of one proxied request, in the shape of the terminating
/// forward proxy: connection extensions (ingress, egress) wrapped in the
/// request, with a fork for the response.
struct RequestShape {
    request: Extensions,
    response: Extensions,
}

/// `offset` picks other marker types, so shapes differ in how their types
/// spread over the filter slots.
macro_rules! request_shape {
    ($name:ident, $offset:literal) => {
        fn $name() -> RequestShape {
            // the accepted client connection: transport and TLS metadata
            let ingress = Extensions::new();
            insert_all!(ingress, Deep, 0; 0 1 2 3 4 5 6 7);
            insert_all!(ingress, Marker, $offset; 0 1 2 3 4 5 6 7 8);

            // the pooled upstream connection
            let egress = Extensions::new();
            insert_all!(egress, Marker, $offset; 10 11 12 13 14 15 16 17 18 19 20);

            let request = Extensions::new();
            request.insert(Ingress(ingress));
            insert_all!(request, Marker, $offset; 30 31 32);
            request.insert(Egress(egress.clone()));
            request.insert(Egress(egress));

            let response = request.fork();
            insert_all!(response, Marker, $offset; 40 41);

            assert!(response.get_ref::<Deep<7>>().is_some());
            assert!(response.get_ref::<Absent<0>>().is_none());
            assert!(response.egress().is_some());
            RequestShape { request, response }
        }
    };
}

request_shape!(shape_0, 0);
request_shape!(shape_1, 100);
request_shape!(shape_2, 200);
request_shape!(shape_3, 300);

fn shapes() -> [RequestShape; 4] {
    [shape_0(), shape_1(), shape_2(), shape_3()]
}

/// 16 optional extensions that are not set anywhere, on 4 shapes: 64 lookups.
#[divan::bench]
fn get_ref_miss_x64(bencher: divan::Bencher) {
    let shapes = shapes();
    bencher.counter(ItemsCount::new(64usize)).bench_local(|| {
        for shape in &shapes {
            get_all!(shape.response, Absent; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
        }
    });
}

/// Extensions in the oldest entries of the wrapped ingress connection,
/// on 4 shapes: 32 lookups.
#[divan::bench]
fn get_ref_hit_oldest_x32(bencher: divan::Bencher) {
    let shapes = shapes();
    bencher.counter(ItemsCount::new(32usize)).bench_local(|| {
        for shape in &shapes {
            get_all!(shape.response, Deep; 0 1 2 3 4 5 6 7);
        }
    });
}

/// The newest entry: the best case, which the filters must not slow down.
#[divan::bench]
fn get_ref_hit_newest(bencher: divan::Bencher) {
    let shape = shape_0();
    bencher.bench_local(|| black_box(shape.response.get_ref::<Marker<41>>()));
}

/// The 24 optional TLS overrides, none set (the common case), on 4 shapes:
/// what the pool resolves per considered connection to decide whether it
/// may be reused.
#[divan::bench]
fn tls_pool_id_no_overrides_x4(bencher: divan::Bencher) {
    let shapes = shapes();
    let provider = BoringTlsClientConfigProvider;
    bencher.counter(ItemsCount::new(4usize)).bench_local(|| {
        for shape in &shapes {
            black_box(provider.pool_id(&shape.request));
        }
    });
}

/// The same 24-way lookup on a store that holds no TLS extension at all.
#[divan::bench]
fn tls_pool_id_empty(bencher: divan::Bencher) {
    let extensions = Extensions::new();
    let provider = BoringTlsClientConfigProvider;
    bencher.bench_local(|| black_box(provider.pool_id(&extensions)));
}

/// Inserting into a fresh level, as done for every request and response.
#[divan::bench]
fn new_level_and_insert(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let ext = Extensions::new();
        ext.insert(Marker::<0>);
        ext.insert(Marker::<1>);
        black_box(ext)
    });
}

/// Forking the response extensions off the request.
#[divan::bench]
fn fork_and_insert(bencher: divan::Bencher) {
    let shape = shape_0();
    bencher.bench_local(|| {
        let fork = shape.request.fork();
        fork.insert(Marker::<0>);
        black_box(fork)
    });
}

/// A chain of `depth` levels, each holding two entries.
fn chain(depth: usize) -> Extensions {
    let mut ext = Extensions::new();
    ext.insert(Marker::<0>);
    ext.insert(Marker::<1>);
    for _ in 1..depth {
        ext = ext.fork();
        ext.insert(Marker::<2>);
        ext.insert(Marker::<3>);
    }
    ext
}

/// Cloning a handle, as done when wrapping a connection or forking.
#[divan::bench(args = [1, 4, 8])]
fn clone_chain(bencher: divan::Bencher, depth: usize) {
    let ext = chain(depth);
    bencher.bench_local(|| black_box(ext.clone()));
}

/// A fork nothing is inserted into, as left by layers that fork defensively.
#[divan::bench(args = [1, 4, 8])]
fn fork_chain_empty(bencher: divan::Bencher, depth: usize) {
    let ext = chain(depth);
    bencher.bench_local(|| black_box(ext.fork()));
}

/// Wrapping a connection's extensions into a request, as every proxied request does.
#[divan::bench(args = [1, 4])]
fn insert_egress_wrapper(bencher: divan::Bencher, depth: usize) {
    let conn = chain(depth);
    bencher.bench_local(|| {
        let request = Extensions::new();
        request.insert(Egress(conn.clone()));
        black_box(request)
    });
}

/// A fresh level filled with `n` entries: the per-level storage cost.
#[divan::bench(args = [1, 4, 8, 16, 64])]
fn new_level_with_entries(bencher: divan::Bencher, n: usize) {
    bencher.bench_local(|| {
        let ext = Extensions::new();
        for _ in 0..n {
            ext.insert(Marker::<0>);
        }
        black_box(ext)
    });
}

/// Layering a request over a connector's base config, as TLS handshakes do.
#[divan::bench]
fn fork_with_base(bencher: divan::Bencher) {
    let request = chain(3);
    let base = chain(1);
    bencher.bench_local(|| black_box(request.fork().with_base(&base)));
}

/// One level of `n` entries, oldest first `Marker<0>`.
fn level(n: usize) -> Extensions {
    let ext = Extensions::new();
    macro_rules! upto {
        ($($k:literal)+) => {
            $( if n > $k { ext.insert(Marker::<$k>); } )+
        };
    }
    upto!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
    ext
}

/// A hit on the oldest entry of a level of `n` entries: a full scan of the
/// level. Long-lived connection levels of 6 and 12 entries take most of the
/// scans of a busy proxy.
#[divan::bench(args = [2, 4, 6, 8, 12, 16])]
fn get_ref_full_level_scan(bencher: divan::Bencher, n: usize) {
    let ext = level(n);
    bencher.bench_local(|| black_box(ext.get_ref::<Marker<0>>()));
}
