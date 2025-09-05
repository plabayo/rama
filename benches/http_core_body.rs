#![deny(warnings)]

use rama::bytes::Buf;
use rama::futures::StreamExt;
use rama::futures::stream;
use rama::http::body::{
    Frame,
    util::{BodyExt, StreamBody},
};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Run registered benchmarks.
    divan::main();
}

macro_rules! bench_stream {
    ($bencher:ident, bytes: $bytes:expr, count: $count:expr, $total_ident:ident, $body_pat:pat, $block:expr) => {{
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt build");

        let $total_ident: usize = $bytes * $count;
        let __s: &'static [&'static [u8]] = &[&[b'x'; $bytes] as &[u8]; $count] as _;

        $bencher
            .counter(divan::counter::BytesCount::of_slice(__s))
            .bench(|| {
                rt.block_on(async {
                    let $body_pat = StreamBody::new(
                        stream::iter(__s.iter())
                            .map(|&s| Ok::<_, std::convert::Infallible>(Frame::data(s))),
                    );

                    $block;
                });
            });
    }};
}

macro_rules! benches {
    ($($name:ident, $bytes:expr, $count:expr;)+) => (
        mod aggregate {
            use super::*;

            $(
            #[divan::bench]
            fn $name(b: divan::Bencher) {
                bench_stream!(b, bytes: $bytes, count: $count, total, body, {
                    let buf = BodyExt::collect(body).await.unwrap().aggregate();
                    assert_eq!(buf.remaining(), total);
                });
            }
            )+
        }

        mod manual_into_vec {
            use super::*;

            $(
                #[divan::bench]
            fn $name(b: divan::Bencher) {
                bench_stream!(b, bytes: $bytes, count: $count, total, mut body, {
                    let mut vec = Vec::new();
                    while let Some(chunk) = body.next().await {
                        vec.extend_from_slice(&chunk.unwrap().into_data().unwrap());
                    }
                    assert_eq!(vec.len(), total);
                });
            }
            )+
        }

        mod to_bytes {
            use super::*;

            $(
            #[divan::bench]
            fn $name(b: divan::Bencher) {
                bench_stream!(b, bytes: $bytes, count: $count, total, body, {
                    let bytes = BodyExt::collect(body).await.unwrap().to_bytes();
                    assert_eq!(bytes.len(), total);
                });
            }
            )+
        }
    )
}

// ===== Actual Benchmarks =====

benches! {
    bytes_1_000_count_2, 1_000, 2;
    bytes_1_000_count_10, 1_000, 10;
    bytes_10_000_count_1, 10_000, 1;
    bytes_10_000_count_10, 10_000, 10;
}
