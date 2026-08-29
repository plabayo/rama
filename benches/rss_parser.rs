#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{AllocProfiler, black_box, counter::BytesCount};
use rama::{http::protocols::rss::Rss2FeedStream, io::LossyUtf8Reader};
use std::{future::Future, sync::OnceLock};
use tokio::io::{AsyncReadExt as _, BufReader};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const FEED: &[u8] = include_bytes!("../rama-http/tests/rss-corpus/podcast-v2.rss.xml");
const EXPECTED_ITEMS: usize = 512;

fn benchmark_feed() -> &'static [u8] {
    static INPUT: OnceLock<Vec<u8>> = OnceLock::new();
    INPUT.get_or_init(|| {
        let source = std::str::from_utf8(FEED).unwrap();
        let item_start = source.find("<item>").unwrap();
        let item_end = item_start + source[item_start..].find("</item>").unwrap() + 7;
        let item = &source.as_bytes()[item_start..item_end];
        let mut input = Vec::with_capacity(FEED.len() + item.len() * (EXPECTED_ITEMS - 1));
        input.extend_from_slice(&FEED[..item_start]);
        for _ in 0..EXPECTED_ITEMS {
            input.extend_from_slice(item);
        }
        input.extend_from_slice(&FEED[item_end..]);
        input
    })
}

fn invalid_utf8_stream() -> &'static [u8] {
    static INPUT: OnceLock<Vec<u8>> = OnceLock::new();
    INPUT.get_or_init(|| {
        let mut input = Vec::with_capacity(28 * 1024);
        for _ in 0..2048 {
            input.extend_from_slice(b"text\xf0\x9f\x92\xa9\xfftail\xe2\x82");
        }
        input
    })
}

fn main() {
    divan::main();
}

fn pollster_block_on<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::hint::spin_loop();
    }
}

async fn parse(strict: bool) -> usize {
    let reader = BufReader::new(benchmark_feed());
    let stream = if strict {
        Rss2FeedStream::new_strict(reader).await.unwrap()
    } else {
        Rss2FeedStream::new(reader).await.unwrap()
    };
    stream.collect().await.unwrap().items.len()
}

async fn decode_invalid_split_utf8() -> usize {
    let input = invalid_utf8_stream();
    let inner = BufReader::with_capacity(7, input);
    let mut reader = LossyUtf8Reader::new(inner);
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    output.len()
}

/// Strict parsing keeps the caller's concrete buffered reader and avoids
/// parser-internal dynamic dispatch.
#[divan::bench(sample_count = 100)]
fn rss2_strict(bencher: divan::Bencher) {
    let feed = benchmark_feed();
    bencher
        .counter(BytesCount::new(feed.len()))
        .bench_local(|| {
            let items = pollster_block_on(parse(true));
            assert_eq!(items, EXPECTED_ITEMS);
            black_box(items)
        });
}

/// Lenient parsing measures the lossy UTF-8 adapter's zero-copy valid-input
/// path on a representative real-world podcast feed.
#[divan::bench(sample_count = 100)]
fn rss2_lenient(bencher: divan::Bencher) {
    let feed = benchmark_feed();
    bencher
        .counter(BytesCount::new(feed.len()))
        .bench_local(|| {
            let items = pollster_block_on(parse(false));
            assert_eq!(items, EXPECTED_ITEMS);
            black_box(items)
        });
}

/// Invalid and split UTF-8 forces the retained transform-buffer path. The
/// seven-byte inner buffer deliberately splits valid multibyte sequences too.
#[divan::bench(sample_count = 30)]
fn lossy_invalid_split(bencher: divan::Bencher) {
    let input = invalid_utf8_stream();
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| black_box(pollster_block_on(decode_invalid_split_utf8())));
}
