#![expect(clippy::expect_used, reason = "benchmark inputs are valid JSON")]

use divan::{Bencher, black_box, counter::BytesCount};
use rama::{
    bytes::Bytes,
    futures::{Stream, StreamExt, TryStreamExt, stream},
    http::{Body, BodyExtractExt},
    stream::{
        io::{StreamReader, SyncIoBridge},
        json::{ArrayParseConfig, JsonArrayReadStream},
    },
    utils::octets::{kib, mib},
};
use serde::{
    Deserialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::Value;
use std::{
    fmt,
    io::{self, BufReader},
    pin::Pin,
    task::{Context, Waker},
};
use tokio::{runtime::Builder, task::JoinSet};

mod bench_alloc;

#[derive(Deserialize)]
#[expect(
    dead_code,
    reason = "benchmark measures construction and drop of typed records"
)]
struct Record {
    id: u64,
    name: Box<str>,
    active: bool,
    tags: Vec<Box<str>>,
}

#[derive(Clone, Copy)]
struct Case {
    bytes: usize,
    frame: usize,
    clients: usize,
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}KiB-{}KiB-{}clients",
            self.bytes / kib(1),
            self.frame / kib(1),
            self.clients
        )
    }
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (bytes, concurrency) in [
        (kib(2), 256),
        (kib(16), 256),
        (kib(64), 64),
        (kib(256), 64),
        (mib(16), 8),
    ] {
        for frame in [kib(1), kib(16), kib(64)] {
            for clients in [1, concurrency] {
                cases.push(Case {
                    bytes,
                    frame,
                    clients,
                });
            }
        }
    }
    cases
}

fn payload(size: usize, lines: bool) -> (Bytes, usize) {
    let record = br#"{"id":123,"name":"Ada","active":true,"tags":["one","two"]}"#;
    let count = (size - 1) / (record.len() + 1);
    let mut out = Vec::with_capacity(size);
    if !lines {
        out.push(b'[');
    }
    for index in 0..count {
        if index != 0 {
            out.push(if lines { b'\n' } else { b',' });
        }
        out.extend_from_slice(record);
    }
    out.resize(size - 1, b' ');
    out.push(if lines { b'\n' } else { b']' });
    (Bytes::from(out), count)
}

fn body(mut data: Bytes, frame: usize) -> Body {
    Body::from_stream(stream::iter(std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let len = frame.min(data.len());
        Some(Ok::<_, io::Error>(data.split_to(len)))
    })))
}

#[derive(Clone, Copy)]
enum Method {
    Blocking(usize),
    Streaming,
    Collect,
    Lines,
    Array,
}

async fn decode<T: DeserializeOwned + Send + 'static>(method: Method, body: Body) -> usize {
    match method {
        Method::Blocking(capacity) => {
            let frames = body.into_data_stream().map_err(io::Error::other);
            let reader = StreamReader::new(frames);
            tokio::task::spawn_blocking(move || {
                let reader = SyncIoBridge::new(reader);
                if capacity == 0 {
                    serde_json::from_reader::<_, Vec<T>>(reader)
                } else {
                    serde_json::from_reader(BufReader::with_capacity(capacity, reader))
                }
                .expect("valid JSON")
                .len()
            })
            .await
            .expect("parser joined")
        }
        Method::Streaming => body
            .try_into_json_streaming::<Vec<T>>()
            .await
            .expect("valid JSON")
            .len(),
        Method::Collect => body
            .try_into_json::<Vec<T>>()
            .await
            .expect("valid JSON")
            .len(),
        Method::Array => count(body.into_json_array_stream::<T>()).await,
        Method::Lines => count(body.into_json_stream::<T>()).await,
    }
}

async fn count<T>(
    items: impl rama::futures::Stream<Item = Result<T, rama::error::BoxError>>,
) -> usize {
    let mut items = std::pin::pin!(items);
    let mut count = 0;
    while let Some(item) = items.next().await {
        black_box(item.expect("valid record"));
        count += 1;
    }
    count
}

fn measure<T: DeserializeOwned + Send + 'static>(bencher: Bencher, case: Case, method: Method) {
    let rt = Builder::new_multi_thread().build().expect("runtime");
    let (data, expected) = payload(case.bytes, matches!(method, Method::Lines));
    // Reuse each small-body worker across requests to measure steady-state throughput.
    let requests = if case.bytes == kib(2) && !matches!(method, Method::Blocking(0)) {
        64
    } else {
        1
    };
    bencher
        .counter(BytesCount::new(case.bytes * case.clients * requests))
        .bench_local(|| {
            rt.block_on(async {
                let mut workers = JoinSet::new();
                for _ in 0..case.clients {
                    let data = data.clone();
                    workers.spawn(async move {
                        for _ in 0..requests {
                            assert_eq!(
                                decode::<T>(method, body(data.clone(), case.frame)).await,
                                expected
                            );
                        }
                    });
                }
                while let Some(result) = workers.join_next().await {
                    result.expect("worker joined");
                }
            });
        });
}

macro_rules! benchmark {
    ($name:ident, $method:expr) => {
        #[divan::bench(types = [Record, Value], args = cases(), sample_count = 3, sample_size = 1)]
        fn $name<T: DeserializeOwned + Send + 'static>(bencher: Bencher, case: Case) {
            measure::<T>(bencher, case, $method);
        }
    };
}

benchmark!(unbuffered, Method::Blocking(0));
benchmark!(bufreader, Method::Blocking(kib(64)));
benchmark!(single_value, Method::Streaming);
benchmark!(collect, Method::Collect);
benchmark!(ndjson, Method::Lines);
benchmark!(array, Method::Array);

fn crossover_cases() -> Vec<Case> {
    [kib(64), kib(256), mib(1)]
        .map(|bytes| Case {
            bytes,
            frame: kib(16),
            clients: 64,
        })
        .to_vec()
}

#[divan::bench(args = crossover_cases(), consts = [0, 16, 64, 256], sample_count = 5, sample_size = 1)]
fn crossover<const BUFFER_KIB: usize>(bencher: Bencher, case: Case) {
    let method = if BUFFER_KIB == 0 {
        Method::Collect
    } else {
        Method::Blocking(kib(BUFFER_KIB))
    };
    measure::<Record>(bencher, case, method);
}

#[divan::bench(args = [8, 16, 64, 256], sample_count = 5, sample_size = 1)]
fn sync_client_buffer(bencher: Bencher, buffer_kib: usize) {
    let rt = rama::rt::blocking::Runtime::try_new().expect("runtime");
    let (data, expected) = payload(mib(1), false);
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let frames = body(data.clone(), kib(64))
                .into_data_stream()
                .map_err(io::Error::other);
            let reader = rt.io(StreamReader::new(frames));
            let records: Vec<Record> =
                serde_json::from_reader(BufReader::with_capacity(kib(buffer_kib), reader))
                    .expect("valid JSON");
            assert_eq!(black_box(records).len(), expected);
        });
}

/// Longest time the in-task path spends parsing between two awaits.
#[divan::bench(types = [Record, Value])]
fn in_task_parse_at_probe_limit<T: DeserializeOwned>(bencher: Bencher) {
    let (data, expected) = payload(kib(16), false);
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let records: Vec<T> = serde_json::from_slice(black_box(&data)).expect("valid JSON");
            assert_eq!(black_box(records).len(), expected);
        });
}

#[divan::bench(types = [Record, Value], sample_count = 5, sample_size = 1)]
fn slice_single_core<T: DeserializeOwned>(bencher: Bencher) {
    let (data, expected) = payload(mib(16), false);
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let records: Vec<T> = serde_json::from_slice(black_box(&data)).expect("valid JSON");
            assert_eq!(black_box(records).len(), expected);
        });
}

#[divan::bench(types = [Record, Value], sample_count = 5, sample_size = 1)]
fn reader_single_core<T: DeserializeOwned>(bencher: Bencher) {
    let (data, expected) = payload(mib(16), false);
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let reader = BufReader::with_capacity(kib(64), black_box(data.as_ref()));
            let records: Vec<T> = serde_json::from_reader(reader).expect("valid JSON");
            assert_eq!(black_box(records).len(), expected);
        });
}

#[divan::bench(types = [Record, Value, IgnoredAny], sample_count = 5, sample_size = 1)]
fn array_single_core<T: DeserializeOwned>(bencher: Bencher) {
    let rt = Builder::new_current_thread().build().expect("runtime");
    let (data, expected) = payload(mib(16), false);
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let source = body(data.clone(), kib(16)).into_data_stream();
            assert_eq!(
                rt.block_on(count(JsonArrayReadStream::<T, _>::new(source))),
                expected
            );
        });
}

#[divan::bench(args = [1, 64], sample_count = 5, sample_size = 1)]
fn spanning_element(bencher: Bencher, frame_kib: usize) {
    let rt = Builder::new_current_thread().build().expect("runtime");
    let mut data = Vec::from(b"[\"".as_slice());
    data.resize(mib(8) + 2, b'x');
    data.extend_from_slice(b"\"]");
    let data = Bytes::from(data);
    let config = ArrayParseConfig::default()
        .with_max_element_bytes(std::num::NonZeroUsize::new(mib(9)).expect("positive limit"));
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let items = body(data.clone(), kib(frame_kib))
                .into_json_array_stream_with_config::<IgnoredAny>(config);
            assert_eq!(rt.block_on(count(items)), 1);
        });
}

/// Each frame owns its bytes so the profiler includes the live transport frame.
#[divan::bench(sample_count = 5, sample_size = 1)]
fn array_buffered_bytes(bencher: Bencher) {
    let (data, expected) = payload(mib(16), false);
    let runtime = Builder::new_current_thread().build().expect("runtime");
    bencher
        .counter(BytesCount::new(data.len()))
        .bench_local(|| {
            let frames = stream::iter(
                data.chunks(kib(16))
                    .map(|chunk| Ok::<_, io::Error>(Box::<[u8]>::from(chunk))),
            );
            let reader = JsonArrayReadStream::<IgnoredAny, _>::new(frames);
            assert_eq!(runtime.block_on(count(reader)), expected);
        });
}

/// All readers stay live, with one shared input frame to isolate decoder memory.
#[divan::bench(args = [0, 1, 4, 32], sample_count = 3, sample_size = 1)]
fn stalled_50000_readers(bencher: Bencher, partial_kib: usize) {
    let mut prefix = vec![b'['];
    if partial_kib > 0 {
        prefix.push(b'"');
        prefix.resize(1 + kib(partial_kib), b'x');
    }
    let prefix = Bytes::from(prefix);
    bencher.bench_local(|| {
        let mut readers = Vec::with_capacity(50_000);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..50_000 {
            let source =
                stream::iter([Ok::<_, io::Error>(prefix.clone())]).chain(stream::pending());
            let mut reader = JsonArrayReadStream::<IgnoredAny, _>::new(source);
            assert!(Pin::new(&mut reader).poll_next(&mut cx).is_pending());
            readers.push(reader);
        }
        black_box(readers);
    });
}

fn main() {
    divan::main();
}
