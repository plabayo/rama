//! Compare the same workloads with the feature absent, inactive, paused and recording.
//!
//! cargo bench --bench dial9 --features http,net
//! cargo bench --bench dial9 --features http,net,dial9
//!
//! These in-memory workloads isolate lifecycle and body/forwarding costs; they
//! do not predict production CPU, storage, profiling-source or network costs.

#![expect(clippy::unwrap_used, reason = "benchmark fixtures must be valid")]

use rama::{
    Service as _, ServiceInput,
    http::{Body, Request, Response, body::util::BodyExt as _},
    io::BridgeIo,
    net::proxy::IoForwardService,
    rt::{Executor, OwnedRuntime},
    service::service_fn,
};
use std::{convert::Infallible, hint::black_box};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod bench_alloc;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Inactive,
    #[cfg(feature = "dial9")]
    Paused,
    #[cfg(feature = "dial9")]
    Recording,
}

const MODES: &[Mode] = &[
    Mode::Inactive,
    #[cfg(feature = "dial9")]
    Mode::Paused,
    #[cfg(feature = "dial9")]
    Mode::Recording,
];

struct Fixture {
    runtime: OwnedRuntime,
    #[cfg(feature = "dial9")]
    _directory: Option<rama::utils::fs::TempDir>,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(2).enable_all();
        match mode {
            Mode::Inactive => Self {
                runtime: OwnedRuntime::from_tokio(builder.build().unwrap()),
                #[cfg(feature = "dial9")]
                _directory: None,
            },
            #[cfg(feature = "dial9")]
            Mode::Paused | Mode::Recording => {
                use rama::telemetry::dial9::{
                    Dial9HandleTokioExt as _, DiskBuffer, TokioAttachOptions, recorder,
                };
                let directory = rama::utils::fs::tempdir().unwrap();
                let writer = DiskBuffer::builder()
                    .base_path(directory.path())
                    .max_file_size(8 << 20)
                    .max_total_size(32 << 20)
                    .build()
                    .unwrap();
                let recorder = recorder(writer).build();
                assert!(recorder.handle().is_enabled());
                if matches!(mode, Mode::Paused) {
                    recorder.handle().disable();
                }
                let runtime = recorder
                    .handle()
                    .attach_tokio_runtime(builder, TokioAttachOptions::default())
                    .unwrap();
                Self {
                    runtime: OwnedRuntime::from_dial9((recorder, runtime)),
                    _directory: Some(directory),
                }
            }
        }
    }
}

#[divan::bench(args = MODES, sample_count = 100, sample_size = 100)]
fn http_response(bencher: divan::Bencher, mode: Mode) {
    let fixture = Fixture::new(mode);
    let service = service_fn(|_: Request| async {
        Ok::<_, Infallible>(Response::new(Body::from("response")))
    });
    #[cfg(feature = "dial9")]
    let service = {
        use rama::Layer as _;
        rama::http::layer::dial9::Dial9Layer::new().layer(service)
    };
    bencher.bench_local(|| {
        fixture.runtime.block_on(async {
            let response = service.serve(Request::new(Body::empty())).await.unwrap();
            black_box(response.into_body().collect().await.unwrap());
        })
    });
}

/// One complete 4 KiB flow, including setup and teardown.
#[divan::bench(args = MODES, sample_count = 100, sample_size = 100)]
fn short_proxy_flow(bencher: divan::Bencher, mode: Mode) {
    let fixture = Fixture::new(mode);
    bencher.bench_local(|| {
        fixture.runtime.block_on(async {
            let (mut client, ingress) = tokio::io::duplex(8192);
            let (mut origin, egress) = tokio::io::duplex(8192);
            let forward = IoForwardService::new(Executor::new());
            let bridge = forward.serve(BridgeIo(
                ServiceInput::new(ingress),
                ServiceInput::new(egress),
            ));
            let exchange = async {
                client.write_all(&[42; 4096]).await.unwrap();
                client.shutdown().await.unwrap();
                origin.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                origin.read_to_end(&mut bytes).await.unwrap();
                black_box(bytes);
            };
            let (result, ()) = tokio::join!(bridge, exchange);
            result.unwrap();
        })
    });
}

/// A long-lived tunnel: lifecycle recording must not add a per-chunk event.
#[divan::bench(args = MODES, sample_count = 100, sample_size = 10)]
fn proxy_megabyte(bencher: divan::Bencher, mode: Mode) {
    let fixture = Fixture::new(mode);
    let (mut client, ingress) = tokio::io::duplex(64 << 10);
    let (mut origin, egress) = tokio::io::duplex(64 << 10);
    let bridge = fixture.runtime.spawn(async move {
        IoForwardService::new(Executor::new())
            .serve(BridgeIo(
                ServiceInput::new(ingress),
                ServiceInput::new(egress),
            ))
            .await
            .unwrap();
    });
    bencher
        .counter(divan::counter::BytesCount::new(1_usize << 20))
        .bench_local(|| {
            fixture.runtime.block_on(async {
                let write = async {
                    for _ in 0..64 {
                        client.write_all(&[42; 16 << 10]).await.unwrap();
                    }
                };
                let read = async {
                    let mut buffer = [0; 16 << 10];
                    for _ in 0..64 {
                        origin.read_exact(&mut buffer).await.unwrap();
                    }
                    black_box(buffer);
                };
                tokio::join!(write, read);
            });
        });
    fixture.runtime.block_on(async {
        client.shutdown().await.unwrap();
        origin.shutdown().await.unwrap();
        bridge.await.unwrap();
    });
}

fn main() {
    divan::main();
}
