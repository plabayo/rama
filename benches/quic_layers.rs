//! Private QUIC queue and stream-storage baselines.
//!
//! Run: `cargo bench -p rama --bench quic_layers --features quic,test-utils`.
//! Run on an idle machine, separately from builds and other timed benchmarks.
//! Queue rounds retain their fixture across iterations to expose recurring burst/drain reallocations.
//! Protocol fixtures exclude preowned payload construction but include ownership release. Their
//! sample size is one so prepared inputs cannot accumulate an unbounded payload working set.
//! Concurrent queue rounds include command channels and OS wake/scheduling, but exclude thread
//! creation and joining; allocator reporting is the measured coordinator thread, not all workers.
//! These are layer costs, not end-to-end QUIC throughput or connection-level loss recovery.

use divan::{AllocProfiler, black_box, counter::ItemsCount};
use rama::quic::benchmarks::{Assembly, ConcurrentQueues, Queues, SendRecovery};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(args = [1, 16, 32, 64, 128])]
fn queue_burst_static_payload(bencher: divan::Bencher, burst: usize) {
    let mut queues = Queues::new(1, burst);
    black_box(queues.round(false));
    bencher
        .counter(ItemsCount::new(burst))
        .bench_local(|| black_box(queues.round(false)));
    queues.verify_drained();
    black_box(queues.observe());
}

#[divan::bench(args = [1, 16, 32, 64, 128])]
fn queue_burst_owned_payload(bencher: divan::Bencher, burst: usize) {
    let mut queues = Queues::new(1, burst);
    black_box(queues.round(true));
    bencher
        .counter(ItemsCount::new(burst))
        .bench_local(|| black_box(queues.round(true)));
    queues.verify_drained();
    black_box(queues.observe());
}

#[divan::bench(args = [1, 8, 64, 128])]
fn shared_endpoint_sparse_queues(bencher: divan::Bencher, connections: usize) {
    let mut queues = Queues::new(connections, 1);
    black_box(queues.round(false));
    bencher
        .counter(ItemsCount::new(connections))
        .bench_local(|| black_box(queues.round(false)));
    queues.verify_drained();
    black_box(queues.observe());
}

#[divan::bench(args = [1, 2, 4, 8])]
fn shared_endpoint_concurrent_consumers(bencher: divan::Bencher, connections: usize) {
    let mut queues = ConcurrentQueues::new(connections, 128);
    black_box(queues.round());
    bencher
        .counter(ItemsCount::new(connections * 128))
        .bench_local(|| black_box(queues.round()));
    queues.verify_drained();
}

// Drop-time verification is outside the measured closure with `bench_local_refs`.
struct CheckedAssembly(Assembly);

impl Drop for CheckedAssembly {
    fn drop(&mut self) {
        self.0.verify();
    }
}

#[divan::bench(args = [1, 4, 16, 128, 512], sample_count = 100, sample_size = 1)]
fn assembler_in_order(bencher: divan::Bencher, chunks: usize) {
    bencher
        .counter(ItemsCount::new(chunks))
        .with_inputs(|| CheckedAssembly(Assembly::new(chunks, false)))
        .bench_local_refs(|fixture| black_box(fixture.0.run()));
}

#[divan::bench(args = [1, 4, 16, 128, 512], sample_count = 100, sample_size = 1)]
fn assembler_reverse_fragmented(bencher: divan::Bencher, chunks: usize) {
    bencher
        .counter(ItemsCount::new(chunks))
        .with_inputs(|| CheckedAssembly(Assembly::new(chunks, true)))
        .bench_local_refs(|fixture| black_box(fixture.0.run()));
}

struct CheckedSend {
    fixture: SendRecovery,
    recovered: bool,
}

impl Drop for CheckedSend {
    fn drop(&mut self) {
        self.fixture.verify(self.recovered);
    }
}

#[divan::bench(args = [1, 4, 16, 128, 512], sample_count = 100, sample_size = 1)]
fn send_buffer_retransmit_and_retire(bencher: divan::Bencher, chunks: usize) {
    bencher
        .counter(ItemsCount::new(chunks))
        .with_inputs(|| CheckedSend {
            fixture: SendRecovery::new(chunks, false),
            recovered: true,
        })
        .bench_local_refs(|fixture| black_box(fixture.fixture.recover()));
}

#[divan::bench(args = [1, 4, 16, 128, 512], sample_count = 100, sample_size = 1)]
fn send_buffer_ack_in_order(bencher: divan::Bencher, chunks: usize) {
    bencher
        .counter(ItemsCount::new(chunks))
        .with_inputs(|| CheckedSend {
            fixture: SendRecovery::new(chunks, true),
            recovered: false,
        })
        .bench_local_refs(|fixture| fixture.fixture.acknowledge(false));
}

#[divan::bench(args = [1, 4, 16, 128, 512], sample_count = 100, sample_size = 1)]
fn send_buffer_ack_reverse(bencher: divan::Bencher, chunks: usize) {
    bencher
        .counter(ItemsCount::new(chunks))
        .with_inputs(|| CheckedSend {
            fixture: SendRecovery::new(chunks, true),
            recovered: false,
        })
        .bench_local_refs(|fixture| fixture.fixture.acknowledge(true));
}
