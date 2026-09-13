//! Public observer/encoder/recorder allocation baselines.
//!
//! Run with `cargo bench -p rama --bench quic_qlog --features quic`. Divan reports allocations
//! in the measured producer closure; async worker driving is deliberately excluded.
//! Accepted recorder samples submit 256 events to an empty queue while its worker waits
//! in `begin`. Every submission must succeed. Setup, verification, draining and
//! shutdown happen outside the measured closure through `bench_local_refs`.
#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and encoding must succeed"
)]

use divan::{AllocProfiler, black_box, counter::ItemsCount};
use rama::quic::{
    ConnectionId,
    qlog::{
        JsonSeqEncoder, QlogConfig, QlogEncoder, QlogEventView, QlogOutput, QlogRecorder, QlogSink,
        QueueLimits, TraceInfo,
        event::{
            EventView, LifecycleEventView, NegotiationEventView, PacketEvent,
            lifecycle::{ConnectionClosedView, ReasonView},
            negotiation::{AlpnIdentifierView, HexView},
            packet::{Packet, PacketHeader, PacketType, RawInfo},
        },
    },
};
use std::{
    borrow::Cow,
    io::{self, Cursor, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::Notify;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

fn event<'a>(kind: &str, alpn: &'a [u8], time: Instant) -> QlogEventView<'a> {
    let fields = if kind == "packet" {
        PacketEvent::PacketSent(Packet {
            header: PacketHeader {
                packet_type: PacketType::OneRtt,
                packet_number: 42,
            },
            raw: Some(RawInfo { length: 1200 }),
        })
        .into()
    } else {
        NegotiationEventView::AlpnInformation {
            chosen_alpn: AlpnIdentifierView {
                byte_value: HexView(Cow::Borrowed(alpn)),
            },
        }
        .into()
    };
    QlogEventView {
        group_id: ConnectionId::try_from_bytes(b"qlogbench").unwrap(),
        time,
        fields,
    }
}

#[derive(Default)]
struct Counter(AtomicU64);

impl QlogSink for Counter {
    fn emit(&self, event: &QlogEventView<'_>) -> bool {
        let amount = match &event.fields.event {
            EventView::Packet(PacketEvent::PacketSent(packet)) => packet.raw.unwrap().length,
            EventView::Negotiation(NegotiationEventView::AlpnInformation { chosen_alpn }) => {
                chosen_alpn.byte_value.0.len()
            }
            _ => 0,
        };
        self.0.fetch_add(amount as u64, Ordering::Relaxed);
        true
    }
}

#[divan::bench(args = ["packet", "alpn"])]
fn borrowed_inline_counter(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    let counter = Counter::default();
    let observer: &dyn QlogSink = black_box(&counter);
    bencher.bench_local(|| black_box(observer.emit(black_box(&event))));
    black_box(counter.0.load(Ordering::Relaxed));
}

#[divan::bench(args = ["packet", "alpn"])]
fn borrowed_filtered_fanout(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    let sinks = (
        Counter::default().filtered(|event| event.fields.tuple.is_none()),
        Counter::default(),
    );
    let observer: &dyn QlogSink = black_box(&sinks);
    bencher.bench_local(|| black_box(observer.emit(black_box(&event))));
}

// Example private binary sink: a one-byte tag, CID length and bytes, then
// little-endian packet number/length or ALPN length/bytes. No owned event or
// intermediate JSON value is needed. This is a benchmark format, not qlog.
fn compact(event: &QlogEventView<'_>, output: &mut impl Write) -> io::Result<()> {
    output.write_all(&[event.group_id.len() as u8])?;
    output.write_all(&event.group_id)?;
    match &event.fields.event {
        EventView::Packet(PacketEvent::PacketSent(packet)) => {
            output.write_all(&[0])?;
            output.write_all(&packet.header.packet_number.to_le_bytes())?;
            output.write_all(&(packet.raw.unwrap().length as u64).to_le_bytes())
        }
        EventView::Negotiation(NegotiationEventView::AlpnInformation { chosen_alpn }) => {
            let bytes = chosen_alpn.byte_value.0.as_ref();
            output.write_all(&[1])?;
            output.write_all(&(bytes.len() as u64).to_le_bytes())?;
            output.write_all(bytes)
        }
        _ => Err(io::Error::other("unsupported benchmark event")),
    }
}

#[divan::bench(args = ["packet", "alpn"])]
fn borrowed_compact_fixed_writer(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    let mut output = Cursor::new([0u8; 1024]);
    bencher.bench_local(|| {
        output.set_position(0);
        compact(black_box(&event), black_box(&mut output)).unwrap();
        black_box(&output);
    });
}

#[divan::bench(args = ["packet", "alpn"])]
fn acquire_owned_event(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    // Returning ownership lets Divan defer destruction beyond the timing window.
    bencher.bench_local(|| black_box(&event).to_owned());
}

/// Includes driving the async encoder on a current-thread runtime into fixed memory.
#[divan::bench(args = ["packet", "alpn"])]
fn borrowed_async_json_fixed_writer(bencher: divan::Bencher, kind: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let alpn = *b"h3";
    let time = Instant::now();
    let event = event(kind, &alpn, time);
    let info = TraceInfo {
        title: None,
        description: None,
        start_time: time,
    };
    let mut encoder = JsonSeqEncoder;
    let mut bytes = [0u8; 1024];
    let mut output = Cursor::new(bytes.as_mut_slice());
    runtime
        .block_on(encoder.event(&info, &event, &mut output))
        .unwrap();
    bencher.bench_local(|| {
        output.set_position(0);
        runtime
            .block_on(encoder.event(&info, black_box(&event), black_box(&mut output)))
            .unwrap();
        black_box(&output);
    });
}

#[divan::bench(args = ["packet", "alpn"])]
fn disabled_recorder(bencher: divan::Bencher, kind: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let recorder = QlogConfig::default()
        .with_writer(tokio::io::sink())
        .with_enabled(false)
        .start()
        .unwrap();
    runtime.block_on(recorder.flush()).unwrap();
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    bencher.bench_local(|| black_box(recorder.emit(black_box(&event))));
    assert_eq!(recorder.stats().submitted_events, 0);
    runtime.block_on(recorder.shutdown()).unwrap();
}

const BATCH: usize = 256;

struct ParkedOutput {
    ready: Arc<Notify>,
    release: Arc<Notify>,
    written: Arc<AtomicU64>,
}

impl QlogOutput for ParkedOutput {
    async fn begin(&mut self, _info: &TraceInfo) -> io::Result<()> {
        self.ready.notify_one();
        self.release.notified().await;
        Ok(())
    }
    async fn event(&mut self, event: &QlogEventView<'_>) -> io::Result<()> {
        black_box(event);
        self.written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct RecorderBatch {
    recorder: QlogRecorder,
    release: Arc<Notify>,
    written: Arc<AtomicU64>,
    runtime: tokio::runtime::Runtime,
    accepted: usize,
    expected_drops: u64,
}

impl RecorderBatch {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let ready = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let written = Arc::new(AtomicU64::new(0));
        let recorder = runtime.block_on(async {
            QlogConfig::default()
                .with_output(ParkedOutput {
                    ready: ready.clone(),
                    release: release.clone(),
                    written: written.clone(),
                })
                .with_queue_limits(QueueLimits {
                    max_queued_events: BATCH,
                    max_queued_bytes: BATCH * 4096,
                    max_event_bytes: 4096,
                })
                .start()
                .unwrap()
        });
        runtime.block_on(ready.notified());
        Self {
            recorder,
            release,
            written,
            runtime,
            accepted: 0,
            expected_drops: 0,
        }
    }
}

impl Drop for RecorderBatch {
    fn drop(&mut self) {
        let stats = self.recorder.stats();
        // Always release and await the task before asserting, including failed samples.
        self.release.notify_one();
        self.runtime.block_on(self.recorder.shutdown()).unwrap();
        assert_eq!(self.accepted, BATCH);
        assert_eq!(stats.submitted_events, BATCH as u64);
        assert_eq!(stats.queued_events, BATCH);
        assert_eq!(stats.dropped_events, self.expected_drops);
        assert_eq!(stats.oversized_events, 0);
        assert_eq!(self.written.load(Ordering::Relaxed), BATCH as u64);
    }
}

/// Allocation counts are per 256-event batch, including cold queue block growth.
/// Dividing the packet/ALPN difference by 256 exposes the ALPN ownership copy.
#[divan::bench(args = ["packet", "alpn"], sample_count = 30, sample_size = 1)]
fn accepted_recorder_batch(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    bencher
        .counter(ItemsCount::new(BATCH))
        .with_inputs(RecorderBatch::new)
        .bench_local_refs(|batch| {
            let mut accepted = 0;
            for _ in 0..BATCH {
                accepted += usize::from(batch.recorder.emit(black_box(&event)));
            }
            batch.accepted = black_box(accepted);
        });
}

/// Full admission capacity must reject even borrowed fields without copying them.
#[divan::bench(args = ["packet", "alpn"])]
fn saturated_recorder(bencher: divan::Bencher, kind: &str) {
    let alpn = *b"h3";
    let event = event(kind, &alpn, Instant::now());
    let mut batch = RecorderBatch::new();
    for _ in 0..BATCH {
        batch.accepted += usize::from(batch.recorder.emit(&event));
    }
    assert_eq!(batch.accepted, BATCH);
    assert_eq!(batch.recorder.stats().queued_events, BATCH);
    let mut attempts = 0;
    let mut accepted = 0;
    bencher.bench_local(|| {
        accepted += usize::from(black_box(batch.recorder.emit(black_box(&event))));
        attempts += 1;
    });
    batch.expected_drops = attempts;
    assert_eq!(accepted, 0);
    // Drop also verifies that the original batch is preserved and fully written.
}

/// An oversized borrowed diagnostic reason must be rejected before ownership.
#[divan::bench]
fn oversized_borrowed_reason(bencher: divan::Bencher) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let recorder = QlogConfig::default()
        .with_writer(tokio::io::sink())
        .with_queue_limits(QueueLimits {
            max_queued_events: BATCH,
            max_queued_bytes: BATCH * 4096,
            max_event_bytes: 4096,
        })
        .start()
        .unwrap();
    runtime.block_on(recorder.flush()).unwrap();
    let reason = [b'x'; 8192];
    let event = QlogEventView {
        group_id: ConnectionId::try_from_bytes(b"qlogbench").unwrap(),
        time: Instant::now(),
        fields: LifecycleEventView::Closed(ConnectionClosedView {
            initiator: "remote",
            trigger: "error",
            reason: Some(ReasonView::Bytes(Cow::Borrowed(&reason))),
            ..Default::default()
        })
        .into(),
    };
    let mut attempts = 0;
    let mut accepted = 0;
    bencher.bench_local(|| {
        accepted += usize::from(black_box(recorder.emit(black_box(&event))));
        attempts += 1;
    });
    runtime.block_on(recorder.shutdown()).unwrap();
    let stats = recorder.stats();
    assert_eq!(accepted, 0);
    assert_eq!(stats.submitted_events, 0);
    assert_eq!(stats.queued_events, 0);
    assert_eq!(stats.queued_bytes, 0);
    assert_eq!(stats.dropped_events, attempts);
    assert_eq!(stats.oversized_events, attempts);
}
