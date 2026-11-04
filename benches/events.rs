//! What a typed event costs at the emit site.
//!
//! The case that has to be free is a crate emitting a fact nobody listens to:
//! one atomic load and a branch, with the event itself never built. The
//! baseline builds the same event and keeps it, so the difference shows what
//! the lazy closure saves. The listener rows are the whole round: build the
//! event, call one listener inline, with and without that listener asking for
//! the time of the emit.

use divan::black_box;
use rama::telemetry::event::{Emitted, Emitter, Event, EventDispatcher};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::time::Instant;

mod bench_alloc;

fn main() {
    divan::main();
}

#[derive(Clone, Event)]
struct PathChanged {
    connection: u64,
    peer: u16,
}

// Uses the time without reading the clock again, so the rows below measure
// `at()` itself.
fn since(at: Instant, base: Instant) -> u64 {
    at.saturating_duration_since(base).as_nanos() as u64
}

fn path_changed() -> PathChanged {
    PathChanged {
        connection: black_box(42),
        peer: black_box(443),
    }
}

#[divan::bench]
fn build_event_baseline(bencher: divan::Bencher) {
    bencher.bench(|| black_box(path_changed()));
}

#[divan::bench]
fn emit_without_listeners(bencher: divan::Bencher) {
    let dispatcher = EventDispatcher::default();
    let emitter = Emitter::<PathChanged>::from_dispatcher(&dispatcher);

    bencher.bench(|| emitter.emit_with(path_changed));
}

#[divan::bench]
fn emit_with_one_listener(bencher: divan::Bencher) {
    let dispatcher = EventDispatcher::default();
    let emitter = Emitter::<PathChanged>::from_dispatcher(&dispatcher);
    let seen = Arc::new(AtomicU64::new(0));

    let listener = seen.clone();
    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, PathChanged>| {
        listener.fetch_add(
            event.event().connection + u64::from(event.event().peer),
            Ordering::Relaxed,
        );
    });

    bencher.bench(|| emitter.emit_with(path_changed));
    black_box(seen.load(Ordering::Relaxed));
}

#[divan::bench]
fn emit_with_one_listener_reading_the_time(bencher: divan::Bencher) {
    let dispatcher = EventDispatcher::default();
    let emitter = Emitter::<PathChanged>::from_dispatcher(&dispatcher);
    let seen = Arc::new(AtomicU64::new(0));

    let base = Instant::now();
    let listener = seen.clone();
    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, PathChanged>| {
        listener.fetch_add(
            event.event().connection + since(event.at(), base),
            Ordering::Relaxed,
        );
    });

    bencher.bench(|| emitter.emit_with(path_changed));
    black_box(seen.load(Ordering::Relaxed));
}

#[divan::bench]
fn emit_at_with_one_listener_reading_the_time(bencher: divan::Bencher) {
    let dispatcher = EventDispatcher::default();
    let emitter = Emitter::<PathChanged>::from_dispatcher(&dispatcher);
    let seen = Arc::new(AtomicU64::new(0));

    let base = Instant::now();
    let listener = seen.clone();
    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, PathChanged>| {
        listener.fetch_add(
            event.event().connection + since(event.at(), base),
            Ordering::Relaxed,
        );
    });

    let at = Instant::now();
    bencher.bench(|| emitter.emit_at(at, path_changed));
    black_box(seen.load(Ordering::Relaxed));
}
