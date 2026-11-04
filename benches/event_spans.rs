//! What a span costs at a unit root, against what rama pays there today.
//!
//! The case that has to be free is an inactive span, with no listener and no
//! span adapter: no event built, one branch per poll, and a drop that does
//! nothing. `plain_future` is that same future without a span around it. The
//! tracing rows are what a unit root does today, a `trace_root_span!` plus
//! `.instrument`, measured both with the span disabled and with a subscriber
//! that enables it, so the span adapter row and the tracing row pay for the
//! same work.

use divan::black_box;
use rama::net::id::ConnectionId;
use rama::tcp::server::{TcpServerConnectionClosed, TcpServerConnectionOpened};
use rama::telemetry::event::{EventDispatcher, SpanEmitter, SpanFutureExt as _};
use rama::telemetry::tracing::{
    Instrument as _, subscriber::util::SubscriberInitExt as _, trace_root_span,
};
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

mod bench_alloc;

fn main() {
    divan::main();
}

fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    future.as_mut().poll(&mut context)
}

async fn work() -> u64 {
    black_box(1)
}

fn accepted(connection: ConnectionId) -> TcpServerConnectionOpened {
    TcpServerConnectionOpened {
        connection,
        local: None,
        peer: ([127, 0, 0, 1], 0).into(),
    }
}

#[divan::bench]
fn plain_future(bencher: divan::Bencher) {
    bencher.bench(|| black_box(poll_once(work())));
}

#[divan::bench]
fn span_inactive(bencher: divan::Bencher) {
    let dispatcher = EventDispatcher::default();
    let spans = SpanEmitter::<TcpServerConnectionOpened>::from_dispatcher(&dispatcher);

    bencher.bench(|| {
        let connection = ConnectionId::next();
        let span = spans.open_with(
            || accepted(connection),
            move || TcpServerConnectionClosed { connection },
        );
        black_box(poll_once(work().observe_ref(&span)))
    });
}

#[divan::bench]
fn span_with_a_tracing_adapter(bencher: divan::Bencher) {
    let _subscriber = rama::telemetry::tracing::subscriber::registry().set_default();
    let dispatcher = EventDispatcher::default();
    let _adapter = dispatcher.add_span_adapter(TcpServerConnectionOpened::tracing_spans());
    let spans = SpanEmitter::<TcpServerConnectionOpened>::from_dispatcher(&dispatcher);

    bencher.bench(|| {
        let connection = ConnectionId::next();
        let span = spans.open_with(
            || accepted(connection),
            move || TcpServerConnectionClosed { connection },
        );
        let polled = black_box(poll_once(work().observe_ref(&span)));
        span.close_with(|end| end);
        polled
    });
}

#[divan::bench]
fn tracing_span_disabled(bencher: divan::Bencher) {
    bencher.bench(|| {
        let span = trace_root_span!(
            "tcp::serve_graceful",
            otel.kind = "server",
            network.peer.port = 0,
            network.protocol.name = "tcp",
        );
        black_box(poll_once(work().instrument(span)))
    });
}

#[divan::bench]
fn tracing_span_enabled(bencher: divan::Bencher) {
    let _subscriber = rama::telemetry::tracing::subscriber::registry().set_default();

    bencher.bench(|| {
        let span = trace_root_span!(
            "tcp::serve_graceful",
            otel.kind = "server",
            network.peer.port = 0,
            network.protocol.name = "tcp",
        );
        black_box(poll_once(work().instrument(span)))
    });
}
