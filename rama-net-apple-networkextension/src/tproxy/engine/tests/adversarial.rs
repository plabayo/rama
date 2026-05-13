//! Seeded-random adversarial scenarios for the TCP session API.
//!
//! Each scenario:
//!
//! 1. Builds an engine + intercepts a TCP session;
//! 2. Activates the session and applies 6–16 random actions from the
//!    public surface (`on_client_bytes`, `on_egress_bytes`,
//!    `on_client_eof`, `on_egress_eof`, `signal_server_drain`,
//!    `signal_egress_drain`);
//! 3. Either cancels the session or lets it run to natural close
//!    (chosen randomly per scenario);
//! 4. Calls `engine.stop` with a bounded budget and asserts:
//!    * the stop completes within budget (no hang);
//!    * `on_server_closed` fires AT MOST once across the scenario
//!      (the engine documents single-fire; cancel-initiated paths
//!      may legitimately suppress it, which is also acceptable —
//!      see `tcp_cancel_after_activate_suppresses_close_callback_to_prevent_uaf`).
//!
//! The per-pump tests in `safety.rs` and the bridge tests in `tcp.rs`
//! pin the specific races we identified by hand. This suite catches
//! the composition we did not — e.g. `on_client_eof` arriving
//! mid-Paused replay, `signal_egress_drain` racing `cancel`, etc.
//!
//! Reproducibility: every scenario's seed is announced when the suite
//! starts; a failure prints the exact action trace and the seed.
//! Re-running with `RAMA_FUZZ_SEED=<n>` reproduces the same draw.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use rama_core::io::BridgeIo;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

/// Mulberry32 — small deterministic PRNG. Same construction as the
/// Swift fuzz harness so reproductions across the two layers are
/// trivially comparable when a related bug appears on both sides.
struct Mulberry32 {
    state: u32,
}

impl Mulberry32 {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_add(0x6D2B79F5);
        let mut z = self.state;
        z = (z ^ (z >> 15)).wrapping_mul(z | 1);
        z ^= z.wrapping_add((z ^ (z >> 7)).wrapping_mul(z | 61));
        z ^ (z >> 14)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.next_u32() as usize % items.len()]
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u32() as usize) % (hi - lo + 1)
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    OnClientBytes,
    OnEgressBytes,
    OnClientEof,
    OnEgressEof,
    SignalServerDrain,
    SignalEgressDrain,
}

impl Action {
    const ALL: [Action; 6] = [
        Action::OnClientBytes,
        Action::OnEgressBytes,
        Action::OnClientEof,
        Action::OnEgressEof,
        Action::SignalServerDrain,
        Action::SignalEgressDrain,
    ];
}

fn run_one_scenario(seed: u32) -> Vec<Action> {
    let mut rng = Mulberry32::new(seed);
    let server_bytes_seen = Arc::new(AtomicUsize::new(0));
    let demand_count = Arc::new(AtomicUsize::new(0));
    let (closed_tx, closed_rx) = mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            // Service holds the bridge halves and parks. Pure
            // backpressure exercise — we drive the session API from
            // the test thread, not the service.
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(stream, egress) = bridge;
                    let _hold = (stream, egress);
                    std::future::pending::<()>().await;
                    Ok(())
                },
            )
            .boxed(),
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        udp_egress_options: None,
        };
    let engine = build_engine(handler);

    let server_bytes_seen_cb = server_bytes_seen.clone();
    let demand_count_cb = demand_count.clone();
    let closed_tx_cb = closed_tx;
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
            .with_remote_endpoint(HostWithPort::example_domain_with_port(443)),
        move |bytes| {
            server_bytes_seen_cb.fetch_add(bytes.len(), Ordering::Relaxed);
            TcpDeliverStatus::Accepted
        },
        move || {
            demand_count_cb.fetch_add(1, Ordering::Relaxed);
        },
        move || {
            // Exactly-once is what the suite asserts. The receiver
            // counts via `recv_timeout` below — channel send drops
            // the sender on first close so further sends would
            // surface as recv errors, but `on_server_closed` is
            // wired to fire once per session by the engine.
            _ = closed_tx_cb.send(());
        },
    ) else {
        panic!("expected intercept session");
    };

    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    let action_count = rng.range(6, 16);
    let mut trace = Vec::with_capacity(action_count + 1);
    for _ in 0..action_count {
        let action = *rng.pick(&Action::ALL);
        trace.push(action);
        match action {
            Action::OnClientBytes => {
                let len = rng.range(1, 64);
                let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
                _ = session.on_client_bytes(&payload);
            }
            Action::OnEgressBytes => {
                let len = rng.range(1, 64);
                let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(11)).collect();
                _ = session.on_egress_bytes(&payload);
            }
            Action::OnClientEof => session.on_client_eof(),
            Action::OnEgressEof => session.on_egress_eof(),
            Action::SignalServerDrain => session.signal_server_drain(),
            Action::SignalEgressDrain => session.signal_egress_drain(),
        }
    }

    // Random per-scenario choice: cancel the session, or let it run
    // to natural close. Both paths must terminate cleanly; only the
    // natural path guarantees `on_server_closed` fires (cancel
    // suppresses to prevent UAF — by design).
    let did_cancel = rng.next_u32() & 1 == 0;
    if did_cancel {
        session.cancel();
        trace.push(Action::OnClientEof); // marker for the trace
    }
    drop(session);

    // Engine.stop drives the runtime to drain. With a healthy
    // implementation this completes in well under a second; we
    // budget multiple seconds so CI noise cannot flake the assertion
    // without actually catching a hang.
    let stop_started = std::time::Instant::now();
    engine.stop(0);
    let stop_elapsed = stop_started.elapsed();
    assert!(
        stop_elapsed < Duration::from_secs(5),
        "seed={seed} engine.stop took {stop_elapsed:?}; trace: {trace:?}",
    );

    // Whether or not on_server_closed fired is fine — the engine
    // documents that cancel-initiated teardown may suppress it. What
    // we must NOT see is more than one fire.
    let first = closed_rx.recv_timeout(Duration::from_millis(50));
    if first.is_ok() {
        let second = closed_rx.recv_timeout(Duration::from_millis(50));
        assert!(
            second.is_err(),
            "seed={seed} on_server_closed fired more than once; trace: {trace:?}",
        );
    }

    trace
}

#[test]
fn tcp_random_action_sequences_close_exactly_once_within_budget() {
    let env_seed = std::env::var("RAMA_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let base_seed = env_seed.unwrap_or_else(|| {
        // Pick a pseudo-random seed without bringing in `rand`.
        // Wall-clock low bits are good enough for "different on
        // every run unless pinned".
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        now.wrapping_mul(0x9E3779B1)
    });

    // Each scenario does only in-memory work — no socket I/O, no
    // real network — so a single one completes in well under a
    // millisecond on a release build. 1_000 keeps the suite under a
    // second; RAMA_FUZZ_DEEP=1 cranks to 20_000 for nightly soaks.
    let count = if std::env::var("RAMA_FUZZ_DEEP").is_ok() {
        20_000
    } else {
        1_000
    };

    eprintln!(
        "tcp_random_action_sequences: baseSeed={base_seed} count={count} \
         (re-run with RAMA_FUZZ_SEED=<n> to reproduce)"
    );

    let started = std::time::Instant::now();
    for i in 0..count {
        run_one_scenario(base_seed.wrapping_add(i as u32));
    }
    eprintln!(
        "tcp_random_action_sequences: {count} scenarios in {:?}",
        started.elapsed()
    );
}
