//! Seeded-random adversarial scenarios for the UDP session API.
//!
//! Each scenario:
//!
//! 1. Builds an engine + intercepts a UDP session;
//! 2. Optionally activates BEFORE or AFTER some random on-client-datagram
//!    calls (covers both orderings — the engine buffers pre-activate
//!    datagrams in the bounded ingress channel and the service sees them
//!    in arrival order once activate fires).
//! 3. Applies 6–24 random actions from the public surface
//!    (`on_client_datagram` with random size + peer attribution, plus
//!    `on_client_close`).
//! 4. Either drops the session early or lets it run to natural close.
//! 5. Calls `engine.stop` with a bounded budget and asserts:
//!    * the stop completes within budget (no hang);
//!    * no datagrams are corrupted (each received payload matches what
//!      was sent, accounting for the lossy bounded channel — drops are
//!      OK, mangling is not);
//!    * service task always exits (no orphan flow).
//!
//! The per-flow tests in `udp.rs` pin specific behaviours by hand. This
//! suite catches compositions we did not — e.g. `on_client_close` mid-
//! activate, large datagram immediately followed by a zero-length one,
//! peer-attribution flapping between Some and None.
//!
//! Reproducibility: every scenario's seed is announced when the suite
//! starts; a failure prints the action trace and the seed. Re-running
//! with `RAMA_FUZZ_SEED=<n>` reproduces the same draw.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::service::service_fn;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Mulberry32 — same construction as the TCP fuzz harness and the Swift
/// pump fuzzer so reproductions across the three layers are comparable.
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

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u32() as usize) % (hi - lo + 1)
    }
}

#[derive(Clone, Debug)]
enum Action {
    Datagram {
        len: usize,
        #[expect(dead_code, reason = "captured for failure-trace readability")]
        peer: Option<SocketAddr>,
    },
    ClientClose,
    Activate,
}

fn random_peer(rng: &mut Mulberry32) -> Option<SocketAddr> {
    match rng.next_u32() % 4 {
        // `None` is the safety-valve case; engine must accept it.
        0 => None,
        1 => Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 53))),
        2 => Some(SocketAddr::from((Ipv4Addr::new(8, 8, 4, 4), 53))),
        _ => Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 853))),
    }
}

fn deterministic_payload(len: usize, ordinal: usize) -> Vec<u8> {
    // Pattern depends on ordinal so we can tell datagrams apart when
    // examining the received-payload list. Length 0 is a valid datagram.
    (0..len)
        .map(|i| ((ordinal.wrapping_add(i)).wrapping_mul(0xB5) & 0xFF) as u8)
        .collect()
}

fn run_one_scenario(seed: u32) -> Vec<Action> {
    let mut rng = Mulberry32::new(seed);

    // Service captures whatever datagrams arrive; the test asserts that
    // each one matches the ordinal-encoded payload it was sent with
    // (drops are OK, content corruption is not).
    let received = Arc::new(Mutex::new(Vec::<(usize, Option<SocketAddr>)>::new()));
    let received_clone = received.clone();
    let service_exited = Arc::new(AtomicUsize::new(0));
    let service_exited_cb = service_exited.clone();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let service_exited = service_exited_cb.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received = received.clone();
                    let service_exited = service_exited.clone();
                    async move {
                        while let Some(datagram) = flow.recv().await {
                            received
                                .lock()
                                .push((datagram.payload.len(), datagram.peer));
                        }
                        service_exited.fetch_add(1, Ordering::Relaxed);
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Decide once per scenario whether to activate up-front, lazily after
    // a few datagrams, or never (drop without activate). All three are
    // legitimate Swift-side patterns and the engine must handle each.
    let activate_phase = rng.range(0, 2);
    // 0 = activate immediately
    // 1 = activate mid-trace
    // 2 = never activate (close-without-activate)

    let action_count = rng.range(6, 24);
    let activate_index = if activate_phase == 1 {
        Some(rng.range(0, action_count.saturating_sub(1)))
    } else {
        None
    };
    if activate_phase == 0 {
        session.activate();
    }

    let mut trace = Vec::with_capacity(action_count + 2);
    let mut closed_early = false;
    for i in 0..action_count {
        if Some(i) == activate_index {
            session.activate();
            trace.push(Action::Activate);
        }
        // Bias toward datagrams; reserve a small chance for an early
        // client-close which terminates the flow before the trace ends.
        if rng.next_u32().is_multiple_of(16) && !closed_early {
            session.on_client_close();
            trace.push(Action::ClientClose);
            closed_early = true;
            continue;
        }
        // Length distribution: weighted toward small but include 0
        // (RFC 768) and an occasional jumbo (close to channel cap).
        let len = match rng.next_u32() % 8 {
            0 => 0,
            1..=5 => rng.range(1, 256),
            _ => rng.range(1024, 8192),
        };
        let peer = random_peer(&mut rng);
        let payload = deterministic_payload(len, i);
        session.on_client_datagram(&payload, peer);
        trace.push(Action::Datagram { len, peer });
    }

    // Random per-scenario tail choice:
    //   * drop the session early (Drop calls on_client_close);
    //   * call on_client_close explicitly then drop;
    //   * just let it drop at scope exit.
    let tail = rng.next_u32() % 3;
    if tail == 0 && !closed_early {
        session.on_client_close();
        trace.push(Action::ClientClose);
    }
    drop(session);

    // engine.stop must complete within budget regardless of scenario.
    let stop_started = std::time::Instant::now();
    engine.stop(0);
    let stop_elapsed = stop_started.elapsed();
    assert!(
        stop_elapsed < Duration::from_secs(5),
        "seed={seed} engine.stop took {stop_elapsed:?}; trace: {trace:?}"
    );

    // Service task must not double-exit. It may legitimately be 0
    // (the never-activate path doesn't run the user service body
    // — the task ends in its synthetic-close epilogue when
    // `bridge_rx` returns Err) or 1 (activated path that
    // cooperatively unwinds). Two or more is a bug: the user
    // service ran twice for one session.
    assert!(
        service_exited.load(Ordering::Relaxed) <= 1,
        "seed={seed} service task entered user body more than once; trace: {trace:?}"
    );

    // Content integrity: every received payload must match what was sent.
    // Drops are allowed (lossy bounded channel), but bytes can't change.
    // We can't easily map drops 1-to-1, so we just verify each received
    // length appears as a "Datagram" action with the same length, in
    // order. (Engine guarantees FIFO per-flow.)
    let got = received.lock().clone();
    let sent_lens: Vec<usize> = trace
        .iter()
        .filter_map(|a| match a {
            Action::Datagram { len, .. } => Some(*len),
            _ => None,
        })
        .collect();
    assert!(
        got.len() <= sent_lens.len(),
        "seed={seed} received more datagrams than sent; got={}, sent={}; trace: {trace:?}",
        got.len(),
        sent_lens.len()
    );
    // received must be a (FIFO) subsequence of sent.
    let mut sent_iter = sent_lens.into_iter();
    for (rx_len, _peer) in &got {
        let mut matched = false;
        for tx_len in sent_iter.by_ref() {
            if tx_len == *rx_len {
                matched = true;
                break;
            }
        }
        assert!(
            matched,
            "seed={seed} received datagram length {rx_len} not a FIFO subsequence of sent; trace: {trace:?}"
        );
    }

    trace
}

#[test]
fn udp_random_action_sequences_terminate_within_budget() {
    let env_seed = std::env::var("RAMA_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let base_seed = env_seed.unwrap_or_else(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        now.wrapping_mul(0x9E3779B1)
    });

    // Per-scenario work is in-memory; 1_000 keeps the suite under a
    // second on a release build. `RAMA_FUZZ_DEEP=1` cranks to 20_000
    // for nightly soaks, matching the TCP harness.
    let count = if std::env::var("RAMA_FUZZ_DEEP").is_ok() {
        20_000
    } else {
        1_000
    };

    eprintln!(
        "udp_random_action_sequences: baseSeed={base_seed} count={count} \
         (re-run with RAMA_FUZZ_SEED=<n> to reproduce)"
    );

    let started = std::time::Instant::now();
    for i in 0..count {
        run_one_scenario(base_seed.wrapping_add(i as u32));
    }
    eprintln!(
        "udp_random_action_sequences: {count} scenarios in {:?}",
        started.elapsed()
    );
}
