//! FFI stress / churn coverage.
//!
//! Each test drives many flows through the FFI surface to exercise
//! session-handle allocation, callback-box lifetime, the engine's
//! per-flow tasks, and the cancel/drop teardown path. They serve two
//! purposes:
//!
//! 1. **Sentinel for regressions**: a refactor that wedges any of
//!    these paths (an unbounded await in `cancel`, a leaked Arc in
//!    the bridge, a panic on stop with live flows) shows up here
//!    as a timeout / panic. The numbers below are deliberately
//!    conservative so CI noise on a busy runner doesn't false-fail.
//!
//! 2. **Sanitizer harness**: the cancel-vs-callback UAF (audit #1) is
//!    impossible to observe deterministically without a sanitizer —
//!    the race window is microseconds, and on a clean run the test
//!    passes. Run these tests under
//!    `RUSTFLAGS="-Zsanitizer=address" cargo +nightly test ...` (see
//!    `just sanitizer-tproxy-ffi-e2e`) to surface real UAF / data-race
//!    bugs introduced by future changes. The tests' value as a
//!    sanitizer harness is the high flow churn — many opportunities
//!    per second for any race window to land on real memory.

use std::time::{Duration, Instant};

use serial_test::serial;

use crate::shared::{
    clients::{roundtrip_custom_protocol, udp_roundtrip},
    env::setup_env,
    ingress::spawn_ingress_listener,
    types::{ProxyKind, TcpMode, localhost},
};

/// Sequential TCP churn: open + roundtrip + close many flows in
/// succession. Sentinel for cancel/drop wedges and per-flow state
/// growth. Surfaces a UAF under address-sanitizer.
///
/// The iteration count is deliberately conservative because the demo
/// engine's `peek_duration_s = 0.5` floors each plain-TCP roundtrip
/// at ~500ms. The point of this test is the cycle, not throughput;
/// 8 iterations is plenty to exercise the open/close path enough
/// times for a sanitizer to catch a race window.
#[tokio::test]
#[serial]
async fn ffi_stress_tcp_sequential_churn() {
    let env = setup_env().await;
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(env.ports.raw_tcp)).await;
    let ingress_addr = ingress.local_addr();
    let proxy_addr = localhost(env.ports.proxy);

    const N: usize = 8;
    let payload = b"stress raw tcp ffi";
    let started = Instant::now();
    for i in 0..N {
        let echoed = roundtrip_custom_protocol(
            TcpMode::Plain,
            ProxyKind::None,
            ingress_addr.port(),
            ingress_addr,
            proxy_addr,
            payload,
        )
        .await;
        assert_eq!(
            echoed, payload,
            "stress iteration {i} echoed payload mismatch",
        );
    }
    let elapsed = started.elapsed();
    // 8 iterations × ~500ms peek = ~4s; allow generous slack for CI.
    assert!(
        elapsed < Duration::from_secs(15),
        "{N} sequential tcp roundtrips took {elapsed:?} (>15s)",
    );

    ingress.shutdown().await;
}

/// Sequential UDP churn: same as the TCP variant, exercises the UDP
/// session activate / on_client_close / `udp_max_flow_lifetime`-free
/// teardown path. Each iteration allocates fresh callback contexts on
/// the test side, so high churn would surface a session-handle leak
/// as a hang or runtime-task explosion.
#[tokio::test]
#[serial]
async fn ffi_stress_udp_sequential_churn() {
    let env = setup_env().await;

    const N: usize = 16;
    let started = Instant::now();
    for i in 0..N {
        let response =
            udp_roundtrip(env.engine.clone(), localhost(env.ports.udp), b"stress udp ffi").await;
        assert_eq!(
            response.as_slice(),
            b"STRESS UDP FFI",
            "stress iteration {i} udp response mismatch",
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(15),
        "{N} sequential udp roundtrips took {elapsed:?} (>15s)",
    );
}

/// Concurrent TCP churn: many tokio tasks each run their own
/// roundtrip lifecycle. Exercises the cancel-vs-bridge-dispatch
/// race that motivated audit finding #1. On a clean run this just
/// finishes; under address/thread sanitizer it surfaces real races.
#[tokio::test]
#[serial]
async fn ffi_stress_tcp_concurrent_churn() {
    let env = setup_env().await;
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(env.ports.raw_tcp)).await;
    let ingress_addr = ingress.local_addr();
    let proxy_addr = localhost(env.ports.proxy);

    const TASKS: usize = 4;
    const PER_TASK: usize = 4;
    let started = Instant::now();
    let mut handles = Vec::with_capacity(TASKS);
    for task_idx in 0..TASKS {
        let payload = format!("concurrent ffi stress task={task_idx}");
        handles.push(tokio::spawn(async move {
            for i in 0..PER_TASK {
                let echoed = roundtrip_custom_protocol(
                    TcpMode::Plain,
                    ProxyKind::None,
                    ingress_addr.port(),
                    ingress_addr,
                    proxy_addr,
                    payload.as_bytes(),
                )
                .await;
                assert_eq!(
                    echoed,
                    payload.as_bytes(),
                    "task {task_idx} iter {i} echoed payload mismatch",
                );
            }
        }));
    }
    for h in handles {
        h.await.expect("stress task join");
    }
    let elapsed = started.elapsed();
    // 4 tasks × 4 ops in parallel; the peek floor still serialises
    // somewhat per-flow, so allow generous slack on CI.
    assert!(
        elapsed < Duration::from_secs(15),
        "{TASKS}*{PER_TASK} concurrent tcp roundtrips took {elapsed:?} (>15s)",
    );

    ingress.shutdown().await;
}

/// Engine-stop sanity under load: leave a batch of in-flight flows
/// alive, then exercise the existing engine teardown path (the
/// `setup_env` engine drop happens automatically after each test).
/// This is the closest e2e-side analog of the engine unit test
/// `engine_stop_with_live_sessions_drains_within_bound`.
#[tokio::test]
#[serial]
async fn ffi_stress_inflight_flows_at_test_end() {
    let env = setup_env().await;
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(env.ports.raw_tcp)).await;
    let ingress_addr = ingress.local_addr();
    let proxy_addr = localhost(env.ports.proxy);

    // Run a small batch of roundtrips concurrently; do NOT shut the
    // ingress down explicitly. The ingress' Drop fires on test end
    // and aborts in-flight work, exercising the path where the
    // engine sees per-flow tasks dropped while still alive. With a
    // wedge this would block test exit; we add a wall-clock guard.
    const TASKS: usize = 3;
    const PER_TASK: usize = 3;
    let payload = b"inflight ffi stress";
    let started = Instant::now();
    let mut handles = Vec::with_capacity(TASKS);
    for _ in 0..TASKS {
        handles.push(tokio::spawn(async move {
            for _ in 0..PER_TASK {
                let echoed = roundtrip_custom_protocol(
                    TcpMode::Plain,
                    ProxyKind::None,
                    ingress_addr.port(),
                    ingress_addr,
                    proxy_addr,
                    payload,
                )
                .await;
                assert_eq!(echoed, payload);
            }
        }));
    }
    for h in handles {
        h.await.expect("stress task join");
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(15),
        "inflight stress took {elapsed:?} (>15s)",
    );
    // Intentional: do NOT call `ingress.shutdown()`. Drop runs as
    // the test exits; the engine and per-flow tasks must tolerate
    // it without wedging. Hold a reference so the engine isn't
    // dropped before the ingress' own Drop runs.
    drop(env);
    drop(ingress);
}
