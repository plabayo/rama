//! High-churn FFI flow lifecycles. Useful as a bounded-time sentinel
//! and as a sanitizer harness — the cancel-vs-callback race window
//! is microseconds wide, so concurrent churn under
//! `RUSTFLAGS="-Z sanitizer=address"` is the only reliable way to
//! observe a real UAF. See `just test-e2e-asan`.

use std::time::{Duration, Instant};

use serial_test::serial;

use crate::shared::{
    clients::{roundtrip_custom_protocol, udp_roundtrip},
    env::setup_env,
    ingress::spawn_ingress_listener,
    types::{ProxyKind, TcpMode, localhost},
};

/// 8 sequential plain-TCP roundtrips. Bounded-time sentinel + ASan
/// harness. Iteration count is small because the demo engine's
/// 500ms peek floor makes each roundtrip slow; the cycle is what
/// matters, not throughput.
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

/// 16 sequential UDP roundtrips through `activate` / `on_client_close`
/// / no-lifetime-cap teardown.
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

/// 4 × 4 concurrent TCP roundtrips. The concurrent shape is what
/// gives a sanitizer the cross-thread race window for cancel-vs-
/// bridge-dispatch.
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

/// Leave flows in-flight at test scope end; the engine + ingress
/// `Drop` paths must tolerate a half-finished batch without wedging.
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
