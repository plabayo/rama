//! Per-flow decision tests: passthrough / blocked / intercept and the
//! decision-deadline backstop.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{
    FlowRefusalAction, TransparentProxyConfig, TransparentProxyFlowMeta,
    TransparentProxyFlowProtocol,
};
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::io::BridgeIo;
use rama_core::rt::Executor;
use rama_core::service::{Service, service_fn};
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

#[derive(Clone)]
enum DecisionProbeHold {
    Delay(Duration),
    Latch(DecisionLatch),
}

#[derive(Clone)]
struct DecisionProbe {
    hold: DecisionProbeHold,
    config: TransparentProxyConfig,
    tcp_calls: Arc<AtomicUsize>,
    udp_calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

struct ProbeActiveGuard(Arc<AtomicUsize>);

impl Drop for ProbeActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl DecisionProbe {
    fn with_flow_refusal_action(mut self, action: FlowRefusalAction) -> Self {
        self.config = self.config.with_flow_refusal_action(action);
        self
    }

    async fn enter(&self) {
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(active, Ordering::Relaxed);
        let _guard = ProbeActiveGuard(self.active.clone());
        match &self.hold {
            DecisionProbeHold::Delay(delay) => tokio::time::sleep(*delay).await,
            DecisionProbeHold::Latch(latch) => {
                latch.arrive();
                latch.wait_for_release().await;
            }
        }
    }

    fn calls(&self) -> usize {
        self.tcp_calls.load(Ordering::Relaxed) + self.udp_calls.load(Ordering::Relaxed)
    }
}

struct DecisionLatchState {
    arrivals: Mutex<usize>,
    arrivals_changed: Condvar,
    released: std::sync::atomic::AtomicBool,
    release_notify: tokio::sync::Notify,
}

#[derive(Clone)]
struct DecisionLatch(Arc<DecisionLatchState>);

impl DecisionLatch {
    fn new() -> Self {
        Self(Arc::new(DecisionLatchState {
            arrivals: Mutex::new(0),
            arrivals_changed: Condvar::new(),
            released: std::sync::atomic::AtomicBool::new(false),
            release_notify: tokio::sync::Notify::new(),
        }))
    }

    fn arrive(&self) {
        let mut arrivals = self.0.arrivals.lock();
        *arrivals += 1;
        self.0.arrivals_changed.notify_all();
    }

    fn wait_for_arrivals(&self, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut arrivals = self.0.arrivals.lock();
        while *arrivals < expected {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if self
                .0
                .arrivals_changed
                .wait_for(&mut arrivals, remaining)
                .timed_out()
            {
                break;
            }
        }
        assert!(
            *arrivals >= expected,
            "decision latch observed only {} of {expected} arrivals",
            *arrivals,
        );
    }

    async fn wait_for_release(&self) {
        loop {
            let notified = self.0.release_notify.notified();
            if self.0.released.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn release(&self) {
        self.0.released.store(true, Ordering::Release);
        self.0.release_notify.notify_waiters();
    }
}

struct ReleaseDecisionLatchOnDrop(DecisionLatch);

impl Drop for ReleaseDecisionLatchOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl TransparentProxyHandler for DecisionProbe {
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        self.config.clone()
    }

    async fn match_tcp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> FlowAction<
        impl Service<BridgeIo<crate::TcpFlow, crate::NwTcpStream>, Output = (), Error = Infallible>,
    > {
        self.tcp_calls.fetch_add(1, Ordering::Relaxed);
        self.enter().await;
        FlowAction::<TestTcpService>::Passthrough
    }

    async fn match_udp_flow(
        &self,
        _exec: Executor,
        _meta: TransparentProxyFlowMeta,
    ) -> FlowAction<impl Service<crate::UdpFlow, Output = (), Error = Infallible>> {
        self.udp_calls.fetch_add(1, Ordering::Relaxed);
        self.enter().await;
        FlowAction::<TestUdpService>::Passthrough
    }
}

#[derive(Clone)]
struct DecisionProbeFactory(DecisionProbe);

impl TransparentProxyHandlerFactory for DecisionProbeFactory {
    type Handler = DecisionProbe;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(Ok(self.0.clone()))
    }
}

fn decision_probe(delay: Duration) -> DecisionProbe {
    DecisionProbe {
        hold: DecisionProbeHold::Delay(delay),
        config: TransparentProxyConfig::new(),
        tcp_calls: Arc::new(AtomicUsize::new(0)),
        udp_calls: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    }
}

fn latched_decision_probe() -> (DecisionProbe, DecisionLatch) {
    let latch = DecisionLatch::new();
    let probe = DecisionProbe {
        hold: DecisionProbeHold::Latch(latch.clone()),
        config: TransparentProxyConfig::new(),
        tcp_calls: Arc::new(AtomicUsize::new(0)),
        udp_calls: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    };
    (probe, latch)
}

#[test]
fn tcp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn udp_session_passthrough_by_default() {
    let engine = build_engine(TestHandler::passthrough());
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
}

#[test]
fn tcp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Blocked),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });
    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[test]
fn udp_session_can_be_blocked() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Blocked),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });
    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
}

#[test]
fn app_message_panic_drops_message_without_aborting_engine() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| panic!("boom app message")),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });

    let reply = engine.handle_app_message(Bytes::from_static(b"ping"));
    assert!(reply.is_none());

    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
    engine.stop(0);
}

#[test]
fn tcp_decision_panic_blocks_by_default() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| panic!("boom tcp decision")),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });

    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
    engine.stop(0);
}

#[test]
fn tcp_decision_panic_honors_passthrough_action() {
    let engine = build_engine_with_decision_deadline(
        TestHandler {
            app_message_handler: Arc::new(|_| None),
            tcp_matcher: Arc::new(|_| panic!("boom tcp decision")),
            udp_matcher: Arc::new(|_| FlowAction::Passthrough),
            tcp_egress_options: None,
            on_sleep: None,
            on_wake: None,
        },
        Duration::from_secs(2),
        super::super::DecisionDeadlineAction::Passthrough,
    );

    let decision = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Passthrough));
    engine.stop(0);
}

#[test]
fn udp_decision_panic_blocks_by_default() {
    let engine = build_engine(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|_| panic!("boom udp decision")),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    });

    let decision = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    );
    assert!(matches!(decision, SessionFlowAction::Blocked));
    engine.stop(0);
}

#[derive(Clone)]
struct SlowMatchHandler {
    delay: Duration,
}

impl TransparentProxyHandler for SlowMatchHandler {
    fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        TransparentProxyConfig::new()
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<crate::TcpFlow, crate::NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestTcpService>::Intercept {
                meta,
                service: service_fn(
                    |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                        let BridgeIo(stream, egress) = bridge;
                        let _hold = (stream, egress);
                        std::future::pending::<()>().await;
                        Ok(())
                    },
                )
                .boxed(),
            }
        }
    }

    fn match_udp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<impl Service<crate::UdpFlow, Output = (), Error = Infallible>>,
    > + Send
    + '_ {
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            FlowAction::<TestUdpService>::Intercept {
                meta,
                service: service_fn(|flow: crate::UdpFlow| async move {
                    let _hold = flow;
                    std::future::pending::<()>().await;
                    Ok(())
                })
                .boxed(),
            }
        }
    }
}

#[derive(Clone)]
struct SlowMatchHandlerFactory(SlowMatchHandler);

impl TransparentProxyHandlerFactory for SlowMatchHandlerFactory {
    type Handler = SlowMatchHandler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        _ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        let h = self.0.clone();
        std::future::ready(Ok(h))
    }
}

#[test]
fn decision_deadline_blocks_slow_handler_by_default() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .build()
    .expect("build engine");

    let started = Instant::now();
    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(action, SessionFlowAction::Blocked),
        "expected Blocked on deadline"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "decision deadline should fire before slow handler completes (elapsed: {elapsed:?})"
    );
    engine.stop(0);
}

#[test]
fn decision_deadline_passthrough_when_action_is_passthrough() {
    let engine = TransparentProxyEngineBuilder::new(SlowMatchHandlerFactory(SlowMatchHandler {
        delay: Duration::from_secs(5),
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_deadline(Duration::from_millis(100))
    .with_decision_deadline_action(super::super::DecisionDeadlineAction::Passthrough)
    .build()
    .expect("build engine");

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Passthrough));
    engine.stop(0);
}

#[test]
fn decision_deadline_does_not_fire_for_fast_handlers() {
    // Fast intercept — well within the configured 2s deadline.
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
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
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine_with_decision_deadline(
        handler,
        Duration::from_secs(2),
        super::super::DecisionDeadlineAction::Block,
    );

    let action = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    assert!(matches!(action, SessionFlowAction::Intercept(_)));
    engine.stop(0);
}

#[test]
fn decision_concurrency_limit_rejects_zero_at_build_time() {
    let result = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler::passthrough()))
        .with_runtime_factory(TestRuntimeFactory)
        .with_decision_concurrency_limit(0)
        .build();
    let Err(error) = result else {
        panic!("zero decision concurrency must be rejected");
    };
    assert!(
        error
            .to_string()
            .contains("decision_concurrency_limit must be > 0")
    );
}

#[test]
fn shared_tcp_udp_decision_gate_uses_default_refusal_independently_of_block_deadline() {
    assert_shared_tcp_udp_decision_gate(Some(4));
}

#[test]
fn shared_tcp_udp_decision_gate_uses_production_default_limit() {
    assert_shared_tcp_udp_decision_gate(None);
}

fn assert_shared_tcp_udp_decision_gate(configured_limit: Option<usize>) {
    let expected_limit = configured_limit.unwrap_or(DEFAULT_DECISION_CONCURRENCY_LIMIT);
    let (probe, latch) = latched_decision_probe();
    let _release_on_drop = ReleaseDecisionLatchOnDrop(latch.clone());
    let mut builder = TransparentProxyEngineBuilder::new(DecisionProbeFactory(probe.clone()))
        .with_runtime_factory(TestRuntimeFactory)
        .with_decision_deadline(Duration::from_secs(30))
        .with_decision_deadline_action(DecisionDeadlineAction::Block);
    if let Some(limit) = configured_limit {
        builder = builder.with_decision_concurrency_limit(limit);
    }
    let engine = Arc::new(builder.build().expect("build engine"));

    let mut workers = Vec::new();
    for flow_id in 0..expected_limit {
        let engine = engine.clone();
        workers.push(std::thread::spawn(move || {
            let mut meta = TransparentProxyFlowMeta::new(if flow_id % 2 == 0 {
                TransparentProxyFlowProtocol::Tcp
            } else {
                TransparentProxyFlowProtocol::Udp
            });
            meta.flow_id = flow_id as u64 + 1;
            if flow_id % 2 == 0 {
                engine.new_tcp_session(meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
            } else {
                match engine.new_udp_session(meta, |_| {}, |_| {}, || {}) {
                    SessionFlowAction::Blocked => SessionFlowAction::Blocked,
                    SessionFlowAction::Passthrough => SessionFlowAction::Passthrough,
                    SessionFlowAction::Intercept(_) => panic!("probe never intercepts"),
                }
            }
        }));
    }

    latch.wait_for_arrivals(expected_limit);
    assert_eq!(probe.active.load(Ordering::Acquire), expected_limit);
    let tcp_overload = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    let udp_overload = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    );
    assert!(matches!(tcp_overload, SessionFlowAction::Passthrough));
    assert!(matches!(udp_overload, SessionFlowAction::Passthrough));
    assert_eq!(
        probe.calls(),
        expected_limit,
        "overload must not invoke policy"
    );

    latch.release();
    for worker in workers {
        assert!(matches!(
            worker.join().expect("decision worker panicked"),
            SessionFlowAction::Passthrough
        ));
    }
    let snapshot = engine.decision_concurrency_snapshot_for_test();
    assert_eq!(snapshot.limit, expected_limit);
    assert_eq!(snapshot.active, 0);
    assert_eq!(snapshot.peak_active, expected_limit);
    assert_eq!(snapshot.overload_refusals, 2);
    assert_eq!(probe.peak.load(Ordering::Relaxed), expected_limit);
    if let Ok(engine) = Arc::try_unwrap(engine) {
        engine.stop(0);
    }
}

#[test]
fn saturated_decision_gate_honors_block_refusal_independently_of_deadline() {
    let (probe, latch) = latched_decision_probe();
    let probe = probe.with_flow_refusal_action(FlowRefusalAction::Block);
    let _release_on_drop = ReleaseDecisionLatchOnDrop(latch.clone());
    let engine = Arc::new(
        TransparentProxyEngineBuilder::new(DecisionProbeFactory(probe.clone()))
            .with_runtime_factory(TestRuntimeFactory)
            .with_decision_deadline(Duration::from_secs(30))
            .with_decision_deadline_action(DecisionDeadlineAction::Passthrough)
            .with_decision_concurrency_limit(1)
            .build()
            .expect("build engine"),
    );
    let worker_engine = engine.clone();
    let worker = std::thread::spawn(move || {
        worker_engine.new_udp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
            |_| {},
            |_| {},
            || {},
        )
    });
    latch.wait_for_arrivals(1);
    assert_eq!(probe.active.load(Ordering::Acquire), 1);

    let overload = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    );
    let udp_overload = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    );
    assert!(matches!(overload, SessionFlowAction::Blocked));
    assert!(matches!(udp_overload, SessionFlowAction::Blocked));
    assert_eq!(probe.calls(), 1, "overload must not invoke policy");
    latch.release();
    assert!(matches!(
        worker.join().expect("decision worker panicked"),
        SessionFlowAction::Passthrough
    ));
    let snapshot = engine.decision_concurrency_snapshot_for_test();
    assert_eq!(snapshot.active, 0);
    assert_eq!(snapshot.overload_refusals, 2);
    if let Ok(engine) = Arc::try_unwrap(engine) {
        engine.stop(0);
    }
}

#[test]
fn decision_permit_recovers_after_deadline_and_panic() {
    let timeout_probe = decision_probe(Duration::from_secs(5));
    let timeout_engine =
        TransparentProxyEngineBuilder::new(DecisionProbeFactory(timeout_probe.clone()))
            .with_runtime_factory(TestRuntimeFactory)
            .with_decision_deadline(Duration::from_millis(20))
            .with_decision_concurrency_limit(1)
            .build()
            .expect("build timeout engine");
    for _ in 0..2 {
        assert!(matches!(
            timeout_engine.new_tcp_session(
                TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
                |_| TcpDeliverStatus::Accepted,
                || {},
                || {},
            ),
            SessionFlowAction::Blocked
        ));
    }
    assert_eq!(timeout_probe.calls(), 2);
    let timeout_snapshot = timeout_engine.decision_concurrency_snapshot_for_test();
    assert_eq!(timeout_snapshot.active, 0);
    assert_eq!(timeout_snapshot.overload_refusals, 0);
    timeout_engine.stop(0);

    let panic_calls = Arc::new(AtomicUsize::new(0));
    let panic_calls_for_handler = panic_calls.clone();
    let panic_engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |_| {
            panic_calls_for_handler.fetch_add(1, Ordering::Relaxed);
            panic!("synthetic decision panic")
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_concurrency_limit(1)
    .build()
    .expect("build panic engine");
    for _ in 0..2 {
        assert!(matches!(
            panic_engine.new_tcp_session(
                TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
                |_| TcpDeliverStatus::Accepted,
                || {},
                || {},
            ),
            SessionFlowAction::Blocked
        ));
    }
    assert_eq!(panic_calls.load(Ordering::Relaxed), 2);
    let panic_snapshot = panic_engine.decision_concurrency_snapshot_for_test();
    assert_eq!(panic_snapshot.active, 0);
    assert_eq!(panic_snapshot.overload_refusals, 0);
    panic_engine.stop(0);
}

#[test]
fn fast_sequential_mass_decisions_are_never_shed() {
    const FLOW_COUNT: usize = 2_000;
    let tcp_calls = Arc::new(AtomicUsize::new(0));
    let udp_calls = Arc::new(AtomicUsize::new(0));
    let tcp_calls_for_handler = tcp_calls.clone();
    let udp_calls_for_handler = udp_calls.clone();
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |_| {
            tcp_calls_for_handler.fetch_add(1, Ordering::Relaxed);
            FlowAction::Passthrough
        }),
        udp_matcher: Arc::new(move |_| {
            udp_calls_for_handler.fetch_add(1, Ordering::Relaxed);
            FlowAction::Passthrough
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    }))
    .with_runtime_factory(TestRuntimeFactory)
    .with_decision_concurrency_limit(1)
    .build()
    .expect("build engine");

    for flow_id in 0..FLOW_COUNT {
        if flow_id % 2 == 0 {
            assert!(matches!(
                engine.new_tcp_session(
                    TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
                    |_| TcpDeliverStatus::Accepted,
                    || {},
                    || {},
                ),
                SessionFlowAction::Passthrough
            ));
        } else {
            assert!(matches!(
                engine.new_udp_session(
                    TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
                    |_| {},
                    |_| {},
                    || {},
                ),
                SessionFlowAction::Passthrough
            ));
        }
    }
    assert_eq!(tcp_calls.load(Ordering::Relaxed), FLOW_COUNT / 2);
    assert_eq!(udp_calls.load(Ordering::Relaxed), FLOW_COUNT / 2);
    let snapshot = engine.decision_concurrency_snapshot_for_test();
    assert_eq!(snapshot.active, 0);
    assert_eq!(snapshot.peak_active, 1);
    assert_eq!(snapshot.overload_refusals, 0);
    engine.stop(0);
}
