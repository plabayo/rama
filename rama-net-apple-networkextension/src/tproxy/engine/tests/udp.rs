//! UDP-specific tests: datagram delivery and read-demand callback wiring.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use parking_lot::Mutex;
use rama_core::service::service_fn;
use rama_net::address::HostWithPort;
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[test]
fn udp_probe_ack_preserves_credit_until_delivery() {
    check_udp_probe(UdpProbeCompletion::Deliver);
}

#[test]
fn udp_probe_requires_matching_ack_before_delivery() {
    check_udp_probe(UdpProbeCompletion::BeforeAck);
}

#[test]
fn udp_probe_ack_after_close_cannot_restore_credit_or_demand() {
    check_udp_probe(UdpProbeCompletion::AfterClose);
}

#[derive(Clone, Copy)]
enum UdpProbeCompletion {
    Deliver,
    BeforeAck,
    AfterClose,
}

fn check_udp_probe(completion: UdpProbeCompletion) {
    let (received_tx, received_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let received_tx = received_tx.clone();
            let flow_id = meta.flow_id;
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        if let Some(datagram) = flow.recv().await {
                            received_tx.send((flow_id, datagram)).unwrap();
                        }
                        let _hold = flow;
                        std::future::pending::<Result<(), Infallible>>().await
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_ingress_per_flow_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .with_udp_ingress_global_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .with_udp_ingress_probe_lease(Duration::from_secs(30))
        .without_udp_idle_timeout()
        .build()
        .unwrap();
    let budget = engine.udp_ingress_budget_for_test();
    let mut sessions = Vec::new();
    let mut demands = Vec::new();
    for flow_id in 1..=2 {
        let (demand_tx, demand_rx) = std::sync::mpsc::channel();
        let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
        meta.flow_id = flow_id;
        let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
            meta,
            |_| {},
            move |probe_id| {
                _ = demand_tx.send(probe_id);
            },
            || {},
        ) else {
            panic!("expected intercepted probe-aware session");
        };
        session.activate();
        assert_eq!(demand_rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        sessions.push(session);
        demands.push(demand_rx);
    }

    let payload = vec![0x71; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];
    sessions[0].on_client_datagram(&payload, None);
    let (flow_id, holder) = received_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(flow_id, 1);
    sessions[1].on_client_datagram(&payload, None);
    assert_eq!(budget.snapshot().global_waiters, 1);
    drop(holder);
    let probe_id = demands[1].recv_timeout(Duration::from_secs(5)).unwrap();
    assert_ne!(probe_id, 0);
    assert_eq!(budget.snapshot().provisional_probe_bytes, payload.len());
    assert_eq!(budget.snapshot().charged_bytes, payload.len());

    match completion {
        UdpProbeCompletion::Deliver => {
            sessions[1].on_client_read_complete(probe_id);
            sessions[1].on_client_read_complete(probe_id);
            assert_eq!(budget.snapshot().provisional_probe_bytes, payload.len());
            sessions[1].on_client_datagram(&payload, None);
            let (flow_id, received) = received_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(flow_id, 2);
            assert_eq!(received.payload.as_ref(), payload);
            assert_eq!(budget.snapshot().provisional_probe_bytes, 0);
            assert_eq!(budget.snapshot().retained_bytes, payload.len());
            drop(received);
        }
        UdpProbeCompletion::BeforeAck => {
            sessions[0].on_client_read_complete(probe_id);
            sessions[1].on_client_read_complete(probe_id + 1);
            sessions[1].on_client_datagram(&payload, None);
            received_rx.try_recv().expect_err("no datagram admitted");
            assert_eq!(budget.snapshot().retained_bytes, 0);
            assert_eq!(budget.snapshot().global_waiters, 1);
            assert_eq!(budget.snapshot().provisional_probe_bytes, payload.len());
            assert_eq!(budget.snapshot().dropped_global_bytes_full, 2);
        }
        UdpProbeCompletion::AfterClose => {
            sessions[1].on_client_close();
            assert_eq!(budget.snapshot().charged_bytes, 0);
            sessions[1].on_client_read_complete(probe_id);
            sessions[1].on_client_datagram(&payload, None);
            received_rx.try_recv().expect_err("no datagram admitted");
            demands[1].try_recv().expect_err("no demand after close");
        }
    }
    for session in &mut sessions {
        session.on_client_close();
    }
    engine.stop(0);
    assert_eq!(budget.snapshot().charged_bytes, 0);
    assert_eq!(budget.snapshot().global_waiters, 0);
}

#[test]
fn udp_bridge_delivers_server_datagram() {
    let got = Arc::new(Mutex::new(Vec::<u8>::new()));
    let got_clone = got.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                if let Some(datagram) = flow.recv().await {
                    // Echo back — Datagram carries peer; reuse the
                    // same Datagram so the reply is correlated to
                    // the originating peer.
                    flow.send(datagram);
                }
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
        move |datagram: crate::Datagram| {
            let mut lock = got_clone.lock();
            lock.extend_from_slice(&datagram.payload);
            _ = notify_tx.send(());
        },
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"ping", None);

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert_eq!(got.lock().as_slice(), b"ping");
}

#[test]
fn udp_echo_releases_ingress_payload_without_reentering_callback_gate() {
    assert_udp_echo_payload_release_does_not_reenter_callback_gate(false, false);
}

#[test]
fn udp_panicking_echo_callback_releases_ingress_payload_without_reentering_gate() {
    assert_udp_echo_payload_release_does_not_reenter_callback_gate(true, false);
}

#[test]
fn udp_callback_drops_prior_retained_datagram_without_reentering_gate() {
    assert_udp_echo_payload_release_does_not_reenter_callback_gate(false, true);
}

#[test]
fn udp_panicking_callback_drops_prior_retained_datagram_without_reentering_gate() {
    assert_udp_echo_payload_release_does_not_reenter_callback_gate(true, true);
}

fn assert_udp_echo_payload_release_does_not_reenter_callback_gate(
    callback_panics: bool,
    drop_prior_payload: bool,
) {
    let (callback_entered_tx, callback_entered_rx) = std::sync::mpsc::channel();
    let (callback_return_tx, callback_return_rx) = std::sync::mpsc::channel();
    let callback_return_rx = Mutex::new(callback_return_rx);
    let (echo_finished_tx, echo_finished_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let echo_finished_tx = echo_finished_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let echo_finished_tx = echo_finished_tx.clone();
                    async move {
                        if drop_prior_payload {
                            let first = flow.recv().await.expect("receive prior payload");
                            flow.send(first);
                        }
                        let datagram = flow.recv().await.expect("receive the full-cap payload");
                        flow.send(datagram);
                        _ = echo_finished_tx.send(());
                        Ok(())
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_ingress_per_flow_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .without_udp_idle_timeout()
        .with_stop_drain_max_wait(Duration::from_millis(100))
        .build()
        .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let retained_prior = Mutex::new(None);
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        move |datagram| {
            // This callback obeys the contract: it never calls the session.
            // Retain its argument until the producer establishes byte pressure.
            if drop_prior_payload && datagram.payload.len() == MAX_UDP_DATAGRAM_PAYLOAD_SIZE - 1 {
                *retained_prior.lock() = Some(datagram);
                _ = callback_entered_tx.send(());
                return;
            }
            _ = callback_entered_tx.send(());
            callback_return_rx
                .lock()
                .recv_timeout(Duration::from_secs(2))
                .expect("release the datagram callback");
            // The retained allocation belongs to an earlier callback, so
            // pinning only the current argument cannot prevent this reentry.
            drop(retained_prior.lock().take());
            assert!(!callback_panics, "synthetic UDP echo callback panic");
        },
        |_| {},
        move || _ = closed_tx.send(()),
    ) else {
        panic!("expected intercept session");
    };
    session.activate();
    if drop_prior_payload {
        session.on_client_datagram(&vec![0; MAX_UDP_DATAGRAM_PAYLOAD_SIZE - 1], None);
        callback_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("retain the prior datagram in the server callback");
        session.on_client_datagram(b"x", None);
    } else {
        session.on_client_datagram(&vec![0; MAX_UDP_DATAGRAM_PAYLOAD_SIZE], None);
    }
    callback_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("echo must enter the server callback");
    session.on_client_datagram(b"overflow", None);
    assert_eq!(budget.snapshot().dropped_flow_bytes_full, 1);
    callback_return_tx.send(()).expect("release callback");

    let finished = if callback_panics {
        closed_rx.recv_timeout(Duration::from_secs(1)).is_ok()
    } else {
        echo_finished_rx
            .recv_timeout(Duration::from_secs(1))
            .is_ok()
    };
    if !finished {
        // A regressed service worker holds callback_active forever. Avoid an
        // unbounded session Drop and let the engine's bounded stop dispose its
        // runtime so this assertion reports the defect instead of hanging.
        #[expect(clippy::mem_forget)] // Only the deliberately wedged failure path.
        std::mem::forget(session);
        engine.stop(0);
        panic!("dropping the echoed ingress payload reentered its callback lifetime gate");
    }
    session.on_client_close();
    engine.stop(0);
    assert_eq!(budget.snapshot().retained_bytes, 0);
}

fn assert_udp_service_panic_runs_close_epilogue(flow_id: u64, panic_while_polling: bool) {
    install_close_capture();
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let service: TestUdpService = if panic_while_polling {
                service_fn(|_flow: crate::UdpFlow| async move {
                    panic!("synthetic udp service poll panic")
                })
                .boxed()
            } else {
                service_fn(
                    |_flow: crate::UdpFlow| -> std::future::Ready<Result<(), Infallible>> {
                        panic!("synthetic udp service construction panic")
                    },
                )
                .boxed()
            };
            FlowAction::Intercept { meta, service }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);
    let (closed_tx, closed_rx) = std::sync::mpsc::channel::<()>();
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = flow_id;

    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };
    session.activate();

    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("panicking service must still notify Swift close");
    let started = std::time::Instant::now();
    while flow_close_reason(flow_id).is_none() && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        flow_close_reason(flow_id).as_deref(),
        Some("service_panic"),
        "construction and poll panics must retain their distinct close reason",
    );
    session.on_client_close();
    engine.stop(0);
}

#[test]
fn udp_service_construction_panic_runs_close_epilogue() {
    assert_udp_service_panic_runs_close_epilogue(0xE1E1_2101, false);
}

#[test]
fn udp_service_poll_panic_runs_close_epilogue() {
    assert_udp_service_panic_runs_close_epilogue(0xE1E1_2102, true);
}

#[test]
fn udp_idle_close_drops_service_before_callbacks_and_byte_snapshot() {
    assert_udp_terminal_drop_precedes_close(UdpTestTermination::Idle, UdpTestDropPanic::None);
}

#[test]
fn udp_max_lifetime_close_drops_service_before_callbacks_and_byte_snapshot() {
    assert_udp_terminal_drop_precedes_close(
        UdpTestTermination::MaxLifetime,
        UdpTestDropPanic::None,
    );
}

#[test]
fn udp_terminal_close_joins_admitted_copy_count_and_publish() {
    const PAYLOAD: &[u8] = b"admitted-before-terminal-close";
    let (service_ready_tx, service_ready_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
    let finish_rx = Arc::new(Mutex::new(Some(finish_rx)));
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let service_ready_tx = service_ready_tx.clone();
            let finish_rx = finish_rx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| {
                    let finish_rx = finish_rx.lock().take().expect("one service invocation");
                    let service_ready_tx = service_ready_tx.clone();
                    async move {
                        _ = service_ready_tx.send(());
                        _ = finish_rx.await;
                        drop(flow);
                        Ok::<(), Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = build_engine(handler);
    let budget = engine.udp_ingress_budget_for_test();
    let close_budget = budget.clone();
    #[cfg(feature = "dial9")]
    let counters = Arc::new(Mutex::new(None::<Arc<UdpFlowByteCounters>>));
    #[cfg(feature = "dial9")]
    let close_counters = counters.clone();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        move || {
            #[cfg(feature = "dial9")]
            let totals = Some(
                close_counters
                    .lock()
                    .as_ref()
                    .expect("installed counters")
                    .snapshot(),
            );
            #[cfg(not(feature = "dial9"))]
            let totals = None::<(u64, u64)>;
            _ = closed_tx.send((close_budget.snapshot(), totals));
        },
    ) else {
        panic!("expected intercepted flow");
    };
    #[cfg(feature = "dial9")]
    {
        *counters.lock() = Some(session.byte_counters.clone());
    }
    let control = session.ingress_control.clone();
    session.activate();
    service_ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("service ready");
    let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let resume_rx = Mutex::new(resume_rx);
    session.before_ingress_copy = Some(Arc::new(move || {
        admitted_tx.send(()).expect("announce admitted submission");
        resume_rx
            .lock()
            .recv_timeout(Duration::from_secs(2))
            .expect("resume ordinary copy");
    }));
    let submitter = std::thread::spawn(move || {
        session.on_client_datagram(PAYLOAD, None);
        session.before_ingress_copy = None;
        session
    });
    admitted_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("submission reserved its slot");
    finish_tx.send(()).expect("finish service");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !control.submission_close_started.load(Ordering::Acquire) {
        assert!(
            std::time::Instant::now() < deadline,
            "receiver started terminal close"
        );
        std::thread::yield_now();
    }
    let closed_before_publish = closed_rx.try_recv();
    // Always release and join the ordinary producer before checking the
    // assertion, including when a broken close implementation returned early.
    resume_tx.send(()).expect("release admitted copy");
    let mut session = submitter.join().expect("ordinary submission completed");
    assert!(matches!(
        closed_before_publish,
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let (snapshot, totals) = closed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("joined close");
    assert_eq!(snapshot.accepted_datagrams, 1);
    assert_eq!(snapshot.accepted_bytes, PAYLOAD.len() as u64);
    assert_eq!(snapshot.retained_bytes, 0);
    assert_eq!(snapshot.charged_bytes, 0);
    #[cfg(feature = "dial9")]
    assert_eq!(totals, Some((PAYLOAD.len() as u64, 0)));
    #[cfg(not(feature = "dial9"))]
    assert_eq!(totals, None);
    session.on_client_datagram(b"after-close", None);
    assert_eq!(budget.snapshot().accepted_datagrams, 1);
    session.on_client_close();
    engine.stop(0);
}

#[test]
fn udp_preactivation_shutdown_owns_and_drains_queued_ingress_before_close() {
    assert_udp_preactivation_terminal_drains_ingress(false);
}

#[test]
fn udp_preactivation_lifetime_owns_and_drains_queued_ingress_before_close() {
    assert_udp_preactivation_terminal_drains_ingress(true);
}

fn assert_udp_preactivation_terminal_drains_ingress(lifetime: bool) {
    const PAYLOAD: &[u8] = b"queued-before-activation";
    let service_calls = Arc::new(AtomicUsize::new(0));
    let calls = service_calls.clone();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let calls = calls.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |_flow: crate::UdpFlow| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    async { Ok::<(), Infallible>(()) }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let builder = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory);
    let engine = if lifetime {
        builder.with_udp_max_flow_lifetime(Duration::from_millis(300))
    } else {
        builder
    }
    .build()
    .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let close_budget = budget.clone();
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demands = demand_count.clone();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| panic!("no preactivation egress callback"),
        move |_| {
            demands.fetch_add(1, Ordering::Relaxed);
        },
        move || {
            _ = closed_tx.send(close_budget.snapshot());
        },
    ) else {
        panic!("expected intercepted flow");
    };
    session.on_client_datagram(PAYLOAD, None);
    assert_eq!(budget.snapshot().retained_bytes, PAYLOAD.len());
    let engine = if lifetime {
        Some(engine)
    } else {
        engine.stop(0);
        None
    };
    let snapshot = closed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("preactivation close");
    assert_eq!(snapshot.accepted_bytes, PAYLOAD.len() as u64);
    assert_eq!(snapshot.retained_bytes, 0);
    assert_eq!(snapshot.charged_bytes, 0);
    assert_eq!(service_calls.load(Ordering::Relaxed), 0);
    assert_eq!(demand_count.load(Ordering::Relaxed), 0);
    session.activate();
    session.on_client_datagram(b"late", None);
    assert_eq!(budget.snapshot().accepted_datagrams, 1);
    session.on_client_close();
    if let Some(engine) = engine {
        engine.stop(0);
    }
}

#[test]
fn udp_idle_close_contains_service_destruction_panic() {
    assert_udp_terminal_drop_precedes_close(UdpTestTermination::Idle, UdpTestDropPanic::Service);
}

#[test]
fn udp_max_lifetime_close_contains_service_destruction_panic() {
    assert_udp_terminal_drop_precedes_close(
        UdpTestTermination::MaxLifetime,
        UdpTestDropPanic::Service,
    );
}

#[test]
fn udp_engine_shutdown_contains_service_destruction_panic() {
    assert_udp_terminal_drop_precedes_close(
        UdpTestTermination::Shutdown,
        UdpTestDropPanic::Service,
    );
}

#[test]
fn udp_idle_close_contains_final_datagram_callback_panic() {
    assert_udp_terminal_drop_precedes_close(UdpTestTermination::Idle, UdpTestDropPanic::Callback);
}

#[derive(Clone, Copy)]
enum UdpTestTermination {
    Idle,
    MaxLifetime,
    Shutdown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UdpTestDropPanic {
    None,
    Service,
    Callback,
}

fn assert_udp_terminal_drop_precedes_close(
    termination: UdpTestTermination,
    drop_panic: UdpTestDropPanic,
) {
    const FINAL_PAYLOAD: &[u8] = b"service-final";
    const QUEUED_PAYLOAD: &[u8] = b"pending-ingress";
    install_close_capture();

    struct FinalDatagramOnDrop {
        flow: crate::UdpFlow,
        datagram: Option<crate::Datagram>,
        panic_after_send: bool,
    }

    impl Drop for FinalDatagramOnDrop {
        fn drop(&mut self) {
            self.flow
                .send(self.datagram.take().expect("owned final datagram"));
            assert!(
                !self.panic_after_send,
                "synthetic UDP service destruction panic"
            );
        }
    }

    #[derive(Debug)]
    enum Observed {
        Datagram(Vec<u8>),
        Closed {
            retained_bytes: usize,
            charged_bytes: usize,
            totals: Option<(u64, u64)>,
        },
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let ready_tx = ready_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let ready_tx = ready_tx.clone();
                    async move {
                        let datagram = flow.recv().await.expect("test ingress datagram");
                        let final_datagram = FinalDatagramOnDrop {
                            flow,
                            datagram: Some(datagram),
                            panic_after_send: drop_panic == UdpTestDropPanic::Service,
                        };
                        _ = ready_tx.send(());
                        std::future::pending::<()>().await;
                        drop(final_datagram);
                        Ok::<(), Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let builder = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory);
    let engine = match termination {
        UdpTestTermination::MaxLifetime => builder
            .with_udp_max_flow_lifetime(Duration::from_millis(300))
            .without_udp_idle_timeout(),
        UdpTestTermination::Idle => builder.with_udp_idle_timeout(Duration::from_millis(200)),
        UdpTestTermination::Shutdown => builder.without_udp_idle_timeout(),
    }
    .build()
    .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let close_budget = budget.clone();
    let (events_tx, events_rx) = std::sync::mpsc::channel();
    let datagram_events_tx = events_tx.clone();
    #[cfg(feature = "dial9")]
    let counters = Arc::new(Mutex::new(None::<Arc<UdpFlowByteCounters>>));
    #[cfg(feature = "dial9")]
    let close_counters = counters.clone();
    let meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    let flow_id = meta.flow_id;
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        meta,
        move |datagram| {
            _ = datagram_events_tx.send(Observed::Datagram(datagram.payload.to_vec()));
            assert!(
                drop_panic != UdpTestDropPanic::Callback,
                "synthetic UDP final datagram callback panic",
            );
        },
        |_| {},
        move || {
            let snapshot = close_budget.snapshot();
            #[cfg(feature = "dial9")]
            let totals = Some(
                close_counters
                    .lock()
                    .as_ref()
                    .expect("installed byte counters")
                    .snapshot(),
            );
            #[cfg(not(feature = "dial9"))]
            let totals = None;
            _ = events_tx.send(Observed::Closed {
                retained_bytes: snapshot.retained_bytes,
                charged_bytes: snapshot.charged_bytes,
                totals,
            });
        },
    ) else {
        panic!("expected intercepted flow");
    };
    #[cfg(feature = "dial9")]
    {
        *counters.lock() = Some(session.byte_counters.clone());
    }
    session.activate();
    session.on_client_datagram(FINAL_PAYLOAD, None);
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("service owns the retained final datagram");
    session.on_client_datagram(QUEUED_PAYLOAD, None);
    let engine = if matches!(termination, UdpTestTermination::Shutdown) {
        engine.stop(0);
        None
    } else {
        Some(engine)
    };

    // Inspect callback order and ownership at the close edge itself. Waiting
    // for eventual task cleanup would miss a close emitted before destruction.
    let first = events_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    let second = events_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("remaining terminal callback");
    let accepted_at_close = budget.snapshot().accepted_datagrams;
    session.on_client_datagram(b"late ingress", None);
    let accepted_after_close = budget.snapshot().accepted_datagrams;
    session.on_client_close();
    if let Some(engine) = engine {
        engine.stop(0);
    }

    assert!(
        matches!(&first, Observed::Datagram(payload) if payload == FINAL_PAYLOAD),
        "the service destructor must send before close: {first:?}",
    );
    let Observed::Closed {
        retained_bytes,
        charged_bytes,
        totals,
    } = second
    else {
        panic!("expected close after the final datagram, got {second:?}");
    };
    assert_eq!(retained_bytes, 0, "close retained ingress payload owners");
    assert_eq!(charged_bytes, 0, "close retained ingress byte charges");
    #[cfg(feature = "dial9")]
    assert_eq!(
        totals,
        Some((
            (FINAL_PAYLOAD.len() + QUEUED_PAYLOAD.len()) as u64,
            FINAL_PAYLOAD.len() as u64,
        )),
        "the terminal byte snapshot must include the destructor's datagram",
    );
    #[cfg(not(feature = "dial9"))]
    assert_eq!(totals, None);
    assert_eq!(accepted_at_close, 2);
    assert_eq!(accepted_after_close, accepted_at_close);
    let expected_reason = if drop_panic != UdpTestDropPanic::None {
        "service_panic"
    } else {
        match termination {
            UdpTestTermination::Idle => "idle_timeout",
            UdpTestTermination::MaxLifetime => "max_lifetime",
            UdpTestTermination::Shutdown => "shutdown",
        }
    };
    assert_eq!(flow_close_reason(flow_id).as_deref(), Some(expected_reason));
    assert!(
        events_rx.try_recv().is_err(),
        "no callback may follow close"
    );
}

#[test]
fn udp_huge_lifetime_and_idle_timeout_still_reach_close_epilogue() {
    const FLOW_ID: u64 = 0xE1E1_2001;
    install_close_capture();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|flow: crate::UdpFlow| async move {
                let _hold = flow;
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_max_flow_lifetime(Duration::MAX)
        .with_udp_idle_timeout(Duration::MAX)
        .build()
        .expect("build engine");
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;

    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, || {})
    else {
        panic!("expected intercept session");
    };
    session.activate();
    session.on_client_datagram(b"activity", None);
    std::thread::sleep(Duration::from_millis(20));
    session.on_client_close();

    let started = std::time::Instant::now();
    while !flow_was_closed(FLOW_ID) && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        flow_was_closed(FLOW_ID),
        "huge timer values must remain cancellable and run the close epilogue"
    );
    engine.stop(0);
}

#[test]
fn udp_max_lifetime_has_distinct_close_reason() {
    const FLOW_ID: u64 = 0xE1E1_2002;
    install_close_capture();
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|flow: crate::UdpFlow| async move {
                let _hold = flow;
                std::future::pending::<()>().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_max_flow_lifetime(Duration::from_millis(30))
        .without_udp_idle_timeout()
        .build()
        .expect("build engine");
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;

    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };
    session.activate();
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("max lifetime must notify Swift close");

    let started = std::time::Instant::now();
    while flow_close_reason(FLOW_ID).is_none() && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("max_lifetime"));
    session.on_client_close();
    engine.stop(0);
}

fn udp_activity_draining_handler(
    received_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> TestHandler {
    TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received_tx = received_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        while flow.recv().await.is_some() {
                            received_tx.send(()).expect("activity receiver");
                        }
                        Ok::<(), Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    }
}

#[test]
fn udp_explicit_max_lifetime_closes_despite_continuous_activity() {
    const FLOW_ID: u64 = 0xE1E1_2003;
    install_close_capture();
    let (received_tx, mut received_rx) = tokio::sync::mpsc::unbounded_channel();
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(
        udp_activity_draining_handler(received_tx),
    ))
    .with_runtime_factory(paused_test_runtime)
    .with_udp_max_flow_lifetime(Duration::from_millis(400))
    .with_udp_idle_timeout(Duration::from_millis(150))
    .build()
    .expect("build engine");
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;

    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };
    session.activate();

    engine.rt.as_ref().unwrap().block_on_borrowed(async {
        // Confirm real service activity at 0..350 ms. Advancing the engine's
        // own clock avoids a descheduled test thread accidentally going idle.
        for _ in 0..8 {
            session.on_client_datagram(b"keepalive", None);
            tokio::time::timeout(Duration::from_millis(1), received_rx.recv())
                .await
                .expect("service must consume each keepalive before time advances")
                .expect("activity receiver must stay open");
            assert_eq!(
                closed_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        // The last keepalive leaves the idle deadline at 500 ms, but the
        // absolute cap must still close at 400 ms.
        tokio::time::timeout(
            Duration::from_millis(1),
            session.service_task.take().unwrap(),
        )
        .await
        .expect("absolute lifetime must close at its deadline")
        .expect("UDP task");
    });
    closed_rx
        .try_recv()
        .expect("max lifetime must notify close");
    assert_eq!(
        flow_close_reason(FLOW_ID).as_deref(),
        Some("max_lifetime"),
        "activity resets idle time but must not extend an explicitly configured absolute cap"
    );
    session.on_client_close();
    stop_paused_engine(engine);
}

#[test]
fn udp_default_no_max_lifetime_allows_activity_to_reset_idle_timeout() {
    const FLOW_ID: u64 = 0xE1E1_2004;
    install_close_capture();
    let (received_tx, mut received_rx) = tokio::sync::mpsc::unbounded_channel();
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(
        udp_activity_draining_handler(received_tx),
    ))
    .with_runtime_factory(paused_test_runtime)
    // Do not configure max lifetime: this exercises the long-lived default.
    .with_udp_idle_timeout(Duration::from_millis(200))
    .build()
    .expect("build engine");
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;

    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };
    session.activate();

    engine.rt.as_ref().unwrap().block_on_borrowed(async {
        // Keep the flow active beyond its 200 ms idle window, confirming that
        // the service consumed each keepalive before advancing the clock.
        for _ in 0..10 {
            session.on_client_datagram(b"keepalive", None);
            tokio::time::timeout(Duration::from_millis(1), received_rx.recv())
                .await
                .expect("service must consume each keepalive before time advances")
                .expect("activity receiver must stay open");
            assert_eq!(
                closed_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            tokio::time::advance(Duration::from_millis(30)).await;
        }
        tokio::time::timeout(
            Duration::from_millis(200),
            session.service_task.take().unwrap(),
        )
        .await
        .expect("idle timeout must close after activity stops")
        .expect("UDP task");
    });
    closed_rx
        .try_recv()
        .expect("idle timeout must close the flow after activity stops");
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("idle_timeout"));
    session.on_client_close();
    stop_paused_engine(engine);
}

/// End-to-end UDP loopback: client sends a datagram, the service
/// (owning egress) sends it via `send_to`, a real loopback UDP
/// "server" replies, and the reply is delivered back through
/// `flow.send`. Exercises the engine ingress path and per-datagram
/// peer attribution end-to-end.
#[test]
fn udp_loopback_multi_peer_service_owned_egress() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    // Two stand-in "remote" servers on loopback. Each echoes with a
    // peer-distinguishing prefix so we can prove that the per-
    // datagram peer attribution survives through the bridge.
    let server_a = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_b = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    server_a
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server_b
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let addr_a = server_a.local_addr().unwrap();
    let addr_b = server_b.local_addr().unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_a = stop.clone();
    let stop_b = stop.clone();
    let thread_a = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !stop_a.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = server_a.recv_from(&mut buf) {
                let mut reply = b"A:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                _ = server_a.send_to(&reply, peer);
            }
        }
    });
    let thread_b = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while !stop_b.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = server_b.recv_from(&mut buf) {
                let mut reply = b"B:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                _ = server_b.send_to(&reply, peer);
            }
        }
    });

    let replies = Arc::new(Mutex::new(Vec::<(Vec<u8>, Option<SocketAddr>)>::new()));
    let replies_clone = replies.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let replies = replies_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |mut flow: crate::UdpFlow| {
                        let replies = replies.clone();
                        let notify_tx = notify_tx.clone();
                        async move {
                            // Service owns egress: one unconnected
                            // tokio UDP socket, `send_to(peer)` per
                            // datagram, `recv_from` per reply. This is
                            // the shape every UDP handler is expected
                            // to implement (or to wrap with whatever
                            // socket pooling / rama-udp transport it
                            // wants).
                            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                                .await
                                .expect("bind egress socket");
                            let mut buf = vec![0u8; 65_535];
                            loop {
                                tokio::select! {
                                    maybe_in = flow.recv() => {
                                        let Some(datagram) = maybe_in else { break };
                                        if let Some(peer) = datagram.peer {
                                            _ = socket.send_to(&datagram.payload, peer).await;
                                        }
                                    }
                                    result = socket.recv_from(&mut buf) => {
                                        let Ok((n, peer)) = result else { break };
                                        let payload = rama_core::bytes::Bytes::copy_from_slice(&buf[..n]);
                                        replies.lock().push((payload.to_vec(), Some(peer)));
                                        _ = notify_tx.send(());
                                        flow.send(crate::Datagram { payload, peer: Some(peer) });
                                    }
                                }
                            }
                            Ok::<_, std::convert::Infallible>(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(addr_a.port())),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();

    // Two datagrams, two different peers — the per-datagram peer is
    // what makes multi-peer UDP (DNS-over-multiple-resolvers, NTP-
    // burst, mDNS) faithfully proxied. Previously each peer needed a
    // distinct NWConnection; with the BSD socket model `send_to`
    // does the dispatch.
    session.on_client_datagram(b"ping", Some(addr_a));
    session.on_client_datagram(b"ping", Some(addr_b));

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    _ = notify_rx.recv_timeout(Duration::from_secs(2));

    session.on_client_close();
    engine.stop(0);
    stop.store(true, Ordering::Relaxed);
    // Unblock the recv_from()s so the helper threads can exit.
    _ = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .and_then(|s| s.send_to(b"", addr_a).and(s.send_to(b"", addr_b)));
    _ = thread_a.join();
    _ = thread_b.join();

    let got = replies.lock().clone();
    assert!(
        got.iter().any(|(p, _)| p.starts_with(b"A:")),
        "expected a reply from peer A; got {got:?}"
    );
    assert!(
        got.iter().any(|(p, _)| p.starts_with(b"B:")),
        "expected a reply from peer B; got {got:?}"
    );
    // The egress recv pump tags each datagram with the peer it came
    // from — without that, multi-peer UDP would not be possible to
    // disambiguate on the service side.
    assert!(
        got.iter().any(|(_, peer)| *peer == Some(addr_a)),
        "expected peer attribution for A; got {got:?}"
    );
    assert!(
        got.iter().any(|(_, peer)| *peer == Some(addr_b)),
        "expected peer attribution for B; got {got:?}"
    );
}

#[test]
fn udp_session_requests_client_read_demand() {
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_clone = demand_count.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                _ = flow.recv().await;
                Ok(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move |_| {
            demand_count_clone.fetch_add(1, Ordering::Relaxed);
            _ = notify_tx.send(());
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"x", None);

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    assert!(demand_count.load(Ordering::Relaxed) >= 1);
}

/// RFC 768 says a UDP datagram with a zero-length payload is valid
/// (the length field can be `8`, header-only). Real protocols use
/// them as keep-alives or signalling pings. The client→service path
/// MUST forward such datagrams instead of silently dropping them.
#[test]
fn udp_zero_length_datagram_from_client_reaches_service() {
    let received = Arc::new(Mutex::new(Vec::<usize>::new()));
    let received_clone = received.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received = received.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        // Capture lengths so we can prove the empty
                        // datagram crossed the boundary; do NOT
                        // filter on `is_empty()` here — that's the
                        // exact mistake the framework had.
                        while let Some(datagram) = flow.recv().await {
                            received.lock().push(datagram.payload.len());
                            _ = notify_tx.send(());
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"", None);
    session.on_client_datagram(b"payload", None);

    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let lens = received.lock().clone();
    assert!(
        lens.contains(&0),
        "zero-length client datagram must reach the service; observed lengths: {lens:?}"
    );
    assert!(
        lens.contains(&7),
        "non-empty follow-up datagram must also be delivered; observed lengths: {lens:?}"
    );
}

/// Mirror of the above for the egress→service direction: a zero-
/// length datagram coming back from a peer (think of a keep-alive
/// reply that carries no payload) must also be forwarded into the
/// service's `egress` half of the bridge. Uses a real loopback UDP
/// server to drive the engine's `recv_from` pump.
#[test]
fn udp_zero_length_datagram_from_egress_reaches_service() {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    let received = Arc::new(Mutex::new(Vec::<usize>::new()));
    let received_clone = received.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received = received_clone.clone();
            let notify_tx = notify_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received = received.clone();
                    let notify_tx = notify_tx.clone();
                    async move {
                        // Service-owned egress socket. Forwards
                        // each ingress datagram to its peer and
                        // records every reply that comes back.
                        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                            .await
                            .expect("bind egress socket");
                        let mut buf = vec![0u8; 65_535];
                        loop {
                            tokio::select! {
                                maybe_in = flow.recv() => {
                                    let Some(datagram) = maybe_in else { break };
                                    if let Some(peer) = datagram.peer {
                                        _ = socket.send_to(&datagram.payload, peer).await;
                                    }
                                }
                                result = socket.recv_from(&mut buf) => {
                                    let Ok((n, _peer)) = result else { break };
                                    received.lock().push(n);
                                    _ = notify_tx.send(());
                                }
                            }
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    // Stand-in peer that the engine's egress will reach via send_to,
    // and that will reply with an empty + a non-empty datagram.
    let server = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((_, peer)) = server.recv_from(&mut buf) {
            _ = server.send_to(b"", peer);
            _ = server.send_to(b"payload", peer);
        }
    });

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
            .with_remote_endpoint(HostWithPort::local_ipv4(server_addr.port())),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.on_client_datagram(b"kick", Some(server_addr));

    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    _ = notify_rx.recv_timeout(Duration::from_secs(2));
    session.on_client_close();
    engine.stop(0);
    _ = server_thread.join();

    let lens = received.lock().clone();
    assert!(
        lens.contains(&0),
        "zero-length egress datagram must reach the service; observed lengths: {lens:?}"
    );
    assert!(
        lens.contains(&7),
        "non-empty follow-up datagram must also be delivered; observed lengths: {lens:?}"
    );
}

/// Contract: when a service sends a `Datagram` with `peer = None`
/// (the safety-valve case the framework reserves for kernel-
/// attribution gaps), the engine must deliver it as-is to
/// `on_server_datagram` — drop / fallback is the *Swift* writer
/// pump's problem (it caches the latest known peer and logs a
/// stall episode once). The engine itself must not crash, must
/// not synthesise a peer, must not silently drop.
#[test]
fn udp_send_with_no_peer_is_delivered_to_callback_with_none() {
    let peers = Arc::new(Mutex::new(Vec::<Option<std::net::SocketAddr>>::new()));
    let peers_clone = peers.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|flow: crate::UdpFlow| async move {
                flow.send(crate::Datagram::without_peer(
                    rama_core::bytes::Bytes::from_static(b"orphan"),
                ));
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        move |datagram: crate::Datagram| {
            peers_clone.lock().push(datagram.peer);
            _ = notify_tx.send(());
        },
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let got = peers.lock().clone();
    assert_eq!(
        got,
        vec![None],
        "engine must deliver Datagram::without_peer with peer = None, untouched"
    );
}

/// `activate()` arriving after the engine has already stopped must
/// not panic and must not leak: the service task is gone, so
/// `flow_tx.send` fails, the `UdpFlow` is dropped, and that
/// drop is the only externally observable event. Pin the
/// silent-failure path described in the activate doc.
#[test]
fn udp_activate_after_engine_stop_is_safe_noop() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                while flow.recv().await.is_some() {}
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    // Stop the engine before activate — the per-flow service task
    // is cancelled by `parent_guard`, so the next `flow_tx.send`
    // will fail with a dropped receiver.
    engine.stop(0);

    // Must not panic, must not hang.
    session.activate();
    // Drop the session — its drop calls `on_client_close`, which
    // also must be safe post-stop.
    drop(session);
}

/// Double-`activate()` on the same session is misuse but must be
/// observable as a warning, not a panic / UB. The second call
/// finds `pending = None` and returns. Pin the no-crash invariant.
#[test]
fn udp_double_activate_is_safe_noop() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                while flow.recv().await.is_some() {}
                Ok::<_, std::convert::Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    session.activate(); // second call must be a logged no-op
    engine.stop(0);
}

/// A UDP datagram approaching the maximum payload size (just
/// under 64 KiB — the IPv4 UDP cap once the 8-byte header is
/// accounted for) must round-trip through the engine without
/// truncation or panic. Real protocols (BitTorrent uTP, certain
/// game frames) hit close to this boundary; the bounded ingress
/// channel must not malfunction on a single large item.
#[test]
fn udp_large_datagram_near_max_payload_roundtrips() {
    use std::net::{Ipv4Addr, SocketAddr};
    const PAYLOAD_LEN: usize = 65_507; // IPv4 max UDP payload

    let (received_tx, received_rx) = std::sync::mpsc::sync_channel(1);

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received_tx = received_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        if let Some(datagram) = flow.recv().await {
                            _ = received_tx.send((datagram.payload.to_vec(), datagram.peer));
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    let mut payload: Vec<u8> = (0..PAYLOAD_LEN)
        .map(|index| (index as u8).wrapping_mul(0xB5).wrapping_add(0x3D))
        .collect();
    let expected_payload = payload.clone();
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
    session.on_client_datagram(&payload, Some(peer));
    payload.fill(0);
    drop(payload);

    let (received_payload, received_peer) = received_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("large datagram must reach the service");
    engine.stop(0);

    assert_eq!(received_peer, Some(peer));
    assert_eq!(received_payload, expected_payload);
}

/// Contract: when a service sends a `Datagram` whose peer is an
/// IPv6 `SocketAddrV6` with a non-zero `scope_id` (link-local
/// addressing — `fe80::1%en0` style), the engine's
/// `on_server_datagram` callback must observe the *same* scope
/// identifier. The FFI marshaling layer carries the scope id in
/// a dedicated `u32` field; this test pins the end-to-end path
/// inside the engine (no FFI boundary crossed, but the path
/// exercises the same SocketAddr that the FFI will round-trip
/// elsewhere).
#[test]
fn udp_send_preserves_ipv6_scope_id_through_engine_callback() {
    use std::net::{Ipv6Addr, SocketAddrV6};

    let observed = Arc::new(Mutex::new(Vec::<Option<std::net::SocketAddr>>::new()));
    let observed_clone = observed.clone();
    let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

    let scoped_peer = std::net::SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        5353,
        0,
        4, // non-zero zone id
    ));

    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let scoped_peer = scoped_peer;
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| async move {
                    flow.send(crate::Datagram::new(
                        rama_core::bytes::Bytes::from_static(b"scoped"),
                        scoped_peer,
                    ));
                    Ok::<_, std::convert::Infallible>(())
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        move |datagram: crate::Datagram| {
            observed_clone.lock().push(datagram.peer);
            _ = notify_tx.send(());
        },
        |_| {},
        || {},
    ) else {
        panic!("expected intercept session");
    };

    session.activate();
    _ = notify_rx.recv_timeout(Duration::from_secs(1));
    engine.stop(0);

    let got = observed.lock().clone();
    assert_eq!(got.len(), 1, "exactly one datagram expected; got {got:?}");
    let Some(peer) = got[0] else {
        panic!("expected Some peer, got None");
    };
    assert_eq!(peer, scoped_peer);
    match peer {
        std::net::SocketAddr::V6(v6) => {
            assert_eq!(v6.scope_id(), 4, "scope id must survive the engine path");
        }
        std::net::SocketAddr::V4(_) => panic!("expected V6"),
    }
}

#[test]
fn udp_max_payload_charge_survives_bytes_clones_and_resumes_after_final_drop() {
    use std::net::{Ipv6Addr, SocketAddrV6};

    let (received_tx, received_rx) = std::sync::mpsc::sync_channel(1);
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received_tx = received_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        if let Some(datagram) = flow.recv().await {
                            _ = received_tx.send(datagram);
                        }
                        let _hold = flow;
                        std::future::pending::<Result<(), std::convert::Infallible>>().await
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_ingress_per_flow_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .with_udp_ingress_global_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE * 2)
        .build()
        .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_for_sink = demand_count.clone();
    let (initial_demand_tx, initial_demand_rx) = std::sync::mpsc::sync_channel(1);

    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move |_| {
            let previous = demand_count_for_sink.fetch_add(1, Ordering::Relaxed);
            if previous == 0 {
                _ = initial_demand_tx.send(());
            }
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();
    initial_demand_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("service recv must request initial read");

    let peer = std::net::SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 7));
    let mut payload: Vec<u8> = (0..MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .map(|index| (index as u8).wrapping_mul(0x6D).wrapping_add(0xA7))
        .collect();
    let expected_payload = payload.clone();
    session.on_client_datagram(&payload, Some(peer));
    payload.fill(0);
    drop(payload);
    let datagram = received_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("service must receive maximum-size datagram");
    assert_eq!(datagram.peer, Some(peer));
    assert_eq!(datagram.payload.as_ref(), expected_payload.as_slice());
    assert_eq!(
        session.udp_ingress_retained_bytes_for_test(),
        MAX_UDP_DATAGRAM_PAYLOAD_SIZE
    );

    let retained_clone = datagram.payload.clone();
    drop(datagram);
    let blocked_payload = vec![0; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];
    session.on_client_datagram(&blocked_payload, Some(peer));
    let full_snapshot = budget.snapshot();
    assert_eq!(full_snapshot.retained_bytes, MAX_UDP_DATAGRAM_PAYLOAD_SIZE);
    assert_eq!(full_snapshot.dropped_flow_bytes_full, 1);
    assert_eq!(
        demand_count.load(Ordering::Relaxed),
        1,
        "byte Full must not request another read"
    );
    assert_eq!(retained_clone.as_ref(), expected_payload.as_slice());

    drop(retained_clone);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while demand_count.load(Ordering::Relaxed) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "final Bytes clone drop did not resume the byte-stalled flow"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(budget.snapshot().retained_bytes, 0);
    session.on_client_close();
    engine.stop(0);
}

#[test]
fn udp_count_full_resumes_only_after_recv_releases_a_slot() {
    let (start_tx, start_rx) = tokio::sync::watch::channel(false);
    let (received_tx, received_rx) = std::sync::mpsc::sync_channel(1);
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let start_rx = start_rx.clone();
            let received_tx = received_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let mut start_rx = start_rx.clone();
                    let received_tx = received_tx.clone();
                    async move {
                        _ = start_rx.wait_for(|start| *start).await;
                        if let Some(datagram) = flow.recv().await {
                            _ = received_tx.send(datagram);
                        }
                        Ok::<_, std::convert::Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_channel_capacity(2)
        .build()
        .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_for_sink = demand_count.clone();
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move |_| {
            demand_count_for_sink.fetch_add(1, Ordering::Relaxed);
        },
        || {},
    ) else {
        panic!("expected intercept session");
    };
    session.activate();

    session.on_client_datagram(b"one", None);
    session.on_client_datagram(b"two", None);
    session.on_client_datagram(b"full", None);
    assert_eq!(budget.snapshot().dropped_count_full, 1);
    assert_eq!(demand_count.load(Ordering::Relaxed), 0);

    start_tx.send(true).expect("start service receive");
    let received = received_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("service must receive one queued datagram");
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while demand_count.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "count capacity release did not resume the flow"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(received);
    session.on_client_close();
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while budget.snapshot().retained_bytes != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "close leaked UDP bytes"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    engine.stop(0);
}

#[test]
fn udp_global_release_wakes_a_stalled_flow_with_an_empty_local_queue() {
    const FLOW_A: u64 = 0xA001;
    const FLOW_B: u64 = 0xB001;
    let (a_tx, a_rx) = std::sync::mpsc::sync_channel(1);
    let (b_tx, b_rx) = std::sync::mpsc::sync_channel(1);
    let (b_probe_tx, b_probe_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(move |meta| {
            let received_tx = if meta.flow_id == FLOW_A {
                a_tx.clone()
            } else {
                b_tx.clone()
            };
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        if let Some(datagram) = flow.recv().await {
                            _ = received_tx.send(datagram);
                        }
                        let _hold = flow;
                        std::future::pending::<Result<(), std::convert::Infallible>>().await
                    }
                })
                .boxed(),
            }
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(TestRuntimeFactory)
        .with_udp_ingress_per_flow_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .with_udp_ingress_global_max_bytes(MAX_UDP_DATAGRAM_PAYLOAD_SIZE)
        .with_udp_ingress_probe_lease(Duration::from_secs(1))
        .build()
        .expect("build engine");
    let budget = engine.udp_ingress_budget_for_test();
    let a_demands = Arc::new(AtomicUsize::new(0));
    let b_demands = Arc::new(AtomicUsize::new(0));
    let a_demands_cb = a_demands.clone();
    let b_demands_cb = b_demands.clone();

    let mut meta_a = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta_a.flow_id = FLOW_A;
    let SessionFlowAction::Intercept(mut session_a) = engine.new_udp_session(
        meta_a,
        |_| {},
        move |_| {
            a_demands_cb.fetch_add(1, Ordering::Relaxed);
        },
        || {},
    ) else {
        panic!("expected flow A");
    };
    let mut meta_b = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta_b.flow_id = FLOW_B;
    let SessionFlowAction::Intercept(mut session_b) = engine.new_udp_session(
        meta_b,
        |_| {},
        move |probe_id| {
            if probe_id != 0 {
                _ = b_probe_tx.send(probe_id);
            }
            b_demands_cb.fetch_add(1, Ordering::Relaxed);
        },
        || {},
    ) else {
        panic!("expected flow B");
    };
    session_a.activate();
    session_b.activate();

    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while a_demands.load(Ordering::Relaxed) == 0 || b_demands.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "initial pull demand missing"
        );
        std::thread::sleep(Duration::from_millis(2));
    }

    let payload = vec![0x61; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];
    session_a.on_client_datagram(&payload, None);
    let held_a = a_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("flow A must retain the global budget");
    session_b.on_client_datagram(&payload, None);
    let snapshot = budget.snapshot();
    assert_eq!(snapshot.dropped_global_bytes_full, 1);
    assert_eq!(snapshot.global_waiters, 1);
    assert!(
        b_rx.try_recv().is_err(),
        "globally full flow B queue must be empty"
    );

    let demands_before_release = b_demands.load(Ordering::Relaxed);
    drop(held_a);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while b_demands.load(Ordering::Relaxed) == demands_before_release {
        assert!(
            std::time::Instant::now() < deadline,
            "global release did not wake one stalled empty flow"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(budget.snapshot().global_waiters, 0);

    let probe_id = b_probe_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    session_b.on_client_read_complete(probe_id);
    session_b.on_client_datagram(&payload, None);
    let held_b = b_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("resumed flow B must receive the next datagram");
    drop(held_b);
    session_a.on_client_close();
    session_b.on_client_close();
    engine.stop(0);
    assert_eq!(budget.snapshot().retained_bytes, 0);
}

#[test]
fn udp_default_global_budget_bounds_many_flows_and_engine_stop_releases_queues() {
    const FLOW_COUNT: usize = 65;
    const FILLED_FLOW_COUNT: usize = 64;
    const DATAGRAMS_PER_FLOW: usize = 4;
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|flow: crate::UdpFlow| async move {
                let _hold = flow;
                std::future::pending::<Result<(), std::convert::Infallible>>().await
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);
    let budget = engine.udp_ingress_budget_for_test();
    let mut sessions = Vec::with_capacity(FLOW_COUNT);
    for flow_id in 1..=FLOW_COUNT {
        let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
        meta.flow_id = flow_id as u64;
        let SessionFlowAction::Intercept(mut session) =
            engine.new_udp_session(meta, |_| {}, |_| {}, || {})
        else {
            panic!("expected intercepted flow {flow_id}");
        };
        session.activate();
        sessions.push(session);
    }

    let payload = vec![0xC3; MAX_UDP_DATAGRAM_PAYLOAD_SIZE];
    for session in sessions.iter_mut().take(FILLED_FLOW_COUNT) {
        for _ in 0..DATAGRAMS_PER_FLOW {
            session.on_client_datagram(&payload, None);
        }
    }
    sessions[FILLED_FLOW_COUNT].on_client_datagram(&payload, None);

    let expected = FILLED_FLOW_COUNT * DATAGRAMS_PER_FLOW * MAX_UDP_DATAGRAM_PAYLOAD_SIZE;
    let snapshot = budget.snapshot();
    assert_eq!(expected, 16_776_960);
    assert_eq!(snapshot.retained_bytes, expected);
    assert!(snapshot.retained_bytes <= DEFAULT_UDP_INGRESS_GLOBAL_MAX_BYTES);
    assert_eq!(snapshot.peak_retained_bytes, expected);
    assert_eq!(snapshot.accepted_datagrams, 256);
    assert_eq!(snapshot.dropped_global_bytes_full, 1);

    engine.stop(0);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while budget.snapshot().retained_bytes != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "engine stop did not release queued UDP payloads"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(budget.snapshot().global_waiters, 0);
    drop(sessions);
    assert_eq!(budget.snapshot().global_waiters, 0);
}

#[test]
fn udp_service_panic_releases_retained_ingress_and_closes_demand() {
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                let datagram = flow.recv().await.expect("test datagram");
                assert_eq!(datagram.payload.as_ref(), b"panic-payload");
                panic!("synthetic panic after retaining UDP ingress")
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_engine(handler);
    let budget = engine.udp_ingress_budget_for_test();
    let demand_count = Arc::new(AtomicUsize::new(0));
    let demand_count_cb = demand_count.clone();
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp),
        |_| {},
        move |_| {
            demand_count_cb.fetch_add(1, Ordering::Relaxed);
        },
        move || _ = closed_tx.send(()),
    ) else {
        panic!("expected intercepted flow");
    };
    session.activate();
    session.on_client_datagram(b"panic-payload", None);
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("panic must run close epilogue");
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while budget.snapshot().retained_bytes != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "panic leaked UDP bytes"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let demand_after_close = demand_count.load(Ordering::Relaxed);
    session.on_client_datagram(b"late", None);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(demand_count.load(Ordering::Relaxed), demand_after_close);
    session.on_client_close();
    engine.stop(0);
}
