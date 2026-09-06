//! dial9 coverage for the synchronous FFI boundary and delayed flow work.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use dial9::Dial9Handle;
use dial9_trace_format::decoder::Decoder;
use dial9_trace_format::types::FieldValueRef;
use parking_lot::Mutex;
use rama_core::{
    extensions::ExtensionsRef,
    io::BridgeIo,
    service::{Service, service_fn},
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt as _;

/// Serializes tests that build an enabled dial9 recorder, since
/// dial9 allows a single recorder per process (a second `build()` while one is
/// alive returns a disabled recorder).
fn recorder_slot() -> parking_lot::MutexGuard<'static, ()> {
    static SLOT: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    SLOT.lock()
}

fn build_dial9_engine(
    handler: TestHandler,
    trace_dir: &std::path::Path,
) -> TransparentProxyEngine<TestHandler> {
    install_close_capture();
    let writer = dial9::DiskBuffer::builder()
        .base_path(trace_dir)
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = dial9::recorder_or_disabled(writer).build();
    assert!(
        recorder.handle().is_enabled(),
        "expected an enabled recorder; is another one still alive?"
    );

    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(
            DefaultTransparentProxyAsyncRuntimeFactory::new().with_dial9_recorder(recorder),
        )
        .build()
        .expect("build dial9 engine")
}

fn build_dial9_engine_with_udp_max_flow_lifetime(
    handler: TestHandler,
    trace_dir: &std::path::Path,
    lifetime: Duration,
) -> TransparentProxyEngine<TestHandler> {
    install_close_capture();
    let writer = dial9::DiskBuffer::builder()
        .base_path(trace_dir)
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = dial9::recorder_or_disabled(writer).build();
    assert!(
        recorder.handle().is_enabled(),
        "expected an enabled recorder; is another one still alive?"
    );

    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(
            DefaultTransparentProxyAsyncRuntimeFactory::new().with_dial9_recorder(recorder),
        )
        .with_udp_max_flow_lifetime(lifetime)
        .without_udp_idle_timeout()
        .build()
        .expect("build dial9 engine")
}

fn count_dial9_events(trace_dir: &std::path::Path, event_name: &str) -> usize {
    let bytes = std::fs::read(trace_dir.join("trace.0.bin")).expect("sealed dial9 trace");
    let mut decoder = Decoder::new(&bytes).expect("valid dial9 trace");
    let mut count = 0;
    decoder
        .for_each_event(|event| {
            if event.name == event_name {
                count += 1;
            }
        })
        .expect("decode dial9 events");
    count
}

fn dial9_flow_closed_reasons(trace_dir: &std::path::Path) -> Vec<(u64, u64)> {
    let bytes = std::fs::read(trace_dir.join("trace.0.bin")).expect("sealed dial9 trace");
    let mut decoder = Decoder::new(&bytes).expect("valid dial9 trace");
    let mut closed = Vec::new();
    decoder
        .for_each_event(|event| {
            if event.name != "TproxyFlowClosed" {
                return;
            }
            let mut flow_id = None;
            let mut reason = None;
            for (name, value) in event.field_names().zip(event.fields.iter()) {
                match (name, value) {
                    ("flow_id", FieldValueRef::Varint(value)) => flow_id = Some(*value),
                    ("reason", FieldValueRef::Varint(value)) => reason = Some(*value),
                    _ => {}
                }
            }
            closed.push((
                flow_id.expect("TproxyFlowClosed flow_id field"),
                reason.expect("TproxyFlowClosed reason field"),
            ));
        })
        .expect("decode dial9 events");
    closed
}

fn dial9_udp_flow_closed_bytes(trace_dir: &std::path::Path, expected_flow_id: u64) -> (u64, u64) {
    let bytes = std::fs::read(trace_dir.join("trace.0.bin")).expect("sealed dial9 trace");
    let mut decoder = Decoder::new(&bytes).expect("valid dial9 trace");
    let mut totals = None;
    decoder
        .for_each_event(|event| {
            if event.name != "TproxyFlowClosed" {
                return;
            }
            let mut flow_id = None;
            let mut bytes_in = None;
            let mut bytes_out = None;
            for (name, value) in event.field_names().zip(event.fields.iter()) {
                match (name, value) {
                    ("flow_id", FieldValueRef::Varint(value)) => flow_id = Some(*value),
                    ("bytes_in", FieldValueRef::Varint(value)) => bytes_in = Some(*value),
                    ("bytes_out", FieldValueRef::Varint(value)) => bytes_out = Some(*value),
                    _ => {}
                }
            }
            if flow_id == Some(expected_flow_id) {
                totals = Some((
                    bytes_in.expect("TproxyFlowClosed bytes_in field"),
                    bytes_out.expect("TproxyFlowClosed bytes_out field"),
                ));
            }
        })
        .expect("decode dial9 events");
    totals.expect("TproxyFlowClosed row for expected UDP flow")
}

fn dial9_provider_identities(
    trace_dir: &std::path::Path,
    expected_flow_id: u64,
) -> Vec<(String, u64, u64, u64)> {
    let bytes = std::fs::read(trace_dir.join("trace.0.bin")).expect("sealed dial9 trace");
    let mut decoder = Decoder::new(&bytes).expect("valid dial9 trace");
    let mut identities = Vec::new();
    decoder
        .for_each_event(|event| {
            if !matches!(event.name, "TproxyFlowOpened" | "TproxyFlowClosed") {
                return;
            }
            let mut provider_pid = None;
            let mut provider_generation = None;
            let mut flow_id = None;
            for (name, value) in event.field_names().zip(event.fields.iter()) {
                if let FieldValueRef::Varint(value) = value {
                    match name {
                        "provider_pid" => provider_pid = Some(*value),
                        "provider_generation" => provider_generation = Some(*value),
                        "flow_id" => flow_id = Some(*value),
                        _ => {}
                    }
                }
            }
            if flow_id == Some(expected_flow_id) {
                identities.push((
                    event.name.to_owned(),
                    provider_pid.expect("provider_pid field"),
                    provider_generation.expect("provider_generation field"),
                    flow_id.expect("flow_id field"),
                ));
            }
        })
        .expect("decode dial9 identities");
    identities
}

#[test]
fn synchronous_app_message_works_with_dial9_runtime() {
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let mut handler = TestHandler::passthrough();
    handler.app_message_handler = Arc::new(|_| Some(vec![42]));
    let engine = build_dial9_engine(handler, temp_dir.path());

    let reply = engine
        .handle_app_message(rama_core::bytes::Bytes::new())
        .expect("app message reply");
    assert_eq!(reply.as_ref(), &[42]);

    engine.stop(0);
}

#[test]
fn foreign_thread_admission_records_tcp_udp_pairs_without_moving_policy_polling() {
    const TCP_FLOW_ID: u64 = 0xE1E1_3020;
    const UDP_FLOW_ID: u64 = 0xE1E1_3021;
    const SOURCE_PID: i32 = 1234;
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let policy_threads = Arc::new(Mutex::new(Vec::new()));
    let tcp_threads = policy_threads.clone();
    let udp_threads = policy_threads.clone();
    let handler = TestHandler {
        tcp_matcher: Arc::new(move |meta| {
            tcp_threads.lock().push(std::thread::current().id());
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async {
                        drop(bridge);
                        Ok::<(), Infallible>(())
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(move |meta| {
            udp_threads.lock().push(std::thread::current().id());
            FlowAction::Intercept {
                meta,
                service: service_fn(|flow: crate::UdpFlow| async {
                    drop(flow);
                    Ok::<(), Infallible>(())
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let provider_pid = u64::from(engine.provider_pid);
    let provider_generation = engine.provider_generation;

    let (tcp, udp, caller) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // Build and admission deliberately use different OS threads.
                // Runtime attachment warmed only the construction thread's TLS.
                assert!(Dial9Handle::try_current_thread().is_none());
                assert!(!Dial9Handle::current().is_enabled());
                let caller = std::thread::current().id();
                let mut tcp_meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
                tcp_meta.flow_id = TCP_FLOW_ID;
                tcp_meta.source_app_pid = Some(SOURCE_PID);
                let SessionFlowAction::Intercept(mut tcp) =
                    engine.new_tcp_session(tcp_meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
                else {
                    panic!("expected TCP intercept");
                };
                assert!(Dial9Handle::try_current_thread().is_none());
                tcp.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

                let mut udp_meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
                udp_meta.flow_id = UDP_FLOW_ID;
                udp_meta.source_app_pid = Some(SOURCE_PID);
                let SessionFlowAction::Intercept(mut udp) =
                    engine.new_udp_session(udp_meta, |_| {}, |_| {}, || {})
                else {
                    panic!("expected UDP intercept");
                };
                assert!(Dial9Handle::try_current_thread().is_none());
                udp.activate();
                (tcp, udp, caller)
            })
            .join()
            .unwrap()
    });
    engine.stop(0);
    drop((tcp, udp));
    assert_eq!(*policy_threads.lock(), [caller, caller]);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 2);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 2);
    for flow_id in [TCP_FLOW_ID, UDP_FLOW_ID] {
        let mut identities = dial9_provider_identities(temp_dir.path(), flow_id);
        identities.sort();
        assert_eq!(
            identities,
            ["TproxyFlowClosed", "TproxyFlowOpened"].map(|event| (
                event.to_owned(),
                provider_pid,
                provider_generation,
                flow_id,
            )),
        );
    }
    let bytes = std::fs::read(temp_dir.path().join("trace.0.bin")).unwrap();
    Decoder::new(&bytes)
        .unwrap()
        .for_each_event(|event| {
            if !matches!(event.name, "TproxyFlowOpened" | "TproxyFlowClosed") {
                return;
            }
            let fields = event
                .field_names()
                .zip(event.fields.iter())
                .collect::<Vec<_>>();
            let flow_id = fields
                .iter()
                .find(|(name, _)| *name == "flow_id")
                .unwrap()
                .1;
            let protocol = if matches!(flow_id, FieldValueRef::Varint(TCP_FLOW_ID)) {
                1
            } else {
                2
            };
            assert!(fields.iter().any(|(name, value)| *name == "protocol"
                && matches!(value, FieldValueRef::Varint(value) if *value == protocol)));
            assert!(fields.iter().any(|(name, value)| *name == "pid"
                && matches!(value, FieldValueRef::I64(value) if *value == i64::from(SOURCE_PID))));
        })
        .unwrap();
}

#[test]
fn foreign_thread_decision_deadlines_record_tcp_and_udp_events() {
    #[derive(Clone)]
    struct PendingHandler;

    impl TransparentProxyHandler for PendingHandler {
        fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
            crate::tproxy::TransparentProxyConfig::new()
        }

        fn match_tcp_flow(
            &self,
            _: rama_core::rt::Executor,
            _: TransparentProxyFlowMeta,
        ) -> impl Future<
            Output = FlowAction<
                impl Service<
                    BridgeIo<crate::TcpFlow, crate::NwTcpStream>,
                    Output = (),
                    Error = Infallible,
                >,
            >,
        > + Send
        + '_ {
            std::future::pending::<FlowAction<TestTcpService>>()
        }

        fn match_udp_flow(
            &self,
            _: rama_core::rt::Executor,
            _: TransparentProxyFlowMeta,
        ) -> impl Future<
            Output = FlowAction<impl Service<crate::UdpFlow, Output = (), Error = Infallible>>,
        > + Send
        + '_ {
            std::future::pending::<FlowAction<TestUdpService>>()
        }
    }

    const TCP_FLOW_ID: u64 = 0xE1E1_3022;
    const UDP_FLOW_ID: u64 = 0xE1E1_3023;
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let writer = dial9::DiskBuffer::builder()
        .base_path(temp_dir.path())
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = dial9::recorder_or_disabled(writer).build();
    assert!(recorder.handle().is_enabled());
    let engine =
        TransparentProxyEngineBuilder::new(|_| async { Ok::<_, Infallible>(PendingHandler) })
            .with_runtime_factory(
                DefaultTransparentProxyAsyncRuntimeFactory::new().with_dial9_recorder(recorder),
            )
            .with_decision_deadline(Duration::from_millis(20))
            .build()
            .unwrap();

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert!(Dial9Handle::try_current_thread().is_none());
                let mut tcp_meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
                tcp_meta.flow_id = TCP_FLOW_ID;
                assert!(matches!(
                    engine.new_tcp_session(tcp_meta, |_| TcpDeliverStatus::Accepted, || {}, || {}),
                    SessionFlowAction::Blocked
                ));
                assert!(Dial9Handle::try_current_thread().is_none());
                let mut udp_meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
                udp_meta.flow_id = UDP_FLOW_ID;
                assert!(matches!(
                    engine.new_udp_session(udp_meta, |_| {}, |_| {}, || {}),
                    SessionFlowAction::Blocked
                ));
                assert!(Dial9Handle::try_current_thread().is_none());
            })
            .join()
            .unwrap();
    });
    engine.stop(0);

    let bytes = std::fs::read(temp_dir.path().join("trace.0.bin")).unwrap();
    let mut deadlines = Vec::new();
    Decoder::new(&bytes)
        .unwrap()
        .for_each_event(|event| {
            if event.name != "TproxyHandlerDeadline" {
                return;
            }
            let mut flow_id = None;
            let mut deadline_ms = None;
            for (name, value) in event.field_names().zip(event.fields.iter()) {
                match (name, value) {
                    ("flow_id", FieldValueRef::Varint(value)) => flow_id = Some(*value),
                    ("deadline_ms", FieldValueRef::Varint(value)) => deadline_ms = Some(*value),
                    _ => {}
                }
            }
            deadlines.push((flow_id.unwrap(), deadline_ms.unwrap()));
        })
        .unwrap();
    deadlines.sort();
    assert_eq!(deadlines, [(TCP_FLOW_ID, 20), (UDP_FLOW_ID, 20)]);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 0);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 0);
}

#[test]
fn udp_destruction_panic_on_shutdown_pairs_dial9_open_and_close() {
    const FLOW_ID: u64 = 0xE1E1_3010;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");

    struct PanicOnDrop {
        _flow: crate::UdpFlow,
    }

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("synthetic UDP destruction panic under dial9");
        }
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let ready_tx = ready_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |flow: crate::UdpFlow| {
                    let ready_tx = ready_tx.clone();
                    async move {
                        let guard = PanicOnDrop { _flow: flow };
                        _ = ready_tx.send(());
                        std::future::pending::<()>().await;
                        drop(guard);
                        Ok::<(), Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };
    session.activate();
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("service must own its panic-on-drop guard before shutdown");
    engine.stop(0);

    closed_rx
        .try_recv()
        .expect("shutdown must finish the close callback");
    assert!(
        closed_rx.try_recv().is_err(),
        "close callback must fire once"
    );
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("service_panic"));
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 14)]
    );
    session.on_client_close();
}

#[test]
fn tcp_destruction_panic_on_shutdown_preserves_final_bytes_and_dial9_pair() {
    const FLOW_ID: u64 = 0xE1E1_3011;
    const REQUEST: &[u8] = b"request";
    const FINAL_RESPONSE: &[u8] = b"final-response";
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");

    struct FinalWriteOnDrop {
        bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>,
    }

    impl Drop for FinalWriteOnDrop {
        fn drop(&mut self) {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let result = tokio::io::AsyncWrite::poll_write(
                std::pin::Pin::new(&mut self.bridge.0),
                &mut cx,
                FINAL_RESPONSE,
            );
            assert!(matches!(result, std::task::Poll::Ready(Ok(n)) if n == FINAL_RESPONSE.len()));
            panic!("synthetic TCP destruction panic after final response");
        }
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        tcp_matcher: Arc::new(move |meta| {
            let ready_tx = ready_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |mut bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let ready_tx = ready_tx.clone();
                        async move {
                            let mut request = [0; REQUEST.len()];
                            bridge.0.read_exact(&mut request).await.unwrap();
                            assert_eq!(request, REQUEST);
                            let guard = FinalWriteOnDrop { bridge };
                            _ = ready_tx.send(());
                            std::future::pending::<()>().await;
                            drop(guard);
                            Ok::<(), Infallible>(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let provider_pid = engine.provider_pid;
    let provider_generation = engine.provider_generation;
    let (observed_tx, observed_rx) = std::sync::mpsc::channel();
    let closed_tx = observed_tx.clone();
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        meta,
        move |bytes| {
            _ = observed_tx.send(Some(bytes.to_vec()));
            TcpDeliverStatus::Accepted
        },
        || {},
        move || _ = closed_tx.send(None),
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    assert_eq!(session.on_client_bytes(REQUEST), TcpDeliverStatus::Accepted);
    ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("service must own its guard before shutdown");
    engine.stop(0);

    assert_eq!(
        observed_rx.try_recv().unwrap(),
        Some(FINAL_RESPONSE.to_vec())
    );
    assert_eq!(observed_rx.try_recv().unwrap(), None);
    observed_rx
        .try_recv()
        .expect_err("close must not emit additional output or callbacks");
    assert_eq!(flow_close_count(FLOW_ID), 2);
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("service_panic"));
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 14)]
    );
    assert_eq!(
        dial9_udp_flow_closed_bytes(temp_dir.path(), FLOW_ID),
        (REQUEST.len() as u64, FINAL_RESPONSE.len() as u64),
        "close accounting must include the final destructor write",
    );
    let mut identities = dial9_provider_identities(temp_dir.path(), FLOW_ID);
    identities.sort();
    assert_eq!(
        identities,
        vec![
            (
                "TproxyFlowClosed".to_owned(),
                u64::from(provider_pid),
                provider_generation,
                FLOW_ID
            ),
            (
                "TproxyFlowOpened".to_owned(),
                u64::from(provider_pid),
                provider_generation,
                FLOW_ID
            ),
        ]
    );
}

#[test]
fn tcp_service_panic_pairs_dial9_open_and_close() {
    const FLOW_ID: u64 = 0xE1E1_3001;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| {
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| -> std::future::Ready<
                        Result<(), Infallible>,
                    > { panic!("synthetic tcp construction panic under dial9") },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        meta,
        |_| TcpDeliverStatus::Accepted,
        || {},
        move || _ = closed_tx.send(()),
    ) else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("panicking service must close");
    let started = std::time::Instant::now();
    while !flow_was_closed(FLOW_ID) && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        flow_was_closed(FLOW_ID),
        "structured close must precede trace sealing"
    );
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("service_panic"));
    engine.stop(0);

    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 14)]
    );
}

#[test]
fn tcp_engine_stop_before_activate_pairs_dial9_open_and_shutdown_close() {
    const FLOW_ID: u64 = 0xE1E1_3003;
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
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
    let engine = build_dial9_engine(handler, temp_dir.path());
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(session) =
        engine.new_tcp_session(meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
    else {
        panic!("expected intercept session");
    };

    // Retain the pending session (and therefore bridge_tx) across stop. The
    // task must wake from flow cancellation and record its own close epilogue.
    engine.stop(0);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 1)]
    );

    drop(session);
}

#[test]
fn udp_engine_stop_before_activate_pairs_dial9_open_and_shutdown_close() {
    const FLOW_ID: u64 = 0xE1E1_3006;
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
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
    let engine = build_dial9_engine(handler, temp_dir.path());
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(session) = engine.new_udp_session(meta, |_| {}, |_| {}, || {})
    else {
        panic!("expected intercept session");
    };

    engine.stop(0);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 1)]
    );

    drop(session);
}

#[test]
fn engine_stop_waits_for_tcp_close_epilogue_before_sealing_dial9() {
    const FLOW_ID: u64 = 0xE1E1_3007;

    struct BlockOnDrop {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Arc<parking_lot::Mutex<std::sync::mpsc::Receiver<()>>>,
    }

    impl Drop for BlockOnDrop {
        fn drop(&mut self) {
            self.entered.send(()).expect("announce service-future drop");
            self.release
                .lock()
                .recv_timeout(Duration::from_secs(2))
                .expect("release service-future drop");
        }
    }

    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (drop_tx, drop_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Arc::new(parking_lot::Mutex::new(release_rx));
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let started_tx = started_tx.clone();
            let drop_tx = drop_tx.clone();
            let release_rx = release_rx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(
                    move |_bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                        let blocker = BlockOnDrop {
                            entered: drop_tx.clone(),
                            release: release_rx.clone(),
                        };
                        let started_tx = started_tx.clone();
                        async move {
                            let _blocker = blocker;
                            started_tx.send(()).expect("announce service start");
                            std::future::pending::<()>().await;
                            Ok::<(), Infallible>(())
                        }
                    },
                )
                .boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) =
        engine.new_tcp_session(meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
    else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("service task started");

    let (stopped_tx, stopped_rx) = std::sync::mpsc::sync_channel(1);
    let stop_thread = std::thread::spawn(move || {
        engine.stop(0);
        stopped_tx.send(()).expect("announce engine stop");
    });
    drop_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("service future began dropping");
    assert_eq!(
        stopped_rx.recv_timeout(Duration::from_millis(25)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "engine stop returned before the TCP close epilogue completed",
    );
    release_tx.send(()).expect("release service-future drop");
    stopped_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine stop completed after close epilogue");
    stop_thread.join().expect("join engine stop");

    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 1)]
    );
    drop(session);
}

#[test]
fn engine_stop_waits_for_udp_close_epilogue_before_sealing_dial9() {
    const FLOW_ID: u64 = 0xE1E1_3008;
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let (close_entered_tx, close_entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Arc::new(parking_lot::Mutex::new(release_rx));
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
    let engine = build_dial9_engine(handler, temp_dir.path());
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(session) = engine.new_udp_session(
        meta,
        |_| {},
        |_| {},
        move || {
            close_entered_tx
                .send(())
                .expect("announce UDP close callback");
            release_rx
                .lock()
                .recv_timeout(Duration::from_secs(2))
                .expect("release UDP close callback");
        },
    ) else {
        panic!("expected intercept session");
    };

    let (stopped_tx, stopped_rx) = std::sync::mpsc::sync_channel(1);
    let stop_thread = std::thread::spawn(move || {
        engine.stop(0);
        stopped_tx.send(()).expect("announce engine stop");
    });
    close_entered_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("UDP close callback began");
    assert_eq!(
        stopped_rx.recv_timeout(Duration::from_millis(25)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "engine stop returned before the UDP close epilogue completed",
    );
    release_tx.send(()).expect("release UDP close callback");
    stopped_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine stop completed after UDP close epilogue");
    stop_thread.join().expect("join engine stop");

    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 1)]
    );
    drop(session);
}

#[test]
fn tcp_egress_read_error_records_direction_correct_dial9_reason() {
    const FLOW_ID: u64 = 0xE1E1_3004;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(
                |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| async move {
                    let BridgeIo(_ingress, mut egress) = bridge;
                    let mut byte = [0_u8; 1];
                    let error = egress
                        .read(&mut byte)
                        .await
                        .expect_err("synthetic egress read failure");
                    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
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
    let engine = build_dial9_engine(handler, temp_dir.path());
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) =
        engine.new_tcp_session(meta, |_| TcpDeliverStatus::Accepted, || {}, || {})
    else {
        panic!("expected intercept session");
    };
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});
    session.on_egress_error();

    let started = std::time::Instant::now();
    while flow_close_count(FLOW_ID) < 2 && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        flow_close_count(FLOW_ID),
        2,
        "both directional structured close events must precede trace sealing"
    );
    engine.stop(0);

    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 6)],
        "egress read failure is ReadErrorRight, not an ingress clean EOF"
    );
}

#[test]
fn udp_pre_activation_max_lifetime_records_decoded_dial9_reason() {
    const FLOW_ID: u64 = 0xE1E1_3002;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
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
    let engine = build_dial9_engine_with_udp_max_flow_lifetime(
        handler,
        temp_dir.path(),
        Duration::from_millis(30),
    );
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) =
        engine.new_udp_session(meta, |_| {}, |_| {}, move || _ = closed_tx.send(()))
    else {
        panic!("expected intercept session");
    };

    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("pre-activation max lifetime must close the flow");
    let started = std::time::Instant::now();
    while flow_close_reason(FLOW_ID).is_none() && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(flow_close_reason(FLOW_ID).as_deref(), Some("max_lifetime"));
    session.on_client_close();
    engine.stop(0);

    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 13)]
    );
}

#[test]
fn udp_pressure_close_counts_only_accepted_whole_datagrams_after_recovery() {
    const FLOW_ID: u64 = 0xE1E1_3012;
    const PAYLOAD_LEN: usize = 4096;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let (received_tx, received_rx) = std::sync::mpsc::channel();
    let handler = TestHandler {
        udp_matcher: Arc::new(move |meta| {
            let received_tx = received_tx.clone();
            FlowAction::Intercept {
                meta,
                service: service_fn(move |mut flow: crate::UdpFlow| {
                    let received_tx = received_tx.clone();
                    async move {
                        while let Some(datagram) = flow.recv().await {
                            let payload = datagram.payload.to_vec();
                            drop(datagram);
                            _ = received_tx.send(payload);
                        }
                        Ok::<_, Infallible>(())
                    }
                })
                .boxed(),
            }
        }),
        ..TestHandler::passthrough()
    };
    let writer = dial9::DiskBuffer::builder()
        .base_path(temp_dir.path())
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = dial9::recorder_or_disabled(writer).build();
    assert!(recorder.handle().is_enabled());
    let engine = TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(
            DefaultTransparentProxyAsyncRuntimeFactory::new().with_dial9_recorder(recorder),
        )
        .with_udp_channel_capacity(1)
        .without_udp_idle_timeout()
        .build()
        .expect("build dial9 engine with one ingress slot");
    let budget = engine.udp_ingress_budget_for_test();
    let provider_pid = u64::from(engine.provider_pid);
    let provider_generation = engine.provider_generation;
    let (demand_tx, demand_rx) = std::sync::mpsc::channel();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        meta,
        |_| panic!("pressure service must not produce egress"),
        move |_| _ = demand_tx.send(()),
        move || _ = closed_tx.send(()),
    ) else {
        panic!("expected intercept session");
    };

    // Before activation no receiver can race the capacity-one queue. This
    // models a once-only burst: the rejected packet is never submitted again.
    session.on_client_datagram(&[0x11; PAYLOAD_LEN], None);
    session.on_client_datagram(&[0x22; PAYLOAD_LEN], None);
    let pressured = budget.snapshot();
    assert_eq!(pressured.accepted_datagrams, 1);
    assert_eq!(pressured.accepted_bytes, PAYLOAD_LEN as u64);
    assert_eq!(pressured.dropped_count_full, 1);
    assert_eq!(pressured.resumed_count_full, 0);
    session.activate();
    assert_eq!(
        received_rx.recv_timeout(Duration::from_secs(2)),
        Ok(vec![0x11; PAYLOAD_LEN])
    );
    demand_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("dequeue must recover the count-full flow and request ingress");
    assert_eq!(budget.snapshot().resumed_count_full, 1);

    // A new packet after the resume is accepted and contributes its complete
    // payload to the close record; the rejected packet contributes nothing.
    session.on_client_datagram(&[0x33; PAYLOAD_LEN], None);
    assert_eq!(
        received_rx.recv_timeout(Duration::from_secs(2)),
        Ok(vec![0x33; PAYLOAD_LEN])
    );
    engine.stop(0);
    closed_rx
        .try_recv()
        .expect("shutdown must finish the close callback");
    closed_rx
        .try_recv()
        .expect_err("shutdown must not duplicate the close callback");
    received_rx
        .try_recv()
        .expect_err("the pressure-rejected packet must never reach the service");
    let final_snapshot = budget.snapshot();
    assert_eq!(final_snapshot.accepted_datagrams, 2);
    assert_eq!(final_snapshot.accepted_bytes, (2 * PAYLOAD_LEN) as u64);
    assert_eq!(final_snapshot.dropped_count_full, 1);
    assert_eq!(final_snapshot.resumed_count_full, 1);
    assert_eq!(final_snapshot.retained_bytes, 0);
    assert_eq!(
        dial9_udp_flow_closed_bytes(temp_dir.path(), FLOW_ID),
        ((2 * PAYLOAD_LEN) as u64, 0),
        "three once-only sends with one rejection must record two accepted payloads"
    );
    assert_eq!(
        dial9_flow_closed_reasons(temp_dir.path()),
        vec![(FLOW_ID, 1)]
    );
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowOpened"), 1);
    assert_eq!(count_dial9_events(temp_dir.path(), "TproxyFlowClosed"), 1);
    for (_, pid, generation, flow_id) in dial9_provider_identities(temp_dir.path(), FLOW_ID) {
        assert_eq!(
            (pid, generation, flow_id),
            (provider_pid, provider_generation, FLOW_ID)
        );
    }
}

#[test]
fn udp_echo_records_real_dial9_byte_totals() {
    const FLOW_ID: u64 = 0xE1E1_3005;
    const INGRESS_LEN: usize = 64;
    const EGRESS_LEN: usize = 17;
    let _slot = recorder_slot();
    install_close_capture();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(|_| FlowAction::Passthrough),
        udp_matcher: Arc::new(|meta| FlowAction::Intercept {
            meta,
            service: service_fn(|mut flow: crate::UdpFlow| async move {
                if let Some(mut datagram) = flow.recv().await {
                    datagram.payload = rama_core::bytes::Bytes::from_static(&[0x17; EGRESS_LEN]);
                    flow.send(datagram);
                }
                Ok::<_, Infallible>(())
            })
            .boxed(),
        }),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let provider_pid = u64::from(engine.provider_pid);
    let provider_generation = engine.provider_generation;
    let (echo_tx, echo_rx) = std::sync::mpsc::sync_channel(1);
    let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
    let mut meta = TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp);
    meta.flow_id = FLOW_ID;
    let SessionFlowAction::Intercept(mut session) = engine.new_udp_session(
        meta,
        move |datagram| {
            _ = echo_tx.send(datagram.payload.len());
        },
        |_| {},
        move || _ = closed_tx.send(()),
    ) else {
        panic!("expected intercept session");
    };
    session.activate();
    session.on_client_datagram(&[0x5a; INGRESS_LEN], None);

    assert_eq!(echo_rx.recv_timeout(Duration::from_secs(1)), Ok(EGRESS_LEN));
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("completed UDP service must close");
    let started = std::time::Instant::now();
    while !flow_was_closed(FLOW_ID) && started.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(flow_was_closed(FLOW_ID));

    session.on_client_close();
    engine.stop(0);
    assert_eq!(
        dial9_udp_flow_closed_bytes(temp_dir.path(), FLOW_ID),
        (INGRESS_LEN as u64, EGRESS_LEN as u64)
    );
    assert_eq!(
        dial9_provider_identities(temp_dir.path(), FLOW_ID),
        vec![
            (
                "TproxyFlowClosed".to_owned(),
                provider_pid,
                provider_generation,
                FLOW_ID,
            ),
            (
                "TproxyFlowOpened".to_owned(),
                provider_pid,
                provider_generation,
                FLOW_ID,
            ),
        ],
        "open and close must carry the same provider process/generation identity",
    );
}

#[test]
fn external_promote_keeps_engine_dial9_session() {
    let _slot = recorder_slot();
    let temp_dir = rama_utils::fs::tempdir().expect("create trace directory");
    let engine_runtime_id = Arc::new(Mutex::new(None));
    let callback_runtime_id = Arc::clone(&engine_runtime_id);
    let (handle_tx, handle_rx) = std::sync::mpsc::sync_channel(1);
    let handle_tx = Mutex::new(Some(handle_tx));
    let handler = TestHandler {
        app_message_handler: Arc::new(|_| None),
        tcp_matcher: Arc::new(move |meta| {
            let handle_tx = handle_tx.lock().take().expect("single intercept");
            let service = service_fn(
                move |bridge: BridgeIo<crate::TcpFlow, crate::NwTcpStream>| {
                    let handle_tx = handle_tx.clone();
                    async move {
                        let BridgeIo(ingress, _egress) = bridge;
                        let handle = ingress
                            .extensions()
                            .get_ref::<PromoteHandle>()
                            .cloned()
                            .expect("PromoteHandle in extensions");
                        handle_tx.send(handle).expect("send promote handle");
                        std::future::pending::<()>().await;
                        Ok::<(), Infallible>(())
                    }
                },
            );
            FlowAction::Intercept {
                meta,
                service: service.boxed(),
            }
        }),
        udp_matcher: Arc::new(|_| FlowAction::Passthrough),
        tcp_egress_options: None,
        on_sleep: None,
        on_wake: None,
    };
    let engine = build_dial9_engine(handler, temp_dir.path());
    let runtime_id = {
        let _enter = engine.rt.as_ref().unwrap().enter();
        tokio::runtime::Handle::current().id()
    };
    *engine_runtime_id.lock() = Some(runtime_id);
    let SessionFlowAction::Intercept(mut session) = engine.new_tcp_session(
        TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
        |_| TcpDeliverStatus::Accepted,
        || {},
        || {},
    ) else {
        panic!("expected intercept session");
    };
    let (callback_tx, callback_rx) = std::sync::mpsc::sync_channel(1);
    session.register_promote_request_callback(move || {
        let expected_runtime_id =
            (*callback_runtime_id.lock()).expect("engine runtime id initialized");
        callback_tx
            .send(
                Dial9Handle::current().is_enabled()
                    && tokio::runtime::Handle::current().id() == expected_runtime_id,
            )
            .expect("send callback telemetry state");
    });
    session.activate(|_| TcpDeliverStatus::Accepted, || {}, || {});

    let handle = handle_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("receive promote handle");
    let promote = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build caller runtime")
            .block_on(handle.into_passthrough())
    });

    assert!(
        callback_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("promote callback")
    );
    session.confirm_promoted(Ok(()));
    assert!(matches!(
        promote.join().expect("join promote caller"),
        Ok(())
    ));

    session.cancel();
    engine.stop(0);
}
