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
        engine.new_udp_session(meta, |_| {}, || {}, move || _ = closed_tx.send(()))
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
