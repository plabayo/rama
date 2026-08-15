//! dial9 coverage for the synchronous FFI boundary and delayed flow work.

use super::common::*;
use crate::tproxy::engine::*;
use crate::tproxy::{TransparentProxyFlowMeta, TransparentProxyFlowProtocol};
use dial9_tokio_telemetry::{Dial9Config, telemetry::TelemetryHandle};
use parking_lot::Mutex;
use rama_core::{
    extensions::ExtensionsRef,
    io::BridgeIo,
    service::{Service, service_fn},
};
use std::{convert::Infallible, sync::Arc, time::Duration};

fn build_dial9_engine(
    handler: TestHandler,
    trace_path: std::path::PathBuf,
) -> TransparentProxyEngine<TestHandler> {
    let config = Dial9Config::builder()
        .enabled(true)
        .base_path(trace_path)
        .max_file_size(1024 * 1024)
        .max_total_size(4 * 1024 * 1024)
        .build()
        .expect("build dial9 config");

    TransparentProxyEngineBuilder::new(TestHandlerFactory(handler))
        .with_runtime_factory(
            DefaultTransparentProxyAsyncRuntimeFactory::new().with_dial9_config(config),
        )
        .build()
        .expect("build dial9 engine")
}

#[test]
fn synchronous_app_message_runs_in_dial9_session() {
    let temp_dir = tempfile::tempdir().expect("create trace directory");
    let mut handler = TestHandler::passthrough();
    handler.app_message_handler =
        Arc::new(|_| Some(vec![u8::from(TelemetryHandle::current().is_enabled())]));
    let engine = build_dial9_engine(handler, temp_dir.path().join("app-message.bin"));

    let reply = engine
        .handle_app_message(rama_core::bytes::Bytes::new())
        .expect("app message reply");
    assert_eq!(reply.as_ref(), &[1]);

    engine.stop(0);
}

#[test]
fn external_promote_keeps_engine_dial9_session() {
    let temp_dir = tempfile::tempdir().expect("create trace directory");
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
    let engine = build_dial9_engine(handler, temp_dir.path().join("promote.bin"));
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
        callback_tx
            .send(TelemetryHandle::current().is_enabled())
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
