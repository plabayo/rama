//! Endpoint tests for the dial9 integration.

use super::*;
use dial9_trace_format::types::FieldValueRef;
use rama_core::rt::OwnedRuntime;
use rama_core::telemetry::dial9::{
    Dial9Handle, Dial9HandleTokioExt as _, DiskBuffer, TokioAttachOptions, recorder_or_disabled,
};

/// Both tests read the process-wide driver observation, so they never overlap.
fn observation_slot() -> &'static tokio::sync::Mutex<()> {
    static SLOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &SLOT
}

async fn handshake_and_shutdown() {
    let (client_config, server_config) = configs();
    let server = endpoint(
        Some(server_config),
        WeakScope::detached(),
        Duration::from_secs(1),
    );
    let client = endpoint(None, WeakScope::detached(), Duration::from_secs(1));
    let connecting = client
        .connect_with(client_config, server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client_conn, server_conn) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(connecting, async { server.accept().await.unwrap().await })
    })
    .await
    .unwrap();
    client_conn.unwrap();
    server_conn.unwrap();
    assert_eq!(
        tokio::join!(client.shutdown(), server.shutdown()),
        (ShutdownOutcome::Drained, ShutdownOutcome::Drained)
    );
}

#[tokio::test]
async fn without_a_recorder_the_drivers_run_with_a_disabled_handle() {
    let _slot = observation_slot().lock().await;
    assert!(!Dial9Handle::current().is_enabled());
    crate::driver::connection::DRIVER_POLLED_WITH_DIAL9.store(false, Ordering::Relaxed);
    handshake_and_shutdown().await;
    assert!(
        !crate::driver::connection::DRIVER_POLLED_WITH_DIAL9.load(Ordering::Relaxed),
        "no recorder is attached, so drivers must not see an enabled session"
    );
}

#[test]
fn driver_tasks_run_inside_an_attached_dial9_session() {
    let _slot = observation_slot().blocking_lock();
    let temp_dir = rama_utils::fs::tempdir().unwrap();
    let writer = DiskBuffer::builder()
        .base_path(temp_dir.path())
        .max_file_size(rama_utils::octets::mib_u64(1))
        .max_total_size(rama_utils::octets::mib_u64(4))
        .build();
    let recorder = recorder_or_disabled(writer).build();
    assert!(
        recorder.handle().is_enabled(),
        "expected an enabled recorder; is another recorder alive in this process?"
    );
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(2).enable_all();
    let tokio_runtime = recorder
        .handle()
        .attach_tokio_runtime(builder, TokioAttachOptions::default())
        .unwrap();
    let runtime = OwnedRuntime::from_dial9((recorder, tokio_runtime));
    crate::driver::connection::DRIVER_POLLED_WITH_DIAL9.store(false, Ordering::Relaxed);
    runtime.block_on(async {
        assert!(Dial9Handle::current().is_enabled());
        handshake_and_shutdown().await;
        let directory = crate::EndpointRouteDirectory::new(rama_utils::macros::nonzero!(1));
        let endpoint = endpoint(None, WeakScope::detached(), Duration::from_secs(1));
        let registration = directory
            .register(&endpoint, endpoint.local_addr().unwrap().into())
            .unwrap();
        assert!(
            directory
                .route(endpoint.local_addr().unwrap().into(), b"invalid")
                .unwrap()
                .is_none()
        );
        drop(registration);
        #[cfg(feature = "boring")]
        directory.record_fallback(3);
    });
    assert!(
        crate::driver::connection::DRIVER_POLLED_WITH_DIAL9.load(Ordering::Relaxed),
        "connection drivers must run inside the recorder's session"
    );
    runtime.shutdown_bounded(Duration::from_secs(5));
    let mut routing_events = Vec::new();
    let mut fallback_events = 0;
    for entry in std::fs::read_dir(temp_dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "bin") {
            continue;
        }
        let bytes = std::fs::read(path).unwrap();
        dial9_trace_format::decoder::Decoder::new(&bytes)
            .unwrap()
            .for_each_event(|event| {
                let fields: std::collections::BTreeMap<_, _> =
                    event.field_names().zip(event.fields.iter()).collect();
                if event.name == "QuicRoutingSnapshot" {
                    let FieldValueRef::Varint(id) = fields["resource_id"] else {
                        panic!("resource id")
                    };
                    let FieldValueRef::String(reason) = fields["reason"] else {
                        panic!("reason")
                    };
                    let FieldValueRef::Varint(used) = fields["registered_endpoints"] else {
                        panic!("occupancy")
                    };
                    routing_events.push((*id, reason.to_string(), *used));
                }
                if event.name == "QuicMigrationCapacity" {
                    assert!(matches!(fields["affected_total"], FieldValueRef::Varint(3)));
                    fallback_events += 1;
                }
            })
            .unwrap();
    }
    assert_eq!(routing_events.len(), 3);
    let id = routing_events[0].0;
    assert_ne!(id, 0);
    assert_eq!(
        routing_events,
        [
            (id, "registered".into(), 1),
            (id, "miss".into(), 1),
            (id, "released".into(), 0)
        ]
    );
    assert_eq!(fallback_events, usize::from(cfg!(feature = "boring")));
}
