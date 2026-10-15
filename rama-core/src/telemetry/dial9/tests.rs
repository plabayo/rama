use super::*;
use crate::rt::{OwnedRuntime, blocking::Runtime, dial9_test_util};
use std::{collections::BTreeMap, time::Duration};
use trace_format::{decoder::Decoder, types::FieldValueRef};

#[test]
fn contexts_follow_tasks_and_cancelled_operations_end_once() {
    let _slot = dial9_test_util::recorder_slot();
    let dir = rama_utils::fs::tempdir().unwrap();
    let health = RecorderHealth::default();
    let recorder = recorder_or_disabled(
        DiskBuffer::builder()
            .base_path(dir.path())
            .max_total_size(4 << 20)
            .build(),
    )
    .metrics_sink(health.sink())
    .build();
    assert!(recorder.handle().is_enabled());
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().worker_threads(2);
    let runtime = OwnedRuntime::attach_dial9(
        recorder.handle().clone(),
        builder,
        TokioAttachOptions::default(),
    )
    .unwrap();
    runtime.block_on(async {
        assert_eq!(TraceContext::current(), TraceContext::default());
        let parent = Operation::new("parent");
        let context = parent.context();
        context
            .scope(async {
                assert_eq!(TraceContext::current(), context);
                let child_context = crate::rt::spawn(async move {
                    assert_eq!(TraceContext::current(), context);
                    let child = Operation::new("child");
                    let child_context = child.context();
                    child.finish(Outcome::Success);
                    child_context
                })
                .await
                .unwrap();
                assert_eq!(child_context.flow_id(), context.flow_id());
                assert_ne!(child_context.operation_id(), context.operation_id());
                let (tx, rx) = tokio::sync::oneshot::channel();
                let task = crate::rt::spawn(async move {
                    let _operation = Operation::new("cancelled");
                    tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                rx.await.unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                let never_polled = record_result("unpolled", async { Ok::<_, ()>(()) });
                drop(never_polled);
            })
            .await;
        assert_eq!(TraceContext::current(), TraceContext::default());
        parent.finish(Outcome::Success);
        let other = Operation::new("other");
        assert_ne!(other.context().flow_id(), context.flow_id());
        other.finish(Outcome::Success);
        let first = Operation::new("concurrent-one");
        let second = Operation::new("concurrent-two");
        assert_ne!(first.context().flow_id(), second.context().flow_id());
        let check = |operation: Operation| async move {
            let context = operation.context();
            context
                .scope(async {
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                        assert_eq!(TraceContext::current(), context);
                    }
                })
                .await;
            operation.finish(Outcome::Success);
        };
        let (first, second) = tokio::join!(
            crate::rt::spawn(check(first)),
            crate::rt::spawn(check(second))
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(TraceContext::current(), TraceContext::default());
    });
    runtime.shutdown_bounded(Duration::from_secs(1));
    // A runtime borrowing the recorder must not stop its siblings or recorder.
    assert!(recorder.handle().is_enabled());
    recorder.graceful_shutdown(Duration::from_secs(1));
    let health = health.snapshot();
    assert!(health.flushes > 0);
    assert!(health.events >= 8);
    // Upstream snapshots seal counts before finalizing the last segment.
    assert_eq!(health.undrained_segments, 0);
    assert_eq!(health.dropped_batches, 0);
    let bytes = std::fs::read(dir.path().join("trace.0.bin")).unwrap();
    for destination in ["diagnostic-one", "diagnostic-two"] {
        let destination = dir.path().join(destination);
        let report = export_completed_segments(dir.path(), &destination).unwrap();
        assert_eq!(report.segments, ["trace.0.bin"]);
        assert_eq!(report.active_segments, 0);
        assert_eq!(
            std::fs::read(destination.join("trace.0.bin")).unwrap(),
            bytes
        );
    }
    let mut started = BTreeMap::new();
    let mut finished = BTreeMap::new();
    Decoder::new(&bytes)
        .unwrap()
        .for_each_event(|event| {
            if event.name != "RamaOperationStarted" && event.name != "RamaOperationFinished" {
                return;
            }
            let fields: BTreeMap<_, _> = event.field_names().zip(event.fields.iter()).collect();
            let FieldValueRef::String(name) = fields["name"] else {
                panic!("operation name");
            };
            let FieldValueRef::Varint(id) = fields["operation_id"] else {
                panic!("operation id");
            };
            if event.name == "RamaOperationStarted" {
                assert!(started.insert(*id, name.to_string()).is_none());
            } else {
                let FieldValueRef::Varint(outcome) = fields["outcome"] else {
                    panic!("outcome");
                };
                assert!(finished.insert(*id, *outcome).is_none());
            }
        })
        .unwrap();
    assert_eq!(started.len(), 6);
    assert_eq!(started.len(), finished.len());
    for (id, name) in started {
        assert_eq!(
            finished[&id],
            if name == "cancelled" {
                Outcome::Cancelled as u64
            } else {
                Outcome::Success as u64
            }
        );
    }
}

#[test]
fn paused_recorder_can_be_enabled_and_shared_by_blocking_runtimes() {
    let _slot = dial9_test_util::recorder_slot();
    let dir = rama_utils::fs::tempdir().unwrap();
    let writer = DiskBuffer::builder()
        .base_path(dir.path())
        .max_total_size(4 * 1024 * 1024)
        .build();
    let recorder = recorder_or_disabled(writer).paused().build();
    let handle = recorder.handle().clone();
    let first = Runtime::builder()
        .with_dial9_handle(handle.clone())
        .with_worker_threads(1)
        .try_build()
        .unwrap();
    let second = Runtime::builder()
        .with_dial9_recorder(recorder)
        .with_worker_threads(1)
        .try_build()
        .unwrap();
    assert!(handle.is_connected());
    assert!(!handle.is_enabled());
    first.block_on(async {
        let operation = Operation::new("disabled");
        operation.record_event_with::<RamaOperationStarted>(|_| panic!("must stay lazy"));
        assert!(!operation.is_recorded());
    });
    handle.enable();
    for runtime in [&first, &second] {
        runtime.block_on(async {
            assert!(Dial9Handle::current().is_enabled());
        });
    }
    drop(first);
    assert!(handle.is_enabled());
    drop(second);
    assert!(handle.is_stopped());
}
