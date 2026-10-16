//! Explicit, local dial9 recording with application events and a diagnostic copy.
//!
//! Run with `cargo run -p rama-examples --features dial9,http-full --bin dial9_local --
//! --directory /tmp/rama-traces --export-to /tmp/rama-diagnostics`.
//! View the copy with `dial9-viewer serve --local-dir /tmp/rama-diagnostics`.
//! Install the viewer without S3 support using
//! `cargo install --locked dial9-viewer --no-default-features`.
//!
//! Optional dial9 sources belong on the recorder builder below. Enable their
//! corresponding upstream Cargo features in your application. Rama does not
//! choose profiling sources or environment settings for you.

use clap::Parser;
use rama::{
    Layer as _, Service as _,
    error::BoxError,
    http::{Body, Request, Response, body::util::BodyExt as _, layer::dial9::Dial9Layer},
    rt::blocking::Runtime,
    service::service_fn,
    telemetry::dial9::{
        DiskBuffer, Operation, Outcome, RecorderHealth, TokioAttachOptions,
        core::clock_monotonic_ns, export_completed_segments, recorder, trace_format::TraceEvent,
    },
};
use std::{convert::Infallible, path::PathBuf, time::Duration};

#[derive(Parser)]
struct Options {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u64).range(1..))]
    segment_mib: u64,
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u64).range(1..))]
    total_mib: u64,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    rotation_seconds: u64,
    /// A new directory inside a larger diagnostics bundle.
    #[arg(long)]
    export_to: Option<PathBuf>,
}

#[derive(TraceEvent)]
struct ApplicationDecision {
    #[traceevent(timestamp)]
    timestamp_ns: u64,
    flow_id: u64,
    operation_id: u64,
    allowed: bool,
}

fn main() -> Result<(), BoxError> {
    let options = Options::parse();
    let bytes = |mib: u64| mib.checked_mul(1024 * 1024).ok_or("size is too large");
    let writer = DiskBuffer::builder()
        .base_path(&options.directory)
        .max_file_size(bytes(options.segment_mib)?)
        .max_total_size(bytes(options.total_mib)?)
        .rotation_period(Duration::from_secs(options.rotation_seconds))
        .build()?;
    // Rotation controls segment age; total size controls retention. These are
    // eviction budgets, not filesystem quotas. Leave disk headroom. Reusing
    // this directory preserves retained files across application restarts.
    let health = RecorderHealth::default();
    let recorder = recorder(writer)
        .metrics_sink(health.sink())
        .segment_metadata([("application".into(), "rama-dial9-example".into())])
        .build();
    let runtime = Runtime::builder()
        .with_dial9_handle(recorder.handle().clone())
        .with_dial9_attach_options(
            TokioAttachOptions::builder()
                .runtime_name("application")
                .build(),
        )
        .with_worker_threads(2)
        .try_build()?;
    // The recorder remains application-owned. Other runtimes can attach the
    // same handle; shut them all down before finalizing the recorder.
    let service = Dial9Layer::new().layer(service_fn(|_: Request| async {
        let operation = Operation::new("application.policy");
        operation.record_event_with(|context| ApplicationDecision {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            operation_id: context.operation_id(),
            allowed: true,
        });
        operation.finish(Outcome::Success);
        Ok::<_, Infallible>(Response::new(Body::from("recorded response")))
    }));
    runtime.block_on(async {
        let response = service.serve(Request::new(Body::empty())).await?;
        response.into_body().collect().await?;
        Ok::<_, BoxError>(())
    })?;
    drop(runtime);
    recorder.graceful_shutdown(Duration::from_secs(5));
    if let Some(destination) = options.export_to {
        // While recording, call this on a blocking worker. It omits the active
        // segment and reports eviction races; after shutdown it includes the tail.
        let report = export_completed_segments(&options.directory, &destination)?;
        std::fs::write(
            destination.join("recorder-health.json"),
            serde_json::to_vec_pretty(&health.snapshot())?,
        )?;
        rama::telemetry::tracing::info!(?report, "collected dial9 segments");
    }
    Ok(())
}
