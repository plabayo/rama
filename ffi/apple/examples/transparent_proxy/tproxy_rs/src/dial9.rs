//! [dial9] runtime telemetry for the demo extension.
//!
//! Enabled when the FFI init handed us a storage directory (the
//! production code path). In that case traces land under
//! `<storage_dir>/dial9-traces/`. When no storage directory was
//! wired through (e.g. inside the e2e test harness, which loads the
//! static lib directly and skips the regular init pipeline) we keep
//! the runtime plain — recording into a hard-coded `/tmp` path from
//! a test process is more noise than signal.
//!
//! Misconfiguration of an enabled config falls back to a plain
//! runtime via dial9's [`recorder_or_disabled`] semantics rather than
//! failing the engine build.
//!
//! [dial9]: https://github.com/dial9-rs/dial9
//! [`recorder_or_disabled`]: dial9::recorder_or_disabled

use std::time::Duration;

use ::dial9::{DiskBuffer, TokioAttachOptions};
use rama::{
    net::apple::networkextension::tproxy::DefaultTransparentProxyAsyncRuntimeFactory,
    telemetry::tracing, utils::octets::mib_u64,
};

/// Hard-coded defaults for the demo. Copy and tune in your own
/// extension if these don't fit.
const ROTATION_PERIOD: Duration = Duration::from_mins(1);
const MAX_TOTAL_BYTES: u64 = mib_u64(256);
const MAX_FILE_BYTES: u64 = mib_u64(64);

pub(super) fn make_runtime_factory() -> DefaultTransparentProxyAsyncRuntimeFactory {
    let factory = DefaultTransparentProxyAsyncRuntimeFactory::new();

    // The FFI e2e harness builds with `e2e` and runs many engines in one process;
    // the dial9 writer does not follow engine shutdown, so each engine would keep
    // its runtime threads and FDs open.
    if cfg!(feature = "e2e") {
        tracing::debug!("rama-tproxy dial9: disabled in `e2e` builds");
        return factory.without_dial9_recorder();
    }

    // Example-specific opt-out for local diagnostics. Applications should make
    // this choice in their own configuration.
    if let Some("true" | "1") = std::env::var("RAMA_TPROXY_DIAL9_DISABLED").ok().as_deref() {
        tracing::debug!(
            "rama-tproxy dial9: explicitly disabled via RAMA_TPROXY_DIAL9_DISABLED env var",
        );
        return factory.without_dial9_recorder();
    }

    let Some(storage) = super::utils::storage_dir() else {
        tracing::debug!(
            "rama-tproxy dial9: no storage dir provided; running with plain tokio runtime",
        );
        return factory.without_dial9_recorder();
    };

    let trace_dir = storage.join("dial9-traces");
    if let Err(err) = std::fs::create_dir_all(&trace_dir) {
        tracing::error!(
            path = %trace_dir.display(),
            %err,
            "rama-tproxy dial9: failed to create trace dir; running with plain runtime",
        );
        return factory.without_dial9_recorder();
    }

    // Segments land in `<trace_dir>/trace.{n}.bin`.
    let writer = DiskBuffer::builder()
        .base_path(trace_dir)
        .max_file_size(MAX_FILE_BYTES)
        .max_total_size(MAX_TOTAL_BYTES)
        .rotation_period(ROTATION_PERIOD)
        .build();

    let recorder = ::dial9::recorder_or_disabled(writer).build();
    tracing::info!(
        enabled = recorder.handle().is_enabled(),
        "rama-tproxy dial9: recorder configured"
    );
    factory
        .with_dial9_recorder(recorder)
        // Name the runtime so a multi-extension dial9 trace can be
        // disambiguated; cost is a small string in the trace header.
        .with_dial9_attach_options(
            TokioAttachOptions::builder()
                .runtime_name("rama-tproxy-example")
                .build(),
        )
}
