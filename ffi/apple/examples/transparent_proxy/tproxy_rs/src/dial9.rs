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
//! runtime via dial9's [`build_or_disabled`] semantics rather than
//! failing the engine build.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry
//! [`build_or_disabled`]: dial9_tokio_telemetry::Dial9ConfigBuilder::build_or_disabled

use std::time::Duration;

use ::dial9_tokio_telemetry::Dial9Config;
use rama::{
    net::apple::networkextension::tproxy::DefaultTransparentProxyAsyncRuntimeFactory,
    telemetry::tracing,
};

/// Hard-coded defaults for the demo. Copy and tune in your own
/// extension if these don't fit.
const ROTATION_PERIOD: Duration = Duration::from_mins(1);
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn make_runtime_factory() -> DefaultTransparentProxyAsyncRuntimeFactory {
    let factory = DefaultTransparentProxyAsyncRuntimeFactory::new();

    let Some(storage) = super::utils::storage_dir() else {
        tracing::debug!(
            "rama-tproxy dial9: no storage dir provided; running with plain tokio runtime",
        );
        return factory;
    };

    let trace_dir = storage.join("dial9-traces");
    if let Err(err) = std::fs::create_dir_all(&trace_dir) {
        tracing::error!(
            path = %trace_dir.display(),
            %err,
            "rama-tproxy dial9: failed to create trace dir; running with plain runtime",
        );
        return factory;
    }

    let cfg = Dial9Config::builder()
        .enabled(true)
        .base_path(trace_dir.join("trace.bin"))
        .max_file_size(MAX_FILE_BYTES)
        .max_total_size(MAX_TOTAL_BYTES)
        .rotation_period(ROTATION_PERIOD)
        .build_or_disabled();

    tracing::info!(
        path = %trace_dir.display(),
        "rama-tproxy dial9: telemetry enabled",
    );

    factory.with_dial9_config(cfg)
}
