#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{
    env::temp_dir,
    fs::{create_dir_all, exists, remove_file},
};

use rama::telemetry::tracing::{
    appender::{self, Rotation, rolling_dedicated_thread},
    subscriber::{filter, layer::SubscriberExt as _, util::SubscriberInitExt as _},
};

pub fn setup_tracing(test_file: &str) -> appender::non_blocking::WorkerGuard {
    let log_file = format!("{test_file}.log");

    let log_file_dir_path = temp_dir().join("rama").join("e2e-test-logs");
    create_dir_all(&log_file_dir_path).unwrap();

    let log_file_path = log_file_dir_path.join(log_file.clone());
    println!("Tracing will be piped to file {}", log_file_path.display());
    if exists(&log_file_path).unwrap() {
        remove_file(&log_file_path).unwrap();
    }

    // Run the file appender on a dedicated OS thread so log rotations
    // and file I/O don't block whichever runtime worker emitted the
    // event — see `appender::rolling_dedicated_thread`.
    let (non_blocking, _guard) =
        rolling_dedicated_thread(Rotation::NEVER, log_file_dir_path, log_file);

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(filter::LevelFilter::DEBUG)
        .with(file_layer)
        .try_init()
        .expect("subscriber already set");

    _guard
}
