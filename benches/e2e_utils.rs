use std::{
    fs::{create_dir_all, exists, remove_file},
    path::Path,
};

use rama::telemetry::tracing::{
    appender::{self},
    subscriber::{filter, layer::SubscriberExt as _, util::SubscriberInitExt as _},
};

pub fn setup_tracing(test_file: &str) -> appender::non_blocking::WorkerGuard {
    let e2e_test_dir = "e2e-test-logs";
    let log_file = format!("{test_file}.log");
    create_dir_all(e2e_test_dir).unwrap();

    println!("Tracing will be piped to {e2e_test_dir}/{log_file}");
    let log_file_path = Path::new(e2e_test_dir).join(log_file.clone());
    if exists(&log_file_path).unwrap() {
        remove_file(&log_file_path).unwrap();
    }

    let file_appender = appender::rolling::never(e2e_test_dir, log_file);
    let (non_blocking, _guard) = appender::non_blocking(file_appender);

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
