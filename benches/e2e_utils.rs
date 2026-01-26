use std::{
    fs::{create_dir, exists, remove_file},
    path::Path,
};

use rama::telemetry::tracing::{
    self,
    level_filters::LevelFilter,
    subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
};
use tracing_appender::non_blocking::WorkerGuard;

pub fn setup_tracing(test_file: &str) -> WorkerGuard {
    let e2e_test_dir = "e2e-test-logs";
    let log_file = format!("{test_file}.log");
    if !exists(e2e_test_dir).unwrap() {
        create_dir(e2e_test_dir).unwrap();
    }
    println!("Tracing will be piped to {e2e_test_dir}/{log_file}");
    let log_file_path = Path::new(e2e_test_dir).join(log_file.clone());
    if exists(&log_file_path).unwrap() {
        remove_file(&log_file_path).unwrap();
    }

    let file_appender = tracing_appender::rolling::never(e2e_test_dir, log_file);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing::subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    _guard
}
