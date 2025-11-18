#![allow(dead_code)]

use std::{
    process::{Child, ExitStatus},
    sync::Once,
};

use rama::telemetry::tracing::{
    level_filters::LevelFilter,
    subscriber::{self, EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
};

/// Runner for examples.
pub(super) struct ExampleRunner {
    server_process: Child,
}

/// to ensure we only ever register tracing once,
/// in the first test that gets run.
///
/// Dirty but it works, good enough for tests.
static INIT_TRACING_ONCE: Once = Once::new();

/// Initialize tracing for example tests
pub(super) fn init_tracing() {
    INIT_TRACING_ONCE.call_once(|| {
        let _ = subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::TRACE.into())
                    .from_env_lossy(),
            )
            .try_init();
    });
}

impl ExampleRunner {
    /// Run an example server in background.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn run_background(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
    ) -> Self {
        let child = escargot::CargoBuild::new()
            .arg("-p")
            .arg("rama-http-core")
            .arg(format!("--features={}", extra_features.unwrap_or_default()))
            .example(example_name.as_ref())
            .manifest_path("Cargo.toml")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .env("SSLKEYLOGFILE", "./target/test_ssl_key_log.txt")
            .spawn()
            .unwrap();
        Self {
            server_process: child,
        }
    }
}

impl ExampleRunner {
    /// Run an example and wait until it finished.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be ran,
    /// or if it failed while waiting for it to finish.
    pub(super) fn run(example_name: impl AsRef<str>) -> ExitStatus {
        let example_name = example_name.as_ref().to_owned();
        escargot::CargoBuild::new()
            .arg("-p")
            .arg("rama-http-core")
            .arg("--all-features")
            .example(example_name)
            .manifest_path("Cargo.toml")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .status()
            .unwrap()
    }
}

impl std::ops::Drop for ExampleRunner {
    fn drop(&mut self) {
        self.server_process.kill().expect("kill server process");
    }
}
