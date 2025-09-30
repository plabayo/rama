#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::Child,
    sync::Once,
    thread,
};

use base64::Engine;
use rama::telemetry::tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug)]
/// A wrapper around a rama service process.
pub(super) struct RamaService {
    process: Child,
}

impl RamaService {
    /// Start the rama Ip service with the given port.
    pub(super) fn ip(port: u16) -> Self {
        let mut process = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .arg("ip")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .spawn()
            .unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("ip service ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                eprintln!("rama ip >> {line}");
            }
        });

        Self { process }
    }

    /// Start the rama echo service with the given port.
    pub(super) fn echo(port: u16, secure: bool) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        if secure {
            const BASE64: base64::engine::GeneralPurpose =
                base64::engine::general_purpose::STANDARD;

            builder.env(
                "RAMA_TLS_CRT",
                BASE64.encode(include_bytes!("./example_tls.crt")),
            );
            builder.env(
                "RAMA_TLS_KEY",
                BASE64.encode(include_bytes!("./example_tls.key")),
            );
        }

        builder
            .stdout(std::process::Stdio::piped())
            .arg("echo")
            .arg("--ws")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        if secure {
            builder.arg("-s");
        }

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("echo service ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama echo >> {line}");
            }
        });

        Self { process }
    }

    /// Run any rama cmd
    pub(super) fn run(args: Vec<&'static str>) -> Result<String, Box<dyn std::error::Error>> {
        let child = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .stdout(std::process::Stdio::piped())
            .args(args)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .spawn()
            .unwrap();

        let output = child.wait_with_output()?;
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout)?;
        Ok(output)
    }

    /// Run the http command
    pub(super) fn http(
        input_args: Vec<&'static str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["http", "--debug", "-v", "--all", "-F", "-k"];
        args.extend(input_args);
        Self::run(args)
    }

    /// Start the rama serve service with the given port and content path.
    pub(super) fn serve(port: u16, path: Option<PathBuf>) -> Self {
        let secure = true;

        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        if secure {
            const BASE64: base64::engine::GeneralPurpose =
                base64::engine::general_purpose::STANDARD;

            builder.env(
                "RAMA_TLS_CRT",
                BASE64.encode(include_bytes!("./example_tls.crt")),
            );
            builder.env(
                "RAMA_TLS_KEY",
                BASE64.encode(include_bytes!("./example_tls.key")),
            );
        }

        builder
            .stdout(std::process::Stdio::piped())
            .arg("serve")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        if secure {
            builder.arg("-s");
        }

        if let Some(path) = path {
            builder.arg(path);
        }

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("ready to serve") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama serve >> {line}");
            }
        });

        Self { process }
    }
}

impl Drop for RamaService {
    fn drop(&mut self) {
        self.process.kill().expect("kill server process");
    }
}

/// to ensure we only ever register tracing once,
/// in the first test that gets run.
///
/// Dirty but it works, good enough for tests.
static INIT_TRACING_ONCE: Once = Once::new();

/// Initialize tracing for example tests
pub(super) fn init_tracing() {
    INIT_TRACING_ONCE.call_once(|| {
        let _ = tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::TRACE.into())
                    .from_env_lossy(),
            )
            .try_init();
    });
}
