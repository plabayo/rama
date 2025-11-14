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
    pub(super) fn serve_ip(port: u16, transport: bool, secure: bool) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        builder
            .stdout(std::process::Stdio::piped())
            .arg("serve")
            .arg("ip")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

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
            builder.arg("-s");
        }

        if transport {
            builder.arg("-T");
        }

        let mut process = builder.spawn().unwrap();

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
    pub(super) fn serve_echo(port: u16, mode: &'static str) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        if mode.eq_ignore_ascii_case("tls") || mode.eq_ignore_ascii_case("https") {
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
            .arg("echo")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--mode")
            .arg(mode)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        if mode.eq_ignore_ascii_case("http") || mode.eq_ignore_ascii_case("https") {
            builder.arg("--ws");
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

    // Start the rama fp service with the given port.
    pub(super) fn serve_fp(port: u16, secure: bool) -> Self {
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
            .arg("fp")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        if secure {
            builder.arg("--secure");
        }

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("FP Service (auto) listening") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama fp >> {line}");
            }
        });

        Self { process }
    }

    /// Start the rama proxy service with the given port.
    pub(super) fn serve_proxy(port: u16) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        builder
            .stdout(std::process::Stdio::piped())
            .arg("serve")
            .arg("proxy")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("proxy ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama proxy >> {line}");
            }
        });

        Self { process }
    }

    /// Start the rama discard service with the given port.
    pub(super) fn serve_discard(port: u16, mode: &'static str) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        if mode.eq_ignore_ascii_case("tls") {
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
            .arg("discard")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--mode")
            .arg(mode)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("discard service ready") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                println!("rama discard >> {line}");
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
            .stderr(std::process::Stdio::piped())
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
        let mut s = String::from_utf8(output.stderr)?;
        s.push_str(&String::from_utf8(output.stdout)?);
        Ok(s)
    }

    /// Run the http command
    pub(super) fn http(
        input_args: Vec<&'static str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["--verbose", "-L", "-k"];
        args.extend(input_args);
        Self::run(args)
    }

    /// Run the probe tls command
    pub(super) fn probe_tls(addr: &'static str) -> Result<String, Box<dyn std::error::Error>> {
        let args = vec!["probe", "tls", "-k", addr];
        Self::run(args)
    }

    /// Run the probe tcp command
    pub(super) fn probe_tcp(addr: &'static str) -> Result<String, Box<dyn std::error::Error>> {
        let args = vec!["probe", "tcp", addr];
        Self::run(args)
    }

    /// Start the rama serve service with the given port and content path.
    pub(super) fn serve_fs(port: u16, path: Option<PathBuf>) -> Self {
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
            .arg("fs")
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

    // Start the rama stunnel exit node with the default port and the forward address.
    // with self-signed certificates for testing
    pub(super) fn serve_stunnel_exit(bind: &str, forward: &str) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        builder
            .stdout(std::process::Stdio::piped())
            .arg("serve")
            .arg("stunnel")
            .arg("exit")
            .arg("--bind")
            .arg(bind)
            .arg("--forward")
            .arg(forward)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("Stunnel exit node is running") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                eprintln!("rama stunnel-server >> {line}");
            }
        });

        Self { process }
    }

    /// Start the rama stunnel entry node in insecure mode (skip verification).
    pub(super) fn serve_stunnel_entry_insecure(bind: &str, connect: &str) -> Self {
        let mut builder = escargot::CargoBuild::new()
            .package("rama-cli")
            .bin("rama")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command();

        builder
            .stdout(std::process::Stdio::piped())
            .arg("serve")
            .arg("stunnel")
            .arg("entry")
            .arg("--insecure")
            .arg("--bind")
            .arg(bind)
            .arg("--connect")
            .arg(connect)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut process = builder.spawn().unwrap();

        let stdout = process.stdout.take().unwrap();
        let mut stdout = BufReader::new(stdout).lines();

        for line in &mut stdout {
            let line = line.unwrap();
            if line.contains("Stunnel entry node is running") {
                break;
            }
        }

        thread::spawn(move || {
            for line in stdout {
                let line = line.unwrap();
                eprintln!("rama stunnel-client >> {line}");
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
