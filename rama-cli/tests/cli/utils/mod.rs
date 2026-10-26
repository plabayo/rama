#![allow(dead_code)]

#[cfg(test)]
mod startup_tests;

use std::{
    collections::VecDeque,
    io::{self, BufRead, BufReader, Read as _, Write as _},
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Once},
    thread,
    time::{Duration, Instant},
};

use base64::Engine;
use parking_lot::Mutex;
use rama::net::{process::listening_sockets, transport::TransportProtocol};
use rama::telemetry::tracing::{
    level_filters::LevelFilter,
    subscriber::{self, EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
};

/// The `rama` binary cargo built for these tests, run from the workspace root so relative
/// fixture paths such as `test-files` resolve.
pub(super) fn rama_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rama"));
    // Only a test that pipes input gives the child a stdin; an inherited one can block it.
    command.stdin(Stdio::null());
    command.current_dir(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("rama-cli lives in the workspace root"),
    );
    command
}

#[derive(Debug)]
/// A wrapper around a rama service process.
pub(super) struct RamaService {
    process: Child,
    address: SocketAddr,
    startup_deadline: Instant,
    diagnostics: Arc<Mutex<VecDeque<u8>>>,
    stderr_drained: std::sync::mpsc::Receiver<()>,
}

#[derive(Debug, Clone)]
pub(super) enum EchoMode {
    Tcp,
    Udp,
    Tls,
    Http,
    Https,
    HttpsWithGeneratedCert,
    HttpsWithCertIssuer {
        remote_addr: String,
        remote_ca: Option<Vec<u8>>,
        remote_auth: Option<String>,
    },
}

#[derive(Debug, Clone, Copy)]
pub(super) enum IcapTlsMode {
    Plain,
    SelfSigned,
    Files,
}

impl RamaService {
    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn port(&self) -> u16 {
        self.address.port()
    }

    /// HTTP/3 tests require UDP on the same address, even when TCP is ready.
    pub(super) fn wait_for_http3(&mut self) {
        self.wait_for_endpoint(TransportProtocol::Udp);
    }

    // Own the child before taking pipes or performing any fallible readiness work.
    fn spawn(builder: &mut Command, requested: SocketAddr) -> Self {
        Self::spawn_within(builder, requested, Duration::from_secs(10))
    }

    fn spawn_within(builder: &mut Command, requested: SocketAddr, timeout: Duration) -> Self {
        let (stderr_done, stderr_drained) = std::sync::mpsc::sync_channel(1);
        let process = builder
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rama service");
        let mut service = Self {
            process,
            address: requested,
            startup_deadline: Instant::now() + timeout,
            diagnostics: Arc::new(Mutex::new(VecDeque::new())),
            stderr_drained,
        };

        let stderr = service.process.stderr.take().expect("service stderr");
        let diagnostics = service.diagnostics.clone();
        thread::spawn(move || {
            let mut stderr = stderr;
            let mut buffer = [0; 4096];

            while let Ok(length) = stderr.read(&mut buffer) {
                if length == 0 {
                    break;
                }

                let mut tail = diagnostics.lock();
                tail.extend(&buffer[..length]);
                let excess = tail.len().saturating_sub(64 * 1024);
                tail.drain(..excess);
            }

            let _sent = stderr_done.send(());
        });

        service
    }

    /// Whether the service is still running.
    pub(super) fn process_is_running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }

    fn check_running(&mut self) {
        if let Some(status) = self.process.try_wait().expect("check service status") {
            // Include final diagnostics, while bounding the wait in case a
            // descendant inherited stderr and keeps the pipe open.
            let _drained = self.stderr_drained.recv_timeout(Duration::from_millis(200));
            panic!(
                "rama service {} exited during startup: {status}\n{}",
                self.process.id(),
                self.diagnostics()
            );
        }
    }

    pub(super) fn diagnostics(&self) -> String {
        let bytes: Vec<_> = self.diagnostics.lock().iter().copied().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn wait_for_endpoint(&mut self, protocol: TransportProtocol) {
        self.wait_for_endpoint_except(protocol, None);
    }

    fn wait_for_udp_service(&mut self, ready_message: &str) {
        // Mio briefly binds a loopback UDP socket to initialize Winsock. A PID
        // snapshot can catch that socket before the service binds its real one.
        // Use the ready message only as a barrier; discover the address below.
        self.wait_for_diagnostic(ready_message);
        self.wait_for_endpoint(TransportProtocol::Udp);
    }

    fn wait_for_diagnostic(&mut self, message: &str) {
        loop {
            self.check_running();
            if self.diagnostics().contains(message) {
                return;
            }
            let remaining = self
                .startup_deadline
                .saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "rama service {} did not announce {message:?} before timeout\n{}",
                self.process.id(),
                self.diagnostics()
            );
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }

    fn wait_for_endpoint_except(
        &mut self,
        protocol: TransportProtocol,
        exclude: Option<SocketAddr>,
    ) {
        let deadline = self.startup_deadline;
        let mut delay = Duration::from_millis(25);

        // A child can briefly inherit our listeners while exec closes its
        // descriptors. These fixtures must bind their own endpoint.
        let parent_sockets = listening_sockets(std::process::id()).expect("inspect parent sockets");

        loop {
            self.check_running();
            let sockets = listening_sockets(self.process.id());
            self.check_running();

            let sockets = sockets.unwrap_or_else(|error| {
                panic!(
                    "inspect rama service {}: {error}\n{}",
                    self.process.id(),
                    self.diagnostics()
                )
            });

            let candidates: Vec<_> = sockets
                .iter()
                .filter(|socket| {
                    !parent_sockets.contains(socket)
                        && Some(socket.local_addr) != exclude
                        && socket.protocol == protocol
                        && socket.local_addr.ip() == self.address.ip()
                        && (self.address.port() == 0
                            || socket.local_addr.port() == self.address.port())
                })
                .collect();

            match candidates.as_slice() {
                [socket] => {
                    self.address = socket.local_addr;
                    return;
                }
                [] => {}
                _ => panic!(
                    "ambiguous {protocol:?} endpoints for rama service {}: {candidates:?}\n{}",
                    self.process.id(),
                    self.diagnostics()
                ),
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "rama service {} did not bind {:?} before timeout; sockets: {sockets:?}\n{}",
                self.process.id(),
                self.address,
                self.diagnostics()
            );

            thread::sleep(delay.min(remaining));
            delay = (delay * 2).min(Duration::from_millis(200));
        }
    }

    /// Start the rama Ip service with the given port.
    pub(super) fn serve_ip(port: u16, transport: bool, secure: bool) -> Self {
        Self::serve_ip_with_args(port, transport, secure, &[])
    }

    /// Start the rama Ip service with the given port and extra arguments.
    pub(super) fn serve_ip_with_args(
        port: u16,
        transport: bool,
        secure: bool,
        args: &[&str],
    ) -> Self {
        let mut builder = rama_command();

        builder
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
        builder.args(args);

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama echo service with the given port.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn serve_echo(port: u16, mode: EchoMode) -> Self {
        let mut builder = rama_command();

        const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

        if matches!(mode, EchoMode::Tls | EchoMode::Https) {
            builder.env(
                "RAMA_TLS_CRT",
                BASE64.encode(include_bytes!("./example_tls.crt")),
            );
            builder.env(
                "RAMA_TLS_KEY",
                BASE64.encode(include_bytes!("./example_tls.key")),
            );
        } else if matches!(mode, EchoMode::HttpsWithGeneratedCert) {
            // Exercise the CLI's generated P-256 certificate, independently of
            // any certificate or remote issuer configured in the environment.
            builder
                .env_remove("RAMA_TLS_CRT")
                .env_remove("RAMA_TLS_KEY")
                .env_remove("RAMA_TLS_REMOTE");
        } else if let EchoMode::HttpsWithCertIssuer {
            remote_addr,
            remote_ca,
            remote_auth,
        } = &mode
        {
            builder.env("RAMA_TLS_REMOTE", remote_addr);
            if let Some(remote_ca) = remote_ca {
                builder.env("RAMA_TLS_REMOTE_CA", BASE64.encode(remote_ca));
            }
            if let Some(remote_auth) = remote_auth {
                builder.env("RAMA_TLS_REMOTE_AUTH", remote_auth);
            }
        }

        builder
            .arg("serve")
            .arg("echo")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--mode")
            .arg(match &mode {
                EchoMode::Tcp => "tcp",
                EchoMode::Udp => "udp",
                EchoMode::Tls => "tls",
                EchoMode::Http => "http",
                EchoMode::Https
                | EchoMode::HttpsWithGeneratedCert
                | EchoMode::HttpsWithCertIssuer { .. } => "https",
            })
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let http = matches!(
            &mode,
            EchoMode::Http
                | EchoMode::Https
                | EchoMode::HttpsWithGeneratedCert
                | EchoMode::HttpsWithCertIssuer { .. }
        );
        if http {
            builder.arg("--ws");
        }
        if matches!(mode, EchoMode::Udp) {
            enable_service_ready_log(&mut builder, "rama::cmd::serve::echo");
        }

        // HTTP echo loads the embedded profile database before listening.
        let mut service = Self::spawn_within(
            &mut builder,
            ([127, 0, 0, 1], port).into(),
            Duration::from_secs(if http { 60 } else { 10 }),
        );
        if matches!(mode, EchoMode::Udp) {
            service.wait_for_udp_service("udp echo service ready:");
            wait_for_udp_echo(&mut service);
        } else {
            service.wait_for_endpoint(TransportProtocol::Tcp);
        }
        service
    }

    /// Start the Rama ICAP echo service with the given port.
    pub(super) fn serve_icap(port: u16, tls: IcapTlsMode) -> Self {
        let mut builder = rama_command();

        builder
            .arg("serve")
            .arg("icap")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        match tls {
            IcapTlsMode::Plain => {}
            IcapTlsMode::SelfSigned => {
                builder.arg("--secure");
            }
            IcapTlsMode::Files => {
                let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cli/utils");
                builder
                    .arg("--cert")
                    .arg(fixtures.join("example_tls.crt"))
                    .arg("--key")
                    .arg(fixtures.join("example_tls.key"));
            }
        }

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    // Start the rama fp service with the given port.
    pub(super) fn serve_fp(port: u16, secure: bool) -> Self {
        let mut builder = rama_command();

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

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama proxy service with the given port.
    pub(super) fn serve_proxy(port: u16) -> Self {
        let mut builder = rama_command();

        builder
            .arg("serve")
            .arg("proxy")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama proxy service with extra arguments.
    pub(super) fn serve_proxy_with_args(port: u16, args: &[&str]) -> Self {
        let mut builder = rama_command();

        builder
            .arg("serve")
            .arg("proxy")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .args(args)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama proxy service with ICAP request and response adaptation.
    pub(super) fn serve_proxy_icap(port: u16, icap_uri: &str, insecure: bool) -> Self {
        let mut builder = rama_command();

        builder
            .arg("serve")
            .arg("proxy")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--icap")
            .arg(icap_uri)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );
        if insecure {
            builder.arg("--icap-insecure");
        }

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama MITM proxy and inspector on separate loopback ports.
    pub(super) fn serve_proxy_mitm() -> (Self, SocketAddr, String) {
        let mut builder = rama_command();

        builder
            .arg("serve")
            .arg("proxy")
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--mitm=127.0.0.1:0")
            .arg("--inspect-json")
            .stdout(Stdio::piped())
            .env(
                "RUST_LOG",
                "info,rama_core::layer::consume_err=debug,rama_http=debug,rama_tls_boring=debug",
            );

        // MITM initializes the embedded profile database before announcing readiness.
        let mut service = Self::spawn_within(
            &mut builder,
            ([127, 0, 0, 1], 0).into(),
            Duration::from_secs(60),
        );
        let stdout = service
            .process
            .stdout
            .take()
            .expect("inspector JSON output");
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();

            // This is the existing machine interface for the capability token
            // and inspector role, not human log parsing or socket readiness.
            let record = (&mut reader)
                .take(64 * 1024)
                .read_line(&mut line)
                .map_err(|error| error.to_string())
                .and_then(|_| {
                    serde_json::from_str::<serde_json::Value>(&line)
                        .map_err(|error| error.to_string())
                });

            let _sent = tx.send(record);
            let _drained = io::copy(&mut reader, &mut io::sink());
        });

        let ready = loop {
            service.check_running();

            match rx.try_recv() {
                Ok(record) => break record.expect("valid inspector readiness record"),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("inspector output closed\n{}", service.diagnostics())
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }

            assert!(
                Instant::now() < service.startup_deadline,
                "inspector readiness timed out\n{}",
                service.diagnostics()
            );
            thread::sleep(Duration::from_millis(25));
        };

        assert_eq!(ready["event"], "rama.inspector.ready");
        assert_eq!(ready["version"], 1);
        let inspector_address: SocketAddr = ready["api_url"]
            .as_str()
            .unwrap()
            .strip_prefix("http://")
            .unwrap()
            .strip_suffix("/api")
            .unwrap()
            .parse()
            .unwrap();
        let inspector_token = ready["authorization"]["token"].as_str().unwrap().to_owned();
        assert_eq!(inspector_token.len(), 64);

        // Verify both sockets are owned by this child. The machine record gives
        // the role of the second TCP listener, which PID alone cannot infer.
        service.address = inspector_address;
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service.address.set_port(0);
        service.wait_for_endpoint_except(TransportProtocol::Tcp, Some(inspector_address));

        (service, inspector_address, inspector_token)
    }

    /// Start the rama discard service with the given port.
    pub(super) fn serve_discard(port: u16, mode: &str) -> Self {
        let mut builder = rama_command();

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

        let udp = mode.eq_ignore_ascii_case("udp");
        if udp {
            enable_service_ready_log(&mut builder, "rama::cmd::serve::discard");
        }
        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        if udp {
            service.wait_for_udp_service("discard service ready:");
        } else {
            service.wait_for_endpoint(TransportProtocol::Tcp);
        }
        service
    }

    // Start the rama http-test service with the given port.
    pub(super) fn serve_http_test(port: u16, secure: bool) -> Self {
        Self::serve_http_test_with_args(port, secure, &[])
    }

    /// Start the rama http-test service with the given port and extra arguments.
    pub(super) fn serve_http_test_with_args(port: u16, secure: bool, args: &[&str]) -> Self {
        let mut builder = rama_command();

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
            .arg("serve")
            .arg("http-test")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );

        if secure {
            builder.arg("--secure");
        }
        builder.args(args);

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Run any rama cmd
    pub(super) fn run(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
        let child = rama_command()
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
        if !output.status.success() {
            // Surface the child's own diagnostics — otherwise the test
            // panic only carries the args, which is rarely enough to
            // pinpoint what went wrong (TLS handshake? bind in use?
            // bad CLI flag?).
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "rama exited unsuccessfully\n  args: {args:?}\n  status: {status}\n  --- stderr ---\n{stderr}\n  --- stdout ---\n{stdout}",
                status = output.status,
            );
        }
        let mut s = String::from_utf8(output.stderr)?;
        s.push_str(&String::from_utf8(output.stdout)?);
        Ok(s)
    }

    /// Run any rama cmd allowing failure — returns (exit_success,
    /// stdout, stderr) so callers can assert on error diagnostics
    /// without the harness panicking on non-zero exit.
    #[allow(clippy::type_complexity)]
    pub(super) fn run_capture(
        args: &[&str],
    ) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
        let child = rama_command()
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
        Ok((
            output.status.success(),
            String::from_utf8(output.stdout)?,
            String::from_utf8(output.stderr)?,
        ))
    }

    /// Run a command without inheriting proxy settings. `no_proxy` can be used
    /// to force direct routing for a local target while still exercising the
    /// CLI's normal proxy-selection stack.
    #[allow(clippy::type_complexity)]
    pub(super) fn run_capture_isolated(
        args: &[&str],
        no_proxy: Option<&str>,
    ) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
        let mut builder = rama_command();
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            builder.env_remove(name);
        }
        if let Some(no_proxy) = no_proxy {
            builder.env("NO_PROXY", no_proxy);
        }
        let output = builder
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .args(args)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .spawn()?
            .wait_with_output()?;
        Ok((
            output.status.success(),
            String::from_utf8(output.stdout)?,
            String::from_utf8(output.stderr)?,
        ))
    }

    /// Run a rama command with the supplied bytes connected to stdin.
    #[allow(clippy::type_complexity)]
    pub(super) fn run_capture_with_stdin(
        args: &[&str],
        stdin: &[u8],
    ) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
        let mut child = rama_command()
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .args(args)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            )
            .spawn()
            .unwrap();
        let write_result = child.stdin.take().expect("piped stdin").write_all(stdin);
        let output = child.wait_with_output()?;
        write_result?;
        Ok((
            output.status.success(),
            String::from_utf8(output.stdout)?,
            String::from_utf8(output.stderr)?,
        ))
    }

    /// Run the http command
    pub(super) fn http(input_args: Vec<&str>) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["--verbose", "-L", "-k"];
        args.extend(input_args);
        Self::run(&args)
    }

    /// Run the probe tls command
    pub(super) fn probe_tls(addr: &str) -> Result<String, Box<dyn std::error::Error>> {
        let args = vec!["probe", "tls", "-k", addr];
        Self::run(&args)
    }

    /// Run the probe tcp command
    pub(super) fn probe_tcp(addr: &str) -> Result<String, Box<dyn std::error::Error>> {
        let args = vec!["probe", "tcp", addr];
        Self::run(&args)
    }

    /// Run the resolve command
    pub(super) fn resolve(
        domain: &str,
        record_type: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec!["resolve", domain];
        if let Some(rt) = record_type {
            args.push(rt);
        }
        Self::run(&args)
    }

    /// Start the rama serve service with the given port and content path.
    pub(super) fn serve_fs(port: u16, path: Option<PathBuf>) -> Self {
        let secure = true;

        let mut builder = rama_command();

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

        let mut service = Self::spawn(&mut builder, ([127, 0, 0, 1], port).into());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    // Start the rama stunnel exit node with the default port and the forward address.
    // with self-signed certificates for testing
    pub(super) fn serve_stunnel_exit(bind: &str, forward: &str) -> Self {
        let mut builder = rama_command();

        builder
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

        let mut service = Self::spawn(&mut builder, bind.parse().unwrap());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }

    /// Start the rama stunnel entry node in insecure mode (skip verification).
    pub(super) fn serve_stunnel_entry_insecure(bind: &str, connect: &str) -> Self {
        let mut builder = rama_command();

        builder
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

        let mut service = Self::spawn(&mut builder, bind.parse().unwrap());
        service.wait_for_endpoint(TransportProtocol::Tcp);
        service
    }
}

fn enable_service_ready_log(builder: &mut Command, target: &str) {
    // The readiness barrier must also work with an inherited RUST_LOG=off.
    let filter = std::env::var("RUST_LOG").unwrap_or("info".into());
    builder.env("RUST_LOG", format!("{filter},{target}=info"));
}

fn wait_for_udp_echo(service: &mut RamaService) {
    let addr = service.address();
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP echo probe");
    socket
        .set_write_timeout(Some(Duration::from_millis(100)))
        .expect("set UDP echo probe write timeout");

    let expected = b"rama-echo-ready";
    let mut received = [0; 64];

    loop {
        service.check_running();

        let remaining = service
            .startup_deadline
            .saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "rama echo service at {addr} did not respond before timeout\n{}",
            service.diagnostics()
        );
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))
            .expect("set UDP echo probe read timeout");

        let echoed = if socket.send_to(expected, addr).is_ok()
            && let Ok((length, source)) = socket.recv_from(&mut received)
        {
            source == addr && received[..length] == *expected
        } else {
            false
        };

        service.check_running();
        if echoed {
            return;
        }

        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

impl Drop for RamaService {
    fn drop(&mut self) {
        let _killed = self.process.kill();
        let _reaped = self.process.wait();
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
        _ = subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::TRACE.into())
                    .from_env_lossy(),
            )
            .try_init();
    });
}
