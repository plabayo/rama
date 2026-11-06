#![allow(dead_code)]

#[cfg(feature = "http-full")]
pub(super) mod reset_response;

use parking_lot::Mutex;
#[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
use rama::net::{process::ProcessSocket, transport::TransportProtocol};
use rama::telemetry::tracing::{
    self,
    level_filters::LevelFilter,
    subscriber::{self, EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
};
use std::{
    ffi::OsString,
    io::BufRead,
    process::{Child, ChildStderr, ChildStdout, ExitStatus, Output},
    sync::{Arc, Once},
    time::Duration,
};

/// An example binary cargo built for this test run, with this run's features and profile.
#[derive(Debug, Clone, Copy)]
pub(super) struct Example {
    name: &'static str,
    path: &'static str,
}

impl Example {
    #[doc(hidden)]
    pub(super) const fn new(name: &'static str, path: &'static str) -> Self {
        Self { name, path }
    }

    pub(super) fn path(self) -> &'static std::path::Path {
        std::path::Path::new(self.path)
    }
}

/// The named example binary; a test gated looser than its `required-features` fails to compile.
#[allow(
    unused_macros,
    reason = "feature combinations without any example test"
)]
macro_rules! example {
    ($name:literal) => {
        $crate::utils::Example::new($name, env!(concat!("CARGO_BIN_EXE_", $name)))
    };
}
#[allow(
    unused_imports,
    reason = "feature combinations without any example test"
)]
pub(super) use example;

/// One of the child's output streams, so both are drained the same way.
enum StdioStream {
    Out(ChildStdout),
    Err(ChildStderr),
}

/// Read both of the child's streams into one shared list, so it never blocks on a full pipe
/// and its output survives for a failure message.
fn drain(child: &mut Child) -> Arc<Mutex<Vec<String>>> {
    /// Kept for a failure message, not for the whole run.
    const KEEP: usize = 500;
    let said = Arc::new(Mutex::new(Vec::new()));
    for stream in [
        child.stdout.take().map(StdioStream::Out),
        child.stderr.take().map(StdioStream::Err),
    ]
    .into_iter()
    .flatten()
    {
        let said = said.clone();
        std::thread::spawn(move || {
            let reader: Box<dyn BufRead> = match stream {
                StdioStream::Out(out) => Box::new(std::io::BufReader::new(out)),
                StdioStream::Err(err) => Box::new(std::io::BufReader::new(err)),
            };
            for line in reader.lines().map_while(Result::ok) {
                let mut said = said.lock();
                if said.len() == KEEP {
                    said.remove(0);
                }
                said.push(line);
            }
        });
    }
    said
}

#[cfg(feature = "http-full")]
use rama::{
    Layer, Service,
    error::BoxError,
    http::service::client::{HttpClientExt, IntoUrl, RequestBuilder},
    http::ws::handshake::client::{HttpClientWebSocketExt, WebSocketRequestBuilder, WithService},
    http::{
        Body, Request, Response, StreamingBody,
        client::EasyHttpWebClient,
        layer::{
            follow_redirect::FollowRedirectLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
    },
    layer::MapResultLayer,
    service::BoxService,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

#[cfg(all(feature = "http-full", feature = "compression"))]
use rama::http::layer::decompression::DecompressionLayer;

#[cfg(all(feature = "http-full", feature = "boring"))]
use rama::{
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    tls::{
        client::{ServerVerifyMode, TlsClientConfig},
        server::{ServerAuthData, TlsServerConfig},
    },
};

#[cfg(all(
    feature = "http-full",
    any(
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring")),
        feature = "boring"
    )
))]
use rama::rt::Executor;

#[cfg(all(feature = "http-full", feature = "rustls", not(feature = "boring")))]
use rama::tls::client::TlsClientConfig;

#[cfg(feature = "http-full")]
pub(super) type ClientService = BoxService<Request, Response, BoxError>;

/// Runner for examples.
pub(super) struct ExampleRunner {
    pub(super) server_process: Child,
    /// Lines the example printed, when it was started with its output captured. Drained by a
    /// reader of its own so the child never blocks on a full pipe.
    said: Option<Arc<Mutex<Vec<String>>>>,
    #[cfg(feature = "http-full")]
    pub(super) client: ClientService,
    #[cfg(not(feature = "http-full"))]
    _phantom: std::marker::PhantomData<()>,
}

impl ExampleRunner {
    /// Wait for this example to own its expected TCP listener, retaining its fixed demo port.
    #[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
    pub(super) async fn wait_for_tcp(&mut self, address: impl Into<std::net::SocketAddr>) {
        self.wait_for_tcp_within(address, Duration::from_secs(10))
            .await;
    }

    /// Allow expensive initialization before binding, without delaying ready examples.
    #[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
    pub(super) async fn wait_for_tcp_within(
        &mut self,
        address: impl Into<std::net::SocketAddr>,
        limit: Duration,
    ) {
        let expected = ProcessSocket {
            protocol: TransportProtocol::Tcp,
            local_addr: address.into(),
        };

        if let Err(error) = wait_for_socket_matching_within(
            &mut self.server_process,
            |socket| socket == expected,
            limit,
        )
        .await
        {
            panic!("{error}{}", self.said());
        }
    }

    /// Discover the only TCP listener owned by this child, including when it binds port zero.
    #[cfg(any(feature = "http-full", feature = "tcp"))]
    pub(super) async fn tcp_listener_addr(&mut self) -> std::net::SocketAddr {
        wait_for_socket_matching(&mut self.server_process, |socket| {
            socket.protocol == TransportProtocol::Tcp
        })
        .await
        .unwrap_or_else(|error| panic!("{error}{}", self.said()))
        .local_addr
    }

    /// Run an example with its output captured, for a test that needs to read something the
    /// example reports, such as the address it bound.
    pub(super) fn capturing(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Self {
        Self::start(example, args, std::iter::empty::<(&str, &str)>(), true)
    }

    /// Wait for a captured line containing `needle`, or fail with what the example said and
    /// whether it is still running.
    pub(super) async fn wait_for_line(&mut self, needle: &str, limit: Duration) -> String {
        let said = self
            .said
            .clone()
            .expect("this example was started with its output captured");
        let deadline = std::time::Instant::now() + limit;
        loop {
            if let Some(line) = said.lock().iter().find(|line| line.contains(needle)) {
                return line.clone();
            }
            // A dead example is reported now, with its status and output, rather than waited on.
            if let Some(status) = self
                .server_process
                .try_wait()
                .expect("its status is readable")
            {
                panic!(
                    "the example exited with {status} before saying {needle:?}{}",
                    self.said()
                );
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the example did not say {needle:?} within {limit:?}{}",
                self.said()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Everything the example has said so far, for a failure message.
    pub(super) fn said(&self) -> String {
        match &self.said {
            Some(said) => format!("\nwhat the example said:\n{}", said.lock().join("\n")),
            None => String::new(),
        }
    }

    /// Ask the example to stop the way a person would, and wait for it within `limit`.
    ///
    /// `SIGINT` on unix; on Windows `CTRL_BREAK_EVENT`, sent to the example's own process
    /// group, which `default_signal` honours. `Drop` kills and reaps the example either way.
    pub(super) async fn interrupt_within(&mut self, limit: Duration) -> ExitStatus {
        let deadline = std::time::Instant::now() + limit;
        self.ask_to_stop();
        loop {
            if let Some(status) = self
                .server_process
                .try_wait()
                .expect("its status is readable")
            {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the example did not stop within {limit:?} of being asked"
            );
            // Shares a runtime with the test's own peers; blocking it would stop them making
            // the progress the example is waiting for.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(unix)]
    fn ask_to_stop(&self) {
        let pid = self.server_process.id();
        let pid_t = libc::pid_t::try_from(pid).expect("a positive pid");
        #[expect(
            unsafe_code,
            reason = "signalling an owned child needs the raw call; this dependency set has no safe wrapper"
        )]
        // SAFETY: `kill(2)` takes no pointers. `pid_t` is positive, so it names one
        // process, and the child is not reaped yet (no `try_wait` has returned a
        // status), so the pid still names this child.
        let sent = unsafe { libc::kill(pid_t, libc::SIGINT) };
        assert_eq!(sent, 0, "SIGINT reached the example (pid {pid})");
    }

    #[cfg(windows)]
    #[expect(
        unsafe_code,
        reason = "raising a console control event for a child process group requires Windows FFI"
    )]
    fn ask_to_stop(&self) {
        // The signature matches its kernel32 prototype (`wincon.h`): `BOOL` is `i32` and
        // `DWORD` is `u32`.
        unsafe extern "system" {
            fn GenerateConsoleCtrlEvent(event: u32, process_group_id: u32) -> i32;
        }
        const CTRL_BREAK_EVENT: u32 = 1;
        let pid = self.server_process.id();
        // SAFETY: both arguments are plain integers and no pointer crosses the call. Spawned
        // with `CREATE_NEW_PROCESS_GROUP`, the example's pid is the id of the process group it
        // roots: the event reaches the members of that group attached to this console, the
        // example and any descendant that stayed in its group. The example is not reaped yet
        // (no `try_wait` has returned a status), so the id still names that group.
        let raised = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
        assert_ne!(
            raised,
            0,
            "ctrl-break reached the example (pid {pid}): {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Inspect an owned child without connecting to its listener or reading its log output.
#[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
pub(super) async fn wait_for_socket(
    child: &mut Child,
    expected: ProcessSocket,
) -> Result<(), String> {
    wait_for_socket_matching(child, |socket| socket == expected)
        .await
        .map(drop)
}

/// Discover the one socket of `protocol` an owned child has bound, including on port zero.
#[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
pub(super) async fn wait_for_protocol_socket(
    child: &mut Child,
    protocol: TransportProtocol,
) -> Result<std::net::SocketAddr, String> {
    wait_for_socket_matching(child, |socket| socket.protocol == protocol)
        .await
        .map(|socket| socket.local_addr)
}

#[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
async fn wait_for_socket_matching(
    child: &mut Child,
    matches: impl Fn(ProcessSocket) -> bool,
) -> Result<ProcessSocket, String> {
    wait_for_socket_matching_within(child, matches, Duration::from_secs(10)).await
}

#[cfg(any(feature = "http-full", feature = "tcp", feature = "udp"))]
async fn wait_for_socket_matching_within(
    child: &mut Child,
    matches: impl Fn(ProcessSocket) -> bool,
    limit: Duration,
) -> Result<ProcessSocket, String> {
    let pid = child.id();
    let deadline = tokio::time::Instant::now() + limit;
    let mut last_sockets = Vec::new();
    let mut delay = Duration::from_millis(25);

    loop {
        check_child_running(child)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "child {pid} did not bind a matching socket within {limit:?}; last owned sockets: {last_sockets:?}"
            ));
        }
        let sockets = tokio::time::timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || rama::net::process::listening_sockets(pid)),
        )
        .await
        .map_err(|_elapsed| format!("child {pid} readiness deadline ({limit:?}) elapsed during socket inspection; last owned sockets: {last_sockets:?}"))?
        .map_err(|error| format!("child {pid} inspection task failed: {error}"))?
        .map_err(|error| format!("cannot inspect child {pid}: {error}"))?;
        check_child_running(child)?;

        let mut found = sockets.iter().copied().filter(|socket| matches(*socket));
        if let Some(socket) = found.next() {
            if found.next().is_some() {
                return Err(format!(
                    "child {pid} has multiple matching sockets: {sockets:?}"
                ));
            }
            return Ok(socket);
        }

        last_sockets = sockets;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(delay.min(remaining)).await;
        delay = (delay * 2).min(Duration::from_millis(200));
    }
}

fn check_child_running(child: &mut Child) -> Result<(), String> {
    match child.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(status)) => Err(format!(
            "child {} exited with {status} before binding",
            child.id()
        )),
        Err(error) => Err(format!(
            "cannot inspect child {} status: {error}",
            child.id()
        )),
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

/// Workspace root (`rama-examples` lives one level below it). Examples are spawned with
/// this as their working directory so runtime-relative paths (e.g. `test-files/…`)
/// resolve exactly as they did when the examples lived in the root `rama` crate.
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rama-examples crate has a parent workspace directory")
        .to_path_buf()
}

impl ExampleRunner {
    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive(example: Example) -> Self {
        Self::interactive_with_args_and_envs(
            example,
            std::iter::empty::<&str>(),
            std::iter::empty::<(&str, &str)>(),
        )
    }

    /// Run an example server with command-line arguments and create a client.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive_with_args(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Self {
        Self::interactive_with_args_and_envs(example, args, std::iter::empty::<(&str, &str)>())
    }

    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive_with_envs(
        example: Example,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self::interactive_with_args_and_envs(example, std::iter::empty::<&str>(), envs)
    }

    /// The example, to run from the workspace root; a test that drives its client side runs it
    /// with this directly.
    pub(super) fn command(example: Example) -> std::process::Command {
        let mut command = std::process::Command::new(example.path);
        // An inherited stdin can block an example that reads it; only nextest closes it.
        command.stdin(std::process::Stdio::null());
        command.current_dir(workspace_root());
        command
    }

    fn interactive_with_args_and_envs(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self::start(example, args, envs, false)
    }

    /// The one place an example process is started. With `capture`, its output is read by a
    /// reader of its own so the child never blocks on a full pipe, and on Windows it is given a
    /// console of its own so [`Self::interrupt_within`] can raise Ctrl-C for it alone.
    fn start(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
        capture: bool,
    ) -> Self {
        let mut command = Self::command(example);
        command
            .env(
                "RUST_LOG",
                // A captured example's output is read line by line, so its own target is kept at
                // INFO whatever this process inherited: a test waiting for a line the example
                // reports must not depend on the filter the suite happens to run under.
                match (std::env::var("RUST_LOG"), capture) {
                    (Ok(inherited), true) => {
                        format!("{inherited},{}=info", example.name)
                    }
                    (Ok(inherited), false) => inherited,
                    (Err(_), true) => "info".to_owned(),
                    (Err(_), false) => "trace".to_owned(),
                },
            )
            .env("SSLKEYLOGFILE", "./target/test_ssl_key_log.txt")
            .envs(envs)
            .args(args);
        if capture {
            command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt as _;
                // Its own group, so ctrl-break can be sent to the example alone.
                const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
                command.creation_flags(CREATE_NEW_PROCESS_GROUP);
            }
        }
        let mut child = command.spawn().unwrap();
        let said = capture.then(|| drain(&mut child));

        #[cfg(not(feature = "http-full"))]
        {
            Self {
                server_process: child,
                said,
                _phantom: std::marker::PhantomData,
            }
        }

        #[cfg(feature = "http-full")]
        {
            #[cfg(all(not(feature = "rustls"), not(feature = "boring")))]
            let inner_client = EasyHttpWebClient::default();

            #[cfg(feature = "boring")]
            let inner_client = {
                let tls_config = TlsClientConfig::default_http()
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_store_server_cert_chain(true);
                let proxy_tls_config =
                    TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);

                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_boringssl_config(proxy_tls_config)
                    .with_proxy_support()
                    .with_tls_support_using_boringssl(tls_config)
                    .with_default_http_connector(Executor::default())
                    .without_connection_pool()
                    .build_client()
            };

            #[cfg(all(
                feature = "rustls",
                any(feature = "aws-lc", feature = "ring"),
                not(feature = "boring")
            ))]
            let inner_client = {
                let tls_config = TlsClientConfig::default_http()
                    .with_server_verify(rama::tls::client::ServerVerifyMode::Disable)
                    .with_store_server_cert_chain(true);

                let proxy_tls_config = TlsClientConfig::new()
                    .with_server_verify(rama::tls::client::ServerVerifyMode::Disable)
                    .with_keylog(rama::tls::KeyLogIntent::Environment);

                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_rustls_config(proxy_tls_config)
                    .with_proxy_support()
                    .with_tls_support_using_rustls(tls_config)
                    .with_default_http_connector(Executor::default())
                    .without_connection_pool()
                    .build_client()
            };

            let client = (
                MapResultLayer::new(map_internal_client_error),
                TraceLayer::new_for_http(),
                #[cfg(feature = "compression")]
                DecompressionLayer::new(),
                FollowRedirectLayer::default(),
                RetryLayer::new(
                    ManagedPolicy::default().with_backoff(
                        ExponentialBackoff::new(
                            Duration::from_millis(100),
                            Duration::from_secs(60),
                            0.01,
                            HasherRng::default,
                        )
                        .unwrap(),
                    ),
                ),
                AddRequiredRequestHeadersLayer::default(),
            )
                .into_layer(inner_client)
                .boxed();

            Self {
                server_process: child,
                said,
                client,
            }
        }
    }

    #[cfg(feature = "http-full")]
    pub(super) fn set_client(&mut self, client: ClientService) {
        self.client = client;
    }

    #[cfg(feature = "http-full")]
    /// Create a `GET` http request to be sent to the child server.
    pub(super) fn get(&self, url: impl IntoUrl) -> RequestBuilder<'_, ClientService, Response> {
        self.client.get(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `HEAD` http request to be sent to the child server.
    pub(super) fn head(&self, url: impl IntoUrl) -> RequestBuilder<'_, ClientService, Response> {
        self.client.head(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `POST` http request to be sent to the child server.
    pub(super) fn post(&self, url: impl IntoUrl) -> RequestBuilder<'_, ClientService, Response> {
        self.client.post(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `DELETE` http request to be sent to the child server.
    pub(super) fn delete(&self, url: impl IntoUrl) -> RequestBuilder<'_, ClientService, Response> {
        self.client.delete(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `QUERY` http request to be sent to the child server.
    pub(super) fn query(&self, url: impl IntoUrl) -> RequestBuilder<'_, ClientService, Response> {
        self.client.query(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a websocket builder.
    pub(super) fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, ClientService, Body>> {
        self.client.websocket(url)
    }

    #[cfg(feature = "http-full")]
    /// Create an h2 websocket builder.
    pub(super) fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebSocketRequestBuilder<WithService<'_, ClientService, Body>> {
        self.client.websocket_h2(url)
    }
}

impl ExampleRunner {
    /// Run an example and wait until it finished.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be ran,
    /// or if it failed while waiting for it to finish.
    pub(super) async fn run(example: Example) -> ExitStatus {
        tokio::task::spawn_blocking(move || {
            Self::command(example)
                .env(
                    "RUST_LOG",
                    std::env::var("RUST_LOG").unwrap_or("info".into()),
                )
                .status()
                .unwrap()
        })
        .await
        .unwrap()
    }

    /// Run an example with arguments and capture its output.
    ///
    /// # Panics
    ///
    /// This function panics if the example process cannot be spawned
    /// or if it fails while waiting for it to finish.
    pub(super) async fn run_with_args_output(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Output {
        Self::run_with_args_and_envs_output(example, args, std::iter::empty()).await
    }

    /// Run an example with arguments and environment variables and capture its output.
    ///
    /// # Panics
    ///
    /// This function panics if the example process cannot be spawned
    /// or if it fails while waiting for it to finish.
    pub(super) async fn run_with_args_and_envs_output(
        example: Example,
        args: impl IntoIterator<Item = impl AsRef<str>>,
        envs: impl IntoIterator<Item = (String, OsString)>,
    ) -> Output {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_owned())
            .collect::<Vec<_>>();
        let envs = envs.into_iter().collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            let mut command = Self::command(example);
            command.env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("info".into()),
            );
            command.args(args).envs(envs);
            command.output().unwrap()
        })
        .await
        .unwrap()
    }
}

/// TLS server configuration and certificate trusted by a child client.
#[cfg(all(feature = "http-full", feature = "boring"))]
pub(super) struct TestTlsConfig {
    pub(super) server: TlsServerConfig,
    certificate_file: std::path::PathBuf,
}

#[cfg(all(feature = "http-full", feature = "boring"))]
impl TestTlsConfig {
    pub(super) fn new() -> Self {
        let cert_chain =
            CertificateDer::pem_slice_iter(include_bytes!("../../../assets/example.com.crt"))
                .collect::<Result<Vec<_>, _>>()
                .expect("parse test certificate");
        let private_key =
            PrivateKeyDer::from_pem_slice(include_bytes!("../../../assets/example.com.key"))
                .expect("parse test private key");

        Self {
            server: TlsServerConfig::new()
                .with_single_cert(ServerAuthData::new(cert_chain, private_key))
                .with_alpn_http_1(),
            certificate_file: workspace_root().join("examples/assets/example.com.crt"),
        }
    }

    pub(super) fn certificate_file_path(&self) -> &std::path::Path {
        &self.certificate_file
    }
}

impl std::ops::Drop for ExampleRunner {
    fn drop(&mut self) {
        tracing::info!("kill server process");
        // Already-exited is not a failure here, and the wait is what reaps it: killing without
        // waiting leaves a zombie behind for the rest of the run.
        if let Err(error) = self.server_process.kill() {
            tracing::info!("the example had already exited: {error}");
        }
        match self.server_process.wait() {
            Ok(status) => tracing::info!("the example was reaped with {status}"),
            Err(error) => tracing::warn!("the example could not be reaped: {error}"),
        }
    }
}

#[cfg(feature = "http-full")]
fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
    Body: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
