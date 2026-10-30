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
    /// Ctrl-C on both platforms: `SIGINT` on unix, and on Windows a `CTRL_C_EVENT` raised by a
    /// helper inside the console the child was given. The helper is a child of this process
    /// too, so it is awaited inside the same deadline and reaped rather than left running.
    /// `Drop` kills and reaps the example either way.
    pub(super) async fn interrupt_within(&mut self, limit: Duration) -> ExitStatus {
        let deadline = std::time::Instant::now() + limit;
        let mut asking = Asking(self.ask_to_stop());
        loop {
            let raised = asking.raised();
            if let Some(status) = self
                .server_process
                .try_wait()
                .expect("its status is readable")
                && raised
            {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the example did not stop within {limit:?} of being asked (ctrl-c raised: {raised})"
            );
            // Shares a runtime with the test's own peers; blocking it would stop them making
            // the progress the example is waiting for.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(unix)]
    fn ask_to_stop(&self) -> Option<Child> {
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
        None
    }

    /// Raising the event has to happen in a process of its own: it needs `AttachConsole` to
    /// the child's console, which this runner must not do to itself. That process is this same
    /// test binary, re-run with one ignored test selected and the pid in the environment, so
    /// there is no extra binary to build or ship.
    ///
    /// Once `tokio-graceful` honours `CTRL_BREAK`, this collapses to one targeted
    /// `GenerateConsoleCtrlEvent` and no helper at all.
    #[cfg(windows)]
    fn ask_to_stop(&self) -> Option<Child> {
        let pid = self.server_process.id();
        Some(
            std::process::Command::new(
                std::env::current_exe().expect("this test binary's own path"),
            )
            .args(["--ignored", "--exact", CTRL_C_HELPER])
            .stdin(std::process::Stdio::null())
            .env(CTRL_C_PID, pid.to_string())
            .spawn()
            .expect("the ctrl-c helper starts"),
        )
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

/// A child inherits whether ctrl-c is ignored: a runner started from a shell that ignores
/// it would otherwise spawn examples the raised event can never stop.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "restoring default ctrl-c processing requires Windows FFI"
)]
fn process_ctrl_c_in_children() {
    // Declaration matches the kernel32 prototype
    // `BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE, BOOL)` (`consoleapi.h`).
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    static RESTORED: Once = Once::new();
    RESTORED.call_once(|| {
        // SAFETY: a null handler with add=0 requests the documented default ctrl-c processing.
        // Best effort: without a console of its own there is nothing to restore.
        _ = unsafe { SetConsoleCtrlHandler(None, 0) };
    });
}

/// Owns the ctrl-c helper while the interrupt is in flight. It is a child of this process, so
/// every way out of the wait — its own exit, a panic, or the waiting test being dropped — has
/// to end it.
struct Asking(Option<Child>);

impl Asking {
    /// Whether the event has been raised: true at once where no helper is needed, and once the
    /// helper has exited otherwise. Its status is checked here, so a helper that could not raise
    /// the event fails the test rather than passing as a silent absence of ctrl-c.
    fn raised(&mut self) -> bool {
        let Some(helper) = self.0.as_mut() else {
            return true;
        };
        let Some(status) = helper.try_wait().expect("the helper's status is readable") else {
            return false;
        };
        self.0 = None;
        assert!(
            status.success(),
            "ctrl-c was raised in the example's console: {status}"
        );
        true
    }
}

impl Drop for Asking {
    fn drop(&mut self) {
        if let Some(mut helper) = self.0.take() {
            // Both run: a kill that fails because it has already exited still leaves it to reap.
            let killed = helper.kill();
            let reaped = helper.wait();
            if let (Err(killing), Err(reaping)) = (&killed, &reaped) {
                tracing::warn!("the ctrl-c helper outlived its test: {killing}, {reaping}");
            }
        }
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
                const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
                command.creation_flags(CREATE_NEW_CONSOLE);
                process_ctrl_c_in_children();
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

/// The ignored test that acts as the Ctrl-C helper, and the variable carrying the pid to it.
#[cfg(windows)]
const CTRL_C_HELPER: &str = "utils::raise_ctrl_c_for_a_child";
#[cfg(windows)]
const CTRL_C_PID: &str = "RAMA_E2E_CTRL_C_PID";

/// Not a test. `ExampleRunner::interrupt_within` re-runs this binary with this one selected to
/// get a process of its own, which is what `AttachConsole` needs. Without the pid in the
/// environment it does nothing, so an ordinary ignored-test run passes straight over it.
#[cfg(windows)]
#[test]
#[ignore = "the ctrl-c helper `ExampleRunner::interrupt_within` starts"]
#[expect(
    unsafe_code,
    reason = "joining another process console and raising an event requires Windows FFI"
)]
fn raise_ctrl_c_for_a_child() {
    let Ok(pid) = std::env::var(CTRL_C_PID) else {
        return;
    };
    let pid: u32 = pid.parse().expect("a process id");

    // Each signature matches its kernel32 prototype (`consoleapi.h`,
    // `wincon.h`, `errhandlingapi.h`): `BOOL` is `i32`, `DWORD` is `u32`, and
    // `PHANDLER_ROUTINE` is a nullable `BOOL WINAPI (*)(DWORD)`.
    unsafe extern "system" {
        fn FreeConsole() -> i32;
        fn AttachConsole(process_id: u32) -> i32;
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, process_group_id: u32) -> i32;
        fn GetLastError() -> u32;
    }
    const CTRL_C_EVENT: u32 = 0;
    /// Everything attached to the console this process has joined.
    const WHOLE_GROUP: u32 = 0;

    // SAFETY: Detaching this helper requires no pointers or additional preconditions.
    unsafe { FreeConsole() };
    // SAFETY: Windows validates the process ID; this helper has detached its console.
    let attached = unsafe { AttachConsole(pid) };
    assert_ne!(attached, 0, "attached to the console of {pid}: {}", {
        // SAFETY: Reading this thread's last error requires no preconditions.
        unsafe { GetLastError() }
    });
    // The event reaches this process too; ignoring it keeps it alive to report.
    // SAFETY: A null handler with add=1 requests the documented ignore-Ctrl-C behavior.
    let ignored = unsafe { SetConsoleCtrlHandler(None, 1) };
    assert_ne!(ignored, 0, "ignored ctrl-c here: {}", {
        // SAFETY: Reading this thread's last error requires no preconditions.
        unsafe { GetLastError() }
    });
    // SAFETY: Both values are documented constants targeting our attached console.
    let raised = unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, WHOLE_GROUP) };
    assert_ne!(raised, 0, "raised ctrl-c for {pid}: {}", {
        // SAFETY: Reading this thread's last error requires no preconditions.
        unsafe { GetLastError() }
    });
}
