#![allow(dead_code)]

use parking_lot::Mutex;
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
    any(all(feature = "rustls", feature = "aws-lc"), feature = "boring")
))]
use rama::rt::Executor;

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
    /// Run an example with its output captured, for a test that needs to read something the
    /// example reports, such as the address it bound.
    pub(super) fn capturing(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Self {
        Self::start(
            example_name,
            extra_features,
            args,
            std::iter::empty::<(&str, &str)>(),
            true,
        )
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
        #[expect(
            unsafe_code,
            reason = "signalling an owned child needs the raw call; this dependency set has no safe wrapper"
        )]
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) };
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
            .env(CTRL_C_PID, pid.to_string())
            .spawn()
            .expect("the ctrl-c helper starts"),
        )
    }
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

/// Absolute path to the `rama-examples` crate manifest, so escargot builds the right
/// package no matter what working directory the test binary is launched from.
fn examples_manifest_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
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

/// Shared build target directory at the workspace root.
fn examples_target_dir() -> std::path::PathBuf {
    workspace_root().join("target")
}

impl ExampleRunner {
    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
    ) -> Self {
        Self::interactive_with_args_and_envs(
            example_name,
            extra_features,
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
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
    ) -> Self {
        Self::interactive_with_args_and_envs(
            example_name,
            extra_features,
            args,
            std::iter::empty::<(&str, &str)>(),
        )
    }

    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive_with_envs(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self::interactive_with_args_and_envs(
            example_name,
            extra_features,
            std::iter::empty::<&str>(),
            envs,
        )
    }

    fn interactive_with_args_and_envs(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self::start(example_name, extra_features, args, envs, false)
    }

    /// The one place an example process is started. With `capture`, its output is read by a
    /// reader of its own so the child never blocks on a full pipe, and on Windows it is given a
    /// console of its own so [`Self::interrupt_within`] can raise Ctrl-C for it alone.
    fn start(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
        args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
        envs: impl IntoIterator<Item = (&'static str, &'static str)>,
        capture: bool,
    ) -> Self {
        let mut command = escargot::CargoBuild::new()
            .arg(format!(
                "--features=cli,tcp,http-full,proxy-full,{}",
                extra_features.unwrap_or_default()
            ))
            .bin(example_name.as_ref())
            .manifest_path(examples_manifest_path())
            .target_dir(examples_target_dir())
            .run()
            .unwrap()
            .command();
        command
            .current_dir(workspace_root())
            .env(
                "RUST_LOG",
                // A captured example's output is read line by line, so its own target is kept at
                // INFO whatever this process inherited: a test waiting for a line the example
                // reports must not depend on the filter the suite happens to run under.
                match (std::env::var("RUST_LOG"), capture) {
                    (Ok(inherited), true) => {
                        format!("{inherited},{}=info", example_name.as_ref())
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

            #[cfg(all(feature = "rustls", feature = "aws-lc", not(feature = "boring")))]
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
    pub(super) async fn run(example_name: impl AsRef<str>) -> ExitStatus {
        let example_name = example_name.as_ref().to_owned();
        tokio::task::spawn_blocking(|| {
            escargot::CargoBuild::new()
                .arg("--all-features")
                .bin(example_name)
                .manifest_path(examples_manifest_path())
                .target_dir(examples_target_dir())
                .run()
                .unwrap()
                .command()
                .current_dir(workspace_root())
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
        example_name: impl AsRef<str>,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Output {
        Self::run_with_args_and_envs_output(example_name, args, std::iter::empty()).await
    }

    /// Run an example with arguments and environment variables and capture its output.
    ///
    /// # Panics
    ///
    /// This function panics if the example process cannot be spawned
    /// or if it fails while waiting for it to finish.
    pub(super) async fn run_with_args_and_envs_output(
        example_name: impl AsRef<str>,
        args: impl IntoIterator<Item = impl AsRef<str>>,
        envs: impl IntoIterator<Item = (String, OsString)>,
    ) -> Output {
        let example_name = example_name.as_ref().to_owned();
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_owned())
            .collect::<Vec<_>>();
        let envs = envs.into_iter().collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            let mut command = escargot::CargoBuild::new()
                .arg("--all-features")
                .bin(example_name)
                .manifest_path(examples_manifest_path())
                .target_dir(examples_target_dir())
                .run()
                .unwrap()
                .command();
            command.current_dir(workspace_root());
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
#[ignore]
fn raise_ctrl_c_for_a_child() {
    let Ok(pid) = std::env::var(CTRL_C_PID) else {
        return;
    };
    let pid: u32 = pid.parse().expect("a process id");

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

    #[expect(
        unsafe_code,
        reason = "joining another process's console and raising an event there is only reachable through these calls"
    )]
    unsafe {
        FreeConsole();
        assert_ne!(
            AttachConsole(pid),
            0,
            "attached to the console of {pid}: {}",
            GetLastError()
        );
        // The event reaches this process too; ignoring it keeps it alive to report.
        assert_ne!(
            SetConsoleCtrlHandler(None, 1),
            0,
            "ignored ctrl-c here: {}",
            GetLastError()
        );
        assert_ne!(
            GenerateConsoleCtrlEvent(CTRL_C_EVENT, WHOLE_GROUP),
            0,
            "raised ctrl-c for {pid}: {}",
            GetLastError()
        );
    }
}
