#![allow(dead_code)]

use rama::telemetry::tracing::{
    self,
    level_filters::LevelFilter,
    subscriber::{self, EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
};
use std::{
    ffi::OsString,
    process::{Child, ExitStatus, Output},
    sync::Once,
};

#[cfg(feature = "http-full")]
use ::std::time::Duration;

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
    #[cfg(feature = "http-full")]
    pub(super) client: ClientService,
    #[cfg(not(feature = "http-full"))]
    _phantom: std::marker::PhantomData<()>,
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
        let child = command
            .current_dir(workspace_root())
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("trace".into()),
            )
            .env("SSLKEYLOGFILE", "./target/test_ssl_key_log.txt")
            .envs(envs)
            .args(args)
            .spawn()
            .unwrap();

        #[cfg(not(feature = "http-full"))]
        {
            Self {
                server_process: child,
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
        self.server_process.kill().expect("kill server process");
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
