#![allow(dead_code)]

use rama::{
    error::BoxError,
    http::client::proxy::layer::SetProxyAuthHttpHeaderLayer,
    http::service::client::{HttpClientExt, IntoUrl, RequestBuilder},
    http::{
        client::HttpClient,
        layer::{
            follow_redirect::FollowRedirectLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        Request, Response,
    },
    layer::MapResultLayer,
    service::BoxService,
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
    Layer, Service,
};
use std::{
    process::{Child, ExitStatus},
    sync::Once,
    time::Duration,
};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[cfg(feature = "compression")]
use rama::http::layer::decompression::DecompressionLayer;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama::net::tls::{
    client::{ClientConfig, ClientHelloExtension, ServerVerifyMode},
    ApplicationProtocol,
};

pub(super) type ClientService<State> = BoxService<State, Request, Response, BoxError>;

/// Runner for examples.
pub(super) struct ExampleRunner<State = ()> {
    server_process: Child,
    client: ClientService<State>,
}

/// to ensure we only ever register tracing once,
/// in the first test that gets run.
///
/// Dirty but it works, good enough for tests.
static INIT_TRACING_ONCE: Once = Once::new();

/// Initialize tracing for example tests
pub(super) fn init_tracing() {
    INIT_TRACING_ONCE.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::TRACE.into())
                    .from_env_lossy(),
            )
            .init();
    });
}

impl<State> ExampleRunner<State>
where
    State: Clone + Send + Sync + 'static,
{
    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub(super) fn interactive(
        example_name: impl AsRef<str>,
        extra_features: Option<&'static str>,
    ) -> Self {
        let child = escargot::CargoBuild::new()
            .arg(format!(
                "--features=cli,compression,tcp,http-full,proxy-full,{}",
                extra_features.unwrap_or_default()
            ))
            .example(example_name.as_ref())
            .manifest_path("Cargo.toml")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .env("SSLKEYLOGFILE", "./target/test_ssl_key_log.txt")
            .spawn()
            .unwrap();

        let mut inner_client = HttpClient::default();

        #[cfg(any(feature = "rustls", feature = "boring"))]
        {
            inner_client.set_tls_config(ClientConfig {
                server_verify_mode: Some(ServerVerifyMode::Disable),
                extensions: Some(vec![
                    ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![
                        ApplicationProtocol::HTTP_2,
                        ApplicationProtocol::HTTP_11,
                    ]),
                ]),
                ..Default::default()
            });

            inner_client.set_proxy_tls_config(ClientConfig {
                server_verify_mode: Some(ServerVerifyMode::Disable),
                ..Default::default()
            });
        }

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
            SetProxyAuthHttpHeaderLayer::default(),
        )
            .layer(inner_client)
            .boxed();

        Self {
            server_process: child,
            client,
        }
    }

    pub(super) fn set_client(&mut self, client: ClientService<State>) {
        self.client = client;
    }

    /// Create a `GET` http request to be sent to the child server.
    pub(super) fn get(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.get(url)
    }

    /// Create a `HEAD` http request to be sent to the child server.
    pub(super) fn head(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.head(url)
    }

    /// Create a `POST` http request to be sent to the child server.
    pub(super) fn post(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.post(url)
    }

    /// Create a `DELETE` http request to be sent to the child server.
    pub(super) fn delete(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.delete(url)
    }
}

impl ExampleRunner<()> {
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
                .example(example_name)
                .manifest_path("Cargo.toml")
                .target_dir("./target/")
                .run()
                .unwrap()
                .command()
                .status()
                .unwrap()
        })
        .await
        .unwrap()
    }
}

impl<State> std::ops::Drop for ExampleRunner<State> {
    fn drop(&mut self) {
        self.server_process.kill().expect("kill server process");
    }
}

fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, rama::error::BoxError>
where
    E: Into<rama::error::BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
