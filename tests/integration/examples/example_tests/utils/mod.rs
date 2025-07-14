#![allow(dead_code)]

use rama::telemetry::tracing::level_filters::LevelFilter;
use std::{
    process::{Child, ExitStatus},
    sync::Once,
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "http-full")]
use ::std::time::Duration;

#[cfg(feature = "http-full")]
use rama::{
    Layer, Service,
    error::BoxError,
    http::Body,
    http::client::proxy::layer::SetProxyAuthHttpHeaderLayer,
    http::service::client::{HttpClientExt, IntoUrl, RequestBuilder},
    http::ws::handshake::client::{HttpClientWebSocketExt, WebsocketRequestBuilder, WithService},
    http::{
        Request, Response,
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
use rama::{net::tls::client::ServerVerifyMode, tls::boring::client as boring_client};

#[cfg(all(feature = "http-full", feature = "rustls", not(feature = "boring")))]
use rama::tls::rustls::client as rustls_client;

#[cfg(feature = "http-full")]
pub(super) type ClientService<State> = BoxService<State, Request, Response, BoxError>;

/// Runner for examples.
pub(super) struct ExampleRunner<State = ()> {
    pub(super) server_process: Child,
    #[cfg(feature = "http-full")]
    pub(super) client: ClientService<State>,
    #[cfg(not(feature = "http-full"))]
    _phantom: std::marker::PhantomData<State>,
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
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or("trace".into()),
            )
            .env("SSLKEYLOGFILE", "./target/test_ssl_key_log.txt")
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
                let tls_config = boring_client::TlsConnectorDataBuilder::new_http_auto()
                    .with_server_verify_mode(ServerVerifyMode::Disable)
                    .with_store_server_certificate_chain(true)
                    .into_shared_builder();
                let proxy_tls_config = boring_client::TlsConnectorDataBuilder::new()
                    .with_server_verify_mode(ServerVerifyMode::Disable)
                    .into_shared_builder();

                EasyHttpWebClient::builder()
                    .with_default_transport_connector()
                    .with_tls_proxy_support_using_boringssl_config(proxy_tls_config)
                    .with_proxy_support()
                    .with_tls_support_using_boringssl(Some(tls_config))
                    .build()
            };

            #[cfg(all(feature = "rustls", not(feature = "boring")))]
            let inner_client = {
                let tls_config = rustls_client::TlsConnectorDataBuilder::new()
                    .with_no_cert_verifier()
                    .with_alpn_protocols_http_auto()
                    .with_env_key_logger()
                    .expect("connector with env keylogger")
                    .with_store_server_certificate_chain(true)
                    .build();

                let proxy_tls_config = rustls_client::TlsConnectorDataBuilder::new()
                    .with_no_cert_verifier()
                    .with_env_key_logger()
                    .expect("connector with env keylogger")
                    .build();

                EasyHttpWebClient::builder()
                    .with_default_transport_connector()
                    .with_tls_proxy_support_using_rustls_config(proxy_tls_config)
                    .with_proxy_support()
                    .with_tls_support_using_rustls(Some(tls_config))
                    .build()
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
                SetProxyAuthHttpHeaderLayer::default(),
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
    pub(super) fn set_client(&mut self, client: ClientService<State>) {
        self.client = client;
    }

    #[cfg(feature = "http-full")]
    /// Create a `GET` http request to be sent to the child server.
    pub(super) fn get(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.get(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `HEAD` http request to be sent to the child server.
    pub(super) fn head(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.head(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `POST` http request to be sent to the child server.
    pub(super) fn post(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.post(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a `DELETE` http request to be sent to the child server.
    pub(super) fn delete(
        &self,
        url: impl IntoUrl,
    ) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.delete(url)
    }

    #[cfg(feature = "http-full")]
    /// Create a websocket builder.
    pub(super) fn websocket(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<ClientService<State>, Body, State>> {
        self.client.websocket(url)
    }

    #[cfg(feature = "http-full")]
    /// Create an h2 websocket builder.
    pub(super) fn websocket_h2(
        &self,
        url: impl IntoUrl,
    ) -> WebsocketRequestBuilder<WithService<ClientService<State>, Body, State>> {
        self.client.websocket_h2(url)
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
}

impl<State> std::ops::Drop for ExampleRunner<State> {
    fn drop(&mut self) {
        self.server_process.kill().expect("kill server process");
    }
}

#[cfg(feature = "http-full")]
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
