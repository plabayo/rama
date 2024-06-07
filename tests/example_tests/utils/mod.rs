#![allow(dead_code)]

use rama::{
    error::{BoxError, OpaqueError},
    http::{
        client::{HttpClient, HttpClientExt, IntoUrl, RequestBuilder},
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::FollowRedirectLayer,
            required_header::AddRequiredRequestHeadersLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        Request, Response,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    service::{
        util::{backoff::ExponentialBackoff, rng::HasherRng},
        BoxService, Service, ServiceBuilder,
    },
    stream::Stream,
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
};
use std::{
    process::{Child, ExitStatus},
    sync::Once,
    time::Duration,
};
use tokio::net::ToSocketAddrs;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub type ClientService<State> = BoxService<State, Request, Response, BoxError>;

/// Runner for examples.
pub struct ExampleRunner<State = ()> {
    server_process: Child,
    client: ClientService<State>,
}

/// to ensure we only ever register tracing once,
/// in the first test that gets run.
///
/// Dirty but it works, good enough for tests.
static INIT_TRACING_ONCE: Once = Once::new();

/// Initialize tracing for example tests
pub fn init_tracing() {
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
    State: Send + Sync + 'static,
{
    /// Run an example server and create a client for it for interactive testing.
    ///
    /// # Panics
    ///
    /// This function panics if the server process cannot be spawned.
    pub fn interactive(example_name: impl AsRef<str>) -> Self {
        let child = escargot::CargoBuild::new()
            .arg("--all-features")
            .example(example_name.as_ref())
            .manifest_path("Cargo.toml")
            .target_dir("./target/")
            .run()
            .unwrap()
            .command()
            .spawn()
            .unwrap();

        let client = ServiceBuilder::new()
            .map_result(map_internal_client_error)
            .layer(TraceLayer::new_for_http())
            .layer(DecompressionLayer::new())
            .layer(FollowRedirectLayer::default())
            .layer(RetryLayer::new(
                ManagedPolicy::default().with_backoff(
                    ExponentialBackoff::new(
                        Duration::from_millis(100),
                        Duration::from_secs(60),
                        0.01,
                        HasherRng::default,
                    )
                    .unwrap(),
                ),
            ))
            .layer(AddRequiredRequestHeadersLayer::default())
            .service(HttpClient::new(
                ServiceBuilder::new()
                    .layer(HttpsConnectorLayer::auto())
                    .layer(HttpProxyConnectorLayer::from_context())
                    .layer(HttpsConnectorLayer::tunnel())
                    .service(HttpConnector::default()),
            ))
            .boxed();

        Self {
            server_process: child,
            client,
        }
    }

    /// Create a `GET` http request to be sent to the child server.
    pub fn get(&self, url: impl IntoUrl) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.get(url)
    }

    /// Create a `HEAD` http request to be sent to the child server.
    pub fn head(&self, url: impl IntoUrl) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.head(url)
    }

    /// Create a `POST` http request to be sent to the child server.
    pub fn post(&self, url: impl IntoUrl) -> RequestBuilder<ClientService<State>, State, Response> {
        self.client.post(url)
    }

    /// Create a `DELETE` http request to be sent to the child server.
    pub fn delete(
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
    pub async fn run(example_name: impl AsRef<str>) -> ExitStatus {
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

    /// Establish an async R/W to the TCP server behind this [`ExampleRunner`].
    pub async fn connect_tcp(&self, addr: impl ToSocketAddrs) -> Result<impl Stream, OpaqueError> {
        tokio::net::TcpStream::connect(addr)
            .await
            .map_err(OpaqueError::from_std)
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
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
    Body::Error: Into<BoxError>,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
