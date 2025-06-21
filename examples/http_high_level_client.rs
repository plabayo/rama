//! This example demonstrates how to use any http Client
//! layer stack in a high level manner using the HttpClientExt.
//!
//! ```sh
//! cargo run --example http_high_level_client --features=compression,http-full
//! ```
//!
//! # Expected output
//!
//! You should see the output printed and the example should exit with a success status code.
//! In your logs you will also find each request traced twice, once for the client and once for the server.

// rama provides everything out of the box to build a complete web service.

use rama::{
    Context, Layer, Service,
    http::{
        Body, BodyExtractExt, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        headers::{Accept, Authorization, HeaderMapExt},
        layer::{
            auth::{AddAuthorizationLayer, AsyncRequireAuthorizationLayer},
            compression::CompressionLayer,
            decompression::DecompressionLayer,
            retry::{ManagedPolicy, RetryLayer},
            trace::TraceLayer,
        },
        server::HttpServer,
        service::client::HttpClientExt,
        service::web::WebService,
        service::web::response::{IntoResponse, Json},
    },
    net::address::SocketAddress,
    net::user::Basic,
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter},
    utils::{backoff::ExponentialBackoff, rng::HasherRng},
};

// Everything else we need is provided by the standard library, community crates or tokio.

use serde_json::json;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const ADDRESS: SocketAddress = SocketAddress::local_ipv4(62004);

#[tokio::main]
async fn main() {
    setup_tracing();
    tokio::spawn(run_server(ADDRESS));

    // Thanks to the import of [`rama::http::client::HttpClientExt`] we can now also
    // use the high level API for this service stack.
    //
    // E.g. `::post(<uri>).header(k, v).form(<data>).send().await?`
    let client = (
        TraceLayer::new_for_http(),
        DecompressionLayer::new(),
        // you can try to change these credentials or omit them completely,
        // to see the unauthorized responses, in other words: see the auth middleware in action
        //
        // NOTE: the high level http client has also a `::basic` method
        // that can be used to add basic auth headers only for that specific request
        AddAuthorizationLayer::basic("john", "123")
            .as_sensitive(true)
            .if_not_present(true),
        RetryLayer::new(
            ManagedPolicy::default().with_backoff(
                ExponentialBackoff::new(
                    Duration::from_millis(100),
                    Duration::from_secs(30),
                    0.01,
                    HasherRng::default,
                )
                .unwrap(),
            ),
        ),
    )
        .into_layer(EasyHttpWebClient::default());

    //--------------------------------------------------------------------------------
    // Low Level (Regular) http client (stack) service example.
    // It does make use of the `BodyExtractExt` trait to extract the body as string.
    //--------------------------------------------------------------------------------

    let resp = client
        .serve(
            Context::default(),
            Request::builder()
                .uri(format!("http://{ADDRESS}/"))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.try_into_string().await.unwrap();
    tracing::info!("body: {body}");
    assert_eq!(body, "Hello, World!");

    //--------------------------------------------------------------------------------
    // The examples below are high level http client examples
    // using the `HttpClientExt` trait.
    //--------------------------------------------------------------------------------

    // Get Json Response Example

    #[derive(Debug, serde::Deserialize)]
    struct Info {
        name: String,
        example: String,
        magic: u64,
    }

    let info: Info = client
        .get(format!("http://{ADDRESS}/info"))
        .header("x-magic", "42")
        .typed_header(Accept::json())
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    tracing::info!("info: {info:?}");
    assert_eq!(info.name, "Rama");
    assert_eq!(info.example, "http_high_level_client.rs");
    assert_eq!(info.magic, 42);

    // Json Post + String Response Example

    let resp = client
        .post(format!("http://{ADDRESS}/introduce"))
        .json(&json!({"name": "Rama"}))
        .typed_header(Accept::text())
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    tracing::info!("response: {resp}");
    assert_eq!(resp, "Hello, Rama!");

    // Example to show how to set basic auth directly while making request,
    // this will now fail as the credentials are not authorized...

    let resp = client
        .get(format!("http://{ADDRESS}/info"))
        .basic_auth("joe", "456")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

fn setup_tracing() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();
}

async fn run_server(addr: SocketAddress) {
    // artificial delay to show the client retries
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    tracing::info!(
        network.local.address = %addr.ip_addr(),
        network.local.port = %addr.port(),
        "running server",
    );
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            addr,
            (
                TraceLayer::new_for_http(),
                CompressionLayer::new(),
                AsyncRequireAuthorizationLayer::new(auth_request),
            )
                .into_layer(
                    WebService::default()
                        .get("/", "Hello, World!")
                        .get(
                            "/info",
                            async |req: Request| {
                                req.headers()
                                    .get("x-magic")
                                    .and_then(|v| v.to_str().ok())
                                    .and_then(|v| v.parse::<u64>().ok())
                                    .map_or_else(
                                        || Json(json!({"name": "Rama", "example": "http_high_level_client.rs"})),
                                        |magic| {
                                            Json(json!({
                                                "name": "Rama",
                                                "example": "http_high_level_client.rs",
                                                "magic": magic
                                            }))
                                        },
                                    )
                            }
                        )
                        .post(
                            "/introduce",
                            async |Json(data): Json<serde_json::Value>| {
                                format!("Hello, {}!", data["name"].as_str().unwrap())
                            },
                        ),
                ),
        )
        .await
        .unwrap();
}

async fn auth_request<S>(ctx: Context<S>, req: Request) -> Result<(Context<S>, Request), Response> {
    if req
        .headers()
        .typed_get::<Authorization<Basic>>()
        .map(|auth| auth.username() == "john" && auth.password() == "123")
        .unwrap_or_default()
    {
        tracing::info!(
            proxy.user = "john",
            url.full = %req.uri(),
            "authorized request",
        );
        Ok((ctx, req))
    } else {
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}
