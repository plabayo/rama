//! This example demonstrates how to use any http Client
//! layer stack in a high level manner using the HttpClientExt.
//!
//! ```sh
//! cargo run --example http_high_level_client
//! ```
//!
//! # Expected output
//!
//! You should see the output printed and the example should exit with a success status code.

// rama provides everything out of the box to build a complete web service.
use rama::{
    http::{
        client::{HttpClient, HttpClientExt as _},
        layer::trace::TraceLayer,
        response::Json,
        server::HttpServer,
        service::web::WebService,
        Body, BodyExtractExt, Request,
    },
    rt::Executor,
    service::{Context, Service, ServiceBuilder},
};

use serde_json::json;
/// Everything else we need is provided by the standard library, community crates or tokio.
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

const ADDRESS: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() {
    setup_tracing();
    tokio::spawn(async move {
        run_server(ADDRESS).await;
    });

    // TODO: remove this dirty sleep once retry policy is implemented
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // TODO: find an ergonomic way to clone a request for Retry Middleware...
    // TODO: find an ergonomic default for the Retry Policy Middleware...

    // Thanks to the import of [`rama::http::client::HttpClientExt`] we can now also
    // use the high level API for this service stack.
    //
    // E.g. `::post(<uri>).header(k, v).form(<data>).send().await?`
    let client = ServiceBuilder::new().service(HttpClient::new());
    // TODO: enable layers to be added such as trace layer...

    // Low Level Http Client example with easy to use Response body extractor

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
    tracing::info!("body: {:?}", body);
    assert_eq!(body, "Hello, World!");

    // Get Json Response Example

    #[derive(Debug, serde::Deserialize)]
    struct Info {
        name: String,
        example: String,
    }

    let info: Info = client
        .get(format!("http://{ADDRESS}/info"))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    tracing::info!("info: {:?}", info);
    assert_eq!(info.name, "Rama");
    assert_eq!(info.example, "http_high_level_client.rs");

    // Json Post + String Response Example

    let resp = client
        .post(format!("http://{ADDRESS}/introduce"))
        .json(&json!({"name": "Rama"}))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    tracing::info!("resp: {:?}", resp);
    assert_eq!(resp, "Hello, Rama!");
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

async fn run_server(addr: &str) {
    tracing::info!("running service at: {addr}");
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            addr,
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .service(
                    WebService::default()
                        .get("/", "Hello, World!")
                        .get(
                            "/info",
                            Json(json!({"name": "Rama", "example": "http_high_level_client.rs"})),
                        )
                        .post(
                            "/introduce",
                            |Json(data): Json<serde_json::Value>| async move {
                                format!("Hello, {}!", data["name"].as_str().unwrap())
                            },
                        ),
                ),
        )
        .await
        .unwrap();
}
