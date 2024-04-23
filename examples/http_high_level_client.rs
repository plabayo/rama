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
        matcher::HttpMatcher,
        response::{Json, ResponseExt as _},
        server::HttpServer,
        service::web::match_service,
        Body, Request, StatusCode,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    tokio::spawn(async move {
        let addr = "127.0.0.1:8080";
        tracing::info!("running service at: {addr}");
        let exec = Executor::default();
        HttpServer::auto(exec)
            .listen(
                addr,
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                .service(
                        match_service!{
                            HttpMatcher::get("/") => "Hello, World!",
                            HttpMatcher::get("/info") => Json(json!({"name": "Rama", "example": "http_high_level_client.rs"})),
                            HttpMatcher::post("/introduce") => |Json(data): Json<serde_json::Value>| async move {
                                format!("Hello, {}!", data["name"].as_str().unwrap())
                            },
                            _ => StatusCode::NOT_FOUND,
                        }
                    ),
            )
            .await
            .unwrap();
    });

    // TODO: remove this dirty sleep once retry policy is implemented
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // TODO: find an ergonomic way to clone a request for Retry Middleware...
    // TODO: find an ergonomic default for the Retry Policy Middleware...

    let client = ServiceBuilder::new().service(HttpClient::new());
    // TODO: enable layers to be added such as trace layer...

    // Low Level Http Client example with easy to use Response body extractor

    let resp = client
        .serve(
            Context::default(),
            Request::builder()
                .uri("http://127.0.0.1:8080/")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = resp.into_body_string().await.unwrap();
    tracing::info!("body: {:?}", body);
    assert_eq!(body, "Hello, World!");

    // Get Json Response Example

    #[derive(Debug, serde::Deserialize)]
    struct Info {
        name: String,
        example: String,
    }

    let info: Info = client
        .get("http://localhost:8080/info")
        .send(Context::default())
        .await
        .unwrap()
        .into_body_json()
        .await
        .unwrap();
    tracing::info!("info: {:?}", info);
    assert_eq!(info.name, "Rama");
    assert_eq!(info.example, "http_high_level_client.rs");

    // Json Post + String Response Example

    let resp = client
        .post("http://localhost:8080/introduce")
        .json(&json!({"name": "Rama"}))
        .send(Context::default())
        .await
        .unwrap()
        .into_body_string()
        .await
        .unwrap();
    tracing::info!("resp: {:?}", resp);
    assert_eq!(resp, "Hello, Rama!");
}
