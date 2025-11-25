//! An example to showcase how you can classify the User-Agent of incoming requests.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_user_agent_classifier --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62015`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62015
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a JSON body with the user agent info exposed by Rama.

use rama::{
    Layer,
    http::{
        HeaderName,
        server::HttpServer,
        service::web::{
            IntoEndpointService,
            extract::Extension,
            response::{IntoResponse, Json},
        },
    },
    ua::{UserAgent, layer::classifier::UserAgentClassifierLayer},
};

use serde_json::json;

#[tokio::main]
async fn main() {
    HttpServer::default()
        .listen(
            "127.0.0.1:62015",
            UserAgentClassifierLayer::new()
                .with_overwrite_header(HeaderName::from_static("x-proxy-ua"))
                .into_layer(handle.into_endpoint_service()),
        )
        .await
        .unwrap();
}

async fn handle(Extension(ua): Extension<UserAgent>) -> impl IntoResponse {
    Json(json!({
        "ua": ua.header_str(),
        "kind": ua.info().map(|info| info.kind.to_string()),
        "version": ua.info().and_then(|info| info.version),
        "platform": ua.platform().map(|p| p.to_string()),
        "http_agent": ua.http_agent().as_ref().map(ToString::to_string),
        "tls_agent": ua.tls_agent().as_ref().map(ToString::to_string),
    }))
}
