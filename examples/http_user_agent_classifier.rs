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
    extensions::ExtensionsRef,
    http::{
        HeaderName, Request, Response,
        layer::ua::{UserAgent, UserAgentClassifierLayer},
        server::HttpServer,
        service::web::response::{IntoResponse, Json},
    },
    rt::Executor,
    service::service_fn,
};
use serde_json::json;
use std::convert::Infallible;

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:62015",
            UserAgentClassifierLayer::new()
                .overwrite_header(HeaderName::from_static("x-proxy-ua"))
                .into_layer(service_fn(handle)),
        )
        .await
        .unwrap();
}

async fn handle(req: Request) -> Result<Response, Infallible> {
    let ua: &UserAgent = req.extensions().get().unwrap();
    Ok(Json(json!({
        "ua": ua.header_str(),
        "kind": ua.info().map(|info| info.kind.to_string()),
        "version": ua.info().and_then(|info| info.version),
        "platform": ua.platform().map(|p| p.to_string()),
        "http_agent": ua.http_agent().as_ref().map(ToString::to_string),
        "tls_agent": ua.tls_agent().as_ref().map(ToString::to_string),
    }))
    .into_response())
}
