//! A tiny HTTP service whose request and response metadata is modified by
//! JavaScript middleware.
//!
//! Run it with:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_js_middleware \
//!     --features=http-full,js
//! ```
//!
//! Then try an API request:
//!
//! ```sh
//! curl -i -X POST http://127.0.0.1:62059/api/launch
//! ```

#![expect(
    clippy::unwrap_used,
    reason = "example/test/bench: panic-on-error is the standard pattern for demos"
)]

use std::convert::Infallible;

use rama::{
    Layer,
    http::{
        Request, Response, StatusCode, layer::error_handling::ErrorHandlerLayer, server::HttpServer,
    },
    js::http::{JsHttpError, JsHttpLayer},
    service::service_fn,
};

const ADDRESS: &str = "127.0.0.1:62059";

const SCRIPT: &str = r#"
function onRequest() {
    const lane = request.uri.startsWith("/api/") ? "api" : "site";
    request.setHeader(
        "x-rama-route",
        `${lane}:${request.method.toLowerCase()}`,
    );
}

function onResponse() {
    response.setHeader("x-rama-script", "active");
}
"#;

#[tokio::main]
async fn main() {
    let app = JsHttpLayer::new(SCRIPT).into_layer(service_fn(async |request: Request| {
        let route = request
            .headers()
            .get("x-rama-route")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unclassified");

        Ok::<_, Infallible>(Response::new(format!(
            "JavaScript routed this request as {route}\n"
        )))
    }));

    let app = ErrorHandlerLayer::new()
        .error_mapper(|error: JsHttpError<Infallible>| {
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        })
        .into_layer(app);

    HttpServer::default().listen(ADDRESS, app).await.unwrap();
}
