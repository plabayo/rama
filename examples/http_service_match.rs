//! This example demonstrates how to create a web router,
//! without the need of service boxing, as is the case with
//! the use of [`WebService`] as demonstrated in
//! the [`http_web_service_dir_and_api`] example.
//!
//! ```sh
//! cargo run --example http_service_match --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62011`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62011
//! curl -v -X PATCH http://127.0.0.1:62011/echo
//! ```
//!
//! You should see the homepage in your browser.
//! The example will also respond to your request with the method and path of the request as JSON.

// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer,
    http::{
        Request,
        layer::trace::TraceLayer,
        matcher::{HttpMatcher, PathMatcher},
        server::HttpServer,
        service::web::match_service,
        service::web::response::{Html, Json, Redirect},
    },
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let addr = "127.0.0.1:62011";
        tracing::info!("running service at: {addr}");
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(
                addr,
                TraceLayer::new_for_http()
                .into_layer(
                        match_service!{
                            HttpMatcher::get("/") => Html(r##"<h1>Home</h1><a href="/echo">Echo Request</a>"##.to_owned()),
                            PathMatcher::new("/echo") => |req: Request| async move {
                                Json(json!({
                                    "method": req.method().as_str(),
                                    "path": req.uri().path(),
                                }))
                            },
                            _ => Redirect::temporary("/"),
                        }
                    ),
            )
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
