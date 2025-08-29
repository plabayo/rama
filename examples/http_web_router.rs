//! This example demonstrates how to create a web router
//!
//! ```sh
//! cargo run --example http_web_router --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62018`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62018
//! curl -v -X POST http://127.0.0.1:62018/greet/world
//! curl -v http://127.0.0.1:62018/lang/{en,fr,es}
//! curl -v http://127.0.0.1:62018/api/v1/status
//! curl -v http://127.0.0.1:62018/api/v2/status
//! ```
//!
//! You should see the homepage in your browser with the title "Rama Web Router".

// rama provides everything out of the box to build a complete web service.
use rama::{
    Context, Layer,
    http::{
        Request,
        layer::trace::TraceLayer,
        matcher::UriParams,
        server::HttpServer,
        service::web::Router,
        service::web::response::{Html, Json, Redirect},
    },
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde_json::json;
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const ADDRESS: &str = "127.0.0.1:62018";

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

    let graceful = rama::graceful::Shutdown::default();

    let router = Router::new()
        .get("/", Html(r##"<h1>Rama - Web Router</h1>"##.to_owned()))
        // route with a parameter
        .post("/greet/{name}", async |ctx: Context, req: Request| {
            let uri_params = ctx.get::<UriParams>().unwrap();
            let name = uri_params.get("name").unwrap();
            Json(json!({
                "method": req.method().as_str(),
                "message": format!("Hello, {name}!"),
            }))
        })
        // catch-all route
        .get("/lang/{*code}", async |ctx: Context| {
            let translations = [
                ("en", "Welcome to our site!"),
                ("fr", "Bienvenue sur notre site!"),
                ("es", "¡Bienvenido a nuestro sitio!"),
            ];
            let uri_params = ctx.get::<UriParams>().unwrap();
            let code = uri_params.get("code").unwrap();
            let message = translations
                .iter()
                .find(|(lang, _)| *lang == code)
                .map(|(_, message)| *message)
                .unwrap_or("Language not supported");

            Json(json!({
                "message": message,
            }))
        })
        // sub route support - api version health check
        .sub(
            "/api",
            Router::new()
                .sub(
                    "/v1",
                    Router::new().get("/status", async || {
                        Json(json!({
                            "status": "API v1 is up and running",
                        }))
                    }),
                )
                .sub(
                    "/v2",
                    Router::new().get("/status", async || {
                        Json(json!({
                            "status": "API v2 is up and running",
                        }))
                    }),
                ),
        )
        .not_found(Redirect::temporary("/"));

    graceful.spawn_task_fn(async |guard| {
        tracing::info!("running service at: {ADDRESS}");
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(ADDRESS, TraceLayer::new_for_http().into_layer(router))
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
