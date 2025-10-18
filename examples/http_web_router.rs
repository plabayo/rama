//! This example demonstrates how to create a web router.
//!
//! Within this example you also find the use of middleware
//! that can be used to redirect incoming uris to dynamic
//! uri's (derived from request Uri), as well as static one.
//! This can be useful to direct requests to a central destination
//! or to migrate users to new versions.
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
//! curl -v http://127.0.0.1:62018/lang/fr
//! curl -v -L 'http://127.0.0.1:62018/greet?lang=fr'
//! curl -v -L http://127.0.0.1:62018/api/v1/status
//! curl -v http://127.0.0.1:62018/api/v2/status
//! ```
//!
//! You should see the homepage in your browser with the title "Rama Web Router".

// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer,
    extensions::ExtensionsRef,
    http::{
        Request,
        layer::trace::TraceLayer,
        matcher::UriParams,
        server::HttpServer,
        service::web::{
            Router,
            response::{Html, Json, Redirect},
        },
    },
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use rama_http::layer::match_redirect::UriMatchRedirectLayer;
use rama_net::http::uri::UriMatchReplaceRule;
/// Everything else we need is provided by the standard library, community crates or tokio.
use serde_json::json;
use std::{sync::Arc, time::Duration};
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
        .post("/greet/{name}", async |req: Request| {
            let uri_params = req.extensions().get::<UriParams>().unwrap();
            let name = uri_params.get("name").unwrap();
            Json(json!({
                "method": req.method().as_str(),
                "message": format!("Hello, {name}!"),
            }))
        })
        // catch-all route
        .get("/lang/{*code}", async |req: Request| {
            let translations = [
                ("en", "Welcome to our site!"),
                ("fr", "Bienvenue sur notre site!"),
                ("es", "¡Bienvenido a nuestro sitio!"),
            ];
            let uri_params = req.extensions().get::<UriParams>().unwrap();
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
            Router::new().sub(
                "/v2",
                Router::new().get("/status", async || {
                    Json(json!({
                        "status": "API v2 is up and running",
                    }))
                }),
            ),
        )
        .not_found(Redirect::temporary("/"));

    let middlewares = (
        TraceLayer::new_for_http(),
        UriMatchRedirectLayer::permanent(Arc::new([
            UriMatchReplaceRule::try_new("*/v1/*", "$1/v2/$2").unwrap(), // upgrade users as-is to v2 (backwards compatible)
            // this is now a new endpoint,
            // NOTE though that query matches are pretty fragile,
            // and instead you should try to keep it to the authority, scheme and path only,
            // and instead either preserve or drop the query parameter
            UriMatchReplaceRule::try_new("*/greet\\?lang=*", "$1/lang/$2").unwrap(),
        ])),
    );

    graceful.spawn_task_fn(async |guard| {
        tracing::info!("running service at: {ADDRESS}");
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(ADDRESS, middlewares.into_layer(router))
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
