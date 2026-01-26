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
    http::{
        Method,
        headers::exotic::XClacksOverhead,
        layer::set_header::SetResponseHeaderLayer,
        layer::{match_redirect::UriMatchRedirectLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{
            Router,
            extract::Path,
            response::{Html, Json, Redirect},
        },
    },
    net::http::uri::UriMatchReplaceRule,
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};

const ADDRESS: &str = "127.0.0.1:62018";

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

    #[derive(Debug, Deserialize)]
    struct PostGreetForPathParams {
        name: String,
    }

    #[derive(Debug, Deserialize)]
    struct GetGreetingPathParams {
        code: String,
    }

    let router = Router::new()
        .with_get("/", Html(r##"<h1>Rama - Web Router</h1>"##.to_owned()))
        // route with a parameter
        .with_post(
            "/greet/{name}",
            async |method: Method, Path(PostGreetForPathParams { name }): Path<PostGreetForPathParams>| {
                Json(json!({
                    "method": method.as_str(),
                    "message": format!("Hello, {name}!"),
                }))
            },
        )
        // catch-all route
        .with_get(
            "/lang/{*code}",
            async |Path(GetGreetingPathParams { code }): Path<GetGreetingPathParams>| {
                let translations = [
                    ("en", "Welcome to our site!"),
                    ("fr", "Bienvenue sur notre site!"),
                    ("es", "¡Bienvenido a nuestro sitio!"),
                ];
                let message = translations
                    .iter()
                    .find(|(lang, _)| *lang == code)
                    .map(|(_, message)| *message)
                    .unwrap_or("Language not supported");

                Json(json!({
                    "message": message,
                }))
            },
        )
        // sub route support - api version health check
        .with_sub_router_make_fn("/api", |router| {
            router.with_sub_router_make_fn("/v2", |router| {
                router.with_get("/status", async || {
                    Json(json!({
                        "status": "API v2 is up and running",
                    }))
                })
            })
        })
        .with_not_found(Redirect::temporary("/"));

    let middlewares = (
        TraceLayer::new_for_http(),
        SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
        UriMatchRedirectLayer::permanent([
            UriMatchReplaceRule::try_new("*/v1/*", "$1/v2/$2").unwrap(), // upgrade users as-is to v2 (backwards compatible)
            // this is now a new endpoint,
            // NOTE though that query matches are pretty fragile,
            // and instead you should try to keep it to the authority, scheme and path only,
            // and instead either preserve or drop the query parameter
            UriMatchReplaceRule::try_new("*/greet\\?lang=*", "$1/lang/$2").unwrap(),
        ]),
    );

    graceful.spawn_task_fn(async |guard| {
        tracing::info!("running service at: {ADDRESS}");
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(ADDRESS, Arc::new(middlewares.into_layer(router)))
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
