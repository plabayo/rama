//! This example demonstrates how a single `Router` serves static files next to an API.
//!
//! The router combines:
//! - routes: `GET /coin` shows the coin clicker page and `POST /coin` increments the counter;
//! - a path-bound matcher: `GET /home` answers loopback clients only;
//! - a nested router: `GET /api/coins` returns the counter as JSON;
//! - a directory mount at `/` serving `test-files/examples/webservice`;
//! - a path-less matcher: requests accepting `application/json` that nothing else
//!   answered get a JSON 404;
//! - a not-found service redirecting everything else to `/error.html`.
//!
//! Routes win over the directory mount, so `/coin` never reaches it, while a file
//! the directory does not hold falls through to the path-less matcher and then
//! to the not-found service.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_router_dir_and_api --features=compression,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:12013`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:12013
//! curl -v http://127.0.0.1:12013/api/coins
//! curl -v -H 'accept: application/json' http://127.0.0.1:12013/missing
//! ```
//!
//! You should see the homepage in your browser.
//! You can also click on the coin to increment the counter.
//! Please also try the legal page and some other non-existing pages.

// rama provides everything out of the box to build a complete web service.
#![expect(
    clippy::unwrap_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer,
    extensions::Extensions,
    http::{
        HeaderValue, StatusCode,
        header::ACCEPT,
        layer::{
            compression::CompressionLayer, error_handling::ErrorHandlerLayer, trace::TraceLayer,
        },
        matcher::HttpMatcher,
        protocols::html::{
            PreEscaped, a, body, button, footer, form, h1, h2, head, html, link, p, style, title,
        },
        server::HttpServer,
        service::web::{
            Router,
            extract::State,
            response::{Html, IntoResponse, Json, Redirect},
        },
    },
    layer::ArcLayer,
    net::stream::{SocketInfo, matcher::SocketMatcher},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

#[derive(Debug, Default)]
struct AppState {
    counter: AtomicU64,
}

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

    let addr = "0.0.0.0:12013";
    tracing::info!("running service at: {addr}");

    let state = Arc::new(AppState::default());

    HttpServer::default()
        .listen(
            addr,
            (
                TraceLayer::new_for_http(),
                CompressionLayer::new(),
                ArcLayer::new(),
                ErrorHandlerLayer::new(),
            )
                .into_layer(
                    Router::new_with_state(state)
                        .with_not_found(Redirect::temporary("/error.html"))
                        .with_get("/coin", coin_page)
                        .with_post(
                            "/coin",
                            async |state: State<Arc<AppState>>, ext: Extensions| {
                                state.0.counter.fetch_add(1, Ordering::AcqRel);
                                coin_page(state, ext).await
                            },
                        )
                        .with_matcher(
                            HttpMatcher::get("/home").and_socket(SocketMatcher::loopback()),
                            Html("Home Sweet Home!".to_owned()),
                        )
                        .with_sub_router_make_fn("/api", |api| {
                            api.with_get("/coins", async |State(state): State<Arc<AppState>>| {
                                Json(json!({
                                    "coins": state.counter.load(Ordering::Acquire),
                                }))
                            })
                        })
                        .with_dir("/", "test-files/examples/webservice")
                        .with_matcher(
                            HttpMatcher::header_contains(
                                ACCEPT,
                                HeaderValue::from_static("application/json"),
                            ),
                            (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))),
                        ),
                ),
        )
        .await
        .unwrap();
}

async fn coin_page(State(state): State<Arc<AppState>>, ext: Extensions) -> impl IntoResponse {
    // The home-link variant uses an `<a>` element wrapping the emoji; the
    // remote variant is just the emoji. We wrap in `Either` so both arms
    // have the same type.
    let emoji_block = if ext
        .get_ref::<SocketInfo>()
        .unwrap()
        .peer_addr()
        .ip_addr
        .is_loopback()
    {
        rama::http::protocols::html::Either::A(a!(href = "/home", "🏠"))
    } else {
        rama::http::protocols::html::Either::B("🌍")
    };

    let count = state.counter.load(Ordering::Acquire);

    // The CSS happens to contain `{` / `}` characters that we want
    // rendered verbatim, so we wrap it in `PreEscaped`.
    const CSS: PreEscaped<&str> = PreEscaped(
        "body { display: flex; justify-content: center; align-items: center;\
         height: 100vh; flex-direction: column; text-align: center; }\
         footer { position: absolute; bottom: 0; width: 100%; text-align: center; }",
    );

    html!(
        head!(
            title!("Coin Clicker"),
            link!(rel = "stylesheet", href = "/style/reset.css"),
            link!(rel = "icon", href = "/favicon.png", r#type = "image/x-icon"),
            style!(CSS),
        ),
        body!(
            h2!(emoji_block, " Coin Clicker"),
            h1!(id = "coinCount", count),
            p!("Click the button for more coins."),
            form!(
                action = "/coin",
                method = "post",
                button!(r#type = "submit", PreEscaped("&#x1F4B0; Click")),
            ),
            footer!(p!(
                "See ",
                a!(href = "/legal.html", "the legal page"),
                " for more information on your rights.",
            )),
        ),
    )
}
