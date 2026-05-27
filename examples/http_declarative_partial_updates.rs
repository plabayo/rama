//! Declarative Partial Updates — stream an HTML shell first, fill in
//! slow fragments out-of-order as each future completes.
//!
//! Based on: <https://developer.chrome.com/blog/declarative-partial-updates>
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_declarative_partial_updates --features=http-full
//! ```
//!
//! # Expected output
//!
//! Server listens on `:64805`. Open in a browser:
//!
//! ```sh
//! open http://127.0.0.1:64805
//! ```
//!
//! The 🦙 dashboard shell appears immediately with a "loading…" banner and
//! three spinning-llama skeletons declared `recs → herd → ping`. Fragments
//! stream back in the reverse order: `ping` (~500ms), `herd` (~2s),
//! `recs` (~4s) — each skeleton swaps out as its content lands; the banner
//! disappears once all three have arrived.
//!
//! The shell carries a small inline polyfill (`<script>` in `<head>`,
//! synchronous) that wires up the `<?marker …>` ↔ `<template for=…>` swap
//! via `MutationObserver`. We can't reuse GoogleChromeLabs'
//! `template-for-polyfill` for this — it explicitly batches body-level
//! template swaps until `DOMContentLoaded` fires, which only happens after
//! the streaming response closes, so every fragment would appear at once
//! at the end. Chrome 148+ ships native support behind
//! `chrome://flags/#enable-experimental-web-platform-features`; the inline
//! polyfill is harmless when native already swapped. Pass `?polyfill=false`
//! on the request URL to skip the polyfill entirely (e.g. to test against
//! native support, or measure the baseline shell).
//!
//! The pipeline also layers in [`StreamCompressionLayer`] (so each
//! fragment chunk is compressed and flushed on its own, not held back
//! until the body ends) and [`AddRequiredResponseHeadersLayer`] (so the
//! response carries the usual server/date/request-id headers).
//!
//! [`StreamCompressionLayer`]: rama::http::layer::compression::stream::StreamCompressionLayer
//! [`AddRequiredResponseHeadersLayer`]: rama::http::layer::required_header::AddRequiredResponseHeadersLayer

#![expect(
    clippy::expect_used,
    reason = "example: panic-on-error is the standard demo pattern"
)]

use rama::{
    Layer,
    http::{
        Response,
        html::{
            IntoHtml, PreEscaped, body, div, h1, h2, head, html, li, marker, meta, p, script,
            section, span, style, title, ul,
        },
        layer::{
            compression::stream::StreamCompressionLayer,
            required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer,
        },
        server::HttpServer,
        service::web::{
            Router,
            extract::Query,
            response::{IntoResponse, PartialUpdates},
        },
    },
    layer::ArcLayer,
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};
use serde::Deserialize;
use std::time::Duration;

const POLYFILL: &str = include_str!("http_declarative_partial_updates.js");
const STYLE: &str = include_str!("http_declarative_partial_updates.css");

#[derive(Debug, Deserialize)]
struct DashboardQuery {
    /// `?polyfill=false` opts out of the inline polyfill — useful for
    /// Chrome 148+ with the experimental flag, or for measuring the
    /// non-polyfilled baseline. Anything else (including no query) keeps
    /// the polyfill on.
    polyfill: Option<bool>,
}

async fn dashboard(Query(q): Query<DashboardQuery>) -> Response {
    let polyfill = q.polyfill.unwrap_or(true).then(|| {
        // Synchronous so the MutationObserver is armed before any body
        // content (and any `<template for=…>`) streams in.
        script!(PreEscaped(POLYFILL))
    });

    let shell = html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            title!("🦙 rama partial updates"),
            style!(PreEscaped(STYLE)),
            polyfill,
        ),
        body!(
            div!(class = "banner", "loading dashboard… (this can take ~4s)"),
            h1!("🦙 llama dashboard"),
            p!(
                class = "lede",
                "Three async panels — declared slow → medium → fast — stream \
                 in reverse as each completes. Their skeletons swap out as \
                 their fragments arrive.",
            ),
            panel("Feed recommendations", "recs"),
            panel("Herd telemetry", "herd"),
            panel("Edge ping", "ping"),
        ),
    );

    PartialUpdates::new(shell)
        .fragment("recs", async {
            tokio::time::sleep(Duration::from_millis(4000)).await;
            recs()
        })
        .fragment("herd", async {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            herd()
        })
        .fragment("ping", async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            ping()
        })
        .into_response()
}

fn panel(heading: &'static str, name: &'static str) -> impl IntoHtml {
    section!(
        class = "panel",
        h2!(heading),
        div!(class = "spinner", span!(class = "llama", "🦙"), " loading…",),
        marker(name),
    )
}

fn recs() -> impl IntoHtml {
    ul!(
        li!("Build a proxy in a weekend"),
        li!("Llama your TLS termination"),
        li!("Read the rama book over coffee"),
    )
}

fn herd() -> impl IntoHtml {
    p!(
        "alive: ",
        span!(class = "metric", "42"),
        " · egress: ",
        span!(class = "metric", "3.7 MB/s"),
    )
}

fn ping() -> impl IntoHtml {
    p!(class = "ok", "all edge nodes responding in <50ms")
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

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(64805), exec.clone())
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );
    tracing::info!("open http://{bind_address} in your browser");

    graceful.spawn_task(async move {
        let app = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            StreamCompressionLayer::new(),
            ArcLayer::new(),
        )
            .into_layer(Router::new().with_get("/", dashboard));
        listener.serve(HttpServer::auto(exec).service(app)).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
