//! This example demonstrates how to use the `WebService` to serve static files and an API.
//!
//! The service has the following endpoints:
//! - `GET /`: show the dummy homepage
//! - `GET /coin`: show the coin clicker page
//! - `POST /coin`: increment the coin counter
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_web_service_dir_and_api --features=compression,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62013`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62013
//! ```
//!
//! You should see a the homepage in your browser.
//! You can also click on the coin to increment the counter.
//! please also try go to the legal page and some other non-existing pages.

// rama provides everything out of the box to build a complete web service.
use rama::{
    Context, Layer,
    http::{
        layer::{compression::CompressionLayer, trace::TraceLayer},
        matcher::HttpMatcher,
        response::{Html, Redirect},
        server::HttpServer,
        service::web::WebService,
    },
    net::stream::{SocketInfo, matcher::SocketMatcher},
    rt::Executor,
};

use std::sync::Arc;
/// Everything else we need is provided by the standard library, community crates or tokio.
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Default)]
struct AppState {
    counter: AtomicU64,
}

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

    let addr = "0.0.0.0:62013";
    tracing::info!("running service at: {addr}");
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen_with_state(
            Arc::new(AppState::default()),
            addr,
            (TraceLayer::new_for_http(), CompressionLayer::new()).layer(
                WebService::default()
                    .not_found(Redirect::temporary("/error.html"))
                    .get("/coin", coin_page)
                    .post("/coin", |ctx: Context<Arc<AppState>>| async move {
                        ctx.state().counter.fetch_add(1, Ordering::AcqRel);
                        coin_page(ctx).await
                    })
                    .on(
                        HttpMatcher::get("/home").and_socket(SocketMatcher::loopback()),
                        Html("Home Sweet Home!".to_owned()),
                    )
                    .dir("/", "test-files/examples/webservice"),
            ),
        )
        .await
        .unwrap();
}

async fn coin_page(ctx: Context<Arc<AppState>>) -> Html<String> {
    let emoji = if ctx
        .get::<SocketInfo>()
        .unwrap()
        .peer_addr()
        .ip()
        .is_loopback()
    {
        r#"<a href="/home">🏠</a>"#
    } else {
        "🌍"
    };

    let count = ctx.state().counter.load(Ordering::Acquire);
    Html(format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Coin Clicker</title>
    <link rel="stylesheet" href="/style/reset.css">
    <link rel="icon" href="/favicon.png" type="image/x-icon">
    <style>
        body {{
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            flex-direction: column;
            text-align: center;
        }}

        footer {{
            position: absolute;
            bottom: 0;
            width: 100%;
            text-align: center;
        }}
    </style>
</head>
<body>
    <h2>{emoji} Coin Clicker</h2>
    <h1 id="coinCount">{count}</h1>
    <p>Click the button for more coins.</p>
    <form action="/coin" method="post">
        <button type="submit">&#x1F4B0; Click</button>
    </form>

    <footer>
        <p>
            See <a href="/legal.html">the legal page</a> for more information on your rights.
        </p>
    </footer>
</body>
</html>
    "#
    ))
}
