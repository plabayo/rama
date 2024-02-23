use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rama::http::layer::{compression::CompressionLayer, trace::TraceLayer};
use rama::http::response::{Html, Redirect};
use rama::http::service::web::extract::State;
use rama::{
    http::{server::HttpServer, service::web::WebService},
    rt::Executor,
    service::ServiceBuilder,
};
use std::sync::atomic::Ordering;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

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

    let addr = "127.0.0.1:8080";
    tracing::info!("running service at: {addr}");
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen_with_state(
            AppState::default(),
            addr,
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .service(
                    WebService::default()
                        .not_found(Redirect::temporary("/error.html"))
                        .get("/coin", |State(state): State<AppState>| async move {
                            coin_page(state)
                        })
                        .post("/coin", |State(state): State<AppState>| async move {
                            state.counter.fetch_add(1, Ordering::SeqCst);
                            coin_page(state)
                        })
                        .dir("/", "test-files/examples/webservice"),
                ),
        )
        .await
        .unwrap();
}

fn coin_page(state: Arc<AppState>) -> Html<String> {
    let count = state.counter.load(Ordering::SeqCst);
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
    <h2>Coin Clicker</h2>
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
