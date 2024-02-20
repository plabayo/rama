use bytes::Bytes;
use rama::http::layer::trace::TraceLayer;
use rama::{
    http::{
        dep::http_body_util::BodyExt,
        layer::compression::CompressionLayer,
        server::HttpServer,
        service::web::{matcher::UriParams, WebService},
        IntoResponse, Request, StatusCode,
    },
    rt::Executor,
    service::{Context, ServiceBuilder},
};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Default)]
struct AppState {
    db: RwLock<HashMap<String, Bytes>>,
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
            // by default the k8s health service is always ready and alive,
            // optionally you can define your own conditional closures to define
            // more accurate health checks
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .service(
                    WebService::default()
                        .get_fn(
                            "/keys",
                            |ctx: Context<AppState>, _req: Request| async move {
                                let keys = ctx.state().db.read().await.keys().fold(
                                    String::new(),
                                    |a, b| {
                                        if a.is_empty() {
                                            b.clone()
                                        } else {
                                            format!("{a}, {b}")
                                        }
                                    },
                                );
                                Ok(keys)
                            },
                        )
                        .get(
                            "/:key",
                            // only compress the get Action, not the Post Action
                            ServiceBuilder::new()
                                .layer(CompressionLayer::new())
                                .service_fn(|ctx: Context<AppState>, _req: Request| async move {
                                    let key = ctx.get::<UriParams>().unwrap().get("key").unwrap();
                                    Ok(match ctx.state().db.read().await.get(key) {
                                        Some(b) => b.clone().into_response(),
                                        None => StatusCode::NOT_FOUND.into_response(),
                                    })
                                }),
                        )
                        .post_fn("/:key", |ctx: Context<AppState>, req: Request| async move {
                            let key = ctx.get::<UriParams>().unwrap().get("key").unwrap();
                            let value = match req.into_body().collect().await {
                                Err(_) => return Ok(StatusCode::BAD_REQUEST),
                                Ok(b) => b.to_bytes(),
                            };
                            ctx.state().db.write().await.insert(key.to_owned(), value);
                            Ok(StatusCode::OK)
                        }),
                    // TODO: support nesting of services so that we can also support
                    // endpoints that have common layers (e.g. auth layer for admin)
                ),
        )
        .await
        .unwrap();
}
