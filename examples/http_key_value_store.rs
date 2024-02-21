use bytes::Bytes;
use rama::http::layer::trace::TraceLayer;
use rama::http::layer::validate_request::ValidateRequestHeaderLayer;
use rama::http::response::Json;
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
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
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
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .service(
                    WebService::default()
                        .get("/", Json(json!({
                                "GET /": "show this API documentation in Json Format",
                                "GET /keys": "list all keys for which (bytes) data is stored",
                                "GET /:key": "return a 200 Ok containing the (bytes) data stored at <key>, and a 404 Not Found otherwise",
                                "POST /:key": "store the given request payload as the value referenced by <key>, returning a 400 Bad Request if no payload was defined",
                            })))
                        .get("/keys", list_keys)
                        // TODO: add /* automatically to end of path, so we can use the rest of the path as a key :) zzzzzzzzz
                        // will make or remove prefix logic a lot easier... damn
                        .nest("/admin", ServiceBuilder::new()
                            .layer(ValidateRequestHeaderLayer::bearer("secret-token"))
                            .service(WebService::default()
                                .delete("/keys", |ctx: Context<AppState>, _req: Request| async move {
                                    ctx.state().db.write().await.clear();
                                    Ok(StatusCode::OK)
                                })
                                .delete("/item/:key", |ctx: Context<AppState>, _req: Request| async move {
                                    let key = ctx.get::<UriParams>().unwrap().get("key").unwrap();
                                    Ok(match ctx.state().db.write().await.remove(key) {
                                        Some(_) => StatusCode::OK,
                                        None => StatusCode::NOT_FOUND,
                                    })
                                })))
                        .get(
                            "/item/:key",
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
                        .post("/item/:key", |ctx: Context<AppState>, req: Request| async move {
                            let key = ctx.get::<UriParams>().unwrap().get("key").unwrap();
                            let value = match req.into_body().collect().await {
                                Err(_) => return Ok(StatusCode::BAD_REQUEST),
                                Ok(b) => b.to_bytes(),
                            };
                            if value.is_empty() {
                                return Ok(StatusCode::BAD_REQUEST);
                            }
                            ctx.state().db.write().await.insert(key.to_owned(), value);
                            Ok(StatusCode::OK)
                        }),
                ),
        )
        .await
        .unwrap();
}

/// a service_fn can be a regular fn, instead of a closure
async fn list_keys(ctx: Context<AppState>, _req: Request) -> Result<impl IntoResponse, Infallible> {
    let keys = ctx
        .state()
        .db
        .read()
        .await
        .keys()
        .fold(String::new(), |a, b| {
            if a.is_empty() {
                b.clone()
            } else {
                format!("{a}, {b}")
            }
        });
    Ok(keys)
}
