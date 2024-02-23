use rama::http::layer::trace::TraceLayer;
use rama::http::layer::validate_request::ValidateRequestHeaderLayer;
use rama::http::response::Json;
use rama::http::service::web::extract::{Bytes, Path, State};
use rama::{
    http::{
        layer::compression::CompressionLayer,
        server::HttpServer,
        service::web::{IntoEndpointService, WebService},
        IntoResponse, StatusCode,
    },
    rt::Executor,
    service::ServiceBuilder,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Default)]
struct AppState {
    db: RwLock<HashMap<String, bytes::Bytes>>,
}

#[derive(Debug, Deserialize)]
struct ItemParam {
    key: String,
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
                        .nest("/admin", ServiceBuilder::new()
                            .layer(ValidateRequestHeaderLayer::bearer("secret-token"))
                            .service(WebService::default()
                                .delete("/keys", |State(state): State<AppState>| async move {
                                    state.db.write().await.clear();
                                })
                                .delete("/item/:key", |State(state): State<AppState>, Path(params): Path<ItemParam>| async move {
                                    match state.db.write().await.remove(&params.key) {
                                        Some(_) => StatusCode::OK,
                                        None => StatusCode::NOT_FOUND,
                                    }
                                })))
                        .get(
                            "/item/:key",
                            // only compress the get Action, not the Post Action
                            ServiceBuilder::new()
                                .layer(CompressionLayer::new())
                                .service((|State(state): State<AppState>, Path(params): Path<ItemParam>| async move {
                                    match state.db.read().await.get(&params.key) {
                                        Some(b) => b.clone().into_response(),
                                        None => StatusCode::NOT_FOUND.into_response(),
                                    }
                                }).into_endpoint_service()),
                        )
                        .post("/items", |State(state): State<AppState>, Json(dict): Json<HashMap<String, String>>| async move {
                            let mut db = state.db.write().await;
                            for (k, v) in dict {
                                db.insert(k, bytes::Bytes::from(v));
                            }
                            StatusCode::OK
                        })
                        .post("/item/:key", |State(state): State<AppState>, Path(params): Path<ItemParam>, Bytes(value): Bytes| async move {
                            if value.is_empty() {
                                return StatusCode::BAD_REQUEST;
                            }
                            state.db.write().await.insert(params.key, value);
                            StatusCode::OK
                        }),
                ),
        )
        .await
        .unwrap();
}

/// a service_fn can be a regular fn, instead of a closure
async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    state.db.read().await.keys().fold(String::new(), |a, b| {
        if a.is_empty() {
            b.clone()
        } else {
            format!("{a}, {b}")
        }
    })
}
