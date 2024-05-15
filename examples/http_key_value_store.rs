//! An example key-value store service that stores bytes data.
//! It is meant to demonstrate the [`WebService`] and [`HttpServer`] capabilities in Rama at a high level.
//!
//! [`WebService`]: crate::http::service::web::WebService
//! [`HttpServer`]: crate::http::server::HttpServer
//!
//! This example demonstrates how to use rama to create a key-value store web service.
//! The service has the following endpoints:
//! - `GET /`: show this API documentation in Json Format
//! - `GET /keys`: list all keys for which (bytes) data is stored
//! - `GET /item/:key`: return a 200 Ok containing the (bytes) data stored at <key>, and a 404 Not Found otherwise
//! - `HEAD /item/:key`: return a 200 Ok if found and a 404 Not Found otherwise
//! - `POST /item/:key`: store the given request payload as the value referenced by <key>, returning a 400 Bad Request if no payload was defined
//!
//! The service also has admin endpoints:
//! - `DELETE /keys`: clear all keys and their associated data
//! - `DELETE /item/:key`: remove the data stored at <key>, returning a 200 Ok if the key was found, and a 404 Not Found otherwise
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_key_value_store
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62006`. You can use `curl` to interact with the service:
//!
//! ```sh
//! # show the API documentation
//! curl -v http://127.0.0.1:62006
//!
//! # store multiple key value pairs
//! curl -v -X POST http://127.0.0.1:62006/items \
//!     -H 'content-type: application/json' \
//!     -d '{"key1": "value1", "key2": "value2"}'
//!
//! # list all keys
//! curl -v http://127.0.0.1:62006/keys
//!
//! # store a single key value pair
//! curl -v -X POST http://127.0.0.1:62006/item/key3 -d "value3"
//!
//! # get the value for a key
//! curl -v http://127.0.0.1:62006/item/key3
//!
//! # check existence for a key
//! curl -v -XHEAD http://127.0.0.1:62006/item/key3
//!
//! # delete a key
//! curl -v -X DELETE http://127.0.0.1:62006/admin/item/key3 -H "Authorization: Bearer secret-token"
//! ```

use rama::{
    http::{
        layer::{
            compression::CompressionLayer, trace::TraceLayer,
            validate_request::ValidateRequestHeaderLayer,
        },
        matcher::HttpMatcher,
        response::Json,
        server::HttpServer,
        service::web::{
            extract::{Bytes, Path, State},
            IntoEndpointService, WebService,
        },
        IntoResponse, Method, StatusCode,
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

    let addr = "127.0.0.1:62006";
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
                                "GET /item/:key": "return a 200 Ok containing the (bytes) data stored at <key>, and a 404 Not Found otherwise",
                                "HEAD /item/:key": "return a 200 Ok if found, and a 404 Not Found otherwise",
                                "POST /item/:key": "store the given request payload as the value referenced by <key>, returning a 400 Bad Request if no payload was defined",
                                "admin": {
                                    "DELETE /keys": "clear all keys and their associated data",
                                    "DELETE /item/:key": "remove the data stored at <key>, returning a 200 Ok if the key was found, and a 404 Not Found otherwise"
                                }
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
                        .on(
                            HttpMatcher::method_get().or_method_head().and_path("/item/:key"),
                            // only compress the get Action, not the Post Action
                            ServiceBuilder::new()
                                .layer(CompressionLayer::new())
                                .service((|State(state): State<AppState>, Path(params): Path<ItemParam>, method: Method| async move {
                                    match method {
                                        Method::GET => {
                                            match state.db.read().await.get(&params.key) {
                                                Some(b) => b.clone().into_response(),
                                                None => StatusCode::NOT_FOUND.into_response(),
                                            }
                                        }
                                        Method::HEAD => {
                                            if state.db.read().await.contains_key(&params.key) {
                                                StatusCode::OK
                                            } else {
                                                StatusCode::NOT_FOUND
                                            }.into_response()
                                        }
                                        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
