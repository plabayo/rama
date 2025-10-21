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
//! cargo run --example http_key_value_store --features=compression,http-full
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
    Layer,
    conversion::FromRef,
    http::{
        Method, StatusCode,
        layer::{
            compression::CompressionLayer, trace::TraceLayer,
            validate_request::ValidateRequestHeaderLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            IntoEndpointServiceWithState, WebService,
            extract::{Bytes, Path, State},
            response::{IntoResponse, Json},
        },
    },
    net::{address::SocketAddress, user::Bearer},
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter},
    utils::macros::impl_deref,
};

use ahash::HashMap;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Clone, Debug, Default)]
/// Contains the global shared state
///
/// It's best practise to make sure this is splittable in
/// smaller more focussed parts so handlers can request
/// only the things they need
struct AppState {
    db: Db,
}

#[derive(Debug, Clone, Default)]
struct Db(Arc<RwLock<HashMap<String, bytes::Bytes>>>);

impl_deref!(Db: Arc<RwLock<HashMap<String, bytes::Bytes>>>);

// By implementing FromRef for all parts of our State, handlers can
// now only request the parts they need.

impl FromRef<AppState> for Db {
    fn from_ref(input: &AppState) -> Self {
        input.db.clone()
    }
}

// AppState is cloneable so implement FromRef<AppState> is enough. But here
// we decided that our GlobalState will be `Arc<AppState>`. We do this so we can
// add more fields to AppState but cloning it stays the same size. For this
// specific use case this is way too overkill, but we do it do demonstrate that it's possible.

impl FromRef<Arc<AppState>> for Db {
    fn from_ref(input: &Arc<AppState>) -> Self {
        input.db.clone()
    }
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

    let addr = SocketAddress::local_ipv4(62006);
    tracing::info!(
        network.local.address = %addr.ip_addr(),
        network.local.port = %addr.port(),
        "running service",
    );
    let exec = Executor::default();
    let state = Arc::new(AppState::default());
    HttpServer::auto(exec)
        .listen(
            addr,
            (TraceLayer::new_for_http())
                .into_layer(
                    WebService::default()
                        .with_state(state.clone())
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
                        .nest_service("/admin", ValidateRequestHeaderLayer::auth(Bearer::new_static("secret-token"))
                            .into_layer(WebService::default().with_state(state.clone())
                                .delete("/keys", async |State(db): State<Db>| {
                                    db.write().await.clear();
                                })
                                .delete("/item/:key", async |State(db): State<Db>, Path(params): Path<ItemParam>| {
                                    match db.write().await.remove(&params.key) {
                                        Some(_) => StatusCode::OK,
                                        None => StatusCode::NOT_FOUND,
                                    }
                                })))
                        .on(
                            HttpMatcher::method_get().or_method_head().and_path("/item/:key"),
                            // only compress the get Action, not the Post Action
                            CompressionLayer::new()
                                .into_layer((async |State(db): State<Db>, Path(params): Path<ItemParam>, method: Method| {
                                    match method {
                                        Method::GET => {
                                            match db.read().await.get(&params.key) {
                                                Some(b) => b.clone().into_response(),
                                                None => StatusCode::NOT_FOUND.into_response(),
                                            }
                                        }
                                        Method::HEAD => {
                                            if db.read().await.contains_key(&params.key) {
                                                StatusCode::OK
                                            } else {
                                                StatusCode::NOT_FOUND
                                            }.into_response()
                                        }
                                        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                    }
                                }).into_endpoint_service_with_state(state.clone())),
                        )
                        .post("/items", async |State(db): State<Db>, Json(dict): Json<HashMap<String, String>>| {
                            let mut db = db.write().await;
                            for (k, v) in dict {
                                db.insert(k, bytes::Bytes::from(v));
                            }
                            StatusCode::OK
                        })

                        .post("/item/:key", async |State(db): State<Db>, Path(params): Path<ItemParam>, Bytes(value): Bytes| {
                            if value.is_empty() {
                                return StatusCode::BAD_REQUEST;
                            }
                           db.write().await.insert(params.key, value);
                            StatusCode::OK
                        }),
                ),
        )
        .await
        .unwrap();
}

/// a service_fn can be a regular fn, instead of a closure
async fn list_keys(State(db): State<Db>) -> impl IntoResponse {
    db.read().await.keys().fold(String::new(), |a, b| {
        if a.is_empty() {
            b.clone()
        } else {
            format!("{a}, {b}")
        }
    })
}
