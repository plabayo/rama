//! Rama's implementation of the Datastar SDK Test suite,
//! used to verify if the rama datastar module is datastar-spec compliant.
//!
//! Learn more at <https://github.com/starfederation/datastar/tree/main/sdk/test>.
//!
//! ```sh
//! cargo run --example http_sse_datastar_test_suite --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62036`.
//! With this setup you can now run the test suite runners from the datastar repo.

use rama::{
    Layer,
    futures::async_stream::stream,
    http::{
        layer::trace::TraceLayer,
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            Router,
            extract::datastar::ReadSignals,
            response::{IntoResponse, Sse},
        },
        sse::{
            datastar::PatchSignals,
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

    let graceful = rama::graceful::Shutdown::default();

    let listener = TcpListener::bind(SocketAddress::default_ipv4(62036))
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());

        let router = Arc::new(Router::new().match_route(
            "/test",
            HttpMatcher::method_get().or_method_post(),
            handlers::test,
        ));

        let app = (TraceLayer::new_for_http()).into_layer(router);
        listener
            .serve_graceful(guard, HttpServer::auto(exec).service(app))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

pub mod handlers {
    use indexmap::IndexMap;
    use rama_http::sse::datastar::{
        ElementPatchMode, ExecuteScript, PatchElements,
        execute_script::{ScriptAttribute, ScriptType},
    };
    use serde::Deserialize;
    use serde_json::{Map, Value};

    use super::*;

    #[derive(Deserialize)]
    pub struct TestCase {
        pub events: Vec<TestCaseEvent>,
    }

    #[derive(Deserialize)]
    #[serde(tag = "type")]
    pub enum TestCaseEvent {
        #[serde(alias = "executeScript")]
        ExecuteScript {
            script: String,
            #[serde(alias = "eventId")]
            event_id: Option<String>,
            #[serde(alias = "retryDuration")]
            retry_duration: Option<u64>,
            attributes: Option<IndexMap<String, Value>>,
            #[serde(alias = "autoRemove")]
            auto_remove: Option<bool>,
        },
        #[serde(rename = "patchElements")]
        PatchElements {
            elements: Option<String>,
            #[serde(alias = "eventId")]
            event_id: Option<String>,
            #[serde(alias = "retryDuration")]
            retry_duration: Option<u64>,
            selector: Option<String>,
            mode: Option<String>,
            #[serde(alias = "useViewTransition")]
            use_view_transition: Option<bool>,
        },
        #[serde(rename = "patchSignals")]
        PatchSignals {
            signals: Option<Map<String, Value>>,
            #[serde(alias = "signals-raw")]
            signals_raw: Option<String>,
            #[serde(alias = "eventId")]
            event_id: Option<String>,
            #[serde(alias = "retryDuration")]
            retry_duration: Option<u64>,
            #[serde(alias = "onlyIfMissing")]
            only_if_missing: Option<bool>,
        },
    }

    pub async fn test(ReadSignals(test_case): ReadSignals<TestCase>) -> impl IntoResponse {
        Sse::new(KeepAliveStream::new(
            KeepAlive::new(),
            stream! {
                for event in test_case.events {
                    let sse_event = match event {
                        TestCaseEvent::ExecuteScript { script, event_id, retry_duration, attributes, auto_remove } => {
                            let mut event = ExecuteScript {
                                script: script.into(),
                                auto_remove,
                                attributes: attributes.map(|attributes| {
                                    attributes.into_iter().filter_map(|(key, value)| match key.as_str() {
                                        "src" => Some(ScriptAttribute::Src(value.as_str().unwrap_or_default().to_owned())),
                                        "type" => Some(ScriptAttribute::Type(match value.as_str().unwrap_or_default() {
                                            "module" => ScriptType::Module,
                                            "importmap" => ScriptType::ImportMap,
                                            mime => mime.parse().map(ScriptType::Mime).inspect_err(|err| tracing::error!("failed to parse exec script type attribute as mime ({mime}): {err}")).unwrap_or_default(),
                                        })),
                                        "async" => if value.as_bool().unwrap_or_default() {
                                            Some(ScriptAttribute::Async)
                                        } else {
                                            None
                                        },
                                        "defer" => if value.as_bool().unwrap_or_default() {
                                            Some(ScriptAttribute::Defer)
                                        } else {
                                            None
                                        },
                                        "nomodule" => if value.as_bool().unwrap_or_default() {
                                            Some(ScriptAttribute::NoModule)
                                        } else {
                                            None
                                        },
                                        "integrity" => Some(ScriptAttribute::Integrity(value.as_str().unwrap_or_default().to_owned())),
                                        "crossorigin" => Some(ScriptAttribute::CrossOrigin(value.as_str().unwrap_or_default().into())),
                                        "referrerpolicy" => Some(ScriptAttribute::ReferrerPolicy(value.as_str().unwrap_or_default().into())),
                                        "charset" => Some(ScriptAttribute::Charset(value.as_str().unwrap_or_default().into())),
                                        _ => Some(ScriptAttribute::Custom { key, value: Some(value.to_string().trim_matches('"').to_owned()) }),
                                    }).collect()
                                }),
                            }.into_datastar_event();
                            if let Some(id) = event_id
                                && let Err(err) = event.try_set_id(id) {
                                    tracing::error!("failed to set id of event: {err}");
                                }
                            if let Some(retry) = retry_duration {
                                event.set_retry(retry);
                            }
                            event
                        }
                        TestCaseEvent::PatchElements { elements, event_id, retry_duration, mode, selector, use_view_transition } => {
                            let mut event = PatchElements {
                                elements: elements.map(Into::into),
                                selector: selector.map(Into::into),
                                mode: match mode.as_deref().unwrap_or_default() {
                                    "inner" => ElementPatchMode::Inner,
                                    "remove" => ElementPatchMode::Remove,
                                    "replace" => ElementPatchMode::Replace,
                                    "prepend" => ElementPatchMode::Prepend,
                                    "append" => ElementPatchMode::Append,
                                    "before" => ElementPatchMode::Before,
                                    "after" => ElementPatchMode::After,
                                    _ => ElementPatchMode::Outer, // includes "outer"
                                },
                                use_view_transition: use_view_transition.unwrap_or_default(),
                            }.into_datastar_event();
                            if let Some(id) = event_id
                                && let Err(err) = event.try_set_id(id) {
                                    tracing::error!("failed to set id of event: {err}");
                                }
                            if let Some(retry) = retry_duration {
                                event.set_retry(retry);
                            }
                            event
                        },
                        TestCaseEvent::PatchSignals { signals, signals_raw, event_id, retry_duration, only_if_missing } => {
                            let mut event = PatchSignals {
                                signals: signals_raw.unwrap_or_else(|| signals.map(|signals| serde_json::to_string(&signals).unwrap_or_default()).unwrap_or_default()),
                                only_if_missing: only_if_missing.unwrap_or_default(),
                            }.into_datastar_event();
                            if let Some(id) = event_id
                                && let Err(err) = event.try_set_id(id) {
                                    tracing::error!("failed to set id of event: {err}");
                                }
                            if let Some(retry) = retry_duration {
                                event.set_retry(retry);
                            }
                            event
                        },
                    };

                    yield Ok::<_, Infallible>(sse_event);
                }
            },
        ))
    }
}
