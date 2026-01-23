//! This example demonstrates how to use the abortable service
//! to allow one to cancel the transport layer from within the application layer.
//!
//! ```sh
//! cargo run --example http_abort --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62047`. You can use your curl to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62047
//! ```
//!
//! abort will drop connection before response received:
//!
//! ```sh
//! curl -v http://127.0.0.1:62047/abort
//! ```

// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer,
    http::{
        StatusCode,
        headers::exotic::XClacksOverhead,
        layer::{set_header::SetResponseHeaderLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::Router,
        service::web::extract::Extension,
    },
    layer::{AbortableLayer, abort::AbortController},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use std::{sync::Arc, time::Duration};

const ADDRESS: &str = "127.0.0.1:62047";

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

    let router = Router::new().with_get("/", StatusCode::OK).with_get(
        "/abort",
        async |Extension(controller): Extension<AbortController>| {
            controller.abort().await;
            StatusCode::INTERNAL_SERVER_ERROR
        },
    );

    let http_middlewares = (
        TraceLayer::new_for_http(),
        SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
    );

    let tcp_svc = AbortableLayer::new().into_layer(
        HttpServer::auto(Executor::graceful(graceful.guard()))
            .service(Arc::new(http_middlewares.into_layer(router))),
    );

    graceful.spawn_task_fn(async |guard| {
        tracing::info!("running service at: {ADDRESS}");
        let exec = Executor::graceful(guard);
        TcpListener::bind(ADDRESS, exec)
            .await
            .unwrap()
            .serve(tcp_svc)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
