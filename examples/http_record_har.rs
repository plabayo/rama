//! This example showcases the use of the HAR logger layer
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_record_har --features=http-full
//! ```
use rama::{
    Context, Layer, Service,
    graceful::Shutdown,
    http::{
        Request,
        layer::har::{layer::HARExportLayer, request_comment::RequestComment},
        server::HttpServer,
        service::web::response::Html,
    },
    layer::{ConsumeErrLayer, TimeoutLayer},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};
use rama_http::{
    Body,
    service::web::{WebService, response::IntoResponse},
};

use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    let graceful = Shutdown::default();

    let req_comment = RequestComment::new("making a comment");

    let mut ext = http::Extensions::new();
    ext.insert(req_comment);

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());

        let http_app = WebService::default().get(
            "/",
            Html(format!(
                r##"
            <html>
                <head>
                    <title>Rama — Http Service Hello</title>
                </head>
                <body>
                    <h1>Hello</h1>
                </body>
            </html>
            "##,
            )),
        );

        let http_service =
            // http server does now accept errors to bubble up as
            // it would be ambigious in how you want this to be handled!
            (ConsumeErrLayer::default(), HARExportLayer::default()).into_layer(http_app);

        let tcp_http_service = HttpServer::auto(exec).service(http_service);

        let tcp_service = (TimeoutLayer::new(Duration::from_secs(8)),).into_layer(tcp_http_service);

        TcpListener::bind("127.0.0.1:62010")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
