//! This example showcases the use of the HAR logger layer
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_record_har --features=http-full
//! ```
use rama::{
    Context,
    Layer, 
    graceful::Shutdown, 
    http::Request,
    http::layer::har::layer::HARExportLayer,
    http::layer::har::request_comment::RequestComment,
    http::service::web::response::Html,
    http::server::HttpServer, rt::Executor, tcp::server::TcpListener,
    service::service_fn,
    layer::TimeoutLayer,
};

use std::time::Duration;

#[tokio::main]
async fn main() {
    let graceful = Shutdown::default();

    let req_comment = RequestComment::new("making a comment");

    let mut ext = http::Extensions::new();
    ext.insert(req_comment);

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());

        let http_service = (HARExportLayer::default())
            .into_layer(service_fn(async |ctx: Context<()>, req: Request| {
                Ok(Html(format!(
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
                )))
        }));

        let tcp_http_service = HttpServer::auto(exec).service(http_service);

        TcpListener::bind("127.0.0.1:62010")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                (
                    TimeoutLayer::new(Duration::from_secs(8))
                )
                    .into_layer(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
