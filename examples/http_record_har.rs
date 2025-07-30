//! This example showcases the use of the HAR logger layer
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_record_har --features=http-full
//! ```
use rama::{
    Layer, graceful::Shutdown, http::server::HttpServer, rt::Executor, tcp::server::TcpListener,
};

use std::time::Duration;

#[tokio::main]
async fn main() {
    let graceful = Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard.clone());

        let http_service = (HARExportLayer::new()).into_layer();

        let tcp_http_service = HttpServer::auto(exec).service(http_service);
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
