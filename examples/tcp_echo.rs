use std::time::Duration;

use rama::core::transport::tcp::server::{
    echo::echo, layer::log::LogLayer, Listener, Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    Listener::bind("127.0.0.1:20018")
        .graceful_ctrl_c()
        .timeout(Some(Duration::from_secs(5)))
        .serve(
            tower::ServiceBuilder::new()
                .concurrency_limit(1)
                .layer(LogLayer)
                .service(echo),
        )
        .await
}
