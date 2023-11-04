use std::time::Duration;

use rama::graceful::{Shutdown, ShutdownGuardAdderLayer};
use rama::server::tcp::TcpListener;
use rama::stream::service::EchoService;
use rama::Service;

use tower_async::{service_fn, ServiceBuilder};
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

    let shutdown = Shutdown::default();

    shutdown.spawn_task_fn(|guard| async {
        let guard = guard.downgrade();
        TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener")
            .serve(service_fn(|stream| async {
                let guard = guard.clone();
                tokio::spawn(async move {
                    ServiceBuilder::new()
                        .layer(ShutdownGuardAdderLayer::new(guard))
                        .service(EchoService::new())
                        .call(stream)
                        .await
                        .expect("call EchoService");
                });
                Ok::<(), std::convert::Infallible>(())
            }))
            .await
            .expect("serve incoming TCP connections");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
