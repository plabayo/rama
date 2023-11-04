use std::time::Duration;

use rama::graceful::{Shutdown, ShutdownGuardAdderLayer};
use rama::server::tcp::TcpListener;
use rama::service::spawn::SpawnLayer;
use rama::stream::service::EchoService;

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
        TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener")
            .layer(ShutdownGuardAdderLayer::new(guard.downgrade()))
            .layer(SpawnLayer::new())
            .serve::<_, EchoService, _>(EchoService::new())
            .await
            .expect("serve incoming TCP connections");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
