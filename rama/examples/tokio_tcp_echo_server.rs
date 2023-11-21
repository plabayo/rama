use std::time::Duration;

use rama::{
    graceful::Shutdown,
    server::tcp::TcpListener,
    service::{limit::ConcurrentPolicy, Layer, Service},
    state::Extendable,
    stream::layer::BytesRWTrackerHandle,
    stream::service::EchoService,
};

use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[rama::main]
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
        let tcp_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP Listener");
        tracing::info!(
            "listening for incoming TCP connections on {}",
            tcp_listener.local_addr().unwrap()
        );

        tcp_listener.set_ttl(30).expect("set TTL");

        tcp_listener
            .spawn()
            .limit(ConcurrentPolicy::new(2))
            .timeout(Duration::from_secs(30))
            .bytes_tracker()
            .layer(TcpLogLayer)
            .serve_graceful::<_, EchoService, _>(guard, EchoService::new())
            .await
            .expect("serve incoming TCP connections");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
pub struct TcpLogService<S> {
    service: S,
}

impl<S, Stream> Service<Stream> for TcpLogService<S>
where
    S: Service<Stream>,
    Stream: Extendable,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&self, stream: Stream) -> Result<Self::Response, Self::Error> {
        let handle = stream
            .extensions()
            .get::<BytesRWTrackerHandle>()
            .expect("bytes tracker is enabled")
            .clone();

        let result = self.service.call(stream).await;

        tracing::info!(
            "bytes read: {}, bytes written: {}",
            handle.read(),
            handle.written(),
        );

        result
    }
}

pub struct TcpLogLayer;

impl<S> Layer<S> for TcpLogLayer {
    type Service = TcpLogService<S>;

    fn layer(&self, service: S) -> Self::Service {
        TcpLogService { service }
    }
}
