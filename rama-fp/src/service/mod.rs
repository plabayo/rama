use rama::{
    http::{server::HttpServer, service::web::WebService},
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, LimitLayer, TimeoutLayer},
        util::backoff::ExponentialBackoff,
        ServiceBuilder,
    },
    tcp::server::TcpListener,
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod data;
mod endpoints;
mod report;
mod state;

pub use state::State;

pub async fn run(interface: String, port: u16) -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let http_address = format!("{}:{}", interface, port);

    graceful.spawn_task_fn(|guard| async move {
        tracing::info!("FP Service listening on: {http_address}");
        TcpListener::build_with_state(State::default())
            .bind(http_address)
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard.clone(),
                ServiceBuilder::new()
                    .map_result(|result| {
                        if let Err(err) = result {
                            tracing::warn!(error = %err, "rama service failed");
                        }
                        Ok::<_, Infallible>(())
                    })
                    .layer(TimeoutLayer::new(Duration::from_secs(8)))
                    .layer(LimitLayer::new(ConcurrentPolicy::with_backoff(
                        2048,
                        ExponentialBackoff::default(),
                    )))
                    .service(
                        HttpServer::auto(Executor::graceful(guard)).service(
                            ServiceBuilder::new().service(
                                WebService::default()
                                    .get("/", endpoints::get_root)
                                    .get("/assets/style.css", endpoints::get_assets_style),
                            ),
                        ),
                    ),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}
