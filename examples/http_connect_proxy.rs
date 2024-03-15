//! An example to showcase how one can build an unauthenticated http proxy server.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_connect_proxy
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:8080 http://www.example.com/
//! curl -v -x http://127.0.0.1:8080 https://www.example.com/
//! ```
//!
//! You should see the response from the server.

use rama::{
    http::{
        client::HttpClient,
        layer::{
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodFilter,
        server::HttpServer,
        service::web::extract::{FromRequestParts, Host},
        Body, IntoResponse, Request, Response, StatusCode,
    },
    rt::Executor,
    service::{service_fn, Context, Service, ServiceBuilder},
    tcp::utils::is_connection_error,
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    // TODO: what about the hop headers?!

    graceful.spawn_task_fn(|guard| async move {
        let exec = Executor::graceful(guard.clone());
        HttpServer::auto(exec)
            .listen_graceful(
                guard,
                "127.0.0.1:8080",
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(UpgradeLayer::new(
                        MethodFilter::CONNECT,
                        service_fn(http_connect_accept),
                        service_fn(http_connect_proxy),
                    ))
                    .service_fn(http_plain_proxy),
            )
            .await
            .unwrap();
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept<S>(
    mut ctx: Context<S>,
    req: Request,
) -> Result<(Response, Context<S>, Request), Response>
where
    S: Send + Sync + 'static,
{
    // TODO: should we support http connect better?
    // e.g. by always adding the host

    let (parts, body) = req.into_parts();
    let host = match Host::from_request_parts(&ctx, &parts).await {
        Ok(host) => host,
        Err(err) => {
            tracing::error!(error = %err, "error extracting host");
            return Err(err.into_response());
        }
    };
    let req = Request::from_parts(parts, body);

    tracing::info!("accept CONNECT to {}", host.0);
    ctx.insert(host);

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy<S>(ctx: Context<S>, mut upgraded: Upgraded) -> Result<(), Infallible>
where
    S: Send + Sync + 'static,
{
    let Host(host) = ctx.get().unwrap();
    tracing::info!("CONNECT to {}", host);
    let mut stream = match tokio::net::TcpStream::connect(&host).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(error = %err, "error connecting to host");
            return Ok(());
        }
    };
    if let Err(err) = tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await {
        if !is_connection_error(&err) {
            tracing::error!(error = %err, "error copying data");
        }
    }
    Ok(())
}

async fn http_plain_proxy<S>(ctx: Context<S>, req: Request) -> Result<Response, Infallible>
where
    S: Send + Sync + 'static,
{
    let client = HttpClient::new();
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = %err, "error in client request");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
