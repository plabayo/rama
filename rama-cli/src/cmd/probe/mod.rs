//! rama probe service

use std::{
    fs::File,
    io::{BufRead, BufReader},
    time::Duration,
};

use clap::Args;
use rama::{
    cli::args::RequestArgsBuilder,
    error::{BoxError, OpaqueError},
    http::{
        client::HttpClient,
        layer::{
            decompression::DecompressionLayer,
            follow_redirect::{policy::Limited, FollowRedirectLayer},
            required_header::AddRequiredRequestHeadersLayer,
            timeout::TimeoutLayer,
        },
        Request, Response, StatusCode,
    },
    proxy::http::client::HttpProxyConnectorLayer,
    rt::Executor,
    service::{Context, Service, ServiceBuilder},
    tcp::service::HttpConnector,
    tls::rustls::client::HttpsConnectorLayer,
    utils::graceful::{self, Shutdown, ShutdownGuard},
};
use tokio::sync::oneshot;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::error::ErrorWithExitCode;
mod writer;

// TODO Future features:
// 1. Add -o to write the output to a file
// 2. match strings
// 3. host

/// rama domain prober
#[derive(Args, Debug, Clone)]
pub struct CliCommandProbe {
    #[arg(long)]
    /// print debug info
    debug: bool,

    #[arg(short = 'l', long)]
    /// A file containing domains to probe
    list: Option<String>,

    #[arg(short = 'v', long)]
    /// print verbose output
    verbose: bool,

    // For the first cut I am imagining a usage example like:
    // rama probe domains.txt
    // where "domains.txt" is just a file containing simple domains like google.com
    args: Option<Vec<String>>,
}

pub(crate) fn pretty_print_status_code(status_code: StatusCode, domain: String) {
    match status_code.as_u16() {
        200 => eprintln!("{}: \x1b[32m{}\x1b[0m", domain, status_code), // Green
        301 => eprintln!("{}: \x1b[33m{}\x1b[0m", domain, status_code), // Yellow
        400 => eprintln!("{}: \x1b[31m{}\x1b[0m", domain, status_code), // Red
        _ => eprintln!("{}: {}", domain, status_code),                  // Default color
    }
}

/// Run the rama probe command
pub async fn run(cfg: CliCommandProbe) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(
                    if cfg.debug {
                        if cfg.verbose {
                            LevelFilter::TRACE
                        } else {
                            LevelFilter::DEBUG
                        }
                    } else {
                        LevelFilter::ERROR
                    }
                    .into(),
                )
                .from_env_lossy(),
        )
        .init();
    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                let _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        let _ = tx_final.send(result);
                    }
                    Err(_) => {
                        let _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });
    shutdown.spawn_task_fn(move |guard| async move {
        let result = run_inner(guard, cfg).await;
        let _ = tx.send(result);
    });

    let _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}
async fn run_inner(guard: ShutdownGuard, cfg: CliCommandProbe) -> Result<(), BoxError> {
    //HACK: Remove and maybe replace with some kind of illegal/too many arguments error of some kind
    if cfg.args.clone().is_none() {
        let filename = &cfg.clone().list.unwrap();
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let mut request_args_builder = RequestArgsBuilder::new();
            request_args_builder.parse_arg(line.clone());
            let request = request_args_builder.build()?;

            let client = create_client(guard.clone(), cfg.clone()).await?;

            let response = client.serve(Context::default(), request).await?;
            let status = response.status();
            pretty_print_status_code(status, line);
            if status.is_client_error() {
                return Err(ErrorWithExitCode::new(
                    4,
                    OpaqueError::from_display(format!("client http error, status: {status}")),
                )
                .into());
            } else if status.is_server_error() {
                return Err(ErrorWithExitCode::new(
                    5,
                    OpaqueError::from_display(format!("server http error, status: {status}")),
                )
                .into());
            }
        }
    } else {
        let domains = cfg.args.clone().unwrap();
        for domain in domains {
            let mut request_args_builder = RequestArgsBuilder::new();
            request_args_builder.parse_arg(domain.clone());
            let request = request_args_builder.build()?;

            let client = create_client(guard.clone(), cfg.clone()).await?;

            let response = client.serve(Context::default(), request).await?;
            let status = response.status();
            pretty_print_status_code(status, domain);
            if status.is_client_error() {
                return Err(ErrorWithExitCode::new(
                    4,
                    OpaqueError::from_display(format!("client http error, status: {status}")),
                )
                .into());
            } else if status.is_server_error() {
                return Err(ErrorWithExitCode::new(
                    5,
                    OpaqueError::from_display(format!("server http error, status: {status}")),
                )
                .into());
            }
        }
    }

    Ok(())
}
async fn create_client<S>(
    guard: ShutdownGuard,
    cfg: CliCommandProbe,
) -> Result<impl Service<S, Request, Response = Response, Error = BoxError>, BoxError>
where
    S: Send + Sync + 'static,
{
    // Pass None for both modes so we can just pretty print the status code
    let (request_writer_mode, response_writer_mode) = (None, None);
    let writer_kind = writer::WriterKind::Stdout;
    let executor = Executor::graceful(guard);
    let (request_writer, response_writer) = writer::create_traffic_writers(
        &executor,
        writer_kind,
        false, // Do not write headers
        request_writer_mode,
        response_writer_mode,
    )
    .await?;

    let client_builder = ServiceBuilder::new()
        .map_result(map_internal_client_error)
        .layer(TimeoutLayer::new(Duration::from_secs(180)))
        .layer(FollowRedirectLayer::with_policy(Limited::new(0)))
        .layer(response_writer)
        .layer(DecompressionLayer::new())
        .layer(AddRequiredRequestHeadersLayer::default())
        .layer(request_writer);
    Ok(client_builder.service(HttpClient::new(
        ServiceBuilder::new()
            .layer(HttpProxyConnectorLayer::try_from_env_default().unwrap())
            .layer(HttpsConnectorLayer::tunnel())
            .service(HttpConnector::default()),
    )))
}
fn map_internal_client_error<E, Body>(
    result: Result<Response<Body>, E>,
) -> Result<Response, BoxError>
where
    E: Into<BoxError>,
    Body: rama::http::dep::http_body::Body<Data = bytes::Bytes> + Send + Sync + 'static,
    Body::Error: Into<BoxError>,
{
    match result {
        Ok(response) => Ok(response.map(rama::http::Body::new)),
        Err(err) => Err(err.into()),
    }
}
