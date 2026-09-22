//! HTTP/3 with the ordinary Rama request, response, body and service interfaces.
//!
//! Run with `--features http-full,rustls,ring` (or `http-full,boring`).
//! Supply a PEM certificate/key for the server and its trusted CA for the client:
//!
//! ```sh
//! cargo run -p rama-examples --bin http3_client_server --features http-full,rustls,ring -- server --cert cert.pem --key key.pem
//! cargo run -p rama-examples --bin http3_client_server --features http-full,rustls,ring -- client --ca cert.pem --url https://localhost:4433/ --body hello
//! ```
//! The server echoes a streamed POST body, including trailers. GET returns a greeting.
//! The client repeats requests through the normal multiplex connection pool.

use clap::{Parser, Subcommand};
use rama::{
    Service, ServiceInput,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::BoxError,
    extensions::Extensions,
    graceful::Shutdown,
    http::{
        Body, Method, Request, Response, Version,
        body::util::BodyExt as _,
        client::{EasyHttpConnectorBuilder, Http3Connector},
        server::HttpServer,
    },
    net::address::SocketAddress,
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    telemetry::tracing::{self, level_filters::LevelFilter, subscriber::EnvFilter},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
struct Args {
    /// Increase logging detail; RUST_LOG overrides this default.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(long, default_value = "127.0.0.1:4433")]
        listen: SocketAddress,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    Client {
        #[arg(long)]
        ca: PathBuf,
        #[arg(long, default_value = "https://localhost:4433/")]
        url: String,
        #[arg(long)]
        body: Option<String>,
        #[arg(long, default_value_t = 3)]
        count: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let level = match args.verbose {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    tracing::subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy(),
        )
        .init();
    let (finished, completed) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = completed => {},
        }
    });
    let exec = Executor::graceful(shutdown.guard());
    match args.mode {
        Mode::Server { listen, cert, key } => {
            let auth = ServerAuthData {
                cert_chain: CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
                private_key: PrivateKeyDer::from_pem_file(key)?,
                ocsp: None,
            };
            let tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([b"h3".as_slice().into()].into_iter().collect());
            let server = HttpServer::new_http3(exec.clone());
            let mut transport = TransportConfig::default();
            server.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
            config.set_transport_config(Arc::new(transport));
            let endpoint = Endpoint::build(exec.clone())
                .with_server_config(config)
                .bind_address(listen)
                .await?;
            tracing::info!("HTTP/3 listening on {}", endpoint.local_addr()?);
            let guard = shutdown.guard();
            let service = server.service(service_fn(echo));
            loop {
                let incoming = tokio::select! {
                    _ = guard.cancelled() => break,
                    incoming = endpoint.accept() => match incoming {
                        Some(incoming) => incoming,
                        None => break,
                    },
                };
                let service = service.clone();
                exec.spawn_task(async move {
                    let result: Result<(), BoxError> = async {
                        let connection = incoming.await?;
                        tracing::info!("accepted HTTP/3 connection");
                        service
                            .serve(ServiceInput {
                                input: connection,
                                extensions: Extensions::new(),
                            })
                            .await?;
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        tracing::debug!(%error, "connection ended");
                    }
                });
            }
            drop(service);
            drop(guard);
            endpoint.shutdown().await;
        }
        Mode::Client {
            ca,
            url,
            body,
            count,
        } => {
            let anchors = CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?;
            let tls = TlsClientConfig::new().try_with_server_trust_anchors(anchors)?;
            let connector = Http3Connector::<Body>::builder(exec.clone())
                .with_tls_config(tls.clone())
                .build()
                .await?;
            let client_builder = EasyHttpConnectorBuilder::new()
                .with_default_transport_connector()
                .with_default_dns_connector()
                .without_tls_proxy_support()
                .with_proxy_support();
            #[cfg(feature = "rustls")]
            let client_builder = client_builder.with_tls_support_using_rustls(tls.clone());
            #[cfg(all(not(feature = "rustls"), feature = "boring"))]
            let client_builder = client_builder.with_tls_support_using_boringssl(tls.clone());
            #[cfg(not(any(feature = "rustls", feature = "boring")))]
            let client_builder = client_builder.without_tls_support();
            let client = client_builder
                .with_default_http_connector(exec.clone())
                .with_http3_support(connector)
                .with_default_connection_pool()
                .build_client();
            for _ in 0..count {
                let request = Request::builder()
                    .uri(url.as_str())
                    .version(Version::HTTP_3)
                    .method(if body.is_some() {
                        Method::POST
                    } else {
                        Method::GET
                    })
                    .body(body.clone().map_or_else(Body::empty, Body::from))?;
                let response =
                    tokio::time::timeout(Duration::from_secs(15), client.serve(request)).await??;
                assert_eq!(response.version(), Version::HTTP_3);
                let status = response.status();
                let received = response.into_body().collect().await?;
                tracing::info!(%status, trailers = ?received.trailers(), "HTTP/3 response");
                tracing::info!("{}", String::from_utf8_lossy(&received.to_bytes()));
            }
            drop(client);
        }
    }
    _ = finished.send(());
    drop(exec);
    shutdown
        .shutdown_with_limit(Duration::from_secs(15))
        .await?;
    tracing::info!("HTTP/3 shutdown joined");
    Ok(())
}

async fn echo(request: Request) -> Result<Response, Infallible> {
    let body = if request.method() == Method::GET {
        Body::from("hello over HTTP/3\n")
    } else {
        request.into_body()
    };
    Ok(Response::new(body))
}
