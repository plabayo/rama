//! WebSockets over HTTP/3 (RFC 9220) with the ordinary Rama WebSocket and HTTP APIs.
//!
//! The server enables Extended CONNECT and routes `CONNECT /echo` to a WebSocket echo
//! service; the client bootstraps the socket with `:protocol websocket` over QUIC.
//!
//! Run with `--features http-full,rustls,ring` (or `http-full,boring`), supplying a PEM
//! certificate/key for the server and its trusted CA for the client:
//!
//! ```sh
//! cargo run -p rama-examples --bin ws_over_h3 --features http-full,rustls,ring -- server --cert cert.pem --key key.pem
//! cargo run -p rama-examples --bin ws_over_h3 --features http-full,rustls,ring -- client --ca cert.pem --url wss://localhost:4433/echo --message hello
//! ```
//!
//! The client sends each message, prints the echo and completes the close handshake.
//! It can also be reached with `rama send --http3 wss://localhost:4433/echo`.

use clap::{Parser, Subcommand};
use rama::{
    Layer, Service,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
    futures::{StreamExt as _, stream::FuturesUnordered},
    graceful::Shutdown,
    http::{
        client::{EasyHttpConnectorBuilder, Http3Connector},
        layer::error_handling::ErrorHandlerLayer,
        server::HttpServer,
        service::web::Router,
        ws::{
            Message, handshake::client::HttpClientWebSocketExt as _,
            handshake::server::WebSocketAcceptor,
        },
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    telemetry::tracing::{self, level_filters::LevelFilter, subscriber::EnvFilter},
    tls::{
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
};
use std::{path::PathBuf, sync::Arc, time::Duration};

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
        #[arg(long, default_value = "wss://localhost:4433/echo")]
        url: String,
        #[arg(long = "message", default_value = "hello over HTTP/3")]
        messages: Vec<String>,
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
            serve(&shutdown, exec.clone(), listen, cert, key).await?
        }
        Mode::Client { ca, url, messages } => {
            let anchors = CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?;
            let tls = TlsClientConfig::new().try_with_server_trust_anchors(anchors)?;
            let connector = Http3Connector::builder(exec.clone())
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
            let mut socket = client
                .websocket_h3(url.as_str())
                .handshake(Extensions::new())
                .await?;
            for message in messages {
                socket.send_message(Message::text(message)).await?;
                let echo = socket.recv_message().await?;
                tracing::info!("WebSocket echo over HTTP/3: {}", echo.into_text()?);
            }
            socket.close(None).await?;
            // The close completes with the server's reply, after which the stream ends.
            let mut replied = false;
            while let Some(message) = socket.next().await {
                replied |= matches!(message?, Message::Close(_));
            }
            if !replied {
                return Err(BoxError::from_static_str(
                    "the server did not answer the close",
                ));
            }
            tracing::info!("WebSocket over HTTP/3 close handshake completed");
            drop(client);
        }
    }
    _ = finished.send(());
    drop(exec);
    shutdown
        .shutdown_with_limit(Duration::from_secs(15))
        .await?;
    tracing::info!("WebSocket over HTTP/3 shutdown joined");
    Ok(())
}

async fn serve(
    shutdown: &Shutdown,
    exec: Executor,
    listen: SocketAddress,
    cert: PathBuf,
    key: PathBuf,
) -> Result<(), BoxError> {
    let auth = ServerAuthData {
        cert_chain: CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
        private_key: PrivateKeyDer::from_pem_file(key)?,
        ocsp: None,
    };
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut server = HttpServer::new_http3(exec.clone());
    // RFC 9220: advertise Extended CONNECT so clients may send `:protocol websocket`.
    server.http3_mut().extended_connect = true;
    let mut transport = TransportConfig::default();
    server.http3().configure_transport(&mut transport)?;
    let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(Executor::new())
        .with_server_config(config)
        .bind_address(listen)
        .await?;
    tracing::info!(
        "WebSocket over HTTP/3 listening on {}",
        endpoint.local_addr()?
    );
    let guard = shutdown.guard();
    let service = server.service(
        (ArcLayer::new(), ErrorHandlerLayer::new()).into_layer(
            Router::new().with_connect(
                "/echo",
                ConsumeErrLayer::trace_as_debug()
                    .into_layer(WebSocketAcceptor::new().into_echo_service()),
            ),
        ),
    );
    let mut connections = FuturesUnordered::new();
    loop {
        let incoming = tokio::select! {
            _ = guard.cancelled() => break,
            finished = connections.next(), if !connections.is_empty() => {
                if let Some(Err(error)) = finished {
                    tracing::debug!(%error, "HTTP/3 connection task ended");
                }
                continue;
            }
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
        };
        let service = service.clone();
        connections.push(exec.spawn_task(async move {
            let result: Result<(), BoxError> = async {
                let connection = incoming.await?;
                tracing::info!("accepted HTTP/3 connection");
                service.serve(connection).await?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "connection ended");
            }
        }));
    }
    drop(service);
    drop(guard);
    let drained = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(result) = connections.next().await {
            result?;
        }
        Ok::<_, tokio::task::JoinError>(())
    })
    .await;
    if !matches!(drained, Ok(Ok(()))) {
        for connection in connections.iter() {
            connection.abort();
        }
        while connections.next().await.is_some() {}
    }
    endpoint.shutdown().await;
    drained??;
    Ok(())
}
