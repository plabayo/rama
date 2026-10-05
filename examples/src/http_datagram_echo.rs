//! HTTP Datagrams (RFC 9297) over HTTP/3 through the ordinary Rama client and server stacks.
//!
//! The server enables Extended CONNECT and echoes every HTTP Datagram of a custom
//! `x-datagram-echo` upgrade token through [`HttpDatagramSession`]. Both sides declare the
//! token's datagram semantics with [`HttpDatagrams`]; with QUIC DATAGRAM negotiated both ways
//! they travel natively (unreliable), otherwise as DATAGRAM capsules.
//!
//! Run with `--features http-full,rustls,ring` (or `http-full,boring`):
//!
//! ```sh
//! cargo run -p rama-examples --bin http_datagram_echo --features http-full,rustls,ring -- server --cert cert.pem --key key.pem
//! cargo run -p rama-examples --bin http_datagram_echo --features http-full,rustls,ring -- client --ca cert.pem --url https://localhost:4433/echo --datagram hello
//! ```

use clap::{Parser, Subcommand};
use rama::{
    Layer, Service,
    bytes::Bytes,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    futures::{StreamExt as _, stream::FuturesUnordered},
    graceful::Shutdown,
    http::{
        Body, Request, Response, Version,
        client::{EasyHttpConnectorBuilder, Http3Connector},
        datagram::{
            HttpDatagramSession, SessionEvent, ViolationPolicy,
            handshake::{
                capsule_response, prepare_capsule_request, validate_capsule_request,
                validate_capsule_response,
            },
        },
        io::upgrade::handle_upgrade,
        layer::error_handling::ErrorHandlerLayer,
        proto::ext::{HttpDatagrams, Protocol},
        server::HttpServer,
        service::web::Router,
    },
    layer::ArcLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol},
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

const TOKEN: Protocol = Protocol::from_static("x-datagram-echo");
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

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
        #[arg(long, default_value = "https://localhost:4433/echo")]
        url: String,
        #[arg(long = "datagram", default_value = "hello datagram")]
        datagrams: Vec<String>,
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
            serve(&shutdown, exec.clone(), listen, cert, key).await?;
        }
        Mode::Client { ca, url, datagrams } => client(exec.clone(), ca, url, datagrams).await?,
    }
    _ = finished.send(());
    drop(exec);
    shutdown
        .shutdown_with_limit(Duration::from_secs(15))
        .await?;
    tracing::info!("HTTP datagram echo shutdown joined");
    Ok(())
}

async fn client(
    exec: Executor,
    ca: PathBuf,
    url: String,
    datagrams: Vec<String>,
) -> Result<(), BoxError> {
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
        .with_default_http_connector(exec)
        .with_http3_support(connector)
        .with_default_connection_pool()
        .build_client();
    let mut request = Request::builder()
        .version(Version::HTTP_3)
        .uri(url.as_str())
        .body(Body::empty())?;
    prepare_capsule_request(&mut request, TOKEN)?;
    // The token defines datagram semantics (RFC 9297 §2): declare them for this request.
    request.extensions().insert(HttpDatagrams);
    let response = client.serve(request).await?;
    validate_capsule_response(
        Version::HTTP_3,
        &TOKEN,
        &response,
        ViolationPolicy::default(),
    )?;
    let mut session = HttpDatagramSession::new(handle_upgrade(&response).await?);
    for datagram in datagrams {
        let sent = session.send_datagram(Bytes::from(datagram.clone())).await?;
        let Some(SessionEvent::Datagram { payload, transport }) =
            tokio::time::timeout(RECEIVE_TIMEOUT, session.recv()).await??
        else {
            return Err(BoxError::from_static_str("session ended before the echo"));
        };
        tracing::info!(
            ?sent,
            ?transport,
            "HTTP datagram echo: {}",
            String::from_utf8_lossy(&payload)
        );
    }
    session.close().await?;
    drop(client);
    Ok(())
}

/// Echo every datagram until the client finishes its data stream.
async fn echo(request: Request) -> Result<Response, Infallible> {
    let protocol = match validate_capsule_request(&request, ViolationPolicy::default()) {
        Ok(protocol) if protocol == TOKEN => protocol,
        // RFC 9220 §3: an unsupported upgrade token gets 501.
        _ => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = rama::http::StatusCode::NOT_IMPLEMENTED;
            return Ok(response);
        }
    };
    let upgrade = handle_upgrade(&request);
    tokio::spawn(async move {
        let result: Result<(), BoxError> = async {
            let mut session = HttpDatagramSession::new(upgrade.await?);
            while let Some(event) = session.recv().await? {
                if let SessionEvent::Datagram { payload, transport } = event {
                    let echoed = session.send_datagram(payload).await?;
                    tracing::debug!(?transport, ?echoed, "echoed HTTP datagram");
                }
            }
            session.close().await?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, "datagram session ended");
        }
    });
    let Ok(response) = capsule_response::<Body>(request.version(), &protocol) else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = rama::http::StatusCode::HTTP_VERSION_NOT_SUPPORTED;
        return Ok(response);
    };
    // Accepting the token declares its datagram semantics for this request.
    response.extensions().insert(HttpDatagrams);
    Ok(response)
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
    // RFC 9220: advertise Extended CONNECT so clients may send a `:protocol` token.
    server.http3_mut().extended_connect = true;
    let mut transport = TransportConfig::default();
    server.http3().configure_transport(&mut transport)?;
    let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(Executor::new())
        .with_server_config(config)
        .bind_address(listen)
        .await?;
    tracing::info!("HTTP datagram echo listening on {}", endpoint.local_addr()?);
    let guard = shutdown.guard();
    let service = server.service(
        (ArcLayer::new(), ErrorHandlerLayer::new())
            .into_layer(Router::new().with_connect("/echo", service_fn(echo))),
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
