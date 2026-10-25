//! A CONNECT-UDP proxy (RFC 9298, one of the MASQUE protocols) and a client sending HTTP/3
//! through it, both built from Rama's layers.
//!
//! Run with `--features http-full,boring`:
//!
//! ```sh
//! cargo run -p rama-examples --bin masque_connect_udp_proxy --features http-full,boring -- proxy --listen 127.0.0.1:4433
//! cargo run -p rama-examples --bin masque_connect_udp_proxy --features http-full,boring -- client \
//!     --proxy masque://127.0.0.1:4433 --insecure --url https://cloudflare-quic.com/
//! ```
//!
//! The proxy serves CONNECT-UDP next to ordinary CONNECT for TCP, on one port: TLS over TCP for
//! HTTP/1.1 and HTTP/2, QUIC over UDP for HTTP/3. Its certificate is self-signed, hence the
//! client's `--insecure`, which skips certificate verification for local testing. Without it
//! the client is `DefaultHttpWebClient::default_masque_with_executor`, verifying both.

use clap::{Parser, Subcommand};
use rama::{
    Layer as _, Service,
    dns::client::DnsConnector,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef as _,
    graceful::Shutdown,
    http::{
        Body, Request, Version,
        body::util::BodyExt as _,
        client::{DefaultHttpWebClient, masque_quic_transport},
        conn::TargetHttpVersion,
        layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        proxy::HttpProxyConnectMatcher,
        server::HttpServer,
    },
    net::{
        address::{ProxyAddress, SocketAddress},
        client::ProxyRoute,
        proxy::IoForwardService,
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{ConnectUdpService, DestinationScopePolicy},
    quic::{Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    tcp::{client::service::TcpConnector, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter, subscriber::EnvFilter},
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve a CONNECT-UDP proxy.
    Proxy {
        /// Address for TCP and UDP alike.
        #[arg(long, default_value = "127.0.0.1:4433")]
        listen: SocketAddress,
        /// Let CONNECT-UDP reach loopback and private targets, refused by default.
        #[arg(long)]
        allow_private: bool,
    },
    /// GET `url` over HTTP/3 through a CONNECT-UDP proxy.
    Client {
        /// The proxy, such as `masque://user:pass@proxy.example:443`.
        #[arg(long)]
        proxy: ProxyAddress,
        /// Skip certificate verification of the proxy and the origin, for local testing.
        #[arg(long)]
        insecure: bool,
        #[arg(long)]
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    match Args::parse().command {
        Command::Proxy {
            listen,
            allow_private,
        } => proxy(listen, allow_private).await,
        Command::Client {
            proxy,
            insecure,
            url,
        } => client(proxy, insecure, &url).await,
    }
}

async fn proxy(listen: SocketAddress, allow_private: bool) -> Result<(), BoxError> {
    let shutdown = Shutdown::default();
    let exec = Executor::graceful(shutdown.guard());

    // CONNECT-UDP for UDP targets, resolved and checked by the proxy, and ordinary CONNECT
    // for TCP targets; any authentication layer goes in front of both.
    let policy = if allow_private {
        DestinationScopePolicy::allow_private()
    } else {
        DestinationScopePolicy::default()
    };
    let connect_udp = ConnectUdpService::try_new(exec.clone(), None)?.with_policy(policy);
    let service = Arc::new(
        UpgradeLayer::new(
            exec.clone(),
            HttpProxyConnectMatcher::new(),
            EagerHttpProxyConnector::new(
                DnsConnector::new(TcpConnector::new()),
                IoForwardService::new(exec.clone()),
            ),
        )
        .into_layer(connect_udp),
    );

    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
    let tcp_tls = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_alpn_http_auto();
    let mut http = HttpServer::auto(exec.clone());
    // HTTP/2 carries CONNECT-UDP as an Extended CONNECT.
    http.h2_mut().set_enable_connect_protocol();
    let listener = TcpListener::bind_address(listen, exec.clone())
        .await
        .context("bind TCP")?;
    let address = SocketAddress::from(listener.local_addr()?);

    let mut h3 = HttpServer::new_http3(exec.clone());
    h3.http3_mut().extended_connect = true;
    // Room for a tunneled QUIC packet in every datagram, and quiet tunnels kept open.
    let mut transport = masque_quic_transport();
    h3.http3().configure_transport(&mut transport)?;
    let quic_tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = ServerConfig::try_from_rama_tls(&quic_tls, TlsOptions::default())?;
    config.set_transport_config(Arc::new(transport));
    let endpoint = Endpoint::build(exec.clone())
        .with_server_config(config)
        .bind_address(address)
        .await
        .context("bind UDP")?;

    exec.spawn_task(
        listener.serve(TlsAcceptorLayer::new(tcp_tls).into_layer(http.service(service.clone()))),
    );
    exec.spawn_task(endpoint.serve(exec.clone(), h3.service(service)));
    // Shutdown waits on the tasks' guards, not on this executor's.
    drop(exec);
    tracing::info!("CONNECT-UDP proxy listening on {address}");

    shutdown
        .shutdown_with_limit(Duration::from_secs(5))
        .await
        .map(drop)
        .map_err(Into::into)
}

async fn client(proxy: ProxyAddress, insecure: bool, url: &str) -> Result<(), BoxError> {
    let (finished, done) = oneshot::channel::<()>();
    let shutdown = Shutdown::new(async move {
        _ = done.await;
    });
    let result = exchange(Executor::graceful(shutdown.guard()), proxy, insecure, url).await;
    finished.send(()).unwrap_or_default();
    // Draining closes the QUIC connections, so no peer waits out an idle timeout.
    shutdown.shutdown_with_limit(Duration::from_secs(1)).await?;
    result
}

async fn exchange(
    exec: Executor,
    proxy: ProxyAddress,
    insecure: bool,
    url: &str,
) -> Result<(), BoxError> {
    let client = if insecure {
        let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
        DefaultHttpWebClient::try_default_masque_using_boringssl(exec, tls.clone(), tls)?
    } else {
        DefaultHttpWebClient::default_masque_with_executor(exec)
    };

    let request = Request::builder()
        .version(Version::HTTP_3)
        .uri(url)
        .body(Body::empty())?;
    request.extensions().insert(ProxyRoute::Proxy(proxy));
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    let response = client.serve(request).await?;
    tracing::info!(version = ?response.version(), status = %response.status(), "response");
    let body = response.into_body().collect().await?.to_bytes();
    tracing::info!("{}", String::from_utf8_lossy(&body));
    Ok(())
}
