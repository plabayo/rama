//! rama proxy service

use clap::Args;
use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext},
    graceful::ShutdownGuard,
    http::{
        BodyLimitLayer, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{EagerHttpProxyConnector, LazyHttpProxyConnectReplyService, UpgradeLayer},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{
        LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RatePolicy, UnlimitedPolicy},
    },
    net::{
        address::SocketAddress,
        proxy::IoForwardService,
        stream::layer::{ThrottleLayer, ThrottleMode},
    },
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing,
    utils::octets::mib,
};
use std::{convert::Infallible, time::Duration};

use crate::utils::rate::opt_per_sec;

#[derive(Debug, Args)]
/// rama proxy server
pub struct CliCommandProxy {
    /// the address to bind to
    #[arg(long, default_value_t = SocketAddress::local_ipv4(8080))]
    bind: SocketAddress,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value_t = 8)]
    /// the timeout in seconds for each connection (0 = no timeout)
    timeout: u64,

    /// timeout in seconds for establishing an egress connection (0 = no timeout)
    #[arg(long, default_value_t = 30)]
    connect_timeout: u64,

    #[arg(long, default_value_t = 0)]
    /// rate limit the proxy in new connections per second (0 = no limit)
    rate: u64,

    #[arg(long, default_value_t = 0)]
    /// throttle each connection at the given byte rate
    /// (bytes per second, both directions; 0 = no throttling)
    throttle: u64,

    /// acknowledge HTTP CONNECT before establishing the egress connection
    ///
    /// By default the proxy connects to the requested target before returning a
    /// successful handshake response.
    #[arg(long, default_value_t = false)]
    lazy_connect: bool,
}

/// run the rama proxy service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandProxy) -> Result<(), BoxError> {
    tracing::info!("starting proxy on: bind interface = {}", cfg.bind);
    let exec = Executor::graceful(graceful);

    let tcp_service = TcpListener::build(exec.clone())
        .bind_address(cfg.bind)
        .await
        .context("bind proxy service")?;

    let bind_address = tcp_service
        .local_addr()
        .context("get local addr of tcp listener")?;

    exec.clone().into_spawn_task(async move {
        let upgrade_layer = if cfg.lazy_connect {
            UpgradeLayer::new_with_services(
                exec.clone(),
                MethodMatcher::CONNECT,
                LazyHttpProxyConnectReplyService::new(),
                IoToProxyBridgeIoLayer::extension_connector_target()
                    .with_connector(
                        (cfg.connect_timeout > 0)
                            .then(|| TimeoutLayer::new(Duration::from_secs(cfg.connect_timeout)))
                            .into_layer(rama::dns::client::DnsConnector::new(
                                rama::tcp::client::service::TcpConnector::new(),
                            )),
                    )
                    .into_layer(IoForwardService::new(exec.clone())),
            )
        } else {
            let connect = EagerHttpProxyConnector::new(
                (cfg.connect_timeout > 0)
                    .then(|| TimeoutLayer::new(Duration::from_secs(cfg.connect_timeout)))
                    .into_layer(rama::dns::client::DnsConnector::new(
                        rama::tcp::client::service::TcpConnector::new(),
                    )),
                IoForwardService::new(exec.clone()),
            );
            UpgradeLayer::new(exec.clone(), MethodMatcher::CONNECT, connect)
        };

        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                upgrade_layer,
                RemoveResponseHeaderLayer::hop_by_hop(),
                RemoveRequestHeaderLayer::hop_by_hop(),
            )
                .into_layer(service_fn(http_plain_proxy)),
        );

        let tcp_service_builder = (
            // protect the http proxy from too large bodies, both from request and response end
            BodyLimitLayer::symmetric(mib(2)),
            opt_per_sec(Some(cfg.rate)).map(|rate| LimitLayer::new(RatePolicy::abort(rate))),
            LimitLayer::new(if cfg.concurrent > 0 {
                Either::A(ConcurrentPolicy::max(cfg.concurrent))
            } else {
                Either::B(UnlimitedPolicy::new())
            }),
            if cfg.timeout > 0 {
                TimeoutLayer::new(Duration::from_secs(cfg.timeout))
            } else {
                TimeoutLayer::never()
            },
            opt_per_sec(Some(cfg.throttle))
                .map(|rate| ThrottleLayer::symmetric(ThrottleMode::per_conn(rate))),
        );

        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "proxy ready: bind interface = {}", cfg.bind,
        );

        tcp_service
            .serve(tcp_service_builder.into_layer(http_service))
            .await;
    });

    Ok(())
}

async fn http_plain_proxy(req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        proxy: CliCommandProxy,
    }

    #[test]
    fn connect_before_reply_is_the_cli_default() {
        let cli = TestCli::parse_from(["test"]);
        assert!(!cli.proxy.lazy_connect);
    }

    #[test]
    fn lazy_connect_remains_available_as_an_opt_in() {
        let cli = TestCli::parse_from(["test", "--lazy-connect"]);
        assert!(cli.proxy.lazy_connect);
    }
}
