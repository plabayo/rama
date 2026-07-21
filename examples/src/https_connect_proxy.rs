//! This example demonstrates how to create an https proxy.
//!
//! This proxy example does not perform any TLS termination on the actual proxied traffic.
//! It is an adaptation of the `http_connect_proxy` example with tls termination for the incoming connections.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin https_connect_proxy --features=http-full,rustls,aws-lc
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62016`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl --proxy-insecure -v -x https://127.0.0.1:62016 --proxy-user 'john:secret' http://www.example.com
//! curl --proxy-insecure -k -v https://127.0.0.1:62016 --proxy-user 'john:secret' https://www.example.com
//! ```
//!
//! You should see in both cases the responses from the example domains.
//!
//! In case you want to use it in a standard browser,
//! you'll need to first import and trust the generated certificate.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    graceful::Shutdown,
    http::{
        Body, BodyLimitLayer, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            proxy_auth::ProxyAuthLayer,
            trace::TraceLayer,
            upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::{proxy::IoForwardService, user::credentials::basic},
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::server::SelfSignedData,
    utils::octets::mib,
};

#[cfg(feature = "boring")]
use rama::tls::boring::server::TlsAcceptorLayer;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use rama::tls::rustls::server::TlsAcceptorLayer;

#[cfg(any(feature = "boring", feature = "rustls"))]
use rama::tls::{KeyLogIntent, server::TlsServerConfig};

use std::convert::Infallible;
use std::time::Duration;

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    #[cfg(any(feature = "rustls", feature = "boring"))]
    let tls_service_data = TlsServerConfig::new()
        .try_with_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self-signed")
        .with_alpn_http_auto()
        .with_keylog(KeyLogIntent::Environment);

    // create tls proxy
    shutdown.spawn_task_fn(async |guard| {
        let exec = Executor::graceful(guard);
        let tcp_service = TcpListener::build(exec.clone())
            .bind_address("127.0.0.1:62016")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62016");

        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filter
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(
                    exec.clone(),
                    MethodMatcher::CONNECT,
                    DefaultHttpProxyConnectReplyService::new(),
                    (
                        ConsumeErrLayer::default(),
                        IoToProxyBridgeIoLayer::extension_connector_target().with_connector(
                            rama::dns::client::DnsConnector::new(
                                rama::tcp::client::service::TcpConnector::new(),
                            ),
                        ),
                    )
                        .into_layer(IoForwardService::new(exec)),
                ),
            )
                .into_layer(service_fn(http_plain_proxy)),
        );

        tcp_service
            .serve(
                (
                    // protect the http proxy from too large bodies, both from request and response end
                    BodyLimitLayer::symmetric(mib(2)),
                    TlsAcceptorLayer::new(tls_service_data).with_store_client_hello(true),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_plain_proxy(req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
    let uri = req.uri().clone();
    tracing::debug!(
        url.full = %req.uri(),
        "proxy connect plain text request",
    );
    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(
                url.full = %uri,
                "error in client request: {err:?}",
            );
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
