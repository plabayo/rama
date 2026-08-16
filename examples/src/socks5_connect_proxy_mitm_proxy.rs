//! An authenticated SOCKS5 CONNECT proxy that uses Rama's Relay/Peek stack to
//! MITM HTTP and HTTPS traffic.
//!
//! The SOCKS5 handshake establishes the requested egress connection before returning success.
//! The resulting ingress/egress pair is then routed by protocol: TLS is mirrored
//! with [`TlsMitmRelay`], while HTTP is relayed with [`HttpMitmRelay`]. This keeps
//! the example on the same connection from handshake through application relay.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin socks5_connect_proxy_mitm_proxy --features=dns,socks5,boring,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62022`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x socks5://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x socks5://127.0.0.1:62022 --proxy-user 'john:secret' https://www.example.com/
//! curl -k -v -x socks5h://127.0.0.1:62022 --proxy-user 'john:secret' https://www.example.com/
//! ```

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{
        HeaderName, HeaderValue,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            trace::TraceLayer,
        },
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, MapOutputLayer, TimeoutLayer},
    net::{http::server::HttpPeekRouter, proxy::IoForwardService, user::credentials::basic},
    proxy::socks5::{Socks5Acceptor, server::Connector},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        boring::proxy::TlsMitmRelay,
        server::{CertificateSubject, PeekTlsClientHelloService, SelfSignedCaConfig},
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());
    let mitm_svc = new_mitm_svc(&exec).context("build MITM relay service")?;

    let tcp_service = TcpListener::bind_address("127.0.0.1:62022", exec.clone())
        .await
        .context("bind proxy to 127.0.0.1:62022")?;
    let socks5_acceptor = Socks5Acceptor::new(exec.clone())
        .with_authorizer(basic!("john", "secret").into_authorizer())
        .with_connector(Connector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(
                rama::dns::client::DnsConnector::new(
                    rama::tcp::client::service::TcpConnector::new(),
                ),
            ),
            mitm_svc,
        ));
    graceful.spawn_task(tcp_service.serve(socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;

    Ok(())
}

fn new_mitm_svc<Ingress, Egress>(
    exec: &Executor,
) -> Result<
    impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone,
    BoxError,
>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        // Decode before HTTP body middleware and restore the upstream encoding
        // afterwards so inspectors operate on representation bytes.
        StreamCompressionLayer::new()
            .with_compress_predicate(MirrorDecompressed::new())
            .with_enforce_not_acceptable(false),
        TraceLayer::new_for_http(),
        SetRequestHeaderLayer::overriding(
            HeaderName::from_static("x-observed"),
            HeaderValue::from_static("1"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-proxy"),
            HeaderValue::from_static(rama::utils::info::NAME),
        ),
        DecompressionLayer::new()
            .with_insert_accept_encoding_header(false)
            .with_tolerate_decode_errors(true),
        ArcLayer::new(),
    ));
    let maybe_http_relay = HttpPeekRouter::new(http_mitm_relay)
        .with_known_non_http_protocol_methods()
        .with_fallback(MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())));

    let tls_mitm_relay =
        TlsMitmRelay::try_new_with_cached_self_signed_issuer(&SelfSignedCaConfig {
            subject: CertificateSubject {
                organisation_name: Some("SOCKS5 MITM Relay Proxy Example".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        })
        .context("build TLS MITM relay")?;

    let app_mitm_relay =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_relay.clone()))
            .with_fallback(maybe_http_relay);

    Ok(Arc::new(
        ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_relay),
    ))
}
