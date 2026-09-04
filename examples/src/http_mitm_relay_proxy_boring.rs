//! This example builds on Rama's Relay/Peek architecture to demonstrate egress
//! request shaping and inspection. CONNECT establishes egress before returning
//! success and hands the resulting ingress/egress pair to the protocol relays.
//!
//! The TLS relay mirrors the ingress ClientHello and target certificate, while
//! HTTP middleware auto-detects the user-agent profile, emulates its outgoing
//! request headers, and prints the final egress headers.
//!
//! Note that this proxy is not production ready, and is only meant
//! to show you how one might start.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_mitm_relay_proxy_boring --features=http-full,boring
//! ```
//!
//! ## Expected output
//!
//! The server will start and listen on `:62049`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62049 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62049 --proxy-user 'john:secret' https://www.example.com/
//! ```

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{
        BodyLimitLayer, HeaderName, HeaderValue,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            trace::TraceLayer,
            traffic_writer::{self, RequestWriterLayer},
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, MapOutputLayer, TimeoutLayer},
    net::{http::server::HttpPeekRouter, proxy::IoForwardService, user::credentials::basic},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::proxy::TlsMitmRelay,
    tls::server::{CertificateSubject, PeekTlsClientHelloService, SelfSignedCaConfig},
    ua::{
        layer::emulate::{UserAgentEmulateHttpRequestModifierLayer, UserAgentEmulateLayer},
        profile::UserAgentDatabase,
    },
    utils::octets::mib,
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

    let ua_db =
        Arc::new(UserAgentDatabase::try_embedded().context("load embedded user-agent database")?);
    let mitm_svc = new_mitm_svc(&exec, ua_db).context("build MITM service")?;

    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind_address("127.0.0.1:62049")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62049");

        let connect = EagerHttpProxyConnector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(
                rama::dns::client::DnsConnector::new(
                    rama::tcp::client::service::TcpConnector::new(),
                ),
            ),
            mitm_svc,
        );
        let http_service = HttpServer::auto(exec).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(
                    Executor::graceful(guard.clone()),
                    MethodMatcher::CONNECT,
                    connect,
                ),
                (
                    RemoveRequestHeaderLayer::hop_by_hop(),
                    SetRequestHeaderLayer::overriding(
                        HeaderName::from_static("x-observed"),
                        HeaderValue::from_static("1"),
                    ),
                    SetResponseHeaderLayer::overriding(
                        HeaderName::from_static("x-proxy"),
                        HeaderValue::from_static(rama::utils::info::NAME),
                    ),
                    SetResponseHeaderLayer::overriding(
                        HeaderName::from_static("x-proxy-version"),
                        HeaderValue::from_static(rama::utils::info::VERSION),
                    ),
                    RemoveResponseHeaderLayer::hop_by_hop(),
                ),
            )
                .into_layer(
                    EasyHttpWebClient::default_with_executor(Executor::graceful(guard))
                        .with_isolate_forward_proxy_auth_error(true),
                ),
        ));

        tcp_service
            .serve(BodyLimitLayer::symmetric(mib(2)).into_layer(http_service))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;

    Ok(())
}

fn new_mitm_svc<Ingress, Egress>(
    exec: &Executor,
    ua_db: Arc<UserAgentDatabase>,
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
        TraceLayer::new_for_http(),
        UserAgentEmulateLayer::new(ua_db)
            .with_try_auto_detect_user_agent(true)
            .with_is_optional(true),
        SetRequestHeaderLayer::overriding(
            HeaderName::from_static("x-observed"),
            HeaderValue::from_static("1"),
        ),
        UserAgentEmulateHttpRequestModifierLayer::default(),
        RequestWriterLayer::stdout_unbounded(exec, Some(traffic_writer::WriterMode::Headers)),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-proxy"),
            HeaderValue::from_static(rama::utils::info::NAME),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-proxy-version"),
            HeaderValue::from_static(rama::utils::info::VERSION),
        ),
        ArcLayer::new(),
    ));
    let maybe_http_relay = HttpPeekRouter::new(http_mitm_relay)
        .with_known_non_http_protocol_methods()
        .with_fallback(MapOutputLayer::new(drop).into_layer(IoForwardService::new(exec.clone())));

    let tls_mitm_relay =
        TlsMitmRelay::try_new_with_cached_self_signed_issuer(&SelfSignedCaConfig {
            subject: CertificateSubject {
                organisation_name: Some("HTTP MITM Relay Proxy Boring Example".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        })
        .context("build TLS mitm relay")?;

    let app_mitm_layer =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_relay.clone()))
            .with_fallback(maybe_http_relay);

    Ok(Arc::new(
        ConsumeErrLayer::trace_as_debug().into_layer(app_mitm_layer),
    ))
}
