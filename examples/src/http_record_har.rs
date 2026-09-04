//! HAR recording layered onto a Relay/Peek HTTP(S) MITM proxy.
//!
//! CONNECT targets are established before tunnel success. TLS and HTTP are inspected through
//! Rama's relay services, while [`HARExportLayer`] records selected traffic.
//! This is a diagnostics example, not a production proxy configuration.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_record_har --features=http-full,boring
//! ```
//!
//! The server listens on `127.0.0.1:62040`:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' https://www.example.com/
//! curl -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' -XPOST http://har.toggle.internal/switch
//! ```
//!
//! Recorded responses expose their HAR path in `x-rama-har-file-path` for
//! demonstration purposes. Do not expose local paths this way in production.

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    http::{
        BodyLimitLayer, HeaderValue, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            har::{
                self,
                layer::HARExportLayer,
                recorder::{FileRecorder, HarFilePath, Recorder},
            },
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
        },
        matcher::{DomainMatcher, MethodMatcher},
        proxy::mitm::HttpMitmRelay,
        server::HttpServer,
        service::web::WebService,
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, MapOutputLayer, TimeoutLayer},
    net::{http::server::HttpPeekRouter, proxy::IoForwardService, user::credentials::basic},
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

    let (har_toggle, har_toggle_ctl) =
        har::toggle::mpsc_toggle(8, graceful.guard_weak().into_cancelled());
    let har_layer = HARExportLayer::new(FileRecorder::default(), har_toggle);
    let mitm_svc =
        new_mitm_svc(&exec, har_layer.clone()).context("build HAR MITM relay service")?;

    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind_address("127.0.0.1:62040")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62040");

        let toggle_har_layer = har_layer.clone();
        let toggle_service = Arc::new(WebService::default().with_post(
            "/switch",
            move |_req: Request| {
                let har_toggle_ctl = har_toggle_ctl.clone();
                let har_layer = toggle_har_layer.clone();
                async move {
                    if let Err(err) = har_toggle_ctl.send(()).await {
                        tracing::error!("failed to toggle HAR recording: {err}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        har_layer.recorder().stop_record().await;
                        StatusCode::OK
                    }
                }
            },
        ));

        let connect = EagerHttpProxyConnector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(
                rama::dns::client::DnsConnector::new(
                    rama::tcp::client::service::TcpConnector::new(),
                ),
            ),
            mitm_svc,
        );
        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                ProxyAuthLayer::new(basic!("john", "secret")),
                HijackLayer::new(DomainMatcher::exact("har.toggle.internal"), toggle_service),
                UpgradeLayer::new(Executor::graceful(guard), MethodMatcher::CONNECT, connect),
                RemoveRequestHeaderLayer::hop_by_hop(),
                MapOutputLayer::new(add_har_file_header),
                MapResponseBodyLayer::new_boxed_streaming_body(),
                StreamCompressionLayer::new()
                    .with_compress_predicate(MirrorDecompressed::new())
                    .with_enforce_not_acceptable(false),
                har_layer,
                DecompressionLayer::new()
                    .with_insert_accept_encoding_header(false)
                    .with_tolerate_decode_errors(true),
                RemoveResponseHeaderLayer::hop_by_hop(),
                ArcLayer::new(),
            )
                .into_layer(
                    EasyHttpWebClient::default_with_executor(exec)
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
    har_layer: HARExportLayer<FileRecorder, Arc<std::sync::atomic::AtomicBool>>,
) -> Result<
    impl Service<BridgeIo<Ingress, Egress>, Output = (), Error = Infallible> + Clone,
    BoxError,
>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
{
    let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        MapOutputLayer::new(add_har_file_header),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        // Record decoded representation bytes, then restore the upstream
        // content coding before returning the response to the client.
        StreamCompressionLayer::new()
            .with_compress_predicate(MirrorDecompressed::new())
            .with_enforce_not_acceptable(false),
        har_layer,
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
                organisation_name: Some("HTTP HAR MITM Relay Example".to_owned()),
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

fn add_har_file_header(mut response: Response) -> Response {
    if let Some(path) = response
        .extensions()
        .get_ref::<HarFilePath>()
        .map(|path| path.display().to_string())
        .and_then(|path| HeaderValue::try_from(path).ok())
    {
        response.headers_mut().insert("x-rama-har-file-path", path);
    }
    response
}
