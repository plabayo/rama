//! HTTP(S) MITM proxy built from Rama's Relay/Peek services.
//!
//! CONNECT targets are established before returning success. Rama then peeks the tunneled
//! protocol, mirrors TLS with [`TlsMitmRelay`], and relays HTTP with
//! [`HttpMitmRelay`]. WebSocket upgrades use [`HttpUpgradeMitmRelayLayer`]
//! instead of hand-written ingress/egress tasks.
//!
//! This example is not production ready. A real deployment should load a
//! persistent, client-trusted MITM CA and define explicit inspection policy.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_mitm_proxy_boring --features=http-full,boring
//! ```
//!
//! The server listens on `127.0.0.1:62017`:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' https://www.example.com/
//! rama -k --proxy http://127.0.0.1:62017 --proxy-user 'john:secret' wss://echo.ramaproxy.org
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
            compression::{MirrorDecompressed, stream::StreamCompressionLayer},
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{EagerHttpProxyConnector, UpgradeLayer, mitm::HttpUpgradeMitmRelayLayer},
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        ws::handshake::{
            matcher::{HttpWebSocketRelayServiceRequestMatcher, WebSocketMatcher},
            mitm::{
                WebSocketRelayInput, WebSocketRelayMessage, WebSocketRelayOutput,
                WebSocketRelayService,
            },
        },
    },
    io::{BridgeIo, Io},
    layer::{ArcLayer, ConsumeErrLayer, HijackLayer, MapOutputLayer, TimeoutLayer},
    net::{http::server::HttpPeekRouter, proxy::IoForwardService, user::credentials::basic},
    rt::Executor,
    service::service_fn,
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
    utils::{macros::match_ignore_ascii_case_str, octets::mib},
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

    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind_address("127.0.0.1:62017")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62017");

        let connect = EagerHttpProxyConnector::new(
            TimeoutLayer::new(Duration::from_secs(30)).into_layer(
                rama::dns::client::DnsConnector::new(
                    rama::tcp::client::service::TcpConnector::new(),
                ),
            ),
            mitm_svc,
        );
        let web_client =
            EasyHttpWebClient::default_with_executor(Executor::graceful(guard.clone()))
                .with_isolate_forward_proxy_auth_error(true);
        let web_client = (
            RemoveRequestHeaderLayer::hop_by_hop(),
            HijackLayer::new(
                WebSocketMatcher::new(),
                websocket_mitm_layer(exec.clone()).into_layer(web_client.clone()),
            ),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(web_client);
        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(Executor::graceful(guard), MethodMatcher::CONNECT, connect),
                (
                    ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                    MapResponseBodyLayer::new_boxed_streaming_body(),
                    StreamCompressionLayer::new()
                        .with_compress_predicate(MirrorDecompressed::new())
                        .with_enforce_not_acceptable(false),
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
                ),
            )
                .into_layer(web_client),
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
        websocket_mitm_layer(exec.clone()),
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
                organisation_name: Some("HTTP MITM Proxy Boring Example".to_owned()),
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

fn websocket_mitm_layer(
    exec: Executor,
) -> HttpUpgradeMitmRelayLayer<
    HttpWebSocketRelayServiceRequestMatcher<
        WebSocketRelayService<
            impl Service<WebSocketRelayInput, Output = WebSocketRelayOutput, Error = Infallible> + Clone,
        >,
    >,
> {
    HttpUpgradeMitmRelayLayer::new(
        exec,
        HttpWebSocketRelayServiceRequestMatcher::new(WebSocketRelayService::new(service_fn(
            inspect_websocket_message,
        ))),
    )
}

async fn inspect_websocket_message(
    input: WebSocketRelayInput,
) -> Result<WebSocketRelayOutput, Infallible> {
    let WebSocketRelayInput {
        direction: _,
        message,
        extensions,
    } = input;

    let messages = match message {
        WebSocketRelayMessage::Text(text) => {
            let filtered = text
                .as_str()
                .split_whitespace()
                .map(|word| {
                    let (prefix, core, suffix) = split_word(word);
                    let replacement = replacement_for_word(core);
                    replacement
                        .map(|replacement| format!("{prefix}{replacement}{suffix}"))
                        .unwrap_or_else(|| word.to_owned())
                })
                .collect::<Vec<_>>()
                .join(" ");
            vec![WebSocketRelayMessage::Text(filtered.into())]
        }
        WebSocketRelayMessage::Binary(_) => Vec::new(),
    };

    Ok(WebSocketRelayOutput {
        messages,
        extensions,
    })
}

fn replacement_for_word(word: &str) -> Option<&'static str> {
    match_ignore_ascii_case_str! {
        match (word) {
            "damn" => Some("frack"),
            "hell" => Some("heckscape"),
            "shit" => Some("gronk"),
            "fuck" => Some("zarquon"),
            "bastard" => Some("shazbot"),
            "crap" => Some("quant-dump"),
            "idiot" => Some("neural-misfire"),
            "stupid" => Some("entropy-brained"),
            _ => None,
        }
    }
}

fn split_word(word: &str) -> (&str, &str, &str) {
    let bytes = word.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();

    while start < end && !bytes[start].is_ascii_alphanumeric() {
        start += 1;
    }
    while end > start && !bytes[end - 1].is_ascii_alphanumeric() {
        end -= 1;
    }

    (&word[..start], &word[start..end], &word[end..])
}
