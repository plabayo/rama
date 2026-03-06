//! This example shows how one can begin with creating a MITM proxy,
//! using a relay approach. This in contrast to `http_mitm_proxy_boring`,
//! where the flow is rather linear, here the approach is to handshake more like a dance.
//!
//! It is as such a more complex flow, but the advantage is that your proxy's
//! TLS acceptor will mimic the certificate and server (TLS) settings from
//! the target and the http client (egress) will nicely be 1:1 tied
//! the ingress traffic and mirror it.
//!
//! Note that this proxy is not production ready, and is only meant
//! to show you how one might start.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_mitm_relay_proxy_boring --features=http-full,boring
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

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsMut,
    http::{
        HeaderName, HeaderValue, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        http::{RequestContext, server::peek_http_stream},
        proxy::{ProxyTarget, StreamBridge, StreamForwardService},
        stream::layer::http::BodyLimitLayer,
        tls::{
            client::ServerVerifyMode,
            server::{SelfSignedData, peek_client_hello_from_stream},
        },
        user::credentials::basic,
    },
    rt::Executor,
    service::service_fn,
    stream::Stream,
    tcp::{client::default_tcp_connect, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::{
        client::TlsConnectorDataBuilder,
        proxy::{
            TlsMitmRelay,
            cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
        },
    },
};

use std::{sync::Arc, time::Duration};

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

    let mitm_svc = MitmHttpsService::try_new(Executor::graceful(graceful.guard()))?;
    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind("127.0.0.1:62049")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62049");

        let http_service = HttpServer::auto(Executor::graceful(guard.clone())).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(
                    Executor::graceful(guard.clone()),
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    ConsumeErrLayer::trace_as_debug().into_layer(mitm_svc),
                ),
                (
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
                ),
            )
                .into_layer(EasyHttpWebClient::default_with_executor(
                    Executor::graceful(guard),
                )),
        ));

        tcp_service
            .serve(BodyLimitLayer::symmetric(2 * 1024 * 1024).into_layer(http_service))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;

    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

#[derive(Debug, Clone)]
struct MitmHttpsService {
    tls_mitm_relay: TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>,
    exec: Executor,
}

impl MitmHttpsService {
    fn try_new(exec: Executor) -> Result<Self, BoxError> {
        let tls_mitm_relay =
            TlsMitmRelay::try_new_with_cached_self_signed_issuer(&SelfSignedData {
                organisation_name: Some("HTTP MITM Relay Proxy Boring Example".to_owned()),
                ..Default::default()
            })
            .context("create tls MITM relay svc with self-signed CA crt")?;
        Ok(Self {
            tls_mitm_relay,
            exec,
        })
    }
}

impl<IO> Service<IO> for MitmHttpsService
where
    IO: Stream + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, ingress_stream: IO) -> Result<Self::Output, Self::Error> {
        let ProxyTarget(address) = ingress_stream
            .extensions()
            .get()
            .cloned()
            .context("find proxy target in input extensions")?;

        let (egress_stream, egress_addr) =
            default_tcp_connect(ingress_stream.extensions(), address, self.exec.clone())
                .await
                .context("establish TCP connection to egress side")?;
        tracing::debug!("managed to establish connection egress: {egress_addr}");

        let (peeked_ingress_stream, maybe_client_hello) =
            peek_client_hello_from_stream(ingress_stream)
                .await
                .context("peek TLS client hello from stream")?;

        if let Some(client_hello) = maybe_client_hello {
            let maybe_connector_data = TlsConnectorDataBuilder::try_from(client_hello)
                .unwrap_or_default()
                .with_server_verify_mode(ServerVerifyMode::Disable)
                .build()
                .inspect_err(|err| {
                    tracing::error!(
                        "failed to build TlsConnectorData: {err}; try anyway without data"
                    )
                })
                .ok();

            let StreamBridge {
                left: tls_ingress_stream,
                right: tls_egress_stream,
            } = self
                .tls_mitm_relay
                .handshake(
                    StreamBridge {
                        left: peeked_ingress_stream,
                        right: egress_stream,
                    },
                    maybe_connector_data,
                )
                .await
                .context("TLS MITM Relay handshake")?;

            mitm_relay_maybe_http_traffic(self.exec.clone(), tls_ingress_stream, tls_egress_stream)
                .await
                .context("within TLS: (maybe) HTTP MITM Relay")
        } else {
            mitm_relay_maybe_http_traffic(self.exec.clone(), peeked_ingress_stream, egress_stream)
                .await
                .context("(maybe) HTTP MITM Relay")
        }
    }
}

async fn mitm_relay_maybe_http_traffic<Ingress, Egress>(
    exec: Executor,
    ingress_stream: Ingress,
    egress_stream: Egress,
) -> Result<(), BoxError>
where
    Ingress: Stream + Unpin + ExtensionsMut,
    Egress: Stream + Unpin + ExtensionsMut,
{
    let (maybe_http_version, peeked_ingress_stream) =
        peek_http_stream(ingress_stream, Some(Duration::from_mins(2)))
            .await
            .context("peek HTTP traffic")?;

    if let Some(http_version) = maybe_http_version {
        tracing::info!("detected HTTP version: {http_version:?}; continue MITM flow");
    } else {
        tracing::info!("no HTTP version detected: transport bytes as-is");
        StreamForwardService::new()
            .serve(StreamBridge {
                left: peeked_ingress_stream,
                right: egress_stream,
            })
            .await
            .context("proxy no-http bytes")?;
        return Ok(());
    }

    HttpMitmRelay::new(exec)
        .with_http_middleware((
            ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
            MapResponseBodyLayer::new_boxed_streaming_body(),
            TraceLayer::new_for_http(),
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
            ArcLayer::new(),
        ))
        .serve(StreamBridge {
            left: peeked_ingress_stream,
            right: egress_stream,
        })
        .await
}
