//! Echo service that echos the http request and tls client config

use rama::{
    Service,
    cli::ForwardKind,
    combinators::Either7,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        HeaderName, HeaderValue, Request,
        header::COOKIE,
        headers::{
            Cookie, HeaderMapExt, SecWebSocketProtocol, all_client_hint_header_name_strings,
            forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
            sec_websocket_extensions,
        },
        layer::{
            catch_panic::CatchPanicLayer, compression::CompressionLayer,
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            set_header::SetResponseHeaderLayer, trace::TraceLayer, ua::UserAgentClassifierLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            match_service,
            response::{IntoResponse, Redirect},
        },
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::{
        AddExtensionLayer, ConsumeErrLayer, HijackLayer, Layer, LimitLayer, TimeoutLayer,
        limit::policy::ConcurrentPolicy,
    },
    net::{socket::Interface, stream::layer::http::BodyLimitLayer, tls::ApplicationProtocol},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::server::TlsAcceptorLayer,
    utils::backoff::ExponentialBackoff,
};

use clap::Args;
use itertools::Itertools;
use std::{convert::Infallible, sync::Arc, time::Duration};

mod data;
mod endpoints;
mod state;
mod storage;

#[doc(inline)]
use state::State;

use crate::utils::{http::HttpVersion, tls::new_server_config};

#[derive(Debug, Clone, Copy, Default)]
pub struct StorageAuthorized;

#[derive(Debug, Args)]
/// rama fp service (used for FP collection in purpose of UA emulation)
pub struct CliCommandFingerprint {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    #[arg(short = 't', long, default_value_t = 300)]
    /// the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    timeout: u64,

    #[arg(long, short = 'f')]
    /// enable support for one of the following "forward" headers or protocols
    ///
    /// Supported headers:
    ///
    /// Forwarded ("for="), X-Forwarded-For
    ///
    /// X-Client-IP Client-IP, X-Real-IP
    ///
    /// CF-Connecting-IP, True-Client-IP
    ///
    /// Or using HaProxy protocol.
    forward: Option<ForwardKind>,

    /// http version to serve FP Service from
    #[arg(long, default_value = "auto")]
    http_version: HttpVersion,

    #[arg(long, short = 's')]
    /// run echo service in secure mode (enable TLS)
    secure: bool,

    #[arg(long)]
    /// use self-signed certs in case secure is enabled
    self_signed: bool,

    #[arg(long, default_value_t = 8)]
    /// the graceful shutdown timeout in seconds (0 = no timeout)
    graceful: u64,
}

/// run the rama FP service
pub async fn run(cfg: CliCommandFingerprint) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let graceful = rama::graceful::Shutdown::default();

    let (tcp_forwarded_layer, http_forwarded_layer) = match &cfg.forward {
        None => (None, None),
        Some(ForwardKind::Forwarded) => {
            (None, Some(Either7::A(GetForwardedHeaderLayer::forwarded())))
        }
        Some(ForwardKind::XForwardedFor) => (
            None,
            Some(Either7::B(GetForwardedHeaderLayer::x_forwarded_for())),
        ),
        Some(ForwardKind::XClientIp) => (
            None,
            Some(Either7::C(GetForwardedHeaderLayer::<XClientIp>::new())),
        ),
        Some(ForwardKind::ClientIp) => (
            None,
            Some(Either7::D(GetForwardedHeaderLayer::<ClientIp>::new())),
        ),
        Some(ForwardKind::XRealIp) => (
            None,
            Some(Either7::E(GetForwardedHeaderLayer::<XRealIp>::new())),
        ),
        Some(ForwardKind::CFConnectingIp) => (
            None,
            Some(Either7::F(GetForwardedHeaderLayer::<CFConnectingIp>::new())),
        ),
        Some(ForwardKind::TrueClientIp) => (
            None,
            Some(Either7::G(GetForwardedHeaderLayer::<TrueClientIp>::new())),
        ),
        Some(ForwardKind::HaProxy) => (Some(HaProxyLayer::default()), None),
    };

    let maybe_tls_server_config = cfg.secure.then(|| {
        new_server_config(Some(match cfg.http_version {
            HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
            HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
            HttpVersion::Auto => {
                vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
            }
        }))
    });

    let tls_acceptor_data = match maybe_tls_server_config {
        None => None,
        Some(cfg) => Some(cfg.try_into()?),
    };

    let ch_headers = all_client_hint_header_name_strings()
        .join(", ")
        .parse::<HeaderValue>()
        .expect("parse header value");

    let pg_url = std::env::var("DATABASE_URL").ok();
    let storage_auth = std::env::var("RAMA_FP_STORAGE_COOKIE").ok();

    let tcp_listener = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind fp service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    graceful.spawn_task_fn(async move |guard|  {
        let ws_service = ConsumeErrLayer::default().into_layer(WebSocketAcceptor::new()
            .with_protocols(SecWebSocketProtocol::new("a").with_additional_protocol("b"))
            .with_protocols_flex(true)
            .with_extensions(sec_websocket_extensions::SecWebSocketExtensions::per_message_deflate())
            .into_service(service_fn(endpoints::ws_api)));

        let inner_http_service = HijackLayer::new(
                HttpMatcher::custom(false),
                service_fn(async || {
                    tracing::debug!(
                        "redirecting to consent: conditions not fulfilled"
                    );
                    Ok::<_, Infallible>(Redirect::temporary("/consent").into_response())
                }),
            )
            .into_layer(match_service!{
                HttpMatcher::get("/report") => endpoints::get_report,
                HttpMatcher::path("/api/ws") => ws_service,
                HttpMatcher::post("/api/fetch/number/:number") => endpoints::post_api_fetch_number,
                HttpMatcher::post("/api/xml/number/:number") => endpoints::post_api_xml_http_request_number,
                HttpMatcher::method_get().or_method_post().and_path("/form") => endpoints::form,
                _ => service_fn(async || {
                    tracing::debug!(
                        "redirecting to consent: fallback"
                    );
                    Ok::<_, Infallible>(Redirect::temporary("/consent").into_response())
                }),
            });

        let http_service = (
            TraceLayer::new_for_http(),
            CompressionLayer::new(),
            CatchPanicLayer::new(),
            AddRequiredResponseHeadersLayer::default(),
            SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-sponsored-by"),
                HeaderValue::from_static("fly.io"),
            ),
            StorageAuthLayer,
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("accept-ch"),
                ch_headers.clone(),
            ),
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("critical-ch"),
                ch_headers.clone(),
            ),
            SetResponseHeaderLayer::if_not_present(
                HeaderName::from_static("vary"),
                ch_headers,
            ),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::trace(tracing::Level::WARN),
            http_forwarded_layer,
            ).into_layer(
                Arc::new(match_service!{
                    // Navigate
                    HttpMatcher::get("/") => Redirect::temporary("/consent"),
                    HttpMatcher::get("/consent") => endpoints::get_consent,
                    // Assets
                    HttpMatcher::get("/assets/style.css") => endpoints::get_assets_style,
                    HttpMatcher::get("/assets/script.js") => endpoints::get_assets_script,
                    // Fingerprinting Endpoints
                    _ => inner_http_service,
                })
            );

        let tcp_service_builder = (
            AddExtensionLayer::new(Arc::new(
                State::new(pg_url, storage_auth.as_deref())
                    .await
                    .expect("create state"),
            )),
            ConsumeErrLayer::trace(tracing::Level::WARN),
            tcp_forwarded_layer,
            TimeoutLayer::new(Duration::from_secs(300)),
            LimitLayer::new(ConcurrentPolicy::max_with_backoff(
                2048,
                ExponentialBackoff::default(),
            )),
            // Limit the body size to 1MB for both request and response
            BodyLimitLayer::symmetric(1024 * 1024),
            tls_acceptor_data.map(|data| {
                TlsAcceptorLayer::new(data).with_store_client_hello(true)
            })
        );

        match cfg.http_version {
            HttpVersion::Auto => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "FP Service (auto) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve_graceful(
                        guard.clone(),
                        tcp_service_builder.into_layer(
                            HttpServer::auto(Executor::graceful(guard)).service(http_service),
                        ),
                    )
                    .await;
            }
            HttpVersion::H1 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "FP Service (HTTP/1.1) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve_graceful(
                        guard,
                        tcp_service_builder.into_layer(HttpServer::http1().service(http_service)),
                    )
                    .await;
            }
            HttpVersion::H2 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "FP Service (H2) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve_graceful(
                        guard.clone(),
                        tcp_service_builder.into_layer(
                            HttpServer::h2(Executor::graceful(guard)).service(http_service),
                        ),
                    )
                    .await;
            }
        }
    });

    let delay = if cfg.graceful > 0 {
        graceful
            .shutdown_with_limit(Duration::from_secs(cfg.graceful))
            .await?
    } else {
        graceful.shutdown().await
    };
    tracing::info!("FP service gracefully shutdown with a delay of: {delay:?}");

    Ok(())
}

#[derive(Debug, Clone, Default)]
struct StorageAuthLayer;

impl<S> Layer<S> for StorageAuthLayer {
    type Service = StorageAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StorageAuthService { inner }
    }
}

struct StorageAuthService<S> {
    inner: S,
}

impl<S: std::fmt::Debug> std::fmt::Debug for StorageAuthService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageAuthService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, Body> Service<Request<Body>> for StorageAuthService<S>
where
    Body: Send + 'static,
    S: Service<Request<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Response, Self::Error> {
        if let Some(cookie) = req.headers().typed_get::<Cookie>() {
            let cookie = cookie
                .iter()
                .filter_map(|(k, v)| {
                    if k.eq_ignore_ascii_case("rama-storage-auth") {
                        if Some(v)
                            == req
                                .extensions()
                                .get::<Arc<State>>()
                                .unwrap()
                                .storage_auth
                                .as_deref()
                        {
                            req.extensions_mut().insert(StorageAuthorized);
                        }
                        Some("rama-storage-auth=xxx".to_owned())
                    } else if !k.starts_with("source-") {
                        Some(format!("{k}={v}"))
                    } else {
                        None
                    }
                })
                .join("; ");
            if !cookie.is_empty() {
                req.headers_mut()
                    .insert(COOKIE, HeaderValue::try_from(cookie).unwrap());
            }
        }

        self.inner.serve(req).await
    }
}
