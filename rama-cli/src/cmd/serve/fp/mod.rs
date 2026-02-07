//! Echo service that echos the http request and tls client config

use rama::{
    Service,
    cli::ForwardKind,
    combinators::{Either, Either7},
    error::{BoxError, ErrorContext},
    extensions::ExtensionsMut,
    graceful::ShutdownGuard,
    http::{
        HeaderName, HeaderValue, Request,
        header::COOKIE,
        headers::{
            Cookie, HeaderMapExt, SecWebSocketProtocol, all_client_hint_header_name_strings,
            exotic::XClacksOverhead,
            forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
            sec_websocket_extensions,
        },
        layer::{
            catch_panic::CatchPanicLayer, compression::CompressionLayer,
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            set_header::SetResponseHeaderLayer, trace::TraceLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            Router,
            response::{IntoResponse, Redirect},
        },
        ws::handshake::server::{ServerWebSocket, WebSocketAcceptor},
    },
    layer::{
        ConsumeErrLayer, Layer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, UnlimitedPolicy},
    },
    net::{socket::Interface, stream::layer::http::BodyLimitLayer, tls::ApplicationProtocol},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::server::TlsAcceptorLayer,
    ua::layer::classifier::UserAgentClassifierLayer,
    utils::{backoff::ExponentialBackoff, collections::non_empty_smallvec, str::non_empty_str},
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

use crate::utils::{http::HttpVersion, tls::try_new_server_config};

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

    #[arg(short = 't', long, default_value_t = 60.)]
    /// the timeout in seconds for each connection
    ///
    /// (<= 0.0 = no timeout)
    timeout: f64,

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
    /// run service in secure mode (enable TLS)
    secure: bool,
}

/// run the rama FP service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandFingerprint) -> Result<(), BoxError> {
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

    let pg_url = std::env::var("DATABASE_URL").ok();
    let storage_auth = std::env::var("RAMA_FP_STORAGE_COOKIE").ok();

    let state = State::new(pg_url, storage_auth.as_deref())
        .await
        .context("create state")?;

    let ws_service = ConsumeErrLayer::default().into_layer(
        WebSocketAcceptor::new()
            .with_protocols(SecWebSocketProtocol(non_empty_smallvec![
                non_empty_str!("a"),
                non_empty_str!("b"),
            ]))
            .with_protocols_flex(true)
            .with_extensions(
                sec_websocket_extensions::SecWebSocketExtensions::per_message_deflate(),
            )
            .into_service(service_fn({
                // TODO: once service_fn (or something similar)
                // is also possible with state, we can unify the state API (usage) here
                let state = state.clone();
                move |ws: ServerWebSocket| {
                    let state = state.clone();
                    endpoints::ws_api(state, ws)
                }
            })),
    );

    let ch_headers = all_client_hint_header_name_strings()
        .join(", ")
        .parse::<HeaderValue>()
        .context("parse header value")?;

    let middlewares = (
        TraceLayer::new_for_http(),
        CompressionLayer::new(),
        CatchPanicLayer::new(),
        SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
        AddRequiredResponseHeadersLayer::default(),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-sponsored-by"),
            HeaderValue::from_static("fly.io"),
        ),
        StorageAuthLayer::new(&state),
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("accept-ch"),
            ch_headers.clone(),
        ),
        SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("critical-ch"),
            ch_headers.clone(),
        ),
        SetResponseHeaderLayer::if_not_present(HeaderName::from_static("vary"), ch_headers),
        UserAgentClassifierLayer::new(),
        ConsumeErrLayer::trace(tracing::Level::WARN),
        http_forwarded_layer,
    );

    let router = Router::new_with_state(state)
        .with_get("/", Redirect::temporary("/consent"))
        .with_get("/consent", endpoints::get_consent)
        // Assets
        .with_get("/assets/style.css", endpoints::get_assets_style)
        .with_get("/assets/script.js", endpoints::get_assets_script)
        // Report and API
        .with_get("/report", endpoints::get_report)
        .with_get("/api/ws", ws_service)
        .with_post(
            "/api/fetch/number/{number}",
            endpoints::post_api_fetch_number,
        )
        .with_post(
            "/api/xml/number/{number}",
            endpoints::post_api_xml_http_request_number,
        )
        .with_match_route(
            "/form",
            HttpMatcher::method_get().or_method_post().and_path("/form"),
            endpoints::form,
        )
        .with_not_found(async || {
            tracing::debug!("redirecting to consent: fallback");
            Redirect::temporary("/consent")
        });

    let http_service = Arc::new(middlewares.into_layer(router));

    serve_http(graceful, cfg, http_service, tcp_forwarded_layer).await
}

async fn serve_http<Response>(
    graceful: ShutdownGuard,
    cfg: CliCommandFingerprint,
    http_service: impl Service<Request, Output = Response, Error = Infallible> + Clone,
    maybe_ha_proxy_layer: Option<HaProxyLayer>,
) -> Result<(), BoxError>
where
    Response: IntoResponse + Send + 'static,
{
    let exec = Executor::graceful(graceful);

    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                Some(match cfg.http_version {
                    HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
                    HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
                    HttpVersion::Auto => {
                        vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                    }
                }),
                exec.clone(),
            )
        })
        .transpose()?;

    let tls_acceptor_data = match maybe_tls_server_config {
        None => None,
        Some(cfg) => Some(cfg.try_into()?),
    };

    let tcp_listener = TcpListener::build(exec.clone())
        .bind(cfg.bind.clone())
        .await
        .context("bind fp service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let tcp_service_builder = (
        ConsumeErrLayer::trace(tracing::Level::WARN),
        maybe_ha_proxy_layer,
        if cfg.timeout > 0. {
            TimeoutLayer::new(Duration::from_secs_f64(cfg.timeout))
        } else {
            TimeoutLayer::never()
        },
        LimitLayer::new(if cfg.concurrent > 0 {
            Either::A(ConcurrentPolicy::max_with_backoff(
                cfg.concurrent,
                ExponentialBackoff::default(),
            ))
        } else {
            Either::B(UnlimitedPolicy::new())
        }),
        // Limit the body size to 1MB for both request and response
        BodyLimitLayer::symmetric(1024 * 1024),
        tls_acceptor_data.map(|data| TlsAcceptorLayer::new(data).with_store_client_hello(true)),
    );

    exec.clone().into_spawn_task(async move {
        match cfg.http_version {
            HttpVersion::Auto => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "FP Service (auto) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::auto(exec).service(http_service)),
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
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::http1(exec).service(http_service)),
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
                    .serve(
                        tcp_service_builder.into_layer(HttpServer::h2(exec).service(http_service)),
                    )
                    .await;
            }
        }
    });

    Ok(())
}

#[derive(Debug, Clone)]
struct StorageAuthLayer {
    storage_auth: Option<String>,
}

impl StorageAuthLayer {
    fn new(state: &State) -> Self {
        Self {
            storage_auth: state.storage_auth.clone(),
        }
    }
}

impl<S> Layer<S> for StorageAuthLayer {
    type Service = StorageAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StorageAuthService {
            inner,
            storage_auth: self.storage_auth.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        StorageAuthService {
            inner,
            storage_auth: self.storage_auth,
        }
    }
}

struct StorageAuthService<S> {
    inner: S,
    storage_auth: Option<String>,
}

impl<S: std::fmt::Debug> std::fmt::Debug for StorageAuthService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageAuthService")
            .field("inner", &self.inner)
            .field("storage_auth", &self.storage_auth)
            .finish()
    }
}

impl<S, Body> Service<Request<Body>> for StorageAuthService<S>
where
    Body: Send + 'static,
    S: Service<Request<Body>>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        if let Some(cookie) = req.headers().typed_get::<Cookie>() {
            let cookie = cookie
                .iter()
                .filter_map(|(k, v)| {
                    if k.eq_ignore_ascii_case("rama-storage-auth") {
                        if Some(v) == self.storage_auth.as_deref() {
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
                match HeaderValue::try_from(cookie) {
                    Ok(value) => {
                        let _ = req.headers_mut().insert(COOKIE, value);
                    }
                    Err(err) => {
                        tracing::error!(
                            "failed to re-insert modified cookie due to creation error: {err}; drop cookie header for security"
                        );
                        while req.headers_mut().remove(COOKIE).is_some() {
                            tracing::debug!("removed cookie header (for security reasons)");
                        }
                    }
                }
            }
        }

        self.inner.serve(req).await
    }
}
