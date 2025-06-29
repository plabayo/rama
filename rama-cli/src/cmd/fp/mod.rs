//! Echo service that echos the http request and tls client config

use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use clap::Args;
use itertools::Itertools;
use rama::{
    Context, Service,
    cli::ForwardKind,
    combinators::Either7,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        HeaderName, HeaderValue, Request,
        header::COOKIE,
        headers::{
            Cookie, HeaderMapExt, all_client_hint_header_name_strings,
            forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
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
    },
    layer::{
        ConsumeErrLayer, HijackLayer, Layer, LimitLayer, TimeoutLayer,
        limit::policy::ConcurrentPolicy,
    },
    net::{
        socket::Interface,
        stream::layer::http::BodyLimitLayer,
        tls::{
            ApplicationProtocol, DataEncoding,
            server::{ServerAuth, ServerAuthData, ServerConfig},
        },
    },
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::server::TlsAcceptorLayer,
    utils::backoff::ExponentialBackoff,
};
use std::{convert::Infallible, sync::Arc, time::Duration};

mod data;
mod endpoints;
mod state;
mod storage;

#[doc(inline)]
use state::State;

use self::state::ACMEData;
use crate::utils::http::HttpVersion;

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

    #[arg(short = 't', long, default_value_t = 8)]
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

    let acme_data = if let Ok(raw_acme_data) = std::env::var("RAMA_ACME_DATA") {
        let acme_data: Vec<_> = raw_acme_data
            .split(';')
            .map(|s| {
                let mut iter = s.trim().splitn(2, ',');
                let key = iter.next().expect("acme data key");
                let value = iter.next().expect("acme data value");
                (key.to_owned(), value.to_owned())
            })
            .collect();
        ACMEData::with_challenges(acme_data)
    } else {
        ACMEData::default()
    };

    let maybe_tls_server_config = cfg.secure.then(|| {
        if cfg.self_signed {
            return ServerConfig {
                application_layer_protocol_negotiation: Some(match cfg.http_version {
                    HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
                    HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
                    HttpVersion::Auto => {
                        vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                    }
                }),
                ..ServerConfig::new(ServerAuth::default())
            };
        }

        let tls_key_pem_raw = std::env::var("RAMA_TLS_KEY").expect("RAMA_TLS_KEY");
        let tls_key_pem_raw = std::str::from_utf8(
            &ENGINE
                .decode(tls_key_pem_raw)
                .expect("base64 decode RAMA_TLS_KEY")[..],
        )
        .expect("base64-decoded RAMA_TLS_KEY valid utf-8")
        .try_into()
        .expect("tls_key_pem_raw => NonEmptyStr (RAMA_TLS_KEY)");
        let tls_crt_pem_raw = std::env::var("RAMA_TLS_CRT").expect("RAMA_TLS_CRT");
        let tls_crt_pem_raw = std::str::from_utf8(
            &ENGINE
                .decode(tls_crt_pem_raw)
                .expect("base64 decode RAMA_TLS_CRT")[..],
        )
        .expect("base64-decoded RAMA_TLS_CRT valid utf-8")
        .try_into()
        .expect("tls_crt_pem_raw => NonEmptyStr (RAMA_TLS_CRT)");
        ServerConfig {
            application_layer_protocol_negotiation: Some(match cfg.http_version {
                HttpVersion::H1 => vec![ApplicationProtocol::HTTP_11],
                HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
                HttpVersion::Auto => {
                    vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                }
            }),
            ..ServerConfig::new(ServerAuth::Single(ServerAuthData {
                private_key: DataEncoding::Pem(tls_key_pem_raw),
                cert_chain: DataEncoding::Pem(tls_crt_pem_raw),
                ocsp: None,
            }))
        }
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

    let tcp_listener = TcpListener::build_with_state(Arc::new(
        State::new(acme_data, pg_url, storage_auth.as_deref())
            .await
            .expect("create state"),
    ))
    .bind(cfg.bind.clone())
    .await
    .map_err(OpaqueError::from_boxed)
    .context("bind fp service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    graceful.spawn_task_fn(async move |guard|  {
        let inner_http_service = HijackLayer::new(
                HttpMatcher::header_exists(HeaderName::from_static("referer"))
                    .and_header_exists(HeaderName::from_static("cookie"))
                    .negate(),
                service_fn(async || {
                    Ok::<_, Infallible>(Redirect::temporary("/consent").into_response())
                }),
            )
            .into_layer(match_service!{
                HttpMatcher::get("/report") => endpoints::get_report,
                HttpMatcher::post("/api/fetch/number/:number") => endpoints::post_api_fetch_number,
                HttpMatcher::post("/api/xml/number/:number") => endpoints::post_api_xml_http_request_number,
                HttpMatcher::method_get().or_method_post().and_path("/form") => endpoints::form,
                _ => Redirect::temporary("/consent"),
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
                    // ACME
                    HttpMatcher::get("/.well-known/acme-challenge/:token") => endpoints::get_acme_challenge,
                    // Assets
                    HttpMatcher::get("/assets/style.css") => endpoints::get_assets_style,
                    HttpMatcher::get("/assets/script.js") => endpoints::get_assets_script,
                    // Fingerprinting Endpoints
                    _ => inner_http_service,
                })
            );

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::WARN),
            tcp_forwarded_layer,
            TimeoutLayer::new(Duration::from_secs(16)),
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

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

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

impl<S, Body> Service<Arc<State>, Request<Body>> for StorageAuthService<S>
where
    Body: Send + 'static,
    S: Service<Arc<State>, Request<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<Arc<State>>,
        mut req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(cookie) = req.headers().typed_get::<Cookie>() {
            let cookie = cookie
                .iter()
                .filter_map(|(k, v)| {
                    if k.eq_ignore_ascii_case("rama-storage-auth") {
                        if Some(v) == ctx.state().storage_auth.as_deref() {
                            ctx.insert(StorageAuthorized);
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

        self.inner.serve(ctx, req).await
    }
}
