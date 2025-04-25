//! Echo '[`Service`] that echos the [`http`] [`Request`] and [`tls`] client config.
//!
//! [`Service`]: crate::Service
//! [`http`]: crate::http
//! [`Request`]: crate::http::Request
//! [`tls`]: crate::tls

use crate::{
    Context, Layer, Service,
    cli::ForwardKind,
    combinators::{Either3, Either7},
    error::{BoxError, OpaqueError},
    http::{
        IntoResponse, Request, Response, Version,
        conn::LastPeerPriorityParams,
        dep::http_body_util::BodyExt,
        header::USER_AGENT,
        headers::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::{
            forwarded::GetForwardedHeadersLayer,
            required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
            ua::{UserAgent, UserAgentClassifierLayer},
        },
        proto::h1::Http1HeaderMap,
        proto::h2::PseudoHeaderOrder,
        proto::h2::frame::InitialPeerSettings,
        response::Json,
        server::HttpServer,
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::fingerprint::Ja4H,
    net::forwarded::Forwarded,
    net::http::RequestContext,
    net::stream::{SocketInfo, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    ua::profile::UserAgentDatabase,
};
#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::{
    net::fingerprint::{Ja3, Ja4},
    net::tls::{
        SecureTransport,
        client::ClientHelloExtension,
        client::{ECHClientHello, NegotiatedTlsParameters},
    },
};
use serde::Serialize;
use serde_json::json;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpStream;

#[cfg(feature = "boring")]
use crate::{
    net::tls::server::ServerConfig,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use crate::tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

#[cfg(feature = "boring")]
type TlsConfig = ServerConfig;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
type TlsConfig = TlsAcceptorData;

#[derive(Debug, Clone)]
/// Builder that can be used to run your own echo [`Service`],
/// echo'ing back information about that request and its underlying transport / presentation layers.
pub struct EchoServiceBuilder<H> {
    concurrent_limit: usize,
    body_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,

    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_server_config: Option<TlsConfig>,

    http_version: Option<Version>,

    http_service_builder: H,

    uadb: Option<std::sync::Arc<UserAgentDatabase>>,
}

impl Default for EchoServiceBuilder<()> {
    fn default() -> Self {
        Self {
            concurrent_limit: 0,
            body_limit: 1024 * 1024,
            timeout: Duration::ZERO,
            forward: None,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: None,

            http_version: None,

            http_service_builder: (),

            uadb: None,
        }
    }
}

impl EchoServiceBuilder<()> {
    /// Create a new [`EchoServiceBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H> EchoServiceBuilder<H> {
    /// set the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    pub fn concurrent(mut self, limit: usize) -> Self {
        self.concurrent_limit = limit;
        self
    }

    /// set the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    pub fn set_concurrent(&mut self, limit: usize) -> &mut Self {
        self.concurrent_limit = limit;
        self
    }

    /// set the body limit in bytes for each request
    pub fn body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    /// set the body limit in bytes for each request
    pub fn set_body_limit(&mut self, limit: usize) -> &mut Self {
        self.body_limit = limit;
        self
    }

    /// set the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// set the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

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
    pub fn forward(self, kind: ForwardKind) -> Self {
        self.maybe_forward(Some(kind))
    }

    /// enable support for one of the following "forward" headers or protocols
    ///
    /// Same as [`Self::forward`] but without consuming `self`.
    pub fn set_forward(&mut self, kind: ForwardKind) -> &mut Self {
        self.forward = Some(kind);
        self
    }

    /// maybe enable support for one of the following "forward" headers or protocols.
    ///
    /// See [`Self::forward`] for more information.
    pub fn maybe_forward(mut self, maybe_kind: Option<ForwardKind>) -> Self {
        self.forward = maybe_kind;
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn tls_server_config(mut self, cfg: TlsConfig) -> Self {
        self.tls_server_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn set_tls_server_config(&mut self, cfg: TlsConfig) -> &mut Self {
        self.tls_server_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn maybe_tls_server_config(mut self, cfg: Option<TlsConfig>) -> Self {
        self.tls_server_config = cfg;
        self
    }

    /// set the http version to use for the http server (auto by default)
    pub fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    /// maybe set the http version to use for the http server (auto by default)
    pub fn maybe_http_version(mut self, version: Option<Version>) -> Self {
        self.http_version = version;
        self
    }

    /// set the http version to use for the http server (auto by default)
    pub fn set_http_version(&mut self, version: Version) -> &mut Self {
        self.http_version = Some(version);
        self
    }

    /// add a custom http layer which will be applied to the existing http layers
    pub fn http_layer<H2>(self, layer: H2) -> EchoServiceBuilder<(H, H2)> {
        EchoServiceBuilder {
            concurrent_limit: self.concurrent_limit,
            body_limit: self.body_limit,
            timeout: self.timeout,
            forward: self.forward,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: self.tls_server_config,

            http_version: self.http_version,

            http_service_builder: (self.http_service_builder, layer),

            uadb: self.uadb,
        }
    }

    /// set the user agent datasbase that if set would be used to look up
    /// a user agent (by ua header string) to see if we have a ja3/ja4 hash.
    pub fn with_user_agent_database(mut self, db: std::sync::Arc<UserAgentDatabase>) -> Self {
        self.uadb = Some(db);
        self
    }

    /// maybe set the user agent datasbase that if set would be used to look up
    /// a user agent (by ua header string) to see if we have a ja3/ja4 hash.
    pub fn maybe_with_user_agent_database(
        mut self,
        db: Option<std::sync::Arc<UserAgentDatabase>>,
    ) -> Self {
        self.uadb = db;
        self
    }

    /// set the user agent datasbase that if set would be used to look up
    /// a user agent (by ua header string) to see if we have a ja3/ja4 hash.
    pub fn set_user_agent_database(&mut self, db: std::sync::Arc<UserAgentDatabase>) -> &mut Self {
        self.uadb = Some(db);
        self
    }
}

impl<H> EchoServiceBuilder<H>
where
    H: Layer<EchoService, Service: Service<(), Request, Response = Response, Error = BoxError>>,
{
    #[allow(unused_mut)]
    /// build a tcp service ready to echo http traffic back
    pub fn build(
        mut self,
        executor: Executor,
    ) -> Result<impl Service<(), TcpStream, Response = (), Error = Infallible>, BoxError> {
        let tcp_forwarded_layer = match &self.forward {
            Some(ForwardKind::HaProxy) => Some(HaProxyLayer::default()),
            _ => None,
        };

        let http_service = self.build_http();

        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let tls_cfg = self.tls_server_config;

        #[cfg(feature = "boring")]
        let tls_cfg: Option<TlsAcceptorData> = match self.tls_server_config {
            Some(cfg) => Some(cfg.try_into()?),
            None => None,
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
            BodyLimitLayer::request_only(self.body_limit),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_cfg.map(|cfg| {
                #[cfg(feature = "boring")]
                return TlsAcceptorLayer::new(cfg).with_store_client_hello(true);
                #[cfg(all(feature = "rustls", not(feature = "boring")))]
                TlsAcceptorLayer::new(cfg).with_store_client_hello(true)
            }),
        );

        let http_transport_service = match self.http_version {
            Some(Version::HTTP_2) => Either3::A(HttpServer::h2(executor).service(http_service)),
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Either3::B(HttpServer::http1().service(http_service))
            }
            Some(_) => {
                return Err(OpaqueError::from_display("unsupported http version").into_boxed());
            }
            None => Either3::C(HttpServer::auto(executor).service(http_service)),
        };

        Ok(tcp_service_builder.into_layer(http_transport_service))
    }

    /// build an http service ready to echo http traffic back
    pub fn build_http(
        &self,
    ) -> impl Service<(), Request, Response: IntoResponse, Error = Infallible> + use<H> {
        let http_forwarded_layer = match &self.forward {
            None | Some(ForwardKind::HaProxy) => None,
            Some(ForwardKind::Forwarded) => Some(Either7::A(GetForwardedHeadersLayer::forwarded())),
            Some(ForwardKind::XForwardedFor) => {
                Some(Either7::B(GetForwardedHeadersLayer::x_forwarded_for()))
            }
            Some(ForwardKind::XClientIp) => {
                Some(Either7::C(GetForwardedHeadersLayer::<XClientIp>::new()))
            }
            Some(ForwardKind::ClientIp) => {
                Some(Either7::D(GetForwardedHeadersLayer::<ClientIp>::new()))
            }
            Some(ForwardKind::XRealIp) => {
                Some(Either7::E(GetForwardedHeadersLayer::<XRealIp>::new()))
            }
            Some(ForwardKind::CFConnectingIp) => {
                Some(Either7::F(GetForwardedHeadersLayer::<CFConnectingIp>::new()))
            }
            Some(ForwardKind::TrueClientIp) => {
                Some(Either7::G(GetForwardedHeadersLayer::<TrueClientIp>::new()))
            }
        };

        (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
        )
            .into_layer(self.http_service_builder.layer(EchoService {
                uadb: self.uadb.clone(),
            }))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner echo-service used by the [`EchoServiceBuilder`].
pub struct EchoService {
    uadb: Option<std::sync::Arc<UserAgentDatabase>>,
}

impl Service<(), Request> for EchoService {
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<()>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let user_agent_info = ctx
            .get()
            .map(|ua: &UserAgent| {
                json!({
                    "user_agent": ua.header_str().to_owned(),
                    "kind": ua.info().map(|info| info.kind.to_string()),
                    "version": ua.info().and_then(|info| info.version),
                    "platform": ua.platform().map(|v| v.to_string()),
                })
            })
            .unwrap_or_default();

        let request_context =
            ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())?;
        let authority = request_context.authority.to_string();
        let scheme = request_context.protocol.to_string();

        let ua_str = req
            .headers()
            .get(USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .map(ToOwned::to_owned);
        tracing::debug!(?ua_str, "echo request received from ua with ua header");

        #[derive(Debug, Serialize)]
        struct FingerprintProfileData {
            hash: String,
            verbose: String,
            matched: bool,
        }

        let ja4h = Ja4H::compute(&req)
            .inspect_err(|err| tracing::error!(?err, "ja4h compute failure"))
            .ok()
            .map(|ja4h| {
                let mut profile_ja4h: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref() {
                    if let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                    {
                        let matched_ja4h = match req.version() {
                            Version::HTTP_10 | Version::HTTP_11 => profile
                                .http
                                .ja4h_h1_navigate(Some(req.method().clone()))
                                .inspect_err(|err| {
                                    tracing::trace!(
                                        ?err,
                                        "ja4h computation of matched profile for incoming h1 req"
                                    )
                                })
                                .ok(),
                            Version::HTTP_2 => profile
                                .http
                                .ja4h_h2_navigate(Some(req.method().clone()))
                                .inspect_err(|err| {
                                    tracing::trace!(
                                        ?err,
                                        "ja4h computation of matched profile for incoming h2 req"
                                    )
                                })
                                .ok(),
                            _ => None,
                        };
                        if let Some(tgt) = matched_ja4h {
                            let hash = format!("{tgt}");
                            let matched = format!("{ja4h}") == hash;
                            profile_ja4h = Some(FingerprintProfileData {
                                hash,
                                verbose: format!("{tgt:?}"),
                                matched,
                            });
                        }
                    }
                }

                json!({
                    "hash": format!("{ja4h}"),
                    "verbose": format!("{ja4h:?}"),
                    "profile": profile_ja4h,
                })
            });

        let (mut parts, body) = req.into_parts();

        let headers: Vec<_> = Http1HeaderMap::new(parts.headers, Some(&mut parts.extensions))
            .into_iter()
            .map(|(name, value)| {
                (
                    name,
                    std::str::from_utf8(value.as_bytes())
                        .map(|s| s.to_owned())
                        .unwrap_or_else(|_| format!("0x{:x?}", value.as_bytes())),
                )
            })
            .collect();

        let body = body.collect().await.unwrap().to_bytes();
        let body = hex::encode(body.as_ref());

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let tls_info = ctx
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .map(|hello| {
                let ja4 = Ja4::compute(ctx.extensions())
                    .inspect_err(|err| tracing::trace!(?err, "ja4 computation"))
                    .ok();

                let mut profile_ja4: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref() {
                    if let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                    {
                        let matched_ja4 = profile
                            .tls
                            .compute_ja4(
                                ctx.get::<NegotiatedTlsParameters>()
                                    .map(|param| param.protocol_version),
                            )
                            .inspect_err(|err| {
                                tracing::trace!(?err, "ja4 computation of matched profile")
                            })
                            .ok();
                        if let (Some(src), Some(tgt)) = (ja4.as_ref(), matched_ja4) {
                            let hash = format!("{tgt}");
                            let matched = format!("{src}") == hash;
                            profile_ja4 = Some(FingerprintProfileData {
                                hash,
                                verbose: format!("{tgt:?}"),
                                matched,
                            });
                        }
                    }
                }

                let ja4 = ja4.map(|ja4| {
                    json!({
                        "hash": format!("{ja4}"),
                        "verbose": format!("{ja4:?}"),
                        "profile": profile_ja4,
                    })
                });

                let ja3 = Ja3::compute(ctx.extensions())
                    .inspect_err(|err| tracing::trace!(?err, "ja3 computation"))
                    .ok();

                let mut profile_ja3: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref() {
                    if let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                    {
                        let matched_ja3 = profile
                            .tls
                            .compute_ja3(
                                ctx.get::<NegotiatedTlsParameters>()
                                    .map(|param| param.protocol_version),
                            )
                            .inspect_err(|err| {
                                tracing::trace!(?err, "ja3 computation of matched profile")
                            })
                            .ok();
                        if let (Some(src), Some(tgt)) = (ja3.as_ref(), matched_ja3) {
                            let hash = format!("{tgt:x}");
                            let matched = format!("{src:x}") == hash;
                            profile_ja3 = Some(FingerprintProfileData {
                                hash,
                                verbose: format!("{tgt}"),
                                matched,
                            });
                        }
                    }
                }

                let ja3 = ja3.map(|ja3| {
                    json!({
                        "hash": format!("{ja3:x}"),
                        "verbose": format!("{ja3}"),
                        "profile": profile_ja3,
                    })
                });

                json!({
                    "header": {
                        "version": hello.protocol_version().to_string(),
                        "cipher_suites": hello
                        .cipher_suites().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        "compression_algorithms": hello
                        .compression_algorithms().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    },
                    "extensions": hello.extensions().iter().map(|extension| match extension {
                        ClientHelloExtension::ServerName(domain) => json!({
                            "id": extension.id().to_string(),
                            "data": domain,
                        }),
                        ClientHelloExtension::SignatureAlgorithms(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::SupportedVersions(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::ApplicationLayerProtocolNegotiation(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::SupportedGroups(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::ECPointFormats(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::CertificateCompression(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::DelegatedCredentials(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::RecordSizeLimit(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.to_string(),
                        }),
                        ClientHelloExtension::EncryptedClientHello(ech) => match ech {
                            ECHClientHello::Outer(ech) => json!({
                                "id": extension.id().to_string(),
                                "data": {
                                    "type": "outer",
                                    "cipher_suite": {
                                        "aead_id": ech.cipher_suite.aead_id.to_string(),
                                        "kdf_id": ech.cipher_suite.kdf_id.to_string(),
                                    },
                                    "config_id": ech.config_id,
                                    "enc":  format!("0x{}", hex::encode(&ech.enc)),
                                    "payload": format!("0x{}", hex::encode(&ech.payload)),
                                },
                            }),
                            ECHClientHello::Inner => json!({
                                "id": extension.id().to_string(),
                                "data": {
                                    "type": "inner",
                                },
                            })

                        }
                        ClientHelloExtension::Opaque { id, data } => if data.is_empty() {
                            json!({
                                "id": id.to_string()
                            })
                        } else {
                            json!({
                                "id": id.to_string(),
                                "data": format!("0x{}", hex::encode(data))
                            })
                        },
                    }).collect::<Vec<_>>(),
                    "ja3": ja3,
                    "ja4": ja4,
                })
            });

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let tls_info: Option<()> = None;

        let mut h2 = None;
        if parts.version == Version::HTTP_2 {
            let initial_peer_settings = parts
                .extensions
                .get::<InitialPeerSettings>()
                .map(|p| p.0.as_ref());

            let pseudo_headers = parts.extensions.get::<PseudoHeaderOrder>();

            let last_priority_params = parts
                .extensions
                .get::<LastPeerPriorityParams>()
                .map(|p| p.0.dependency.clone());

            h2 = Some(json!({
                "settings": initial_peer_settings,
                "pseudo_headers": pseudo_headers,
                "last_priority_params": last_priority_params,
            }));
        }

        Ok(Json(json!({
            "ua": user_agent_info,
            "http": {
                "version": format!("{:?}", parts.version),
                "scheme": scheme,
                "method": format!("{:?}", parts.method),
                "authority": authority,
                "path": parts.uri.path().to_owned(),
                "query": parts.uri.query().map(str::to_owned),
                "h2": h2,
                "headers": headers,
                "payload": body,
                "ja4h": ja4h,
            },
            "tls": tls_info,
            "socket_addr": ctx.get::<Forwarded>()
                .and_then(|f|
                        f.client_socket_addr().map(|addr| addr.to_string())
                            .or_else(|| f.client_ip().map(|ip| ip.to_string()))
                ).or_else(|| ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string())),
        }))
        .into_response())
    }
}
