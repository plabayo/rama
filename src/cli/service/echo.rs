//! Echo '[`Service`] that echos the [`http`] [`Request`] and [`tls`] client config.
//!
//! [`Service`]: crate::Service
//! [`http`]: crate::http
//! [`Request`]: crate::http::Request
//! [`tls`]: crate::tls

use crate::{
    Layer, Service,
    cli::ForwardKind,
    combinators::{Either3, Either7},
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::ExtensionsRef,
    http::{
        Request, Response, Version,
        body::util::BodyExt,
        convert::curl,
        core::h2::frame::EarlyFrameCapture,
        header::USER_AGENT,
        headers::forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::{
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
        },
        proto::h1::Http1HeaderMap,
        proto::h2::PseudoHeaderOrder,
        server::{HttpServer, layer::upgrade::UpgradeLayer},
        service::web::{extract::Json, response::IntoResponse},
        ws::handshake::server::{WebSocketAcceptor, WebSocketEchoService, WebSocketMatcher},
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::fingerprint::AkamaiH2,
    net::fingerprint::Ja4H,
    net::forwarded::Forwarded,
    net::http::RequestContext,
    net::stream::{SocketInfo, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    tcp::TcpStream,
    telemetry::tracing,
    ua::{UserAgent, layer::classifier::UserAgentClassifierLayer, profile::UserAgentDatabase},
};

use serde::Serialize;
use serde_json::json;
use std::{convert::Infallible, time::Duration};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use crate::tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::{
    net::fingerprint::{Ja3, Ja4, PeetPrint},
    net::tls::{
        SecureTransport,
        client::ClientHelloExtension,
        client::{ECHClientHello, NegotiatedTlsParameters},
    },
};
#[cfg(feature = "boring")]
use crate::{
    net::tls::server::ServerConfig,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

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

    ws_support: bool,

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

            ws_support: false,

            http_service_builder: (),

            uadb: None,
        }
    }
}

impl EchoServiceBuilder<()> {
    /// Create a new [`EchoServiceBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H> EchoServiceBuilder<H> {
    crate::utils::macros::generate_set_and_with! {
        /// set the number of concurrent connections to allow
        ///
        /// (0 = no limit)
        pub fn concurrent(mut self, limit: usize) -> Self {
            self.concurrent_limit = limit;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// set the body limit in bytes for each request
        pub fn body_limit(mut self, limit: usize) -> Self {
            self.body_limit = limit;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// set the timeout in seconds for each connection
        ///
        /// (0 = no timeout)
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
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
        pub fn forward(mut self, kind: Option<ForwardKind>) -> Self {
            self.forward = kind;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        #[cfg(any(feature = "rustls", feature = "boring"))]
        /// define a tls server cert config to be used for tls terminaton
        /// by the echo service.
        pub fn tls_server_config(mut self, cfg: Option<TlsConfig>) -> Self {
            self.tls_server_config = cfg;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// set the http version to use for the http server (auto by default)
        pub fn http_version(mut self, version: Option<Version>) -> Self {
            self.http_version = version;
            self
        }
    }

    /// add a custom http layer which will be applied to the existing http layers
    pub fn with_http_layer<H2>(self, layer: H2) -> EchoServiceBuilder<(H, H2)> {
        EchoServiceBuilder {
            concurrent_limit: self.concurrent_limit,
            body_limit: self.body_limit,
            timeout: self.timeout,
            forward: self.forward,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: self.tls_server_config,

            http_version: self.http_version,

            ws_support: self.ws_support,

            http_service_builder: (self.http_service_builder, layer),

            uadb: self.uadb,
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// maybe set the user agent datasbase that if set would be used to look up
        /// a user agent (by ua header string) to see if we have a ja3/ja4 hash.
        pub fn user_agent_database(
            mut self,
            db: Option<std::sync::Arc<UserAgentDatabase>>,
        ) -> Self {
            self.uadb = db;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// define whether or not WS support is enabled
        pub fn ws_support(
            mut self,
            support: bool,
        ) -> Self {
            self.ws_support = support;
            self
        }
    }
}

impl<H> EchoServiceBuilder<H>
where
    H: Layer<EchoService, Service: Service<Request, Response = Response, Error = BoxError>>,
{
    #[allow(unused_mut)]
    /// build a tcp service ready to echo http traffic back
    pub fn build(
        mut self,
        executor: Executor,
    ) -> Result<impl Service<TcpStream, Response = (), Error = Infallible>, BoxError> {
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
            tls_cfg.map(|cfg| TlsAcceptorLayer::new(cfg).with_store_client_hello(true)),
        );

        let http_transport_service = match self.http_version {
            Some(Version::HTTP_2) => Either3::A({
                let mut http = HttpServer::h2(executor);
                if self.ws_support {
                    http.h2_mut().enable_connect_protocol();
                }
                http.service(http_service)
            }),
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Either3::B(HttpServer::http1().service(http_service))
            }
            Some(_) => {
                return Err(OpaqueError::from_display("unsupported http version").into_boxed());
            }
            None => Either3::C({
                let mut http = HttpServer::auto(executor);
                if self.ws_support {
                    http.h2_mut().enable_connect_protocol();
                }
                http.service(http_service)
            }),
        };

        Ok(tcp_service_builder.into_layer(http_transport_service))
    }

    /// build an http service ready to echo http traffic back
    pub fn build_http(
        &self,
    ) -> impl Service<Request, Response: IntoResponse, Error = Infallible> + use<H> {
        let http_forwarded_layer = match &self.forward {
            None | Some(ForwardKind::HaProxy) => None,
            Some(ForwardKind::Forwarded) => Some(Either7::A(GetForwardedHeaderLayer::forwarded())),
            Some(ForwardKind::XForwardedFor) => {
                Some(Either7::B(GetForwardedHeaderLayer::x_forwarded_for()))
            }
            Some(ForwardKind::XClientIp) => {
                Some(Either7::C(GetForwardedHeaderLayer::<XClientIp>::new()))
            }
            Some(ForwardKind::ClientIp) => {
                Some(Either7::D(GetForwardedHeaderLayer::<ClientIp>::new()))
            }
            Some(ForwardKind::XRealIp) => {
                Some(Either7::E(GetForwardedHeaderLayer::<XRealIp>::new()))
            }
            Some(ForwardKind::CFConnectingIp) => {
                Some(Either7::F(GetForwardedHeaderLayer::<CFConnectingIp>::new()))
            }
            Some(ForwardKind::TrueClientIp) => {
                Some(Either7::G(GetForwardedHeaderLayer::<TrueClientIp>::new()))
            }
        };

        (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
            self.ws_support.then(|| {
                UpgradeLayer::new(
                    WebSocketMatcher::default(),
                    {
                        let acceptor = WebSocketAcceptor::default()
                            .with_protocols_flex(true)
                            .with_echo_protocols();

                        #[cfg(feature = "compression")]
                        {
                            acceptor.with_per_message_deflate_overwrite_extensions()
                        }
                        #[cfg(not(feature = "compression"))]
                        {
                            acceptor
                        }
                    },
                    ConsumeErrLayer::trace(tracing::Level::DEBUG)
                        .into_layer(WebSocketEchoService::default()),
                )
            }),
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

impl Service<Request> for EchoService {
    type Response = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let user_agent_info = req
            .extensions()
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

        let request_context = RequestContext::try_from(&req)?;

        let authority = request_context.authority.to_string();
        let scheme = request_context.protocol.to_string();

        let ua_str = req
            .headers()
            .get(USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .map(ToOwned::to_owned);
        tracing::debug!(
            user_agent.original = ua_str,
            "echo request received from ua with ua header",
        );

        #[derive(Debug, Serialize)]
        struct FingerprintProfileData {
            hash: String,
            verbose: String,
            matched: bool,
        }

        let ja4h = Ja4H::compute(&req)
            .inspect_err(|err| tracing::error!("ja4h compute failure: {err:?}"))
            .ok()
            .map(|ja4h| {
                let mut profile_ja4h: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref()
                    && let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                    {
                        let matched_ja4h = match req.version() {
                            Version::HTTP_10 | Version::HTTP_11 => profile
                                .http
                                .ja4h_h1_navigate(Some(req.method().clone()))
                                .inspect_err(|err| {
                                    tracing::trace!(
                                        "ja4h computation of matched profile for incoming h1 req: {err:?}"
                                    )
                                })
                                .ok(),
                            Version::HTTP_2 => profile
                                .http
                                .ja4h_h2_navigate(Some(req.method().clone()))
                                .inspect_err(|err| {
                                    tracing::trace!(
                                        "ja4h computation of matched profile for incoming h2 req: {err:?}"
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

                json!({
                    "hash": format!("{ja4h}"),
                    "verbose": format!("{ja4h:?}"),
                    "profile": profile_ja4h,
                })
            });

        let (parts, body) = req.into_parts();

        let body = body
            .collect()
            .await
            .context("collect request body for echo purposes")?
            .to_bytes();

        let curl_request = curl::cmd_string_for_request_parts_and_payload(&parts, &body);

        let headers: Vec<_> = Http1HeaderMap::new(parts.headers, Some(&parts.extensions))
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

        let body = hex::encode(body.as_ref());

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let tls_info = parts
            .extensions
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .map(|hello| {
                let ja4 = Ja4::compute(parts.extensions.extensions())
                    .inspect_err(|err| tracing::trace!("ja4 computation: {err:?}"))
                    .ok();

                let mut profile_ja4: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref()
                    && let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                {
                    let matched_ja4 = profile
                        .tls
                        .compute_ja4(
                            parts
                                .extensions
                                .get::<NegotiatedTlsParameters>()
                                .map(|param| param.protocol_version),
                        )
                        .inspect_err(|err| {
                            tracing::trace!("ja4 computation of matched profile: {err:?}")
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

                let ja4 = ja4.map(|ja4| {
                    json!({
                        "hash": format!("{ja4}"),
                        "verbose": format!("{ja4:?}"),
                        "profile": profile_ja4,
                    })
                });

                let ja3 = Ja3::compute(parts.extensions.extensions())
                    .inspect_err(|err| tracing::trace!("ja3 computation: {err:?}"))
                    .ok();

                let mut profile_ja3: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref()
                    && let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                {
                    let matched_ja3 = profile
                        .tls
                        .compute_ja3(
                            parts
                                .extensions
                                .get::<NegotiatedTlsParameters>()
                                .map(|param| param.protocol_version),
                        )
                        .inspect_err(|err| {
                            tracing::trace!("ja3 computation of matched profile: {err:?}")
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

                let ja3 = ja3.map(|ja3| {
                    json!({
                        "hash": format!("{ja3:x}"),
                        "verbose": format!("{ja3}"),
                        "profile": profile_ja3,
                    })
                });

                let peet = PeetPrint::compute(parts.extensions.extensions())
                    .inspect_err(|err| tracing::trace!("peet computation: {err:?}"))
                    .ok();

                let mut profile_peet: Option<FingerprintProfileData> = None;

                if let Some(uadb) = self.uadb.as_deref()
                    && let Some(profile) =
                        ua_str.as_deref().and_then(|s| uadb.get_exact_header_str(s))
                {
                    let matched_peet = profile
                        .tls
                        .compute_peet()
                        .inspect_err(|err| {
                            tracing::trace!("peetprint computation of matched profile: {err:?}")
                        })
                        .ok();
                    if let (Some(src), Some(tgt)) = (peet.as_ref(), matched_peet) {
                        let hash = format!("{tgt}");
                        let matched = format!("{src}") == hash;
                        profile_peet = Some(FingerprintProfileData {
                            hash,
                            verbose: format!("{tgt:?}"),
                            matched,
                        });
                    }
                }

                let peet = peet.map(|peet| {
                    json!({
                        "hash": format!("{peet}"),
                        "verbose": format!("{peet:?}"),
                        "profile": profile_peet,
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
                        ClientHelloExtension::ApplicationSettings(v) => json!({
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
                    "peet": peet
                })
            });

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let tls_info: Option<()> = None;

        let mut h2 = None;
        if parts.version == Version::HTTP_2 {
            let early_frames = parts.extensions.get::<EarlyFrameCapture>();
            let pseudo_headers = parts.extensions.get::<PseudoHeaderOrder>();
            let akamai_h2 = AkamaiH2::compute(&parts.extensions)
                .inspect_err(|err| tracing::trace!("akamai h2 compute failure: {err:?}"))
                .ok()
                .map(|akamai| {
                    json!({
                        "hash": format!("{akamai}"),
                        "verbose": format!("{akamai:?}"),
                    })
                });

            h2 = Some(json!({
                "early_frames": early_frames,
                "pseudo_headers": pseudo_headers,
                "akamai_h2": akamai_h2,
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
                "curl": curl_request,
            },
            "tls": tls_info,
            "socket_addr": parts.extensions.get::<Forwarded>()
                .and_then(|f|
                        f.client_socket_addr().map(|addr| addr.to_string())
                            .or_else(|| f.client_ip().map(|ip| ip.to_string()))
                ).or_else(|| parts.extensions.get::<SocketInfo>().map(|v| v.peer_addr().to_string())),
        }))
        .into_response())
    }
}
