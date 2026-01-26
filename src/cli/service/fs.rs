//! [`Service`] that serves a file or directory using [`ServeFile`] or [`ServeDir`], or a placeholder page.

use crate::{
    Layer, Service,
    cli::ForwardKind,
    combinators::Either,
    combinators::{Either3, Either7},
    error::{BoxError, OpaqueError},
    http::{
        Request, Response, Version,
        headers::exotic::XClacksOverhead,
        headers::forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::set_header::SetResponseHeaderLayer,
        layer::{
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
        },
        server::HttpServer,
        service::{
            fs::{DirectoryServeMode, ServeDir, ServeFile},
            web::StaticService,
            web::response::{Html, IntoResponse},
        },
    },
    layer::limit::policy::UnlimitedPolicy,
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::stream::layer::http::BodyLimitLayer,
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    tcp::TcpStream,
    telemetry::tracing,
    ua::layer::classifier::UserAgentClassifierLayer,
};

use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};

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
/// Builder that can be used to run your own serve [`Service`],
/// serving a file or directory, or a placeholder page.
pub struct FsServiceBuilder<H> {
    concurrent_limit: usize,
    body_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,

    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_server_config: Option<TlsConfig>,

    http_version: Option<Version>,

    http_service_builder: H,

    content_path: Option<PathBuf>,
    dir_serve_mode: DirectoryServeMode,
}

impl Default for FsServiceBuilder<()> {
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

            content_path: None,
            dir_serve_mode: DirectoryServeMode::HtmlFileList,
        }
    }
}

impl FsServiceBuilder<()> {
    /// Create a new [`FsServiceBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H> FsServiceBuilder<H> {
    rama_utils::macros::generate_set_and_with! {
        /// set the number of concurrent connections to allow
        ///
        /// (0 = no limit)
        pub fn concurrent(mut self, limit: usize) -> Self {
            self.concurrent_limit = limit;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// set the body limit in bytes for each request
        pub fn body_limit(mut self, limit: usize) -> Self {
            self.body_limit = limit;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// set the timeout in seconds for each connection
        ///
        /// (0 = no timeout)
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
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

    #[cfg(any(feature = "rustls", feature = "boring"))]
    rama_utils::macros::generate_set_and_with! {
        /// define a tls server cert config to be used for tls terminaton
        /// by the serve service.
        pub fn tls_server_config(mut self, cfg: Option<TlsConfig>) -> Self {
            self.tls_server_config = cfg;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// set the http version to use for the http server (auto by default)
        pub fn http_version(mut self, version: Option<Version>) -> Self {
            self.http_version = version;
            self
        }
    }

    /// add a custom http layer which will be applied to the existing http layers
    #[must_use]
    pub fn with_http_layer<H2>(self, layer: H2) -> FsServiceBuilder<(H, H2)> {
        FsServiceBuilder {
            concurrent_limit: self.concurrent_limit,
            body_limit: self.body_limit,
            timeout: self.timeout,
            forward: self.forward,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: self.tls_server_config,

            http_version: self.http_version,

            http_service_builder: (self.http_service_builder, layer),

            content_path: self.content_path,
            dir_serve_mode: self.dir_serve_mode,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the content path to serve (by default it will serve the rama homepage).
        pub fn content_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.content_path = Some(path.into());
            self
        }
    }

    /// Maybe set the content path to serve (by default it will serve the rama homepage).
    #[must_use]
    pub fn maybe_with_content_path<P: Into<PathBuf>>(mut self, path: Option<P>) -> Self {
        self.content_path = path.map(Into::into);
        self
    }

    /// Maybe set the content path to serve (by default it will serve the rama homepage).
    pub fn maybe_set_content_path<P: Into<PathBuf>>(&mut self, path: Option<P>) -> &mut Self {
        self.content_path = path.map(Into::into);
        self
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`DirectoryServeMode`] which defines how to serve directories.
        ///
        /// By default it will use [`DirectoryServeMode::HtmlFileList`].
        ///
        /// Note that this is only used in case the content path is defined
        /// (e.g. using [`Self::content_path`])
        /// and that path points to a valid directory.
        pub fn directory_serve_mode(mut self, mode: DirectoryServeMode) -> Self {
            self.dir_serve_mode = mode;
            self
        }
    }
}

impl<H> FsServiceBuilder<H>
where
    H: Layer<ServeService, Service: Service<Request, Output = Response, Error: Into<BoxError>>>,
{
    /// build a tcp service ready to serve files
    pub fn build(
        self,
        executor: Executor,
    ) -> Result<impl Service<TcpStream, Output = (), Error = Infallible>, BoxError> {
        let tcp_forwarded_layer = match &self.forward {
            Some(ForwardKind::HaProxy) => Some(HaProxyLayer::default()),
            _ => None,
        };

        let http_service = Arc::new(self.build_http()?);

        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let tls_cfg = self.tls_server_config;

        #[cfg(feature = "boring")]
        let tls_cfg: Option<TlsAcceptorData> = match self.tls_server_config {
            Some(cfg) => Some(cfg.try_into()?),
            None => None,
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            LimitLayer::new(if self.concurrent_limit > 0 {
                Either::A(ConcurrentPolicy::max(self.concurrent_limit))
            } else {
                Either::B(UnlimitedPolicy::new())
            }),
            if !self.timeout.is_zero() {
                TimeoutLayer::new(self.timeout)
            } else {
                TimeoutLayer::never()
            },
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
                Either3::B(HttpServer::http1(executor).service(http_service))
            }
            Some(_) => {
                return Err(OpaqueError::from_display("unsupported http version").into_boxed());
            }
            None => Either3::C(HttpServer::auto(executor).service(http_service)),
        };

        Ok(tcp_service_builder.into_layer(http_transport_service))
    }

    /// build an http service ready to serve files
    pub fn build_http(
        &self,
    ) -> Result<impl Service<Request, Output: IntoResponse, Error = Infallible> + use<H>, BoxError>
    {
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

        let serve_service = match &self.content_path {
            None => Either3::A(StaticService::new(Html(include_str!(
                "../../../docs/index.html"
            )))),
            Some(path) if path.is_file() => Either3::B(ServeFile::new(path.clone())),
            Some(path) if path.is_dir() => {
                Either3::C(ServeDir::new(path).with_directory_serve_mode(self.dir_serve_mode))
            }
            Some(path) => {
                return Err(OpaqueError::from_display(format!(
                    "invalid path {path:?}: no such file or directory"
                ))
                .into_boxed());
            }
        };

        let http_service = (
            TraceLayer::new_for_http(),
            SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
        )
            .into_layer(self.http_service_builder.layer(serve_service));

        Ok(http_service)
    }
}

type ServeStaticHtml = StaticService<Html<&'static str>>;
type ServeService = Either3<ServeStaticHtml, ServeFile, ServeDir>;
