//! Rama HTTP server module.

use super::HttpServeResult;
use super::core_conn::HttpCoreConnServer;
use rama_core::Service;
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsMut;
use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::stream::Stream;
use rama_http::service::web::response::IntoResponse;
use rama_http_core::server::conn::auto::Builder as AutoConnBuilder;
use rama_http_core::server::conn::auto::Http1Builder as InnerAutoHttp1Builder;
use rama_http_core::server::conn::auto::Http2Builder as InnerAutoHttp2Builder;
use rama_http_core::server::conn::http1::Builder as Http1ConnBuilder;
use rama_http_core::server::conn::http2::Builder as H2ConnBuilder;
use rama_http_types::Request;
use rama_net::socket::Interface;
use rama_tcp::server::TcpListener;
use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;

#[cfg(target_family = "unix")]
use ::{rama_unix::server::UnixListener, std::path::Path};

/// A builder for configuring and listening over HTTP using a [`Service`].
///
/// Supported Protocols: HTTP/1, H2, Auto (HTTP/1 + H2)
///
/// [`Service`]: rama_core::Service
#[derive(Debug, Clone)]
pub struct HttpServer<B> {
    builder: B,
    exec: Executor,
}

impl Default for HttpServer<AutoConnBuilder> {
    #[inline(always)]
    fn default() -> Self {
        Self::auto(Executor::default())
    }
}

impl HttpServer<Http1ConnBuilder> {
    /// Create a new http/1.1 `Builder` with default settings.
    #[must_use]
    pub fn http1(exec: Executor) -> Self {
        Self {
            builder: Http1ConnBuilder::new(),
            exec,
        }
    }
}

impl HttpServer<Http1ConnBuilder> {
    /// Http1 configuration.
    pub fn http1_mut(&mut self) -> &mut Http1ConnBuilder {
        &mut self.builder
    }
}

impl HttpServer<H2ConnBuilder> {
    /// Create a new h2 `Builder` with default settings.
    #[must_use]
    pub fn h2(exec: Executor) -> Self {
        Self {
            builder: H2ConnBuilder::new(exec.clone()),
            exec,
        }
    }
}

impl HttpServer<H2ConnBuilder> {
    /// H2 configuration.
    pub fn h2_mut(&mut self) -> &mut H2ConnBuilder {
        &mut self.builder
    }
}

impl HttpServer<AutoConnBuilder> {
    /// Create a new dual http/1.1 + h2 `Builder` with default settings.
    #[must_use]
    pub fn auto(exec: Executor) -> Self {
        Self {
            builder: AutoConnBuilder::new(exec.clone()),
            exec,
        }
    }
}

impl HttpServer<AutoConnBuilder> {
    /// Http1 configuration.
    pub fn http1_mut(&mut self) -> InnerAutoHttp1Builder<'_> {
        self.builder.http1()
    }

    /// H2 configuration.
    pub fn h2_mut(&mut self) -> InnerAutoHttp2Builder<'_> {
        self.builder.http2()
    }
}

impl<B> HttpServer<B>
where
    B: HttpCoreConnServer,
{
    /// Turn this `HttpServer` into a [`Service`] that can be used to serve
    /// IO Byte streams (e.g. a TCP Stream) as HTTP.
    pub fn service<S: Clone>(self, service: S) -> HttpService<B, S> {
        HttpService {
            guard: self.exec.guard().cloned(),
            builder: Arc::new(self.builder),
            service,
        }
    }

    /// Serve a single IO Byte Stream (e.g. a TCP Stream) as HTTP.
    pub async fn serve<S, Response, IO>(&self, stream: IO, service: S) -> HttpServeResult
    where
        S: Service<Request, Output = Response, Error = Infallible> + Clone,
        Response: IntoResponse + Send + 'static,
        IO: Stream + ExtensionsMut,
    {
        self.builder
            .http_core_serve_connection(stream, service, self.exec.guard().cloned())
            .await
    }

    /// Listen for connections on the given [`Interface`], serving HTTP connections.
    ///
    /// It's a shortcut in case you don't need to operate on the transport layer directly.
    pub async fn listen<S, Response, I>(self, interface: I, service: S) -> HttpServeResult
    where
        S: Service<Request, Output = Response, Error = Infallible> + Clone,
        Response: IntoResponse + Send + 'static,
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface, self.exec.clone()).await?;
        let service = HttpService {
            guard: self.exec.guard().cloned(),
            builder: Arc::new(self.builder),
            service,
        };
        tcp.serve(service).await;
        Ok(())
    }

    #[cfg(target_family = "unix")]
    #[cfg_attr(docsrs, doc(cfg(target_family = "unix")))]
    /// Listen for connections on the given [`Path`], using a unix (domain) socket, serving HTTP connections.
    ///
    /// It's a shortcut in case you don't need to operate on the unix transport layer directly.
    pub async fn listen_unix<S, Response, P>(self, path: P, service: S) -> HttpServeResult
    where
        S: Service<Request, Output = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        P: AsRef<Path>,
    {
        let socket = UnixListener::bind_path(path, self.exec.clone()).await?;
        let service = HttpService {
            guard: self.exec.guard().cloned(),
            builder: Arc::new(self.builder),
            service: Arc::new(service),
        };
        socket.serve(service).await;
        Ok(())
    }
}

/// A [`Service`] that can be used to serve IO Byte streams (e.g. a TCP Stream) as HTTP.
pub struct HttpService<B, S> {
    guard: Option<ShutdownGuard>,
    builder: Arc<B>,
    service: S,
}

impl<B, S> std::fmt::Debug for HttpService<B, S>
where
    B: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpService")
            .field("guard", &self.guard)
            .field("builder", &self.builder)
            .field("service", &self.service)
            .finish()
    }
}

impl<B, S: Clone> Clone for HttpService<B, S> {
    fn clone(&self) -> Self {
        Self {
            guard: self.guard.clone(),
            builder: self.builder.clone(),
            service: self.service.clone(),
        }
    }
}

impl<B, S, Response, IO> Service<IO> for HttpService<B, S>
where
    B: HttpCoreConnServer,
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
    Response: IntoResponse + Send + 'static,
    IO: Stream + ExtensionsMut,
{
    type Output = ();
    type Error = rama_core::error::BoxError;

    fn serve(
        &self,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let service = self.service.clone();
        self.builder
            .http_core_serve_connection(stream, service, self.guard.clone())
    }
}
