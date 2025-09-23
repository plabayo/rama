//! Rama HTTP server module.

use super::HttpServeResult;
use super::hyper_conn::HttpCoreConnServer;
use rama_core::error::BoxError;
use rama_core::graceful::ShutdownGuard;
use rama_core::rt::Executor;
use rama_core::stream::Stream;
use rama_core::{Context, Service};
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
pub struct HttpServer<B> {
    builder: B,
    guard: Option<ShutdownGuard>,
}

impl<B> fmt::Debug for HttpServer<B>
where
    B: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpServer")
            .field("builder", &self.builder)
            .finish()
    }
}

impl<B> Clone for HttpServer<B>
where
    B: Clone,
{
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            guard: self.guard.clone(),
        }
    }
}

impl HttpServer<Http1ConnBuilder> {
    /// Create a new http/1.1 `Builder` with default settings.
    #[must_use]
    pub fn http1() -> Self {
        Self {
            builder: Http1ConnBuilder::new(),
            guard: None,
        }
    }

    /// Set the guard that can be used by the [`HttpServer`]
    /// in case it is turned into an http1 listener.
    #[must_use]
    pub fn with_guard(mut self, guard: ShutdownGuard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Maybe set the guard that can be used by the [`HttpServer`]
    /// in case it is turned into an http1 listener.
    #[must_use]
    pub fn maybe_with_guard(mut self, guard: Option<ShutdownGuard>) -> Self {
        self.guard = guard;
        self
    }

    /// Set the guard that can be used by the [`HttpServer`]
    /// in case it is turned into an http1 listener.
    pub fn set_guard(&mut self, guard: ShutdownGuard) -> &mut Self {
        self.guard = Some(guard);
        self
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
        let guard = exec.guard().cloned();
        Self {
            builder: H2ConnBuilder::new(exec),
            guard,
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
        let guard = exec.guard().cloned();
        Self {
            builder: AutoConnBuilder::new(exec),
            guard,
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
    pub fn service<S>(self, service: S) -> HttpService<B, S> {
        HttpService::new(self.builder, service)
    }

    /// Serve a single IO Byte Stream (e.g. a TCP Stream) as HTTP.
    pub async fn serve<S, Response, IO>(
        &self,
        ctx: Context,
        stream: IO,
        service: S,
    ) -> HttpServeResult
    where
        S: Service<Request, Response = Response, Error = Infallible> + Clone,
        Response: IntoResponse + Send + 'static,
        IO: Stream,
    {
        self.builder
            .http_core_serve_connection(ctx, stream, service)
            .await
    }

    /// Listen for connections on the given [`Interface`], serving HTTP connections.
    ///
    /// It's a shortcut in case you don't need to operate on the transport layer directly.
    pub async fn listen<S, Response, I>(self, interface: I, service: S) -> HttpServeResult
    where
        S: Service<Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        I: TryInto<Interface, Error: Into<BoxError>>,
    {
        let tcp = TcpListener::bind(interface).await?;
        let service = HttpService::new(self.builder, service);
        match self.guard {
            Some(guard) => tcp.serve_graceful(guard, service).await,
            None => tcp.serve(service).await,
        };
        Ok(())
    }

    #[cfg(target_family = "unix")]
    /// Listen for connections on the given [`Path`], using a unix (domain) socket, serving HTTP connections.
    ///
    /// It's a shortcut in case you don't need to operate on the unix transport layer directly.
    pub async fn listen_unix<S, Response, P>(self, path: P, service: S) -> HttpServeResult
    where
        S: Service<Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        P: AsRef<Path>,
    {
        let unix = UnixListener::bind_path(path).await?;
        let service = HttpService::new(self.builder, service);
        match self.guard {
            Some(guard) => unix.serve_graceful(guard, service).await,
            None => unix.serve(service).await,
        };
        Ok(())
    }
}

/// A [`Service`] that can be used to serve IO Byte streams (e.g. a TCP Stream) as HTTP.
pub struct HttpService<B, S> {
    builder: Arc<B>,
    service: Arc<S>,
}

impl<B, S> std::fmt::Debug for HttpService<B, S>
where
    B: fmt::Debug,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpService")
            .field("builder", &self.builder)
            .field("service", &self.service)
            .finish()
    }
}

impl<B, S> HttpService<B, S> {
    fn new(builder: B, service: S) -> Self {
        Self {
            builder: Arc::new(builder),
            service: Arc::new(service),
        }
    }
}

impl<B, S> Clone for HttpService<B, S> {
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            service: self.service.clone(),
        }
    }
}

impl<B, S, Response, IO> Service<IO> for HttpService<B, S>
where
    B: HttpCoreConnServer,
    S: Service<Request, Response = Response, Error = Infallible>,
    Response: IntoResponse + Send + 'static,
    IO: Stream,
{
    type Response = ();
    type Error = rama_core::error::BoxError;

    fn serve(
        &self,
        ctx: Context,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let service = self.service.clone();
        self.builder
            .http_core_serve_connection(ctx, stream, service)
    }
}
