//! Rama HTTP server module.

use super::hyper_conn::HyperConnServer;
use super::HttpServeResult;
use crate::http::{IntoResponse, Request};
use crate::net::stream::Stream;
use crate::rt::Executor;
use crate::service::{Context, Service};
use crate::tcp::server::TcpListener;
use hyper::server::conn::http2::Builder as H2ConnBuilder;
use hyper::{rt::Timer, server::conn::http1::Builder as Http1ConnBuilder};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::server::conn::auto::Http1Builder as InnerAutoHttp1Builder;
use hyper_util::server::conn::auto::Http2Builder as InnerAutoHttp2Builder;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::ToSocketAddrs;
use tokio_graceful::ShutdownGuard;

/// A builder for configuring and listening over HTTP using a [`Service`].
///
/// Supported Protocols: HTTP/1, H2, Auto (HTTP/1 + H2)
///
/// [`Service`]: crate::service::Service
#[derive(Debug)]
pub struct HttpServer<B> {
    builder: B,
}

impl<B> Clone for HttpServer<B>
where
    B: Clone,
{
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
        }
    }
}

impl HttpServer<Http1ConnBuilder> {
    /// Create a new http/1.1 `Builder` with default settings.
    pub fn http1() -> Self {
        Self {
            builder: Http1ConnBuilder::new(),
        }
    }
}

impl HttpServer<Http1ConnBuilder> {
    /// Http1 configuration.
    pub fn http1_mut(&mut self) -> Http1Config<'_> {
        Http1Config {
            inner: &mut self.builder,
        }
    }
}

/// A configuration builder for HTTP/1 server connections.
#[derive(Debug)]
pub struct Http1Config<'a> {
    inner: &'a mut Http1ConnBuilder,
}

impl<'a> Http1Config<'a> {
    /// Set whether HTTP/1 connections should support half-closures.
    ///
    /// Clients can chose to shutdown their write-side while waiting
    /// for the server to respond. Setting this to `true` will
    /// prevent closing the connection immediately if `read`
    /// detects an EOF in the middle of a request.
    ///
    /// Default is `false`.
    pub fn half_close(&mut self, val: bool) -> &mut Self {
        self.inner.half_close(val);
        self
    }

    /// Enables or disables HTTP/1 keep-alive.
    ///
    /// Default is true.
    pub fn keep_alive(&mut self, val: bool) -> &mut Self {
        self.inner.keep_alive(val);
        self
    }

    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Note that this setting does not affect H2.
    ///
    /// Default is false.
    pub fn title_case_headers(&mut self, enabled: bool) -> &mut Self {
        self.inner.title_case_headers(enabled);
        self
    }

    /// Set whether to support preserving original header cases.
    ///
    /// Currently, this will record the original cases received, and store them
    /// in a private extension on the `Request`. It will also look for and use
    /// such an extension in any provided `Response`.
    ///
    /// Since the relevant extension is still private, there is no way to
    /// interact with the original cases. The only effect this can have now is
    /// to forward the cases in a proxy-like fashion.
    ///
    /// Note that this setting does not affect H2.
    ///
    /// Default is false.
    pub fn preserve_header_case(&mut self, enabled: bool) -> &mut Self {
        self.inner.preserve_header_case(enabled);
        self
    }

    /// Set a timeout for reading client request headers. If a client does not
    /// transmit the entire header within this time, the connection is closed.
    ///
    /// Default is None.
    pub fn header_read_timeout(&mut self, read_timeout: Duration) -> &mut Self {
        self.inner.header_read_timeout(read_timeout);
        self
    }

    /// Set whether HTTP/1 connections should try to use vectored writes,
    /// or always flatten into a single buffer.
    ///
    /// Note that setting this to false may mean more copies of body data,
    /// but may also improve performance when an IO transport doesn't
    /// support vectored writes well, such as most TLS implementations.
    ///
    /// Setting this to true will force hyper to use queued strategy
    /// which may eliminate unnecessary cloning on some TLS backends
    ///
    /// Default is `auto`. In this mode hyper will try to guess which
    /// mode to use
    pub fn writev(&mut self, val: bool) -> &mut Self {
        self.inner.writev(val);
        self
    }

    /// Set the maximum buffer size for the connection.
    ///
    /// Default is ~400kb.
    ///
    /// # Panics
    ///
    /// The minimum value allowed is 8192. This method panics if the passed `max` is less than the minimum.
    pub fn max_buf_size(&mut self, max: usize) -> &mut Self {
        self.inner.max_buf_size(max);
        self
    }

    /// Aggregates flushes to better support pipelined responses.
    ///
    /// Experimental, may have bugs.
    ///
    /// Default is false.
    pub fn pipeline_flush(&mut self, enabled: bool) -> &mut Self {
        self.inner.pipeline_flush(enabled);
        self
    }

    /// Set the timer used in background tasks.
    pub fn timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.inner.timer(timer);
        self
    }
}

impl HttpServer<H2ConnBuilder<Executor>> {
    /// Create a new h2 `Builder` with default settings.
    pub fn h2(exec: Executor) -> Self {
        Self {
            builder: H2ConnBuilder::new(exec),
        }
    }
}

impl<E> HttpServer<H2ConnBuilder<E>> {
    /// H2 configuration.
    pub fn h2_mut(&mut self) -> H2Config<'_, E> {
        H2Config {
            inner: &mut self.builder,
        }
    }
}

/// A configuration builder for H2 server connections.
#[derive(Debug)]
pub struct H2Config<'a, E> {
    inner: &'a mut H2ConnBuilder<E>,
}

impl<'a, E> H2Config<'a, E> {
    /// Sets the [`SETTINGS_INITIAL_WINDOW_SIZE`][spec] option for HTTP2
    /// stream-level flow control.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    ///
    /// [spec]: https://http2.github.io/http2-spec/#SETTINGS_INITIAL_WINDOW_SIZE
    pub fn initial_stream_window_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.initial_stream_window_size(sz);
        self
    }

    /// Sets the max connection-level flow control for HTTP2.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    pub fn initial_connection_window_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.initial_connection_window_size(sz);
        self
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in
    /// `http2_initial_stream_window_size` and
    /// `http2_initial_connection_window_size`.
    pub fn adaptive_window(&mut self, enabled: bool) -> &mut Self {
        self.inner.adaptive_window(enabled);
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    pub fn max_frame_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.max_frame_size(sz);
        self
    }

    /// Sets the [`SETTINGS_MAX_CONCURRENT_STREAMS`][spec] option for HTTP2
    /// connections.
    ///
    /// Default is no limit (`std::u32::MAX`). Passing `None` will do nothing.
    ///
    /// [spec]: https://http2.github.io/http2-spec/#SETTINGS_MAX_CONCURRENT_STREAMS
    pub fn max_concurrent_streams(&mut self, max: impl Into<Option<u32>>) -> &mut Self {
        self.inner.max_concurrent_streams(max);
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    ///
    /// # Cargo Feature
    ///
    pub fn keep_alive_interval(&mut self, interval: impl Into<Option<Duration>>) -> &mut Self {
        self.inner.keep_alive_interval(interval);
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will
    /// be closed. Does nothing if `http2_keep_alive_interval` is disabled.
    ///
    /// Default is 20 seconds.
    ///
    /// # Cargo Feature
    ///
    pub fn keep_alive_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.inner.keep_alive_timeout(timeout);
        self
    }

    /// Set the maximum write buffer size for each H2 stream.
    ///
    /// Default is currently ~400KB, but may change.
    ///
    /// # Panics
    ///
    /// The value must be no larger than `u32::MAX`.
    pub fn max_send_buf_size(&mut self, max: usize) -> &mut Self {
        self.inner.max_send_buf_size(max);
        self
    }

    /// Enables the [extended CONNECT protocol].
    ///
    /// [extended CONNECT protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
    pub fn enable_connect_protocol(&mut self) -> &mut Self {
        self.inner.enable_connect_protocol();
        self
    }

    /// Sets the max size of received header frames.
    ///
    /// Default is currently ~16MB, but may change.
    pub fn max_header_list_size(&mut self, max: u32) -> &mut Self {
        self.inner.max_header_list_size(max);
        self
    }

    /// Set the timer used in background tasks.
    pub fn timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.inner.timer(timer);
        self
    }
}

impl HttpServer<AutoConnBuilder<Executor>> {
    /// Create a new dual http/1.1 + h2 `Builder` with default settings.
    pub fn auto(exec: Executor) -> Self {
        Self {
            builder: AutoConnBuilder::new(exec),
        }
    }
}

impl<E> HttpServer<AutoConnBuilder<E>> {
    /// Http1 configuration.
    pub fn http1_mut(&mut self) -> AutoHttp1Config<'_, E> {
        AutoHttp1Config {
            inner: self.builder.http1(),
        }
    }

    /// H2 configuration.
    pub fn h2_mut(&mut self) -> AutoH2Config<'_, E> {
        AutoH2Config {
            inner: self.builder.http2(),
        }
    }
}

/// A configuration builder for HTTP/1 server connections in auto mode.
pub struct AutoHttp1Config<'a, E> {
    inner: InnerAutoHttp1Builder<'a, E>,
}

impl std::fmt::Debug for AutoHttp1Config<'_, ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoHttp1Config").finish()
    }
}

impl<'a, E> AutoHttp1Config<'a, E> {
    /// Set whether HTTP/1 connections should support half-closures.
    ///
    /// Clients can chose to shutdown their write-side while waiting
    /// for the server to respond. Setting this to `true` will
    /// prevent closing the connection immediately if `read`
    /// detects an EOF in the middle of a request.
    ///
    /// Default is `false`.
    pub fn half_close(&mut self, val: bool) -> &mut Self {
        self.inner.half_close(val);
        self
    }

    /// Enables or disables HTTP/1 keep-alive.
    ///
    /// Default is true.
    pub fn keep_alive(&mut self, val: bool) -> &mut Self {
        self.inner.keep_alive(val);
        self
    }

    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Note that this setting does not affect H2.
    ///
    /// Default is false.
    pub fn title_case_headers(&mut self, enabled: bool) -> &mut Self {
        self.inner.title_case_headers(enabled);
        self
    }

    /// Set whether to support preserving original header cases.
    ///
    /// Currently, this will record the original cases received, and store them
    /// in a private extension on the `Request`. It will also look for and use
    /// such an extension in any provided `Response`.
    ///
    /// Since the relevant extension is still private, there is no way to
    /// interact with the original cases. The only effect this can have now is
    /// to forward the cases in a proxy-like fashion.
    ///
    /// Note that this setting does not affect H2.
    ///
    /// Default is false.
    pub fn preserve_header_case(&mut self, enabled: bool) -> &mut Self {
        self.inner.preserve_header_case(enabled);
        self
    }

    /// Set a timeout for reading client request headers. If a client does not
    /// transmit the entire header within this time, the connection is closed.
    ///
    /// Default is None.
    pub fn header_read_timeout(&mut self, read_timeout: Duration) -> &mut Self {
        self.inner.header_read_timeout(read_timeout);
        self
    }

    /// Set whether HTTP/1 connections should try to use vectored writes,
    /// or always flatten into a single buffer.
    ///
    /// Note that setting this to false may mean more copies of body data,
    /// but may also improve performance when an IO transport doesn't
    /// support vectored writes well, such as most TLS implementations.
    ///
    /// Setting this to true will force hyper to use queued strategy
    /// which may eliminate unnecessary cloning on some TLS backends
    ///
    /// Default is `auto`. In this mode hyper will try to guess which
    /// mode to use
    pub fn writev(&mut self, val: bool) -> &mut Self {
        self.inner.writev(val);
        self
    }

    /// Set the maximum buffer size for the connection.
    ///
    /// Default is ~400kb.
    ///
    /// # Panics
    ///
    /// The minimum value allowed is 8192. This method panics if the passed `max` is less than the minimum.
    pub fn max_buf_size(&mut self, max: usize) -> &mut Self {
        self.inner.max_buf_size(max);
        self
    }

    /// Aggregates flushes to better support pipelined responses.
    ///
    /// Experimental, may have bugs.
    ///
    /// Default is false.
    pub fn pipeline_flush(&mut self, enabled: bool) -> &mut Self {
        self.inner.pipeline_flush(enabled);
        self
    }

    /// Set the timer used in background tasks.
    pub fn timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.inner.timer(timer);
        self
    }
}

/// A configuration builder for H2 server connections in auto mode.
pub struct AutoH2Config<'a, E> {
    inner: InnerAutoHttp2Builder<'a, E>,
}

impl std::fmt::Debug for AutoH2Config<'_, ()> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoH2Config").finish()
    }
}

impl<'a, E> AutoH2Config<'a, E> {
    /// Sets the [`SETTINGS_INITIAL_WINDOW_SIZE`][spec] option for HTTP2
    /// stream-level flow control.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    ///
    /// [spec]: https://http2.github.io/http2-spec/#SETTINGS_INITIAL_WINDOW_SIZE
    pub fn initial_stream_window_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.initial_stream_window_size(sz);
        self
    }

    /// Sets the max connection-level flow control for HTTP2.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    pub fn initial_connection_window_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.initial_connection_window_size(sz);
        self
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in
    /// `http2_initial_stream_window_size` and
    /// `http2_initial_connection_window_size`.
    pub fn adaptive_window(&mut self, enabled: bool) -> &mut Self {
        self.inner.adaptive_window(enabled);
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, hyper will use a default.
    pub fn max_frame_size(&mut self, sz: impl Into<Option<u32>>) -> &mut Self {
        self.inner.max_frame_size(sz);
        self
    }

    /// Sets the [`SETTINGS_MAX_CONCURRENT_STREAMS`][spec] option for HTTP2
    /// connections.
    ///
    /// Default is no limit (`std::u32::MAX`). Passing `None` will do nothing.
    ///
    /// [spec]: https://http2.github.io/http2-spec/#SETTINGS_MAX_CONCURRENT_STREAMS
    pub fn max_concurrent_streams(&mut self, max: impl Into<Option<u32>>) -> &mut Self {
        self.inner.max_concurrent_streams(max);
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    ///
    /// # Cargo Feature
    ///
    pub fn keep_alive_interval(&mut self, interval: impl Into<Option<Duration>>) -> &mut Self {
        self.inner.keep_alive_interval(interval);
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will
    /// be closed. Does nothing if `http2_keep_alive_interval` is disabled.
    ///
    /// Default is 20 seconds.
    ///
    /// # Cargo Feature
    ///
    pub fn keep_alive_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.inner.keep_alive_timeout(timeout);
        self
    }

    /// Set the maximum write buffer size for each H2 stream.
    ///
    /// Default is currently ~400KB, but may change.
    ///
    /// # Panics
    ///
    /// The value must be no larger than `u32::MAX`.
    pub fn max_send_buf_size(&mut self, max: usize) -> &mut Self {
        self.inner.max_send_buf_size(max);
        self
    }

    /// Enables the [extended CONNECT protocol].
    ///
    /// [extended CONNECT protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
    pub fn enable_connect_protocol(&mut self) -> &mut Self {
        self.inner.enable_connect_protocol();
        self
    }

    /// Sets the max size of received header frames.
    ///
    /// Default is currently ~16MB, but may change.
    pub fn max_header_list_size(&mut self, max: u32) -> &mut Self {
        self.inner.max_header_list_size(max);
        self
    }

    /// Set the timer used in background tasks.
    pub fn timer<M>(&mut self, timer: M) -> &mut Self
    where
        M: Timer + Send + Sync + 'static,
    {
        self.inner.timer(timer);
        self
    }
}

impl<B> HttpServer<B>
where
    B: HyperConnServer,
{
    /// Turn this `HttpServer` into a [`Service`] that can be used to serve
    /// IO Byte streams (e.g. a TCP Stream) as HTTP.
    pub fn service<State, S, Response>(self, service: S) -> HttpService<B, S, State>
    where
        S: Service<State, Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
    {
        HttpService::new(self.builder, service)
    }

    /// Serve a single IO Byte Stream (e.g. a TCP Stream) as HTTP.
    pub async fn serve<State, S, Response, IO>(
        &self,
        ctx: Context<State>,
        stream: IO,
        service: S,
    ) -> HttpServeResult
    where
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        IO: Stream,
    {
        self.builder
            .hyper_serve_connection(ctx, stream, service)
            .await
    }

    /// Listen for connections on the given address, serving HTTP connections.
    ///
    /// It's a shortcut in case you don't need to operate on the transport layer directly.
    pub async fn listen<S, Response, A>(self, addr: A, service: S) -> HttpServeResult
    where
        S: Service<(), Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        A: ToSocketAddrs,
    {
        TcpListener::bind(addr)
            .await?
            .serve(self.service(service))
            .await;
        Ok(())
    }

    /// Listen gracefully for connections on the given address, serving HTTP connections.
    ///
    /// Same as [`Self::listen`], but it will respect the given [`ShutdownGuard`],
    /// and also pass it to the service.
    ///
    /// [`ShutdownGuard`]: crate::utils::graceful::ShutdownGuard
    pub async fn listen_graceful<S, Response, A>(
        self,
        guard: ShutdownGuard,
        addr: A,
        service: S,
    ) -> HttpServeResult
    where
        S: Service<(), Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        A: ToSocketAddrs,
    {
        TcpListener::bind(addr)
            .await?
            .serve_graceful(guard, self.service(service))
            .await;
        Ok(())
    }

    /// Listen for connections on the given address, serving HTTP connections.
    ///
    /// Same as [`Self::listen`], but including the given state in the [`Service`]'s [`Context`].
    ///
    /// [`Service`]: crate::service::Service
    /// [`Context`]: crate::service::Context
    pub async fn listen_with_state<State, S, Response, A>(
        self,
        state: State,
        addr: A,
        service: S,
    ) -> HttpServeResult
    where
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        A: ToSocketAddrs,
    {
        TcpListener::build_with_state(state)
            .bind(addr)
            .await?
            .serve(self.service(service))
            .await;
        Ok(())
    }

    /// Listen gracefully for connections on the given address, serving HTTP connections.
    ///
    /// Same as [`Self::listen_graceful`], but including the given state in the [`Service`]'s [`Context`].
    ///
    /// [`Service`]: crate::service::Service
    /// [`Context`]: crate::service::Context
    pub async fn listen_graceful_with_state<State, S, Response, A>(
        self,
        guard: ShutdownGuard,
        state: State,
        addr: A,
        service: S,
    ) -> HttpServeResult
    where
        State: Send + Sync + 'static,
        S: Service<State, Request, Response = Response, Error = Infallible>,
        Response: IntoResponse + Send + 'static,
        A: ToSocketAddrs,
    {
        TcpListener::build_with_state(state)
            .bind(addr)
            .await?
            .serve_graceful(guard, self.service(service))
            .await;
        Ok(())
    }
}

/// A [`Service`] that can be used to serve IO Byte streams (e.g. a TCP Stream) as HTTP.
pub struct HttpService<B, S, State> {
    builder: Arc<B>,
    service: Arc<S>,
    _phantom: std::marker::PhantomData<State>,
}

impl<B, S, State> std::fmt::Debug for HttpService<B, S, State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpService").finish()
    }
}

impl<B, S, State> HttpService<B, S, State> {
    fn new(builder: B, service: S) -> Self {
        Self {
            builder: Arc::new(builder),
            service: Arc::new(service),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B, S, State> Clone for HttpService<B, S, State> {
    fn clone(&self) -> Self {
        Self {
            builder: self.builder.clone(),
            service: self.service.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B, State, S, Response, IO> Service<State, IO> for HttpService<B, S, State>
where
    B: HyperConnServer,
    State: Send + Sync + 'static,
    S: Service<State, Request, Response = Response, Error = Infallible>,
    Response: IntoResponse + Send + 'static,
    IO: Stream,
{
    type Response = ();
    type Error = crate::error::BoxError;

    fn serve(
        &self,
        ctx: Context<State>,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let service = self.service.clone();
        self.builder.hyper_serve_connection(ctx, stream, service)
    }
}
