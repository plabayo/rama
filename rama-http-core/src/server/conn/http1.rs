//! HTTP/1 Server Connections.

use rama_core::error::{BoxError, BoxErrorExt};
use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use httparse::ParserConfig;
use rama_core::Service;
use rama_core::bytes::Bytes;
use rama_core::extensions::ExtensionsRef;
use rama_http::io::upgrade::Upgraded;
use rama_http::{Body, Request, Response};
use rama_net::conn::LingeringClose;
use rama_net::extensions::StreamTransformed;
use std::task::ready;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::body::Incoming as IncomingBody;
use crate::proto;

type Http1Dispatcher<T, B, S> = proto::h1::Dispatcher<
    proto::h1::dispatch::Server<S, IncomingBody>,
    B,
    T,
    proto::ServerTransaction,
>;

pin_project_lite::pin_project! {
    /// A [`Future`] representing an HTTP/1 connection, bound to a
    /// [`Service`](crate::service::Service), returned from
    /// [`Builder::serve_connection`](struct.Builder.html#method.serve_connection).
    ///
    /// To drive HTTP on this connection this future **must be polled**, typically with
    /// `.await`. If it isn't polled, no progress will be made on this connection.
    #[must_use = "futures do nothing unless polled"]
    pub struct Connection<T, S>
    where
        S: Service<Request<IncomingBody>, Output = Response, Error = Infallible>,
    {
        conn: Http1Dispatcher<T, Body, S>,
    }
}

/// A configuration builder for HTTP/1 server connections.
///
/// **Note**: The default values of options are *not considered stable*. They
/// are subject to change at any time.
///
/// # Example
///
/// ```
/// # use std::time::Duration;
/// # use rama_http_core::server::conn::http1::Builder;
/// # fn main() {
/// let mut http = Builder::new();
/// // Set options one at a time
/// http.set_half_close(false);
///
/// // Or, chain multiple options
/// http.set_keep_alive(false).set_title_case_headers(true).try_set_max_buf_size(8192).unwrap();
///
/// # }
/// ```
///
/// Use [`Builder::serve_connection`](struct.Builder.html#method.serve_connection)
/// to bind the built connection to a service.
#[derive(Clone, Debug)]
pub struct Builder {
    h1_parser_config: ParserConfig,
    h1_half_close: bool,
    h1_keep_alive: bool,
    h1_title_case_headers: bool,
    h1_max_headers: Option<usize>,
    h1_header_read_timeout: Duration,
    h1_lingering_close: Option<LingeringClose>,
    h1_writev: Option<bool>,
    max_buf_size: Option<usize>,
    pipeline_flush: bool,
    date_header: bool,
}

/// Deconstructed parts of a `Connection`.
///
/// This allows taking apart a `Connection` at a later time, in order to
/// reclaim the IO object, and additional related pieces.
#[derive(Debug)]
#[non_exhaustive]
pub struct Parts<T, S> {
    /// The original IO object used in the handshake.
    pub io: T,
    /// A buffer of bytes that have been read but not processed as HTTP.
    ///
    /// If the client sent additional bytes after its last request, and
    /// this connection "ended" with an upgrade, the read buffer will contain
    /// those bytes.
    ///
    /// You will want to check for any existing bytes if you plan to continue
    /// communicating on the IO object.
    pub read_buf: Bytes,
    /// The `Service` used to serve this connection.
    pub service: S,
}

// ===== impl Connection =====

impl<I, S> fmt::Debug for Connection<I, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl<I, S> Connection<I, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
    I: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsRef + 'static,
{
    /// Start a graceful shutdown process for this connection.
    ///
    /// This `Connection` should continue to be polled until shutdown
    /// can finish.
    ///
    /// # Note
    ///
    /// This should only be called while the `Connection` future is still
    /// pending. If called after `Connection::poll` has resolved, this does
    /// nothing.
    pub fn graceful_shutdown(mut self: Pin<&mut Self>) {
        self.conn.disable_keep_alive();
    }

    /// Return the inner IO object, and additional information.
    ///
    /// If the IO object has been "rewound" the io will not contain those bytes rewound.
    /// This should only be called after `poll_without_shutdown` signals
    /// that the connection is "done". Otherwise, it may not have finished
    /// flushing all necessary HTTP bytes.
    ///
    /// # Panics
    /// This method will panic if this connection is using an h2 protocol.
    pub fn into_parts(self) -> Parts<I, S> {
        let (io, read_buf, dispatch) = self.conn.into_inner();
        Parts {
            io,
            read_buf,
            service: dispatch.into_service(),
        }
    }

    /// Poll the connection for completion, but without calling `shutdown`
    /// on the underlying IO.
    ///
    /// This is useful to allow running a connection while doing an HTTP
    /// upgrade. Once the upgrade is completed, the connection would be "done",
    /// but it is not desired to actually shutdown the IO object. Instead you
    /// would take it back using `into_parts`.
    pub fn poll_without_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>>
    where
        S: Unpin,
    {
        self.conn.poll_without_shutdown(cx)
    }

    /// Prevent shutdown of the underlying IO object at the end of service the request,
    /// instead run `into_parts`. This is a convenience wrapper over `poll_without_shutdown`.
    ///
    /// # Error
    ///
    /// This errors if the underlying connection protocol is not HTTP/1.
    pub fn without_shutdown(self) -> impl Future<Output = crate::Result<Parts<I, S>>> {
        let mut this = Some(self);
        std::future::poll_fn(move |cx| {
            if let Some(Self { mut conn }) = this.take() {
                match conn.poll_without_shutdown(cx) {
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(Self { conn }.into_parts())),
                    Poll::Pending => {
                        this = Some(Self { conn });
                        Poll::Pending
                    }
                }
            } else {
                Poll::Ready(Err(
                    crate::Error::new_parse_internal().with_display(
                        "h1 server connection w/o shutdown: poll: inner connection already taken: poll after ready?",
                    )))
            }
        })
    }

    /// Enable this connection to support higher-level HTTP upgrades.
    pub fn with_upgrades(self) -> UpgradeableConnection<I, S>
    where
        I: Send,
    {
        UpgradeableConnection { inner: Some(self) }
    }
}

impl<I, S> Future for Connection<I, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
    I: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsRef + 'static,
{
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.conn).poll(cx)) {
            Ok(done) => {
                match done {
                    proto::Dispatched::Shutdown => {}
                    proto::Dispatched::Upgrade(pending) => {
                        // With no `Send` bound on `I`, we can't try to do
                        // upgrades here. In case a user was trying to use
                        // `Body::on_upgrade` with this API, send a special
                        // error letting them know about that.
                        pending.manual();
                    }
                }
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

// ===== impl Builder =====

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Create a new connection builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            h1_parser_config: ParserConfig::default(),
            h1_half_close: false,
            h1_keep_alive: true,
            h1_title_case_headers: false,
            h1_max_headers: None,
            h1_header_read_timeout: Duration::from_secs(30),
            h1_lingering_close: Some(LingeringClose::default()),
            h1_writev: None,
            max_buf_size: None,
            pipeline_flush: false,
            date_header: true,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether HTTP/1 connections should support half-closures.
        ///
        /// Clients can chose to shutdown their write-side while waiting
        /// for the server to respond. Setting this to `true` will
        /// prevent closing the connection immediately if `read`
        /// detects an EOF in the middle of a request.
        ///
        /// Default is `false`.
        pub fn half_close(mut self, val: bool) -> Self {
            self.h1_half_close = val;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enables or disables HTTP/1 keep-alive.
        ///
        /// Default is `true`.
        pub fn keep_alive(mut self, val: bool) -> Self {
            self.h1_keep_alive = val;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether HTTP/1 connections will write header names as title case at
        /// the socket level.
        ///
        /// Default is `false`.
        pub fn title_case_headers(mut self, enabled: bool) -> Self {
            self.h1_title_case_headers = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether multiple spaces are allowed as delimiters in request lines.
        ///
        /// Default is `false`.
        pub fn allow_multiple_spaces_in_request_line_delimiters(mut self, enabled: bool) -> Self {
            self.h1_parser_config
                .allow_multiple_spaces_in_request_line_delimiters(enabled);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether HTTP/1 connections will silently ignored malformed header lines.
        ///
        /// If this is enabled and a header line does not start with a valid header
        /// name, or does not include a colon at all, the line will be silently ignored
        /// and no error will be reported.
        ///
        /// Default is `false`.
        pub fn ignore_invalid_headers(mut self, enabled: bool) -> Self {
            self.h1_parser_config
                .ignore_invalid_headers_in_requests(enabled);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of headers.
        ///
        /// When a request is received, the parser will reserve a buffer to store headers for optimal
        /// performance.
        ///
        /// If server receives more headers than the buffer size, it responds to the client with
        /// "431 Request Header Fields Too Large".
        ///
        /// Note that headers is allocated on the stack by default, which has higher performance. After
        /// setting this value, headers will be allocated in heap memory, that is, heap memory
        /// allocation will occur for each request, and there will be a performance drop of about 5%.
        ///
        /// Default is `100`.
        pub fn max_headers(mut self, val: Option<usize>) -> Self {
            self.h1_max_headers = val;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the lingering close of a connection the server closes while
        /// the client may still be sending: after shutting down its side, the
        /// server keeps reading and discarding what the client sends, within
        /// these bounds, before closing the socket.
        ///
        /// Closing with unread input makes the connection reset instead of
        /// ending cleanly, and a Windows client then drops the response it
        /// has not read yet: for instance a 413 sent while it is still
        /// uploading, or the 400 or 431 for a bad request head.
        ///
        /// It only applies when input may be left unread: a request body the
        /// service did not read, buffered input such as a pipelined request,
        /// or a rejected request head. A clean close, a client that already
        /// ended its stream, an upgraded connection, a service or IO error,
        /// and a graceful shutdown of the server skip it.
        ///
        /// Default is [`LingeringClose::default`]: up to 2 seconds without
        /// data and 30 seconds in total. `None` disables it.
        pub fn lingering_close(mut self, linger: Option<LingeringClose>) -> Self {
            self.h1_lingering_close = linger;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a timeout for reading client request headers. If a client does not
        /// transmit the entire header within this time, the connection is closed.
        ///
        /// Requires a [`Timer`] set by [`Builder::timer`] to take effect. Panics if `header_read_timeout` is configured
        /// without a [`Timer`].
        ///
        /// Default is 30 seconds.
        pub fn header_read_timeout(mut self, read_timeout: Duration) -> Self{
            self.h1_header_read_timeout = read_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether HTTP/1 connections should try to use vectored writes,
        /// or always flatten into a single buffer.
        ///
        /// Note that setting this to false may mean more copies of body data,
        /// but may also improve performance when an IO transport doesn't
        /// support vectored writes well, such as most TLS implementations.
        ///
        /// Setting this to true will force rama_http_core to use queued strategy,
        /// which may eliminate unnecessary cloning on some TLS backends.
        ///
        /// Default is `auto`. In this mode rama_http_core will try to guess which
        /// mode to use.
        pub fn writev(mut self, val: Option<bool>) -> Self {
            self.h1_writev = val;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum buffer size for the connection.
        ///
        /// Default is ~400kb.
        ///
        /// # Error
        ///
        /// The minimum value allowed is 8192. This method errors if the passed `max` is less than the minimum.
        pub fn max_buf_size(mut self, max: Option<usize>) -> Result<Self, BoxError> {
            if max.map(|max| max < proto::h1::MINIMUM_MAX_BUFFER_SIZE).unwrap_or_default() {
                return Err(BoxError::from_static_str("the max_buf_size cannot be smaller than the minimum that h1 specifies"));
            }
            self.max_buf_size = max;
            Ok(self)
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the `date` header should be included in HTTP responses.
        ///
        /// Note that including the `date` header is recommended by RFC 7231.
        ///
        /// Default is `true`.
        pub fn auto_date_header(mut self, enabled: bool) -> Self {
            self.date_header = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Aggregates flushes to better support pipelined responses.
        ///
        /// Experimental, may have bugs.
        ///
        /// Default is `false`.
        pub fn pipeline_flush(mut self, enabled: bool) -> Self {
            self.pipeline_flush = enabled;
            self
        }
    }

    /// Bind a connection together with a [`Service`].
    ///
    /// This returns a Future that must be polled in order for HTTP to be
    /// driven on the connection.
    ///
    /// # Panics
    ///
    /// If a timeout option has been configured, but a `timer` has not been
    /// provided, calling `serve_connection` will panic.
    pub fn serve_connection<I, S>(&self, io: I, service: S) -> Connection<I, S>
    where
        S: Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
        I: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsRef + 'static,
    {
        io.extensions().insert(StreamTransformed {
            by: "rama-http-core::h1::server",
        });
        let mut conn = proto::Conn::new(io);
        conn.set_h1_parser_config(self.h1_parser_config.clone());
        if !self.h1_keep_alive {
            conn.disable_keep_alive();
        }
        if self.h1_half_close {
            conn.set_allow_half_close();
        }
        if self.h1_title_case_headers {
            conn.set_title_case_headers();
        }
        if let Some(max_headers) = self.h1_max_headers {
            conn.set_http1_max_headers(max_headers);
        }
        conn.set_http1_header_read_timeout(self.h1_header_read_timeout);
        conn.set_lingering_close(self.h1_lingering_close);
        if let Some(writev) = self.h1_writev {
            if writev {
                conn.set_write_strategy_queue();
            } else {
                conn.set_write_strategy_flatten();
            }
        }
        conn.set_flush_pipeline(self.pipeline_flush);
        if let Some(max) = self.max_buf_size {
            conn.set_max_buf_size(max);
        }
        if !self.date_header {
            conn.disable_date_header();
        }
        let sd = proto::h1::dispatch::Server::new(service);
        let proto = proto::h1::Dispatcher::new(sd, conn);
        Connection { conn: proto }
    }
}

/// A future binding a connection with a Service with Upgrade support.
#[must_use = "futures do nothing unless polled"]
#[expect(missing_debug_implementations)]
pub struct UpgradeableConnection<T, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible>,
{
    pub(super) inner: Option<Connection<T, S>>,
}

impl<I, S> UpgradeableConnection<I, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
    I: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsRef + 'static,
{
    /// Start a graceful shutdown process for this connection.
    ///
    /// This `Connection` should continue to be polled until shutdown
    /// can finish.
    pub fn graceful_shutdown(mut self: Pin<&mut Self>) {
        // Connection (`inner`) is `None` if it was upgraded (and `poll` is `Ready`).
        // In that case, we don't need to call `graceful_shutdown`.
        if let Some(conn) = self.inner.as_mut() {
            Pin::new(conn).graceful_shutdown();
        }
    }

    /// Return the inner IO object, and additional information provided the connection
    /// has not yet been upgraded.
    pub fn into_parts(self) -> Option<Parts<I, S>> {
        self.inner.map(|conn| conn.into_parts())
    }
}

impl<I, S> Future for UpgradeableConnection<I, S>
where
    S: Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
    I: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsRef + 'static,
{
    type Output = crate::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(conn) = self.inner.as_mut() {
            match ready!(Pin::new(&mut conn.conn).poll(cx)) {
                Ok(proto::Dispatched::Shutdown) => Poll::Ready(Ok(())),
                Ok(proto::Dispatched::Upgrade(pending)) => {
                    let Some(Connection { conn }) = self.inner.take() else {
                        return Poll::Ready(Err(
                            crate::Error::new_parse_internal().with_display(
                                "h1 server upgradeable connection: dispatch upgrade: inner connection already taken",
                            )));
                    };
                    let (io, buf, _) = conn.into_inner();
                    pending.fulfill(Upgraded::new(io, buf));
                    Poll::Ready(Ok(()))
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        } else {
            // inner is `None`, meaning the connection was upgraded, thus it's `Poll::Ready(Ok(()))`
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::service::VoidHttpService;
    use tokio::net::TcpStream;

    use super::*;

    #[test]
    fn test_assert_send_static() {
        fn g<T: Send + 'static>() {}
        g::<Connection<TcpStream, VoidHttpService>>();
        g::<UpgradeableConnection<TcpStream, VoidHttpService>>();
    }
}

/// Lingering close over real sockets: the server rejects an upload without
/// reading it and closes while the client is still sending.
#[cfg(test)]
#[cfg(not(miri))]
mod lingering_tests {
    use std::{
        convert::Infallible,
        io,
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use rama_core::{ServiceInput, service::service_fn};
    use rama_http::StatusCode;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    use super::*;
    use crate::service::RamaHttpService;

    /// Lingers until something other than a timeout ends it.
    fn patient_linger() -> LingeringClose {
        LingeringClose::new().with_idle_timeout(Duration::from_secs(30))
    }

    const UPLOAD_HEAD: &[u8] =
        b"POST /upload HTTP/1.1\r\nhost: localhost\r\ncontent-length: 104857600\r\n\r\n";

    async fn too_large(_req: Request) -> Result<Response, Infallible> {
        let mut response = Response::new(Body::from("too large"));
        *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
        Ok(response)
    }

    /// Serve one connection that answers every request with 413 without
    /// reading its body. The task returns how long the connection lived.
    async fn reject_uploads(builder: Builder) -> (SocketAddr, JoinHandle<Duration>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let started = Instant::now();
            _ = builder
                .serve_connection(
                    ServiceInput::new(stream),
                    RamaHttpService::new(service_fn(too_large)),
                )
                .await;
            started.elapsed()
        });
        (addr, task)
    }

    async fn read_until_end(reader: &mut (impl AsyncRead + Unpin)) -> (Vec<u8>, io::Result<()>) {
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => return (bytes, Ok(())),
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(err) => return (bytes, Err(err)),
            }
        }
    }

    /// Upload at a modest pace and only read the response later, as a client
    /// busy writing its request does.
    async fn upload_then_read(addr: SocketAddr) -> (Vec<u8>, io::Result<()>) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        writer.write_all(UPLOAD_HEAD).await.unwrap();
        let uploading = tokio::spawn(async move {
            let chunk = [b'x'; 16 * 1024];
            for _ in 0..20 {
                if writer.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            writer
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let received = read_until_end(&mut reader).await;
        drop(uploading.await.unwrap());
        received
    }

    fn is_413(bytes: &[u8]) -> bool {
        bytes.starts_with(b"HTTP/1.1 413")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_keeps_the_response_of_a_rejected_upload() {
        for _ in 0..10 {
            let (addr, server) = reject_uploads(Builder::new()).await;
            let (bytes, end) = upload_then_read(addr).await;
            assert!(is_413(&bytes), "{:?}", String::from_utf8_lossy(&bytes));
            end.unwrap();
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("the server kept lingering after the client closed")
                .unwrap();
        }
    }

    /// The control: without lingering, Windows drops the response.
    #[cfg(target_os = "windows")]
    #[tokio::test(flavor = "multi_thread")]
    async fn without_lingering_windows_drops_the_response() {
        for _ in 0..10 {
            let (addr, _server) = reject_uploads(Builder::new().without_lingering_close()).await;
            let (bytes, end) = upload_then_read(addr).await;
            assert!(!is_413(&bytes), "the response survived without lingering");
            assert!(end.is_err());
        }
    }

    /// A client that already ended its stream sends nothing more: no linger.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_lingering_once_the_client_ended_its_stream() {
        let builder = Builder::new().with_lingering_close(patient_linger());
        let (addr, server) = reject_uploads(builder).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0; 12];
        client.read_exact(&mut head).await.unwrap();
        assert!(is_413(&head));
        client.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the server lingered on a client that ended its stream")
            .unwrap();
    }

    /// A clean close after a fully read request leaves nothing unread: the
    /// server closes right away, even while the client keeps its end open.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_lingering_after_a_clean_close() {
        let builder = Builder::new().with_lingering_close(patient_linger());
        let (addr, server) = reject_uploads(builder).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let (bytes, end) = read_until_end(&mut client).await;
        assert!(is_413(&bytes));
        end.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the server lingered after a clean close")
            .unwrap();
        drop(client);
    }

    /// A request head too large to parse gets its 431 through while the
    /// client is still sending that head.
    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_keeps_the_response_to_a_rejected_head() {
        for linger in [true, false] {
            let builder = Builder::new().try_with_max_buf_size(8192).unwrap();
            let builder = if linger {
                builder
            } else {
                builder.without_lingering_close()
            };
            let (addr, server) = reject_uploads(builder).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            writer
                .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\nx-big: ")
                .await
                .unwrap();
            let sending = tokio::spawn(async move {
                let chunk = [b'a'; 4096];
                for _ in 0..20 {
                    if writer.write_all(&chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                writer
            });
            tokio::time::sleep(Duration::from_millis(150)).await;
            let (bytes, end) = read_until_end(&mut reader).await;
            drop(sending.await.unwrap());
            if linger {
                assert!(
                    bytes.starts_with(b"HTTP/1.1 431"),
                    "{:?}",
                    String::from_utf8_lossy(&bytes)
                );
                end.unwrap();
                tokio::time::timeout(Duration::from_secs(5), server)
                    .await
                    .expect("the server kept lingering after the client closed")
                    .unwrap();
            } else if cfg!(target_os = "windows") {
                assert!(bytes.is_empty() && end.is_err(), "the 431 survived");
            }
        }
    }

    /// A head rejected after it was read in full, here for its invalid
    /// `content-length`, leaves nothing buffered, but the client may still
    /// send the body it announced.
    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_keeps_the_response_to_a_rejected_complete_head() {
        let (addr, server) =
            reject_uploads(Builder::new().with_lingering_close(patient_linger())).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nhost: localhost\r\ncontent-length: nope\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0; 12];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 400");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!server.is_finished(), "the server closed without lingering");
        client.write_all(b"the announced body").await.unwrap();
        client.shutdown().await.unwrap();
        let (_, end) = read_until_end(&mut client).await;
        end.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the server kept lingering after the client closed")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_is_bounded_by_its_idle_timeout() {
        let idle = Duration::from_millis(200);
        let builder =
            Builder::new().with_lingering_close(LingeringClose::new().with_idle_timeout(idle));
        let (addr, server) = reject_uploads(builder).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(UPLOAD_HEAD).await.unwrap();
        client.write_all(&[b'x'; 1024]).await.unwrap();
        // The client neither sends more nor ends its stream.
        let lived = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("lingering was not bounded by its idle timeout")
            .unwrap();
        assert!(lived >= idle, "lingered only {lived:?}");
        drop(client);
    }

    /// A client that keeps sending, just often enough to never idle out, is
    /// cut off by the total timeout.
    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_is_bounded_by_its_total_timeout() {
        let timeout = Duration::from_millis(300);
        let builder = Builder::new().with_lingering_close(
            LingeringClose::new()
                .with_idle_timeout(Duration::from_millis(200))
                .with_timeout(timeout),
        );
        let (addr, server) = reject_uploads(builder).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(UPLOAD_HEAD).await.unwrap();
        let trickle = tokio::spawn(async move {
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until && client.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let lived = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("lingering was not bounded by its total timeout")
            .unwrap();
        assert!(lived >= timeout, "lingered only {lived:?}");
        assert!(lived < Duration::from_secs(2), "lingered {lived:?}");
        trickle.abort();
    }

    /// A client that uploads without end and always has the next bytes
    /// ready: reading never waits, which must not stop the lingering from
    /// ending or from yielding.
    struct EndlessUpload {
        sent: usize,
    }

    impl EndlessUpload {
        fn serve(
            builder: &Builder,
        ) -> Connection<
            ServiceInput<Self>,
            impl Service<Request<IncomingBody>, Output = Response, Error = Infallible> + Clone,
        > {
            builder.serve_connection(
                ServiceInput::new(Self { sent: 0 }),
                RamaHttpService::new(service_fn(too_large)),
            )
        }
    }

    impl AsyncRead for EndlessUpload {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let head = &UPLOAD_HEAD[self.sent.min(UPLOAD_HEAD.len())..];
            if head.is_empty() {
                let n = buf.initialize_unfilled().len();
                buf.advance(n);
            } else {
                let n = head.len().min(buf.remaining());
                buf.put_slice(&head[..n]);
                self.sent += n;
            }
            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for EndlessUpload {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // A current-thread runtime only fires timers when the task yields.
    #[tokio::test]
    async fn lingering_on_an_always_ready_client_ends_at_its_timeout() {
        let timeout = Duration::from_millis(200);
        let builder = Builder::new().with_lingering_close(patient_linger().with_timeout(timeout));
        let started = Instant::now();
        EndlessUpload::serve(&builder).await.unwrap();
        let lived = started.elapsed();
        assert!(lived >= timeout, "lingered only {lived:?}");
        assert!(lived < Duration::from_secs(2), "lingered {lived:?}");
    }

    #[tokio::test]
    async fn lingering_on_an_always_ready_client_yields() {
        let connection =
            EndlessUpload::serve(&Builder::new().with_lingering_close(patient_linger()));
        tokio::pin!(connection);
        let started = Instant::now();
        tokio::select! {
            _ = &mut connection => panic!("the connection ended instead of lingering"),
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        connection.as_mut().graceful_shutdown();
        connection.await.unwrap();
        let lived = started.elapsed();
        assert!(lived < Duration::from_secs(2), "lingered {lived:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lingering_is_bounded_by_its_bytes() {
        let builder =
            Builder::new().with_lingering_close(patient_linger().with_max_bytes(64 * 1024));
        let (addr, server) = reject_uploads(builder).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(UPLOAD_HEAD).await.unwrap();
        let flood = tokio::spawn(async move {
            let chunk = [b'x'; 16 * 1024];
            while client.write_all(&chunk).await.is_ok() {}
        });
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("lingering was not bounded by its byte limit")
            .unwrap();
        flood.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn graceful_shutdown_cuts_lingering_short() {
        let builder = Builder::new().with_lingering_close(patient_linger());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        client.write_all(UPLOAD_HEAD).await.unwrap();

        let connection = builder.serve_connection(
            ServiceInput::new(stream),
            RamaHttpService::new(service_fn(too_large)),
        );
        tokio::pin!(connection);
        tokio::select! {
            _ = &mut connection => panic!("the connection ended instead of lingering"),
            () = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        let mut head = [0; 12];
        client.read_exact(&mut head).await.unwrap();
        assert!(is_413(&head));

        connection.as_mut().graceful_shutdown();
        tokio::time::timeout(Duration::from_secs(1), connection)
            .await
            .expect("graceful shutdown waited for the lingering client")
            .unwrap();
        drop(client);
    }
}
