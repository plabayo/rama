use std::{
    convert::Infallible,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_channel::mpsc::{Receiver, Sender};
use futures_channel::{mpsc, oneshot};
use pin_project_lite::pin_project;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{Instrument, debug, trace, trace_root_span, warn};
use rama_core::{bytes::Bytes, combinators::Either};
use rama_core::{error::BoxError, futures::future::FusedFuture};
use rama_core::{
    extensions::ExtensionsMut,
    futures::{Stream, stream::FusedStream},
};
use rama_http::{
    StreamingBody,
    io::upgrade::{self, Upgraded},
};
use rama_http_types::{
    Method, Request, Response, StatusCode, Version, opentelemetry::version_as_protocol_version,
    proto::h2::frame::SettingOrder,
};
use std::task::ready;
use tokio::io::{AsyncRead, AsyncWrite};

use super::ping::{Ponger, Recorder};
use super::{H2Upgraded, PipeToSendStream, SendBuf, ping};
use crate::body::Incoming as IncomingBody;
use crate::client::dispatch::{Callback, SendWhen, TrySendError};
use crate::h2::SendStream;
use crate::h2::client::ResponseFuture;
use crate::h2::client::{Builder, Connection, SendRequest};
use crate::headers;
use crate::proto::Dispatched;
use crate::proto::h2::UpgradedSendStream;

type ClientRx<B> = crate::client::dispatch::Receiver<Request<B>, Response<IncomingBody>>;

///// An mpsc channel is used to help notify the `Connection` task when *all*
///// other handles to it have been dropped, so that it can shutdown.
type ConnDropRef = mpsc::Sender<Infallible>;

///// A oneshot channel watches the `Connection` task, and when it completes,
///// the "dispatch" task will be notified and can shutdown sooner.
type ConnEof = oneshot::Receiver<Infallible>;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024 * 5; // 5mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024 * 2; // 2mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 1024; // 1mb
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb

// The maximum number of concurrent streams that the client is allowed to open
// before it receives the initial SETTINGS frame from the server.
// This default value is derived from what the HTTP/2 spec recommends as the
// minimum value that endpoints advertise to their peers. It means that using
// this value will minimize the chance of the failure where the local endpoint
// attempts to open too many streams and gets rejected by the remote peer with
// the `REFUSED_STREAM` error.
const DEFAULT_INITIAL_MAX_SEND_STREAMS: usize = 100;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32, // alias for initial_window_size
    pub(crate) initial_max_send_streams: usize,
    pub(crate) max_frame_size: Option<u32>,
    pub(crate) max_header_list_size: u32,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) keep_alive_while_idle: bool,
    pub(crate) max_concurrent_reset_streams: Option<usize>,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) enable_push: bool,
    pub(crate) enable_connect_protocol: Option<u32>,
    pub(crate) no_rfc7540_priorities: Option<u32>,
    pub(crate) setting_order: Option<SettingOrder>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            initial_max_send_streams: DEFAULT_INITIAL_MAX_SEND_STREAMS,
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: false,
            max_concurrent_reset_streams: None,
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_pending_accept_reset_streams: None,
            header_table_size: None,
            max_concurrent_streams: None,
            enable_push: false,
            enable_connect_protocol: None,
            no_rfc7540_priorities: None,
            setting_order: None,
        }
    }
}

pub(crate) fn new_builder(config: &Config) -> Builder {
    let mut builder = Builder::default();
    builder
        .initial_max_send_streams(config.initial_max_send_streams)
        .initial_window_size(config.initial_stream_window_size)
        .initial_connection_window_size(config.initial_conn_window_size)
        .max_header_list_size(config.max_header_list_size)
        .max_send_buffer_size(config.max_send_buffer_size)
        .enable_push(config.enable_push);
    if let Some(max) = config.max_frame_size {
        builder.max_frame_size(max);
    }
    if let Some(max) = config.max_concurrent_reset_streams {
        builder.max_concurrent_reset_streams(max);
    }
    if let Some(max) = config.max_pending_accept_reset_streams {
        builder.max_pending_accept_reset_streams(max);
    }
    if let Some(size) = config.header_table_size {
        builder.header_table_size(size);
    }
    if let Some(max) = config.max_concurrent_streams {
        builder.max_concurrent_streams(max);
    }
    if let Some(connect_protocol) = config.enable_connect_protocol {
        builder.enable_connect_protocol(connect_protocol);
    }
    if let Some(no_rfc7540_priorities) = config.no_rfc7540_priorities {
        builder.set_no_rfc7540_priorities(no_rfc7540_priorities);
    }
    if let Some(setting_order) = config.setting_order.clone() {
        builder.setting_order(setting_order);
    }
    builder
}

fn new_ping_config(config: &Config) -> ping::Config {
    ping::Config {
        bdp_initial_window: if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        },
        keep_alive_interval: config.keep_alive_interval,
        keep_alive_timeout: config.keep_alive_timeout,
        keep_alive_while_idle: config.keep_alive_while_idle,
    }
}

#[expect(dead_code)]
pub(crate) async fn handshake<T, B>(
    io: T,
    req_rx: ClientRx<B>,
    config: &Config,
    exec: Executor,
) -> crate::Result<ClientTask<B, T>>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsMut + 'static,
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    handshake_with_builder(new_builder(config), io, req_rx, config, exec).await
}

pub(crate) async fn handshake_with_builder<T, B>(
    builder: Builder,
    io: T,
    req_rx: ClientRx<B>,
    config: &Config,
    exec: Executor,
) -> crate::Result<ClientTask<B, T>>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsMut + 'static,
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    let (h2_tx, mut conn) = builder
        .handshake::<_, SendBuf<B::Data>>(io)
        .await
        .map_err(crate::Error::new_h2)?;

    // An mpsc channel is used entirely to detect when the
    // 'Client' has been dropped. This is to get around a bug
    // in h2 where dropping all SendRequests won't notify a
    // parked Connection.
    let (conn_drop_ref, conn_drop_rx) = mpsc::channel(1);
    let (cancel_tx, conn_eof) = oneshot::channel();

    let ping_config = new_ping_config(config);

    let (conn, ping) = if ping_config.is_enabled() {
        let pp = conn.ping_pong().expect("conn.ping_pong");
        let (recorder, ponger) = ping::channel(pp, &ping_config);

        let conn: Conn<_, B> = Conn::new(ponger, conn);
        (Either::A(conn), recorder)
    } else {
        (Either::B(conn), ping::disabled())
    };
    let conn: ConnMapErr<T, B> = ConnMapErr {
        conn,
        is_terminated: false,
    };

    let task_span = trace_root_span!(
        "h2::task",
        otel.kind = "client",
        network.protocol.name = "http",
        network.protocol.version = version_as_protocol_version(Version::HTTP_2),
    );

    exec.spawn_task(
        H2ClientFuture::Task {
            task: ConnTask::new(conn, conn_drop_rx, cancel_tx),
        }
        .instrument(task_span),
    );

    Ok(ClientTask {
        ping,
        conn_drop_ref,
        conn_eof,
        executor: exec,
        h2_tx,
        req_rx,
        fut_ctx: None,
        marker: PhantomData,
    })
}

pin_project! {
    struct Conn<T, B>
    where
        B: StreamingBody,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
    {
        #[pin]
        ponger: Ponger,
        #[pin]
        conn: Connection<T, SendBuf<<B as StreamingBody>::Data>>,
    }
}

impl<T, B> Conn<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn new(ponger: Ponger, conn: Connection<T, SendBuf<<B as StreamingBody>::Data>>) -> Self {
        Self { ponger, conn }
    }
}

impl<T, B> Future for Conn<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut + 'static,
{
    type Output = Result<(), crate::h2::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match this.ponger.poll(cx) {
            Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                this.conn.set_target_window_size(wnd);
                this.conn.set_initial_window_size(wnd)?;
            }
            Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                debug!("connection keep-alive timed out");
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }

        Pin::new(&mut this.conn).poll(cx)
    }
}

pin_project! {
    struct ConnMapErr<T, B>
    where
        B: StreamingBody,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
        T: Send,
        T: 'static,
    {
        #[pin]
        conn: Either<Conn<T, B>, Connection<T, SendBuf<<B as StreamingBody>::Data>>>,
        #[pin]
        is_terminated: bool,
    }
}

impl<T, B> Future for ConnMapErr<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut,
{
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if *this.is_terminated {
            return Poll::Pending;
        }
        let polled = this.conn.poll(cx);
        if polled.is_ready() {
            *this.is_terminated = true;
        }
        polled.map_err(|_e| {
            debug!("connection error: {_e:?}");
        })
    }
}

impl<T, B> FusedFuture for ConnMapErr<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut + 'static,
{
    fn is_terminated(&self) -> bool {
        self.is_terminated
    }
}

pin_project! {
    pub struct ConnTask<T, B>
    where
        B: StreamingBody,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
        T: Send,
        T: 'static,
    {
        #[pin]
        drop_rx: Receiver<Infallible>,
        #[pin]
        cancel_tx: Option<oneshot::Sender<Infallible>>,
        #[pin]
        conn: ConnMapErr<T, B>,
    }
}

impl<T, B> ConnTask<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn new(
        conn: ConnMapErr<T, B>,
        drop_rx: Receiver<Infallible>,
        cancel_tx: oneshot::Sender<Infallible>,
    ) -> Self {
        Self {
            drop_rx,
            cancel_tx: Some(cancel_tx),
            conn,
        }
    }
}

impl<T, B> Future for ConnTask<T, B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut + 'static,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if !this.conn.is_terminated() && Pin::new(&mut this.conn).poll(cx).is_ready() {
            // ok or err, the `conn` has finished.
            return Poll::Ready(());
        }

        if !this.drop_rx.is_terminated() && Pin::new(&mut this.drop_rx).poll_next(cx).is_ready() {
            // mpsc has been dropped, hopefully polling
            // the connection some more should start shutdown
            // and then close.
            trace!("send_request dropped, starting conn shutdown");
            drop(this.cancel_tx.take().expect("ConnTask Future polled twice"));
        }

        Poll::Pending
    }
}

pin_project! {
    #[project = H2ClientFutureProject]
    pub enum H2ClientFuture<B, T>
    where
        B: StreamingBody,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
        T: Send,
        T: 'static,
    {
        Pipe {
            #[pin]
            pipe: PipeMap<B>,
        },
        Send {
            #[pin]
            send_when: SendWhen<B>,
        },
        Task {
            #[pin]
            task: ConnTask<T, B>,
        },
    }
}

impl<B, T> Future for H2ClientFuture<B, T>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut + 'static,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this {
            H2ClientFutureProject::Pipe { pipe } => pipe.poll(cx),
            H2ClientFutureProject::Send { send_when } => send_when.poll(cx),
            H2ClientFutureProject::Task { task } => task.poll(cx),
        }
    }
}

struct FutCtx<B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    is_connect: bool,
    eos: bool,
    fut: ResponseFuture,
    body_tx: SendStream<SendBuf<B::Data>>,
    body: B,
    cb: Callback<Request<B>, Response<IncomingBody>>,
}

impl<B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin> Unpin
    for FutCtx<B>
{
}

pub(crate) struct ClientTask<B, T>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ping: ping::Recorder,
    conn_drop_ref: ConnDropRef,
    conn_eof: ConnEof,
    executor: Executor,
    h2_tx: SendRequest<SendBuf<B::Data>>,
    req_rx: ClientRx<B>,
    fut_ctx: Option<FutCtx<B>>,
    marker: PhantomData<T>,
}

impl<B, T> ClientTask<B, T>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.h2_tx.is_extended_connect_protocol_enabled()
    }
}

pin_project! {
    pub struct PipeMap<S>
    where
        S: StreamingBody,
    {
        #[pin]
        pipe: PipeToSendStream<S>,
        #[pin]
        conn_drop_ref: Option<Sender<Infallible>>,
        #[pin]
        ping: Option<Recorder>,
    }
}

impl<B> Future for PipeMap<B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let mut this = self.project();

        match Pin::new(&mut this.pipe).poll(cx) {
            Poll::Ready(result) => {
                if let Err(_e) = result {
                    debug!("client request body error: {_e:?}");
                }
                drop(this.conn_drop_ref.take().expect("Future polled twice"));
                drop(this.ping.take().expect("Future polled twice"));
                return Poll::Ready(());
            }
            Poll::Pending => (),
        };
        Poll::Pending
    }
}

impl<B, T> ClientTask<B, T>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Send + Unpin + ExtensionsMut,
{
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn poll_pipe(&mut self, f: FutCtx<B>, cx: &mut Context<'_>) {
        let ping = self.ping.clone();

        let send_stream = if !f.is_connect {
            if !f.eos {
                let mut pipe = PipeToSendStream::new(f.body, f.body_tx);

                // eagerly see if the body pipe is ready and
                // can thus skip allocating in the executor
                match Pin::new(&mut pipe).poll(cx) {
                    Poll::Ready(_) => (),
                    Poll::Pending => {
                        let conn_drop_ref = self.conn_drop_ref.clone();
                        // keep the ping recorder's knowledge of an
                        // "open stream" alive while this body is
                        // still sending...
                        let ping = ping.clone();

                        let pipe = PipeMap {
                            pipe,
                            conn_drop_ref: Some(conn_drop_ref),
                            ping: Some(ping),
                        };

                        let pipe_span = trace_root_span!(
                            "h2::pipe",
                            otel.kind = "client",
                            network.protocol.name = "http",
                            network.protocol.version = version_as_protocol_version(Version::HTTP_2),
                        );

                        // Clear send task
                        let fut: H2ClientFuture<_, T> = H2ClientFuture::Pipe { pipe };
                        self.executor.spawn_task(fut.instrument(pipe_span));
                    }
                }
            }

            None
        } else {
            Some(f.body_tx)
        };

        let send_span = trace_root_span!(
            "h2::send",
            otel.kind = "client",
            network.protocol.name = "http",
            network.protocol.version = version_as_protocol_version(Version::HTTP_2),
        );

        let fut: H2ClientFuture<_, T> = H2ClientFuture::Send {
            send_when: SendWhen {
                when: ResponseFutMap {
                    fut: f.fut,
                    ping: Some(ping),
                    send_stream: Some(send_stream),
                },
                call_back: Some(f.cb),
            },
        };
        self.executor.spawn_task(fut.instrument(send_span));
    }
}

pin_project! {
    pub(crate) struct ResponseFutMap<B>
    where
        B: StreamingBody,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
    {
        #[pin]
        fut: ResponseFuture,
        #[pin]
        ping: Option<Recorder>,
        #[pin]
        send_stream: Option<Option<SendStream<SendBuf<<B as StreamingBody>::Data>>>>,
    }
}

impl<B> Future for ResponseFutMap<B>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    type Output = Result<Response<crate::body::Incoming>, (crate::Error, Option<Request<B>>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let result = ready!(this.fut.poll(cx));

        let ping = this.ping.take().expect("Future polled twice");
        let send_stream = this.send_stream.take().expect("Future polled twice");

        match result {
            Ok(res) => {
                // record that we got the response headers
                ping.record_non_data();

                let content_length = headers::content_length_parse_all(res.headers());
                if let (Some(mut send_stream), StatusCode::OK) = (send_stream, res.status()) {
                    if content_length.is_some_and(|len| len != 0) {
                        warn!("h2 connect response with non-zero body not supported");

                        send_stream.send_reset(crate::h2::Reason::INTERNAL_ERROR);
                        return Poll::Ready(Err((
                            crate::Error::new_h2(crate::h2::Reason::INTERNAL_ERROR.into()),
                            None::<Request<B>>,
                        )));
                    }
                    let (parts, recv_stream) = res.into_parts();
                    let mut res = Response::from_parts(parts, IncomingBody::empty());

                    let (pending, on_upgrade) = upgrade::pending();
                    let io = H2Upgraded {
                        ping,
                        send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                        recv_stream,
                        buf: Bytes::new(),
                    };
                    let upgraded = Upgraded::new(io, Bytes::new());

                    pending.fulfill(upgraded);
                    res.extensions_mut().insert(on_upgrade);

                    Poll::Ready(Ok(res))
                } else {
                    let res = res.map(|stream| {
                        let ping = ping.for_stream(&stream);
                        IncomingBody::h2(stream, content_length.into(), ping)
                    });
                    Poll::Ready(Ok(res))
                }
            }
            Err(err) => {
                ping.ensure_not_timed_out().map_err(|e| (e, None))?;

                debug!("client response error: {err:?}");
                Poll::Ready(Err((crate::Error::new_h2(err), None::<Request<B>>)))
            }
        }
    }
}

impl<B, T> Future for ClientTask<B, T>
where
    B: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + ExtensionsMut,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match ready!(self.h2_tx.poll_ready(cx)) {
                Ok(()) => (),
                Err(err) => {
                    self.ping.ensure_not_timed_out()?;
                    return if err.reason() == Some(crate::h2::Reason::NO_ERROR) {
                        trace!("connection gracefully shutdown");
                        Poll::Ready(Ok(Dispatched::Shutdown))
                    } else {
                        Poll::Ready(Err(crate::Error::new_h2(err)))
                    };
                }
            };

            // If we were waiting on pending open
            // continue where we left off.
            if let Some(f) = self.fut_ctx.take() {
                self.poll_pipe(f, cx);
                continue;
            }

            match self.req_rx.poll_recv(cx) {
                Poll::Ready(Some((req, cb))) => {
                    // check that future hasn't been canceled already
                    if cb.is_canceled() {
                        trace!("request callback is canceled");
                        continue;
                    }
                    let (head, body) = req.into_parts();
                    let mut req = Request::from_parts(head, ());
                    super::strip_connection_headers(req.headers_mut(), true);
                    if let Some(len) = body.size_hint().exact()
                        && (len != 0 || headers::method_has_defined_payload_semantics(req.method()))
                    {
                        headers::set_content_length_if_missing(req.headers_mut(), len);
                    }

                    let is_connect = req.method() == Method::CONNECT;
                    let eos = body.is_end_stream();

                    if is_connect
                        && headers::content_length_parse_all(req.headers())
                            .is_some_and(|len| len != 0)
                    {
                        warn!("h2 connect request with non-zero body not supported");
                        cb.send(Err(TrySendError {
                            error: crate::Error::new_h2(crate::h2::Reason::INTERNAL_ERROR.into()),
                            message: None,
                        }));
                        continue;
                    }

                    let (fut, body_tx) = match self.h2_tx.send_request(req, !is_connect && eos) {
                        Ok(ok) => ok,
                        Err(err) => {
                            debug!("client send request error: {}", err);
                            cb.send(Err(TrySendError {
                                error: crate::Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    };

                    let f = FutCtx {
                        is_connect,
                        eos,
                        fut,
                        body_tx,
                        body,
                        cb,
                    };

                    // Check poll_ready() again.
                    // If the call to send_request() resulted in the new stream being pending open
                    // we have to wait for the open to complete before accepting new requests.
                    match self.h2_tx.poll_ready(cx) {
                        Poll::Pending => {
                            // Save Context
                            self.fut_ctx = Some(f);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => (),
                        Poll::Ready(Err(err)) => {
                            f.cb.send(Err(TrySendError {
                                error: crate::Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    }
                    self.poll_pipe(f, cx);
                }

                Poll::Ready(None) => {
                    trace!("dispatch::Sender dropped");
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }

                Poll::Pending => match ready!(Pin::new(&mut self.conn_eof).poll(cx)) {
                    // As of Rust 1.82, this pattern is no longer needed, and emits a warning.
                    // But we cannot remove it as long as MSRV is less than that.
                    #[allow(unused)]
                    Ok(never) => match never {},
                    Err(_conn_is_eof) => {
                        trace!("connection task is closed, closing dispatch task");
                        return Poll::Ready(Ok(Dispatched::Shutdown));
                    }
                },
            }
        }
    }
}
