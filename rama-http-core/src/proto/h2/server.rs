use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use crate::h2::server::{Connection, Handshake, SendResponse};
use crate::h2::{Reason, RecvStream};
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{Instrument, debug, trace, trace_root_span, warn};
use rama_http::io::upgrade::{self, OnUpgrade, Pending, Upgraded};
use rama_http::opentelemetry::version_as_protocol_version;
use rama_http_types::{Method, Request, Response, header};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{PipeToSendStream, SendBuf, ping};
use crate::body::{Body, Incoming as IncomingBody};
use crate::common::date;
use crate::headers;
use crate::proto::Dispatched;
use crate::proto::h2::ping::Recorder;
use crate::proto::h2::{H2Upgraded, UpgradedSendStream};
use crate::service::HttpService;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
//
// At the same time, a server more often has multiple clients connected, and
// so is more likely to use more resources than a client would.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 400; // 400kb
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32,
    pub(crate) max_frame_size: u32,
    pub(crate) enable_connect_protocol: bool,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) max_local_error_reset_streams: Option<usize>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) max_header_list_size: u32,
    pub(crate) date_header: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            enable_connect_protocol: false,
            max_concurrent_streams: Some(200),
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS),
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_header_list_size: DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
            date_header: true,
        }
    }
}

pin_project! {
    pub(crate) struct Server<T, S>
    where
        S: HttpService<IncomingBody>,
    {
        exec: Executor,
        service: S,
        state: State<T>,
        date_header: bool,
        close_pending: bool,
    }
}

// TODO: revisit later to see if we really want this

#[allow(clippy::large_enum_variant)]
enum State<T> {
    Handshaking {
        ping_config: ping::Config,
        hs: Handshake<T, SendBuf<Bytes>>,
    },
    Serving(Serving<T>),
}

struct Serving<T> {
    ping: Option<(ping::Recorder, ping::Ponger)>,
    conn: Connection<T, SendBuf<Bytes>>,
    closing: Option<crate::Error>,
    date_header: bool,
}

impl<T, S> Server<T, S>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: HttpService<IncomingBody>,
{
    pub(crate) fn new(io: T, service: S, config: &Config, exec: Executor) -> Self {
        let mut builder = crate::h2::server::Builder::default();
        builder
            .initial_window_size(config.initial_stream_window_size)
            .initial_connection_window_size(config.initial_conn_window_size)
            .max_frame_size(config.max_frame_size)
            .max_header_list_size(config.max_header_list_size)
            .max_local_error_reset_streams(config.max_local_error_reset_streams)
            .max_send_buffer_size(config.max_send_buffer_size);
        if let Some(max) = config.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(max) = config.max_pending_accept_reset_streams {
            builder.max_pending_accept_reset_streams(max);
        }
        if config.enable_connect_protocol {
            builder.enable_connect_protocol();
        }
        let handshake = builder.handshake(io);

        let bdp = if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        };

        let ping_config = ping::Config {
            bdp_initial_window: bdp,
            keep_alive_interval: config.keep_alive_interval,
            keep_alive_timeout: config.keep_alive_timeout,
            // If keep-alive is enabled for servers, always enabled while
            // idle, so it can more aggressively close dead connections.
            keep_alive_while_idle: true,
        };

        Self {
            exec,
            state: State::Handshaking {
                ping_config,
                hs: handshake,
            },
            service,
            date_header: config.date_header,
            close_pending: false,
        }
    }

    pub(crate) fn graceful_shutdown(&mut self) {
        trace!("graceful_shutdown");
        match self.state {
            State::Handshaking { .. } => {
                self.close_pending = true;
            }
            State::Serving(ref mut srv) => {
                if srv.closing.is_none() {
                    srv.conn.graceful_shutdown();
                }
            }
        }
    }
}

impl<T, S> Future for Server<T, S>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: HttpService<IncomingBody>,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            let next = match me.state {
                State::Handshaking {
                    ref mut hs,
                    ref ping_config,
                } => {
                    let mut conn = ready!(Pin::new(hs).poll(cx).map_err(crate::Error::new_h2))?;
                    let ping = if ping_config.is_enabled() {
                        let pp = conn.ping_pong().expect("conn.ping_pong");
                        Some(ping::channel(pp, ping_config))
                    } else {
                        None
                    };
                    State::Serving(Serving {
                        ping,
                        conn,
                        closing: None,
                        date_header: me.date_header,
                    })
                }
                State::Serving(ref mut srv) => {
                    // graceful_shutdown was called before handshaking finished,
                    if me.close_pending && srv.closing.is_none() {
                        srv.conn.graceful_shutdown();
                    }
                    ready!(srv.poll_server(cx, &mut me.service, &me.exec))?;
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }
            };
            me.state = next;
        }
    }
}

impl<T> Serving<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn poll_server<S>(
        &mut self,
        cx: &mut Context<'_>,
        service: &mut S,
        exec: &Executor,
    ) -> Poll<crate::Result<()>>
    where
        S: HttpService<IncomingBody>,
    {
        if self.closing.is_none() {
            loop {
                self.poll_ping(cx);

                match ready!(self.conn.poll_accept(cx)) {
                    Some(Ok((req, mut respond))) => {
                        trace!("incoming request");
                        let content_length = headers::content_length_parse_all(req.headers());
                        let ping = self
                            .ping
                            .as_ref()
                            .map(|ping| ping.0.clone())
                            .unwrap_or_else(ping::disabled);

                        // Record the headers received
                        ping.record_non_data();

                        let is_connect = req.method() == Method::CONNECT;
                        let (mut parts, stream) = req.into_parts();
                        let (req, connect_parts) = if !is_connect {
                            (
                                Request::from_parts(
                                    parts,
                                    IncomingBody::h2(stream, content_length.into(), ping),
                                ),
                                None,
                            )
                        } else {
                            if content_length.is_some_and(|len| len != 0) {
                                warn!("h2 connect request with non-zero body not supported");
                                respond.send_reset(crate::h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Ok(()));
                            }
                            let (pending, upgrade) = upgrade::pending();
                            debug_assert!(parts.extensions.get::<OnUpgrade>().is_none());
                            parts.extensions.insert(upgrade);
                            (
                                Request::from_parts(parts, IncomingBody::empty()),
                                Some(ConnectParts {
                                    pending,
                                    ping,
                                    recv_stream: stream,
                                }),
                            )
                        };

                        let serve_span = trace_root_span!(
                            "h2::stream",
                            otel.kind = "server",
                            http.request.method = %req.method().as_str(),
                            url.full = %req.uri(),
                            url.path = %req.uri().path(),
                            url.query = req.uri().query().unwrap_or_default(),
                            url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                            network.protocol.name = "http",
                            network.protocol.version = version_as_protocol_version(req.version()),
                        );

                        let fut = H2Stream::new(
                            service.serve_http(req),
                            connect_parts,
                            respond,
                            self.date_header,
                        );

                        exec.spawn_task(fut.instrument(serve_span));
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(Err(crate::Error::new_h2(e)));
                    }
                    None => {
                        // no more incoming streams...
                        if let Some((ref ping, _)) = self.ping {
                            ping.ensure_not_timed_out()?;
                        }

                        trace!("incoming connection complete");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        debug_assert!(
            self.closing.is_some(),
            "poll_server broke loop without closing"
        );

        ready!(self.conn.poll_closed(cx).map_err(crate::Error::new_h2))?;

        Poll::Ready(Err(self.closing.take().expect("polled after error")))
    }

    fn poll_ping(&mut self, cx: &mut Context<'_>) {
        if let Some((_, ref mut estimator)) = self.ping {
            match estimator.poll(cx) {
                Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                    self.conn.set_target_window_size(wnd);
                    let _ = self.conn.set_initial_window_size(wnd);
                }
                Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                    debug!("keep-alive timed out, closing connection");
                    self.conn.abrupt_shutdown(crate::h2::Reason::NO_ERROR);
                }
                Poll::Pending => {}
            }
        }
    }
}

pin_project! {
    #[allow(missing_debug_implementations)]
    pub struct H2Stream<F, B>
    where
        B: Body,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
    {
        reply: SendResponse<SendBuf<B::Data>>,
        #[pin]
        state: H2StreamState<F, B>,
        date_header: bool,
    }
}

pin_project! {
    #[project = H2StreamStateProj]
    enum H2StreamState<F, B>
    where
        B: Body,
        B: Send,
        B: 'static,
        B: Unpin,
        B::Data: Send,
        B::Data: 'static,
        B::Error: Into<BoxError>,
    {
        Service {
            #[pin]
            fut: F,
            connect_parts: Option<ConnectParts>,
        },
        Body {
            #[pin]
            pipe: PipeToSendStream<B>,
        },
    }
}

struct ConnectParts {
    pending: Pending,
    ping: Recorder,
    recv_stream: RecvStream,
}

impl<F, B> H2Stream<F, B>
where
    B: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
{
    fn new(
        fut: F,
        connect_parts: Option<ConnectParts>,
        respond: SendResponse<SendBuf<B::Data>>,
        date_header: bool,
    ) -> Self {
        Self {
            reply: respond,
            state: H2StreamState::Service { fut, connect_parts },
            date_header,
        }
    }
}

macro_rules! reply {
    ($me:expr, $res:expr, $eos:expr) => {{
        match $me.reply.send_response($res, $eos) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("send response error: {:?}", e);
                $me.reply.send_reset(Reason::INTERNAL_ERROR);
                return Poll::Ready(Err(crate::Error::new_h2(e)));
            }
        }
    }};
}

impl<F, B, E> H2Stream<F, B>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    E: Into<BoxError>,
{
    fn poll2(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let mut me = self.project();
        loop {
            let next = match me.state.as_mut().project() {
                H2StreamStateProj::Service {
                    fut: h,
                    connect_parts,
                } => {
                    let res = match h.poll(cx) {
                        Poll::Ready(Ok(r)) => r,
                        Poll::Pending => {
                            // Response is not yet ready, so we want to check if the client has sent a
                            // RST_STREAM frame which would cancel the current request.
                            if let Poll::Ready(reason) =
                                me.reply.poll_reset(cx).map_err(crate::Error::new_h2)?
                            {
                                debug!("stream received RST_STREAM: {:?}", reason);
                                return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            let err = crate::Error::new_user_service(e);
                            warn!("http2 service errored: {}", err);
                            me.reply.send_reset(err.h2_reason());
                            return Poll::Ready(Err(err));
                        }
                    };

                    let (head, body) = res.into_parts();
                    let mut res = Response::from_parts(head, ());
                    super::strip_connection_headers(res.headers_mut(), false);

                    // set Date header if it isn't already set if instructed
                    if *me.date_header {
                        res.headers_mut()
                            .entry(header::DATE)
                            .or_insert_with(date::update_and_header_value);
                    }

                    if let Some(connect_parts) = connect_parts.take()
                        && res.status().is_success()
                    {
                        if headers::content_length_parse_all(res.headers())
                            .is_some_and(|len| len != 0)
                        {
                            warn!(
                                "h2 successful response to CONNECT request with body not supported"
                            );
                            me.reply.send_reset(crate::h2::Reason::INTERNAL_ERROR);
                            return Poll::Ready(Err(crate::Error::new_user_header()));
                        }
                        if res.headers_mut().remove(header::CONTENT_LENGTH).is_some() {
                            warn!(
                                "successful response to CONNECT request disallows content-length header"
                            );
                        }
                        let send_stream = reply!(me, res, false);
                        connect_parts.pending.fulfill(Upgraded::new(
                            H2Upgraded {
                                ping: connect_parts.ping,
                                recv_stream: connect_parts.recv_stream,
                                send_stream: unsafe { UpgradedSendStream::new(send_stream) },
                                buf: Bytes::new(),
                            },
                            Bytes::new(),
                        ));
                        return Poll::Ready(Ok(()));
                    }

                    if !body.is_end_stream() {
                        // automatically set Content-Length from body...
                        if let Some(len) = body.size_hint().exact() {
                            headers::set_content_length_if_missing(res.headers_mut(), len);
                        }

                        let body_tx = reply!(me, res, false);
                        H2StreamState::Body {
                            pipe: PipeToSendStream::new(body, body_tx),
                        }
                    } else {
                        reply!(me, res, true);
                        return Poll::Ready(Ok(()));
                    }
                }
                H2StreamStateProj::Body { pipe } => {
                    return pipe.poll(cx);
                }
            };
            me.state.set(next);
        }
    }
}

impl<F, B, E> Future for H2Stream<F, B>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body<Data: Send + 'static, Error: Into<BoxError>> + Send + 'static + Unpin,
    E: Into<BoxError>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll2(cx).map(|res| {
            if let Err(_e) = res {
                debug!("stream error: {:?}", _e);
            }
        })
    }
}
