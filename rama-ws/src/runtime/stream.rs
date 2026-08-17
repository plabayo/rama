use rama_core::error::{BoxError, BoxErrorExt as _};
use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use rama_core::io::Io;
use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    futures::{self, SinkExt, StreamExt},
    telemetry::tracing::{debug, trace},
};
use rama_http::io::upgrade;

use crate::{
    Message, ProtocolError,
    layer::har::observer_from_extensions,
    protocol::{CloseFrame, Role, WebSocket, WebSocketConfig},
    runtime::{
        compat::{self, AllowStd, ContextWaker},
        handshake::without_handshake,
        observer::BoxWebSocketObserver,
    },
};

/// A wrapper around an underlying raw stream which implements the WebSocket
/// protocol.
///
/// A `AsyncWebSocket<S>` represents a handshake that has been completed
/// successfully and both the server and the client are ready for receiving
/// and sending data. Message from a `AsyncWebSocket<S>` are accessible
/// through the respective `Stream` and `Sink`.
#[derive(Debug)]
pub struct AsyncWebSocket<S = upgrade::Upgraded> {
    inner: WebSocket<AllowStd<S>>,
    closing: bool,
    ended: bool,
    /// Tungstenite is probably ready to receive more data.
    ///
    /// `false` once start_send hits `WouldBlock` errors.
    /// `true` initially and after `flush`ing.
    ready: bool,
    observer: Option<BoxWebSocketObserver>,
}

impl<S> AsyncWebSocket<S> {
    /// Convert a raw socket into a AsyncWebSocket without performing a
    /// handshake.
    pub async fn from_raw_socket(stream: S, role: Role, config: Option<WebSocketConfig>) -> Self
    where
        S: Io + Unpin + ExtensionsRef,
    {
        let observer = observer_from_extensions(&stream, role);
        without_handshake(stream, observer, move |allow_std| {
            WebSocket::from_raw_socket(allow_std, role, config)
        })
        .await
    }

    /// Convert a raw socket into a AsyncWebSocket without performing a
    /// handshake.
    pub async fn from_partially_read(
        stream: S,
        part: Vec<u8>,
        role: Role,
        config: Option<WebSocketConfig>,
    ) -> Self
    where
        S: Io + Unpin + ExtensionsRef,
    {
        let observer = observer_from_extensions(&stream, role);
        without_handshake(stream, observer, move |allow_std| {
            WebSocket::from_partially_read(allow_std, part, role, config)
        })
        .await
    }

    pub(crate) fn new(ws: WebSocket<AllowStd<S>>, observer: Option<BoxWebSocketObserver>) -> Self {
        Self {
            inner: ws,
            closing: false,
            ended: false,
            ready: true,
            observer,
        }
    }

    fn poll_observer_ready(&mut self, ctx: &mut Context<'_>) -> Poll<()> {
        let Some(observer) = &mut self.observer else {
            return Poll::Ready(());
        };
        match observer.poll_ready(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                debug!("failed to prepare WebSocket message recording: {err}");
                self.observer.take();
                Poll::Ready(())
            }
        }
    }

    fn record_message(&mut self, outgoing: bool, message: &Message) {
        let Some(observer) = &mut self.observer else {
            return;
        };
        if let Err(err) = observer.record_message(outgoing, message) {
            debug!("failed to record WebSocket message: {err}");
            self.observer.take();
        }
    }

    fn record_error(&mut self, error: &ProtocolError) {
        let Some(observer) = &mut self.observer else {
            return;
        };
        if let Err(err) = observer.record_error(error) {
            debug!("failed to record WebSocket error: {err}");
            self.observer.take();
        }
    }

    fn with_context<F, R>(&mut self, ctx: Option<(ContextWaker, &mut Context<'_>)>, f: F) -> R
    where
        S: Unpin,
        F: FnOnce(&mut WebSocket<AllowStd<S>>) -> R,
        AllowStd<S>: Read + Write,
    {
        trace!("AsyncWebSocket.with_context");
        if let Some((kind, ctx)) = ctx {
            self.inner.get_mut().set_waker(kind, ctx.waker());
        }
        f(&mut self.inner)
    }

    /// Consumes the `AsyncWebSocket` and returns the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner.into_inner().into_inner()
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S
    where
        S: Io + Unpin,
    {
        self.inner.get_ref().get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S
    where
        S: Io + Unpin,
    {
        self.inner.get_mut().get_mut()
    }

    /// Returns a reference to the configuration of the tungstenite stream.
    pub fn get_config(&self) -> &WebSocketConfig {
        self.inner.get_config()
    }

    /// Close the underlying web socket
    pub async fn close(&mut self, msg: Option<CloseFrame>) -> Result<(), ProtocolError>
    where
        S: Io + Unpin,
    {
        self.send(Message::Close(msg)).await
    }
}

impl<S: ExtensionsRef> ExtensionsRef for AsyncWebSocket<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S: Io + Unpin> AsyncWebSocket<S> {
    #[inline]
    /// Writes and immediately flushes a message.
    pub fn send_message(
        &mut self,
        msg: Message,
    ) -> impl Future<Output = Result<(), ProtocolError>> + Send + '_ {
        self.send(msg)
    }

    pub async fn recv_message(&mut self) -> Result<Message, ProtocolError> {
        self.next().await.ok_or_else(|| {
            ProtocolError::Io(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                BoxError::from_static_str(
                    "Connection closed: no messages to be received any longer",
                ),
            ))
        })?
    }
}

impl<T> futures::Stream for AsyncWebSocket<T>
where
    T: Io + Unpin,
{
    type Item = Result<Message, ProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        trace!("Stream.poll_next");

        // The connection has been closed or a critical error has occurred.
        // We have already returned the error to the user, the `Stream` is unusable,
        // so we assume that the stream has been "fused".
        if self.ended {
            return Poll::Ready(None);
        }

        ready!(self.poll_observer_ready(cx));
        match ready!(self.with_context(Some((ContextWaker::Read, cx)), |s| {
            trace!("Stream.with_context poll_next -> read()");
            compat::cvt(s.read())
        })) {
            Ok(v) => {
                self.record_message(false, &v);
                if matches!(&v, Message::Close(_)) {
                    self.observer.take();
                }
                Poll::Ready(Some(Ok(v)))
            }
            Err(e) => {
                self.ended = true;
                if e.is_connection_error() {
                    self.observer.take();
                    Poll::Ready(None)
                } else {
                    self.record_error(&e);
                    self.observer.take();
                    Poll::Ready(Some(Err(e)))
                }
            }
        }
    }
}

impl<T> futures::stream::FusedStream for AsyncWebSocket<T>
where
    T: Io + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.ended
    }
}

impl<T> futures::Sink<Message> for AsyncWebSocket<T>
where
    T: Io + Unpin,
{
    type Error = ProtocolError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.ready {
            // Currently blocked so try to flush the blockage away
            ready!((*self).with_context(Some((ContextWaker::Write, cx)), |s| {
                compat::cvt(s.flush())
            }))
            .map(|()| {
                self.ready = true;
            })?;
        }
        ready!(self.poll_observer_ready(cx));
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        let observed_item = self.observer.is_some().then(|| item.clone());
        match (*self).with_context(None, |s| s.write(item)) {
            Ok(()) => {
                self.ready = true;
                if let Some(item) = observed_item.as_ref() {
                    self.record_message(true, item);
                }
                Ok(())
            }
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // the message was accepted and queued so not an error
                // but `poll_ready` will now start trying to flush the block
                self.ready = false;
                if let Some(item) = observed_item.as_ref() {
                    self.record_message(true, item);
                }
                Ok(())
            }
            Err(e) => {
                self.ready = true;
                debug!("websocket start_send error: {e}");
                self.record_error(&e);
                self.observer.take();
                Err(e)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        (*self)
            .with_context(Some((ContextWaker::Write, cx)), |s| compat::cvt(s.flush()))
            .map(|r| {
                self.ready = true;
                match r {
                    Err(err) if err.is_connection_error() => {
                        // WebSocket connection has just been closed. Flushing completed, not an error.
                        self.observer.take();
                        Ok(())
                    }
                    other => other,
                }
            })
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ready = true;
        let res = if self.closing {
            // After queueing it, we call `flush` to drive the close handshake to completion.
            (*self).with_context(Some((ContextWaker::Write, cx)), |s| s.flush())
        } else {
            (*self).with_context(Some((ContextWaker::Write, cx)), |s| s.close(None))
        };

        match res {
            Ok(()) => {
                self.observer.take();
                Poll::Ready(Ok(()))
            }
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                trace!("WouldBlock");
                self.closing = true;
                Poll::Pending
            }
            Err(err) => {
                if err.is_connection_error() {
                    self.observer.take();
                    Poll::Ready(Ok(()))
                } else {
                    debug!("websocket close error: {}", err);
                    Poll::Ready(Err(err))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AsyncWebSocket;
    use crate::{
        protocol::{Message, Role, WebSocketConfig},
        runtime::compat::AllowStd,
    };
    use parking_lot::Mutex;
    use rama_core::{ServiceInput, error::BoxError, extensions::ExtensionsRef, futures::Sink};
    use rama_http::layer::har::{
        recorder::{WebSocketCapture, WebSocketCaptureWriter},
        spec::{WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType},
    };
    use std::{
        io::{self, Read, Write},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    fn is_read<T: Read>() {}
    fn is_write<T: Write>() {}
    fn is_unpin<T: Unpin>() {}

    #[test]
    fn web_socket_stream_has_traits() {
        is_read::<AllowStd<tokio::net::TcpStream>>();
        is_write::<AllowStd<tokio::net::TcpStream>>();
        is_unpin::<AsyncWebSocket<tokio::net::TcpStream>>();
    }

    #[derive(Default)]
    struct TestState {
        messages: Mutex<Vec<WebSocketMessage>>,
        closes: AtomicUsize,
    }

    struct TestWriter(Arc<TestState>);

    impl WebSocketCaptureWriter for TestWriter {
        fn start_record(&mut self, message: WebSocketMessage) -> Result<(), BoxError> {
            self.0.messages.lock().push(message);
            Ok(())
        }
    }

    #[derive(Default)]
    struct ReadinessState {
        ready: AtomicBool,
        messages: Mutex<Vec<WebSocketMessage>>,
    }

    struct ReadinessWriter(Arc<ReadinessState>);

    impl WebSocketCaptureWriter for ReadinessWriter {
        fn poll_ready(&mut self, _ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            if self.0.ready.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn start_record(&mut self, message: WebSocketMessage) -> Result<(), BoxError> {
            assert!(self.0.ready.load(Ordering::Acquire));
            self.0.ready.store(false, Ordering::Release);
            self.0.messages.lock().push(message);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum WriteBehavior {
        Pending,
        BrokenPipe,
    }

    struct TestIo(WriteBehavior);

    impl AsyncRead for TestIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0 {
                WriteBehavior::Pending => Poll::Pending,
                WriteBehavior::BrokenPipe => {
                    Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn socket_with_write_behavior(
        behavior: WriteBehavior,
        state: Arc<TestState>,
    ) -> AsyncWebSocket<ServiceInput<TestIo>> {
        let input = ServiceInput::new(TestIo(behavior));
        input.extensions().insert(WebSocketCapture::new(
            TestWriter(state.clone()),
            move || {
                state.closes.fetch_add(1, Ordering::AcqRel);
            },
        ));
        AsyncWebSocket::from_raw_socket(
            input,
            Role::Client,
            Some(WebSocketConfig::default().with_write_buffer_size(0)),
        )
        .await
    }

    #[tokio::test]
    async fn start_send_distinguishes_backpressure_from_fatal_io() {
        let pending_sink = Arc::new(TestState::default());
        let mut pending =
            socket_with_write_behavior(WriteBehavior::Pending, pending_sink.clone()).await;
        std::future::poll_fn(|ctx| Sink::poll_ready(Pin::new(&mut pending), ctx))
            .await
            .expect("pending socket ready");
        Sink::start_send(Pin::new(&mut pending), Message::text("queued"))
            .expect("WouldBlock means the frame was accepted into the write buffer");
        {
            let pending_messages = pending_sink.messages.lock();
            assert_eq!(pending_messages.len(), 1);
            assert_eq!(pending_messages[0].r#type, WebSocketMessageType::Send);
            assert_eq!(pending_messages[0].data.as_str(), "queued");
        }

        let broken_sink = Arc::new(TestState::default());
        let mut broken =
            socket_with_write_behavior(WriteBehavior::BrokenPipe, broken_sink.clone()).await;
        std::future::poll_fn(|ctx| Sink::poll_ready(Pin::new(&mut broken), ctx))
            .await
            .expect("broken socket initially ready");
        Sink::start_send(Pin::new(&mut broken), Message::text("rejected"))
            .expect_err("fatal I/O must reject the send");
        let broken_messages = broken_sink.messages.lock();
        assert_eq!(broken_messages.len(), 1);
        assert_eq!(broken_messages[0].r#type, WebSocketMessageType::Error);
        assert_eq!(broken_messages[0].opcode, WebSocketMessageOpcode::ERROR);
        drop(broken_messages);
        assert_eq!(broken_sink.closes.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn recorder_readiness_backpressures_web_socket_sends() {
        let sink = Arc::new(ReadinessState::default());
        let input = ServiceInput::new(TestIo(WriteBehavior::Pending));
        input
            .extensions()
            .insert(WebSocketCapture::new(ReadinessWriter(sink.clone()), || {}));
        let mut socket = AsyncWebSocket::from_raw_socket(input, Role::Client, None).await;
        let waker = Waker::noop();
        let mut ctx = Context::from_waker(waker);

        assert!(Sink::poll_ready(Pin::new(&mut socket), &mut ctx).is_pending());
        sink.ready.store(true, Ordering::Release);
        assert!(Sink::poll_ready(Pin::new(&mut socket), &mut ctx).is_ready());
        Sink::start_send(Pin::new(&mut socket), Message::text("bounded"))
            .expect("ready recorder accepts message");

        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data.as_str(), "bounded");
    }

    #[tokio::test]
    async fn server_role_uses_client_perspective() {
        let sink = Arc::new(TestState::default());
        let capture = WebSocketCapture::new(TestWriter(sink.clone()), || {});
        let (io, _peer) = tokio::io::duplex(1024);
        let input = ServiceInput::new(io);
        input.extensions().insert(capture);
        let mut socket = AsyncWebSocket::from_raw_socket(input, Role::Server, None).await;

        socket.record_message(false, &Message::text("from-client"));
        socket.record_message(true, &Message::binary(vec![1, 2]));

        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
        assert_eq!(messages[0].opcode, WebSocketMessageOpcode::TEXT);
        assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
        assert_eq!(messages[1].opcode, WebSocketMessageOpcode::BINARY);
    }
}
