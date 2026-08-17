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
use rama_http::layer::har::{
    recorder::{WebSocketCapture, WebSocketCaptureLease},
    spec::{WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType},
};
use rama_utils::time::unix_timestamp_secs;

use crate::{
    Message, ProtocolError,
    protocol::{CloseFrame, Role, WebSocket, WebSocketConfig},
    runtime::{
        compat::{self, AllowStd, ContextWaker},
        handshake::without_handshake,
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
    capture: Option<WebSocketCaptureLease>,
    role: Role,
}

impl<S> AsyncWebSocket<S> {
    /// Convert a raw socket into a AsyncWebSocket without performing a
    /// handshake.
    pub async fn from_raw_socket(stream: S, role: Role, config: Option<WebSocketConfig>) -> Self
    where
        S: Io + Unpin + ExtensionsRef,
    {
        let capture = stream
            .extensions()
            .get_ref::<WebSocketCapture>()
            .and_then(WebSocketCapture::lease);
        without_handshake(stream, capture, role, move |allow_std| {
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
        let capture = stream
            .extensions()
            .get_ref::<WebSocketCapture>()
            .and_then(WebSocketCapture::lease);
        without_handshake(stream, capture, role, move |allow_std| {
            WebSocket::from_partially_read(allow_std, part, role, config)
        })
        .await
    }

    pub(crate) fn new(
        ws: WebSocket<AllowStd<S>>,
        capture: Option<WebSocketCaptureLease>,
        role: Role,
    ) -> Self {
        Self {
            inner: ws,
            closing: false,
            ended: false,
            ready: true,
            capture,
            role,
        }
    }

    fn record_message(&self, outgoing: bool, message: &Message) {
        let Some(capture) = &self.capture else {
            return;
        };
        let message_type = match (self.role, outgoing) {
            (Role::Client, true) | (Role::Server, false) => WebSocketMessageType::Send,
            (Role::Client, false) | (Role::Server, true) => WebSocketMessageType::Receive,
        };
        if let Err(err) = capture.record(into_har_message(message_type, message)) {
            debug!("failed to record WebSocket message: {err}");
        }
    }

    fn record_automatic_response(&self, was_active: bool, message: &Message) {
        if !was_active {
            return;
        }
        match message {
            Message::Ping(data) => self.record_message(true, &Message::Pong(data.clone())),
            Message::Close(close) => self.record_message(true, &Message::Close(close.clone())),
            _ => {}
        }
    }

    fn record_error(&self, error: &ProtocolError) {
        let Some(capture) = &self.capture else {
            return;
        };
        if let Err(err) = capture.record(WebSocketMessage::error(
            unix_timestamp_secs() as f64,
            error.to_string(),
        )) {
            debug!("failed to record WebSocket error: {err}");
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

fn into_har_message(message_type: WebSocketMessageType, message: &Message) -> WebSocketMessage {
    let time = unix_timestamp_secs() as f64;
    match message {
        Message::Text(data) => WebSocketMessage::text(message_type, time, data.as_str()),
        Message::Binary(data) => WebSocketMessage::binary(message_type, time, data),
        Message::Ping(data) => WebSocketMessage::binary_with_opcode(
            message_type,
            time,
            WebSocketMessageOpcode::PING,
            data,
        ),
        Message::Pong(data) => WebSocketMessage::binary_with_opcode(
            message_type,
            time,
            WebSocketMessageOpcode::PONG,
            data,
        ),
        Message::Close(close) => {
            let mut payload = Vec::new();
            if let Some(close) = close {
                payload.extend_from_slice(&u16::from(close.code).to_be_bytes());
                payload.extend_from_slice(close.reason.as_bytes());
            }
            WebSocketMessage::binary_with_opcode(
                message_type,
                time,
                WebSocketMessageOpcode::CLOSE,
                payload,
            )
        }
        Message::Frame(frame) => {
            let opcode = WebSocketMessageOpcode::new(i32::from(u8::from(frame.header().opcode)));
            if opcode == WebSocketMessageOpcode::TEXT
                && let Ok(text) = frame.to_text()
            {
                WebSocketMessage::new(message_type, time, opcode, text)
            } else {
                WebSocketMessage::binary_with_opcode(message_type, time, opcode, frame.payload())
            }
        }
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

        let was_active = self.inner.can_write();
        match ready!(self.with_context(Some((ContextWaker::Read, cx)), |s| {
            trace!("Stream.with_context poll_next -> read()");
            compat::cvt(s.read())
        })) {
            Ok(v) => {
                self.record_message(false, &v);
                // The protocol queues mandatory Pong and Close replies while
                // returning the received message. They are wire messages too,
                // even though the application never calls `send` for them.
                self.record_automatic_response(was_active, &v);
                Poll::Ready(Some(Ok(v)))
            }
            Err(e) => {
                self.ended = true;
                if e.is_connection_error() {
                    Poll::Ready(None)
                } else {
                    self.record_error(&e);
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
        if self.ready {
            Poll::Ready(Ok(()))
        } else {
            // Currently blocked so try to flush the blockage away
            (*self)
                .with_context(Some((ContextWaker::Write, cx)), |s| compat::cvt(s.flush()))
                .map(|r| {
                    self.ready = true;
                    r
                })
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        let capture_item = self.capture.is_some().then(|| item.clone());
        match (*self).with_context(None, |s| s.write(item)) {
            Ok(()) => {
                self.ready = true;
                if let Some(item) = capture_item.as_ref() {
                    self.record_message(true, item);
                }
                Ok(())
            }
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // the message was accepted and queued so not an error
                // but `poll_ready` will now start trying to flush the block
                self.ready = false;
                if let Some(item) = capture_item.as_ref() {
                    self.record_message(true, item);
                }
                Ok(())
            }
            Err(e) => {
                self.ready = true;
                debug!("websocket start_send error: {e}");
                self.record_error(&e);
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
            Ok(()) => Poll::Ready(Ok(())),
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                trace!("WouldBlock");
                self.closing = true;
                Poll::Pending
            }
            Err(err) => {
                if err.is_connection_error() {
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
    use super::into_har_message;
    use crate::{
        protocol::{
            CloseFrame, Message, Role, WebSocketConfig,
            frame::{
                Frame,
                coding::{CloseCode, OpCode, OpCodeData},
            },
        },
        runtime::{AsyncWebSocket, compat::AllowStd},
    };
    use parking_lot::Mutex;
    use rama_core::{ServiceInput, error::BoxError, extensions::ExtensionsRef, futures::Sink};
    use rama_http::layer::har::{
        recorder::{WebSocketCapture, WebSocketCaptureSink},
        spec::{WebSocketMessage, WebSocketMessageOpcode, WebSocketMessageType},
    };
    use std::{
        io::{self, Read, Write},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
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

    #[test]
    fn har_messages_encode_all_application_message_payloads() {
        let cases = [
            (
                Message::text("hello"),
                WebSocketMessageOpcode::TEXT,
                "hello",
            ),
            (
                Message::binary(vec![0_u8, 1, 0xff]),
                WebSocketMessageOpcode::BINARY,
                "AAH/",
            ),
            (
                Message::Ping(vec![2, 3].into()),
                WebSocketMessageOpcode::PING,
                "AgM=",
            ),
            (
                Message::Pong(vec![4, 5].into()),
                WebSocketMessageOpcode::PONG,
                "BAU=",
            ),
            (
                Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "bye".into(),
                })),
                WebSocketMessageOpcode::CLOSE,
                "A+hieWU=",
            ),
            (
                Message::Frame(Frame::message(
                    "raw text",
                    OpCode::Data(OpCodeData::Text),
                    true,
                )),
                WebSocketMessageOpcode::TEXT,
                "raw text",
            ),
            (
                Message::Frame(Frame::message(
                    "raw binary",
                    OpCode::Data(OpCodeData::Binary),
                    true,
                )),
                WebSocketMessageOpcode::BINARY,
                "cmF3IGJpbmFyeQ==",
            ),
        ];

        for (message, opcode, data) in cases {
            let message = into_har_message(WebSocketMessageType::Send, &message);
            assert_eq!(message.r#type, WebSocketMessageType::Send);
            assert_eq!(message.opcode, opcode);
            assert_eq!(message.data.as_str(), data);
            assert!(message.time > 1_700_000_000.0);
        }
    }

    #[derive(Default)]
    struct TestSink {
        messages: Mutex<Vec<WebSocketMessage>>,
    }

    impl WebSocketCaptureSink for TestSink {
        fn record(&self, message: WebSocketMessage) -> Result<(), BoxError> {
            self.messages.lock().push(message);
            Ok(())
        }

        fn close(&self) {}
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
        sink: Arc<TestSink>,
    ) -> AsyncWebSocket<ServiceInput<TestIo>> {
        let input = ServiceInput::new(TestIo(behavior));
        input.extensions().insert(WebSocketCapture::new(sink));
        AsyncWebSocket::from_raw_socket(
            input,
            Role::Client,
            Some(WebSocketConfig::default().with_write_buffer_size(0)),
        )
        .await
    }

    #[tokio::test]
    async fn start_send_distinguishes_backpressure_from_fatal_io() {
        let pending_sink = Arc::new(TestSink::default());
        let mut pending =
            socket_with_write_behavior(WriteBehavior::Pending, pending_sink.clone()).await;
        Sink::start_send(Pin::new(&mut pending), Message::text("queued"))
            .expect("WouldBlock means the frame was accepted into the write buffer");
        {
            let pending_messages = pending_sink.messages.lock();
            assert_eq!(pending_messages.len(), 1);
            assert_eq!(pending_messages[0].r#type, WebSocketMessageType::Send);
            assert_eq!(pending_messages[0].data.as_str(), "queued");
        }

        let broken_sink = Arc::new(TestSink::default());
        let mut broken =
            socket_with_write_behavior(WriteBehavior::BrokenPipe, broken_sink.clone()).await;
        Sink::start_send(Pin::new(&mut broken), Message::text("rejected"))
            .expect_err("fatal I/O must reject the send");
        let broken_messages = broken_sink.messages.lock();
        assert_eq!(broken_messages.len(), 1);
        assert_eq!(broken_messages[0].r#type, WebSocketMessageType::Error);
        assert_eq!(broken_messages[0].opcode, WebSocketMessageOpcode::ERROR);
    }

    #[tokio::test]
    async fn server_role_uses_client_perspective_and_records_auto_close() {
        let sink = Arc::new(TestSink::default());
        let capture = WebSocketCapture::new(sink.clone());
        let (io, _peer) = tokio::io::duplex(1024);
        let input = ServiceInput::new(io);
        input.extensions().insert(capture);
        let socket = AsyncWebSocket::from_raw_socket(input, Role::Server, None).await;

        socket.record_message(false, &Message::text("from-client"));
        socket.record_message(true, &Message::binary(vec![1, 2]));
        socket.record_automatic_response(
            true,
            &Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "done".into(),
            })),
        );
        socket.record_automatic_response(false, &Message::Ping(vec![3].into()));

        let messages = sink.messages.lock();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].r#type, WebSocketMessageType::Send);
        assert_eq!(messages[0].opcode, WebSocketMessageOpcode::TEXT);
        assert_eq!(messages[1].r#type, WebSocketMessageType::Receive);
        assert_eq!(messages[1].opcode, WebSocketMessageOpcode::BINARY);
        assert_eq!(messages[2].r#type, WebSocketMessageType::Receive);
        assert_eq!(messages[2].opcode, WebSocketMessageOpcode::CLOSE);
    }
}
