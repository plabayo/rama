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
    lifecycle: Lifecycle,
    /// Tungstenite is probably ready to receive more data.
    ///
    /// `false` once start_send hits `WouldBlock` errors.
    /// `true` initially and after `flush`ing.
    ready: bool,
}

/// Where an [`AsyncWebSocket`] is between opening and ending its transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// Messages flow in both directions.
    Open,
    /// A close is queued but not yet flushed.
    Closing,
    /// The WebSocket closed; its transport is being shut down.
    ShuttingDown,
    /// The transport was shut down: nothing is left to read.
    Ended,
    /// A protocol error ended the stream; the transport is left as it is.
    Failed,
}

impl<S> AsyncWebSocket<S> {
    /// Convert a raw socket into a AsyncWebSocket without performing a
    /// handshake.
    pub async fn from_raw_socket(stream: S, role: Role, config: Option<WebSocketConfig>) -> Self
    where
        S: Io + Unpin + ExtensionsRef,
    {
        without_handshake(stream, move |allow_std| {
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
        without_handshake(stream, move |allow_std| {
            WebSocket::from_partially_read(allow_std, part, role, config)
        })
        .await
    }

    pub(crate) fn new(ws: WebSocket<AllowStd<S>>) -> Self {
        Self {
            inner: ws,
            lifecycle: Lifecycle::Open,
            ready: true,
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

    /// Start the close handshake by sending a Close frame.
    ///
    /// The handshake completes once the peer's Close is read: keep receiving until the
    /// stream ends. Dropping the socket before that aborts the connection.
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

        match self.lifecycle {
            // Fused: the end or the error was already returned.
            Lifecycle::Ended | Lifecycle::Failed => return Poll::Ready(None),
            Lifecycle::ShuttingDown => {
                ready!(self.poll_shutdown_transport(ContextWaker::Read, cx));
                return Poll::Ready(None);
            }
            Lifecycle::Open | Lifecycle::Closing => (),
        }

        match ready!(self.with_context(Some((ContextWaker::Read, cx)), |s| {
            trace!("Stream.with_context poll_next -> read()");
            compat::cvt(s.read())
        })) {
            Ok(v) => Poll::Ready(Some(Ok(v))),
            Err(e) => {
                // A transport end is clean once the peer's Close arrived; before that it is an
                // abnormal closure (RFC 6455 §7.1.5) and reported.
                if e.is_connection_error() && !self.inner.can_read() {
                    self.begin_shutdown();
                    ready!(self.poll_shutdown_transport(ContextWaker::Read, cx));
                    Poll::Ready(None)
                } else {
                    self.lifecycle = Lifecycle::Failed;
                    Poll::Ready(Some(Err(e)))
                }
            }
        }
    }
}

impl<S: Io + Unpin> AsyncWebSocket<S> {
    /// End the transport cleanly once the WebSocket closed: a FIN on TCP and HTTP/3,
    /// END_STREAM on HTTP/2 (RFC 6455 §7.1.1, RFC 9220 §3). Failures are irrelevant then.
    ///
    /// Polled through the waker proxy with the caller's slot, so split read and sink halves
    /// both get woken.
    fn poll_shutdown_transport(&mut self, kind: ContextWaker, cx: &mut Context<'_>) -> Poll<()> {
        if self.lifecycle != Lifecycle::ShuttingDown {
            return Poll::Ready(());
        }
        let result =
            ready!(self.with_context(Some((kind, cx)), |s| s.get_mut().poll_shutdown(kind)));
        if let Err(error) = result {
            trace!("websocket transport shutdown after close: {error}");
        }
        self.lifecycle = Lifecycle::Ended;
        // A split half parked elsewhere is ready now, even without a transport event.
        let other = match kind {
            ContextWaker::Read => ContextWaker::Write,
            ContextWaker::Write => ContextWaker::Read,
        };
        self.inner.get_ref().wake(other);
        Poll::Ready(())
    }

    /// Start the transport shutdown, unless the socket already ended or failed.
    fn begin_shutdown(&mut self) {
        if matches!(self.lifecycle, Lifecycle::Open | Lifecycle::Closing) {
            self.lifecycle = Lifecycle::ShuttingDown;
        }
    }
}

impl<T> futures::stream::FusedStream for AsyncWebSocket<T>
where
    T: Io + Unpin,
{
    fn is_terminated(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Ended | Lifecycle::Failed)
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
        match (*self).with_context(None, |s| s.write(item)) {
            Ok(()) => {
                self.ready = true;
                Ok(())
            }
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // the message was accepted and queued so not an error
                // but `poll_ready` will now start trying to flush the block
                self.ready = false;
                Ok(())
            }
            Err(e) => {
                self.ready = true;
                debug!("websocket start_send error: {e}");
                Err(e)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.lifecycle == Lifecycle::ShuttingDown {
            ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
            return Poll::Ready(Ok(()));
        }
        let result = ready!(
            (*self).with_context(Some((ContextWaker::Write, cx)), |s| compat::cvt(s.flush()))
        );
        self.ready = true;
        match result {
            // The flush completed the close handshake: end the transport, so the queued close
            // reaches the peer followed by an orderly end of stream.
            Err(err) if err.is_connection_error() && !self.inner.can_write() => {
                self.begin_shutdown();
                ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
                Poll::Ready(Ok(()))
            }
            other => Poll::Ready(other),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.lifecycle {
            Lifecycle::ShuttingDown => {
                ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
                return Poll::Ready(Ok(()));
            }
            Lifecycle::Ended => return Poll::Ready(Ok(())),
            Lifecycle::Open | Lifecycle::Closing | Lifecycle::Failed => (),
        }
        self.ready = true;
        let res = if self.lifecycle == Lifecycle::Closing {
            // After queueing it, we call `flush` to drive the close handshake to completion.
            (*self).with_context(Some((ContextWaker::Write, cx)), |s| s.flush())
        } else {
            (*self).with_context(Some((ContextWaker::Write, cx)), |s| s.close(None))
        };

        match res {
            // The peer's Close arrived and ours is flushed: end the transport as well.
            Ok(()) if !self.inner.can_read() => {
                self.begin_shutdown();
                ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
                Poll::Ready(Ok(()))
            }
            Ok(()) => Poll::Ready(Ok(())),
            Err(ProtocolError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                trace!("WouldBlock");
                if self.lifecycle == Lifecycle::Open {
                    self.lifecycle = Lifecycle::Closing;
                }
                Poll::Pending
            }
            Err(err) => {
                if err.is_connection_error() && !self.inner.can_write() {
                    self.begin_shutdown();
                    ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
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
    use crate::{
        protocol::{Message, Role},
        runtime::{AsyncWebSocket, compat::AllowStd},
    };
    use rama_core::{
        ServiceInput,
        futures::{SinkExt as _, StreamExt as _},
    };
    use std::{
        io::{Read, Write},
        time::Duration,
    };

    fn is_read<T: Read>() {}
    fn is_write<T: Write>() {}
    fn is_unpin<T: Unpin>() {}

    /// A completed close handshake ends the transport cleanly, even while the socket
    /// itself is kept around: the peer observes an orderly end of stream.
    #[tokio::test]
    async fn close_handshake_shuts_down_the_transport() {
        let (server_io, client_io) = tokio::io::duplex(1024);
        let mut server =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None).await;
        let mut client =
            AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;
        client.send(Message::Close(None)).await.unwrap();
        assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
        assert!(server.next().await.is_none());
        let end = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(message) = client.next().await {
                assert!(matches!(message, Ok(Message::Close(_))), "{message:?}");
            }
        })
        .await;
        assert!(
            end.is_ok(),
            "the client never saw the server end the transport"
        );
        drop(server);
    }

    /// A peer transport replaying `reads`, then failing every read and write with `fail`.
    struct Scripted {
        reads: std::collections::VecDeque<Vec<u8>>,
        fail: std::io::ErrorKind,
        written: Vec<u8>,
    }

    impl tokio::io::AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(match self.reads.pop_front() {
                Some(bytes) => {
                    buf.put_slice(&bytes);
                    Ok(())
                }
                None => Err(self.fail.into()),
            })
        }
    }

    impl tokio::io::AsyncWrite for Scripted {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            // The peer's Close is read first; it resets before taking our reply.
            if self.reads.is_empty() && !self.written.is_empty() {
                return std::task::Poll::Ready(Err(self.fail.into()));
            }
            self.written.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    // A client's empty Close frame, masked with a zero key.
    const PEER_CLOSE: [u8; 6] = [0x88, 0x80, 0, 0, 0, 0];

    async fn server_over(reads: Vec<Vec<u8>>) -> AsyncWebSocket<ServiceInput<Scripted>> {
        let io = Scripted {
            reads: reads.into(),
            fail: std::io::ErrorKind::ConnectionReset,
            written: Vec::new(),
        };
        AsyncWebSocket::from_raw_socket(ServiceInput::new(io), Role::Server, None).await
    }

    /// RFC 6455 §7.1.4: once both Close frames crossed, a transport reset is a clean close.
    #[tokio::test]
    async fn a_reset_after_the_closing_handshake_is_a_clean_end() {
        let mut server = server_over(vec![PEER_CLOSE.to_vec()]).await;
        server.close(None).await.unwrap();
        assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
        assert!(server.next().await.is_none());
    }

    /// The peer's Close states how the session ended, even when it resets before our reply.
    #[tokio::test]
    async fn a_reset_after_the_peers_close_is_a_clean_end() {
        let mut server = server_over(vec![PEER_CLOSE.to_vec()]).await;
        assert!(matches!(server.next().await, Some(Ok(Message::Close(_)))));
        let after = server.next().await;
        assert!(
            after.is_none(),
            "no more messages after the peer's Close: {after:?}"
        );
    }

    /// RFC 6455 §7.1.5: a reset before any Close is abnormal (1006), and reported.
    #[tokio::test]
    async fn a_reset_before_any_close_fails_the_stream() {
        let mut server = server_over(Vec::new()).await;
        let error = server.next().await.unwrap().unwrap_err();
        assert!(
            matches!(&error, crate::protocol::ProtocolError::Io(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset),
            "{error:?}"
        );
        assert!(server.next().await.is_none());
    }

    #[test]
    fn web_socket_stream_has_traits() {
        is_read::<AllowStd<tokio::net::TcpStream>>();
        is_write::<AllowStd<tokio::net::TcpStream>>();
        is_unpin::<AsyncWebSocket<tokio::net::TcpStream>>();
    }
}
