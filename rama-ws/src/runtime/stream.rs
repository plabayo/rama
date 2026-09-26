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
    closing: bool,
    ended: bool,
    /// The WebSocket closed; its transport is being shut down.
    shutting_down: bool,
    /// Tungstenite is probably ready to receive more data.
    ///
    /// `false` once start_send hits `WouldBlock` errors.
    /// `true` initially and after `flush`ing.
    ready: bool,
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
            closing: false,
            ended: false,
            shutting_down: false,
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
        if self.shutting_down {
            ready!(self.poll_shutdown_transport(ContextWaker::Read, cx));
            self.ended = true;
            return Poll::Ready(None);
        }

        match ready!(self.with_context(Some((ContextWaker::Read, cx)), |s| {
            trace!("Stream.with_context poll_next -> read()");
            compat::cvt(s.read())
        })) {
            Ok(v) => Poll::Ready(Some(Ok(v))),
            Err(e) => {
                if e.is_connection_error() {
                    self.shutting_down = true;
                    ready!(self.poll_shutdown_transport(ContextWaker::Read, cx));
                    self.ended = true;
                    Poll::Ready(None)
                } else {
                    self.ended = true;
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
        if !self.shutting_down {
            return Poll::Ready(());
        }
        let result =
            ready!(self.with_context(Some((kind, cx)), |s| s.get_mut().poll_shutdown(kind)));
        if let Err(error) = result {
            trace!("websocket transport shutdown after close: {error}");
        }
        self.shutting_down = false;
        Poll::Ready(())
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
        if self.shutting_down {
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
            Err(err) if err.is_connection_error() => {
                self.shutting_down = true;
                ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
                Poll::Ready(Ok(()))
            }
            other => Poll::Ready(other),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.shutting_down {
            ready!(self.poll_shutdown_transport(ContextWaker::Write, cx));
            return Poll::Ready(Ok(()));
        }
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
                    self.shutting_down = true;
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

    #[test]
    fn web_socket_stream_has_traits() {
        is_read::<AllowStd<tokio::net::TcpStream>>();
        is_write::<AllowStd<tokio::net::TcpStream>>();
        is_unpin::<AsyncWebSocket<tokio::net::TcpStream>>();
    }
}
