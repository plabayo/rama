use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use rama_core::stream::Stream;
use rama_core::{
    error::BoxError,
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
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
        S: Stream + Unpin + ExtensionsMut,
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
        S: Stream + Unpin + ExtensionsMut,
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

    /// Consumes the `WebSocketStream` and returns the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner.into_inner().into_inner()
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S
    where
        S: Stream + Unpin,
    {
        self.inner.get_ref().get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S
    where
        S: Stream + Unpin,
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
        S: Stream + Unpin,
    {
        self.send(Message::Close(msg)).await
    }
}

impl<S: ExtensionsRef> ExtensionsRef for AsyncWebSocket<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S: ExtensionsMut> ExtensionsMut for AsyncWebSocket<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.inner.extensions_mut()
    }
}

impl<S: Stream + Unpin> AsyncWebSocket<S> {
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
                BoxError::from("Connection closed: no messages to be received any longer"),
            ))
        })?
    }
}

impl<T> futures::Stream for AsyncWebSocket<T>
where
    T: Stream + Unpin,
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

        match ready!(self.with_context(Some((ContextWaker::Read, cx)), |s| {
            trace!("Stream.with_context poll_next -> read()");
            compat::cvt(s.read())
        })) {
            Ok(v) => Poll::Ready(Some(Ok(v))),
            Err(e) => {
                self.ended = true;
                if e.is_connection_error() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(e)))
                }
            }
        }
    }
}

impl<T> futures::stream::FusedStream for AsyncWebSocket<T>
where
    T: Stream + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.ended
    }
}

impl<T> futures::Sink<Message> for AsyncWebSocket<T>
where
    T: Stream + Unpin,
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
    use crate::runtime::{AsyncWebSocket, compat::AllowStd};
    use std::io::{Read, Write};

    fn is_read<T: Read>() {}
    fn is_write<T: Write>() {}
    fn is_unpin<T: Unpin>() {}

    #[test]
    fn web_socket_stream_has_traits() {
        is_read::<AllowStd<tokio::net::TcpStream>>();
        is_write::<AllowStd<tokio::net::TcpStream>>();
        is_unpin::<AsyncWebSocket<tokio::net::TcpStream>>();
    }
}
