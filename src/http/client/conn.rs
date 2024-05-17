use crate::{http::Request, service::Context};
use pin_project_lite::pin_project;
use std::{fmt, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, Body, State> {
    /// The [`Context`] of the [`Request`] for which a connection was established.
    pub ctx: Context<State>,
    /// The [`Request`] for which a connection was established.
    pub req: Request<Body>,
    /// The established [`ClientConnection`] to the server.
    pub conn: ClientConnection<S>,
}

impl<S: fmt::Debug, Body: fmt::Debug, State: fmt::Debug> fmt::Debug
    for EstablishedClientConnection<S, Body, State>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("ctx", &self.ctx)
            .field("req", &self.req)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<S: Clone, Body: Clone, State> Clone for EstablishedClientConnection<S, Body, State> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            req: self.req.clone(),
            conn: self.conn.clone(),
        }
    }
}

pin_project! {
    /// A connection to a server.
    pub struct ClientConnection<S> {
        // The R/W stream that can be used to communicate with the server.
        #[pin]
        stream: S,

        // The target address connected to.
        addr: SocketAddr,
    }
}

impl<S: fmt::Debug> fmt::Debug for ClientConnection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .field("addr", &self.addr)
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S: Clone> Clone for ClientConnection<S> {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            stream: self.stream.clone(),
        }
    }
}

impl<S> ClientConnection<S> {
    /// Create a new [`ClientConnection`] for the given target [`SocketAddr`] and stream.
    pub fn new(addr: SocketAddr, stream: S) -> Self {
        Self { addr, stream }
    }

    /// Get the target [`SocketAddr`] of this [`ClientConnection`].
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Map the inner stream of this [`ClientConnection`] to a different type.
    pub fn map<S2>(self, f: impl FnOnce(S) -> S2) -> ClientConnection<S2> {
        ClientConnection {
            addr: self.addr,
            stream: f(self.stream),
        }
    }

    /// Consume the [`ClientConnection`] and return the inner stream and target [`SocketAddr`].
    pub fn into_parts(self) -> (SocketAddr, S) {
        (self.addr, self.stream)
    }

    /// Consume the [`ClientConnection`] and return the inner stream.
    pub fn into_stream(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for ClientConnection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for ClientConnection<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}
