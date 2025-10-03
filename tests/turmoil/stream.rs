use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
use rama_net::stream::Socket;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use turmoil::net::TcpStream as TurmoilTcpStream;

pin_project! {
    pub struct TcpStream {
        #[pin]
        pub stream: TurmoilTcpStream,
        pub extensions: Extensions,
    }
}

impl TcpStream {
    pub fn new(stream: TurmoilTcpStream) -> Self {
        Self {
            stream,
            extensions: Extensions::new(),
        }
    }
}

impl From<TurmoilTcpStream> for TcpStream {
    fn from(value: TurmoilTcpStream) -> Self {
        Self::new(value)
    }
}

impl From<TcpStream> for TurmoilTcpStream {
    fn from(value: TcpStream) -> Self {
        value.stream
    }
}

impl ExtensionsRef for TcpStream {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for TcpStream {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

impl Socket for TcpStream {
    #[inline]
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}
