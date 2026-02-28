use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
};
#[cfg(any(target_os = "windows", target_family = "unix"))]
use rama_net::socket;
use rama_net::{address::SocketAddress, stream::Socket};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use tokio::net::TcpStream as TokioTcpStream;

pin_project! {
    #[non_exhaustive]
    #[derive(Debug)]
    pub struct TcpStream {
        #[pin]
        pub stream: TokioTcpStream,
        pub extensions: Extensions,
    }
}

impl TcpStream {
    #[inline(always)]
    pub fn new(stream: TokioTcpStream) -> Self {
        Self {
            stream,
            extensions: Extensions::new(),
        }
    }

    #[cfg(any(target_os = "windows", target_family = "unix"))]
    pub fn try_from_socket(
        socket: socket::core::Socket,
        extensions: Extensions,
    ) -> Result<Self, std::io::Error> {
        let stream = std::net::TcpStream::from(socket);
        Self::try_from_std_tcp_stream(stream, extensions)
    }

    pub fn try_from_std_tcp_stream(
        stream: std::net::TcpStream,
        extensions: Extensions,
    ) -> Result<Self, std::io::Error> {
        stream.set_nonblocking(true)?;
        let stream = TokioTcpStream::from_std(stream)?;
        Ok(Self::from_tokio_tcp_stream(stream, extensions))
    }

    #[inline(always)]
    pub fn from_tokio_tcp_stream(stream: TokioTcpStream, extensions: Extensions) -> Self {
        Self { stream, extensions }
    }
}

impl From<TokioTcpStream> for TcpStream {
    fn from(value: TokioTcpStream) -> Self {
        Self::new(value)
    }
}

impl From<TcpStream> for TokioTcpStream {
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
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        self.stream.local_addr().map(Into::into)
    }

    #[inline]
    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        self.stream.peer_addr().map(Into::into)
    }
}
