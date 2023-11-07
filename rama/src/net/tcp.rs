use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::net::TcpStream as TokioTcpStream;

use crate::{
    state::{Extendable, Extensions},
    stream::{AsyncRead, AsyncWrite, ReadBuf},
};

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct TcpStream<S> {
        #[pin]
        inner: S,
        extensions: Extensions,
    }
}

impl<S> TcpStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
        }
    }

    pub fn into_parts(self) -> (S, Extensions) {
        (self.inner, self.extensions)
    }

    pub fn from_parts(inner: S, extensions: Extensions) -> Self {
        Self { inner, extensions }
    }
}

impl TcpStream<TokioTcpStream> {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }
}

impl<S> Extendable for TcpStream<S> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl<S> AsyncRead for TcpStream<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TcpStream<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
