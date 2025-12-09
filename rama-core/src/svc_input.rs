use std::{
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use crate::extensions::{Extensions, ExtensionsMut, ExtensionsRef};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// A generic service input that implements all rama traits conditionally
    ///
    /// This input type can be used in places where you need a request/stream
    /// that implements things such as [`ExtensionsRef`] without having to
    /// create a custom type for it.
    ///
    /// This is mainly useful for testing or less import request types. In most
    /// cases you should create a new type that implements all the needed traits,
    /// but that is focussed specifically on that use case.
    #[derive(Debug, Clone, Default)]
    pub struct ServiceInput<T> {
        #[pin]
        pub input: T,
        pub extensions: Extensions,
    }
}

impl<T> ServiceInput<T> {
    pub fn new(input: T) -> Self {
        Self {
            input,
            extensions: Extensions::new(),
        }
    }
}

impl<T> ExtensionsRef for ServiceInput<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T> ExtensionsMut for ServiceInput<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T: AsyncRead> AsyncRead for ServiceInput<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().input.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T: AsyncWrite> AsyncWrite for ServiceInput<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().input.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().input.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().input.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().input.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.input.is_write_vectored()
    }
}

impl<T: Read> Read for ServiceInput<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.input.read_vectored(bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.input.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.input.read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.input.read_exact(buf)
    }
}

impl<T: Write> Write for ServiceInput<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.input.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.input.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.input.write_all(buf)
    }

    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> io::Result<()> {
        self.input.write_fmt(args)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.input.write_vectored(bufs)
    }
}
