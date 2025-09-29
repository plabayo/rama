use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use crate::extensions::{Extensions, ExtensionsMut, ExtensionsRef};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// A generic request that implements all rama traits conditionally
    ///
    /// This request type can be used in places where you need a request/stream
    /// that implements things such as [`ExtensionsRef`] without having to
    /// create a custom type for it.
    ///
    /// This is mainly useful for testing or less import request types. In most
    /// cases you should create a new type that implements all the needed traits,
    /// but that is focussed specifically on that use case.
    pub struct GenericRequest<T> {
        #[pin]
        pub request: T,
        pub extensions: Extensions,
    }
}

impl<T> GenericRequest<T> {
    pub fn new(request: T) -> Self {
        Self {
            request,
            extensions: Extensions::new(),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for GenericRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericRequest")
            .field("request", &self.request)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl<T: Default> Default for GenericRequest<T> {
    fn default() -> Self {
        Self {
            request: Default::default(),
            extensions: Default::default(),
        }
    }
}

impl<T: Clone> Clone for GenericRequest<T> {
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            extensions: self.extensions.clone(),
        }
    }
}

impl<T> ExtensionsRef for GenericRequest<T> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<T> ExtensionsMut for GenericRequest<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

impl<T: AsyncRead> AsyncRead for GenericRequest<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().request.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite> AsyncWrite for GenericRequest<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().request.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().request.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().request.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().request.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.request.is_write_vectored()
    }
}
