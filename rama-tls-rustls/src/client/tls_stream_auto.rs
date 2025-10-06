use std::fmt;

use super::RustlsTlsStream;
use pin_project_lite::pin_project;
use rama_core::{
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    stream::Stream,
};
use tokio::io::{AsyncRead, AsyncWrite};

pin_project! {
    /// A stream which can be either a secure or a plain stream.
    pub struct AutoTlsStream<S> {
        #[pin]
        pub(super) inner: AutoTlsStreamData<S>,
    }
}

impl<S: ExtensionsMut> AutoTlsStream<S> {
    pub fn secure(inner: RustlsTlsStream<S>) -> Self {
        Self {
            inner: AutoTlsStreamData::Secure { inner },
        }
    }

    pub fn plain(inner: S) -> Self {
        Self {
            inner: AutoTlsStreamData::Plain { inner },
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for AutoTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoTlsStream")
            .field("inner", &self.inner)
            .finish()
    }
}

pin_project! {
    #[project = AutoTlsStreamDataProj]
    /// A stream which can be either a secure or a plain stream.
    enum AutoTlsStreamData<S> {
        /// A secure stream.
        Secure{ #[pin] inner: RustlsTlsStream<S> },
        /// A plain stream.
        Plain { #[pin] inner: S },
    }
}

impl<S: fmt::Debug> fmt::Debug for AutoTlsStreamData<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secure { inner } => f.debug_tuple("Secure").field(inner).finish(),
            Self::Plain { inner } => f.debug_tuple("Plain").field(inner).finish(),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncRead for AutoTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_read(cx, buf),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_read(cx, buf),
        }
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S> AsyncWrite for AutoTlsStream<S>
where
    S: Stream + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_write(cx, buf),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_flush(cx),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_shutdown(cx),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            AutoTlsStreamData::Secure { inner } => inner.is_write_vectored(),
            AutoTlsStreamData::Plain { inner } => inner.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project().inner.project() {
            AutoTlsStreamDataProj::Secure { inner } => inner.poll_write_vectored(cx, bufs),
            AutoTlsStreamDataProj::Plain { inner } => inner.poll_write_vectored(cx, bufs),
        }
    }
}

impl<S: ExtensionsRef> ExtensionsRef for AutoTlsStream<S> {
    fn extensions(&self) -> &Extensions {
        match &self.inner {
            AutoTlsStreamData::Secure { inner } => inner.get_ref().0.extensions(),
            AutoTlsStreamData::Plain { inner } => inner.extensions(),
        }
    }
}

impl<S: ExtensionsMut> ExtensionsMut for AutoTlsStream<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        match &mut self.inner {
            AutoTlsStreamData::Secure { inner } => inner.get_mut().0.extensions_mut(),
            AutoTlsStreamData::Plain { inner } => inner.extensions_mut(),
        }
    }
}
