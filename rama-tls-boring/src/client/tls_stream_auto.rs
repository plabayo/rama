use super::BoringTlsStream;
use pin_project_lite::pin_project;
use rama_boring::ssl::SslRef;
use rama_core::{
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    stream::Stream,
};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};

pin_project! {
    /// A stream which can be either a secure or a plain stream.
    pub struct AutoTlsStream<S> {
        #[pin]
        pub(super) inner: AutoTlsStreamData<S>,
    }
}

impl<S: ExtensionsMut> AutoTlsStream<S> {
    #[must_use]
    pub fn secure(inner: BoringTlsStream<S>) -> Self {
        Self {
            inner: AutoTlsStreamData::Secure { inner },
        }
    }

    #[must_use]
    pub fn plain(inner: S) -> Self {
        Self {
            inner: AutoTlsStreamData::Plain { inner },
        }
    }

    pub fn ssl_ref(&self) -> Option<&SslRef> {
        match &self.inner {
            AutoTlsStreamData::Secure { inner } => Some(inner.ssl()),
            AutoTlsStreamData::Plain { .. } => None,
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
        Secure{ #[pin] inner: BoringTlsStream<S> },
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

impl<S: ExtensionsRef> ExtensionsRef for AutoTlsStream<S> {
    fn extensions(&self) -> &Extensions {
        match &self.inner {
            AutoTlsStreamData::Secure { inner } => inner.get_ref().extensions(),
            AutoTlsStreamData::Plain { inner } => inner.extensions(),
        }
    }
}

impl<S: ExtensionsMut> ExtensionsMut for AutoTlsStream<S> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        match &mut self.inner {
            AutoTlsStreamData::Secure { inner } => inner.get_mut().extensions_mut(),
            AutoTlsStreamData::Plain { inner } => inner.extensions_mut(),
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

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            AutoTlsStreamData::Secure { inner } => inner.is_write_vectored(),
            AutoTlsStreamData::Plain { inner } => inner.is_write_vectored(),
        }
    }
}
