use std::{
    io,
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    ServiceInput,
    extensions::{Extensions, ExtensionsRef},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

pin_project! {
    /// A per-flow stream presented to the Rama user.
    ///
    /// This behaves like a normal bidirectional byte stream and implements
    /// tokio [`AsyncRead`] + [`AsyncWrite`] + Rama [`Extensions`].
    pub struct TcpFlow {
        #[pin]
        inner: DuplexStream,
        extensions: Extensions,
        io_demand_once: Once,
        on_io_demand: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    }
}

impl TcpFlow {
    #[must_use]
    /// Create a new [`TcpFlow`] that triggers one ingress-read demand when Rust starts I/O.
    pub(crate) fn new_with_io_demand(
        inner: DuplexStream,
        on_io_demand: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            inner,
            extensions: Extensions::new(),
            io_demand_once: Once::new(),
            on_io_demand,
        }
    }

    #[inline(always)]
    fn signal_io_demand_once(&self) {
        if let Some(on_io_demand) = &self.on_io_demand {
            self.io_demand_once.call_once(|| on_io_demand());
        }
    }

    /// Consume the [`TcpFlow`] by mapping the input and
    /// returning this as a new generic [`ServiceInput`].
    pub fn map_input<Input>(self, map: impl FnOnce(DuplexStream) -> Input) -> ServiceInput<Input> {
        let Self {
            inner: duplex_stream,
            extensions,
            io_demand_once: _,
            on_io_demand: _,
        } = self;

        ServiceInput {
            input: map(duplex_stream),
            extensions,
        }
    }
}

impl ExtensionsRef for TcpFlow {
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl AsyncRead for TcpFlow {
    #[inline(always)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.as_ref().get_ref().signal_io_demand_once();
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpFlow {
    #[inline(always)]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.as_ref().get_ref().signal_io_demand_once();
        self.project().inner.poll_write(cx, buf)
    }

    #[inline(always)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline(always)]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
