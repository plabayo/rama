use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extensions, ExtensionsRef};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// A stream that is a new connection nested on top of the one it wraps.
    ///
    /// Reads and writes go to the wrapped stream, but its [`Extensions`] are a
    /// [`Extensions::fork_nested_connection`] of the wrapped stream's: flow data
    /// keeps resolving through, while a fact about the connection underneath (its
    /// negotiated ALPN, its TLS parameters, whether it may be reused, ...) no
    /// longer answers for this one.
    ///
    /// Use it where a connector establishes a new endpoint over an existing
    /// stream without replacing the stream itself, such as a SOCKS5 `CONNECT`.
    /// Protocols that hand out a transport of their own insert the boundary
    /// there instead.
    #[derive(Debug, ExtensionsRef)]
    pub struct NestedConnection<S> {
        #[pin]
        stream: S,
        extensions: Extensions,
    }
}

impl<S: ExtensionsRef> NestedConnection<S> {
    /// Nest a new connection on top of `stream`.
    pub fn new(stream: S) -> Self {
        let extensions = stream.extensions().fork_nested_connection();
        Self { stream, extensions }
    }
}

impl<S> NestedConnection<S> {
    /// The wrapped stream, dropping this connection's own extensions.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S: AsyncRead> AsyncRead for NestedConnection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<S: AsyncWrite> AsyncWrite for NestedConnection<S> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extension;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    #[extension(scope(connection))]
    struct NegotiatedAlpn(u8);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    struct RetryBudget(u32);

    #[derive(Debug, ExtensionsRef)]
    struct FakeStream {
        extensions: Extensions,
    }

    #[test]
    fn nesting_stops_connection_scoped_lookups_and_keeps_flow_data() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));
        proxy.extensions.insert(RetryBudget(3));

        let nested = NestedConnection::new(proxy);

        assert_eq!(nested.extensions().get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(
            nested.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(3))
        );
    }

    #[test]
    fn into_inner_returns_the_wrapped_stream() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));

        let inner = NestedConnection::new(proxy).into_inner();
        assert_eq!(
            inner.extensions().get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(2))
        );
    }
}
