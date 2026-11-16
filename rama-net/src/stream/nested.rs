use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::{
    extensions::{Extensions, ExtensionsRef, NestedConnectionTransfer},
    io::AbortIo,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::client::pool::ConnectionReuse;

/// What a nested connection keeps by default, the transfer every nesting
/// connector starts from.
///
/// Today that is exactly [`ConnectionReuseTransfer`]. This is the one that
/// grows as more of the outer connection turns out to still constrain the
/// nested endpoint, so extend it rather than replace it:
/// `DefaultConnectionTransfer.and(mine)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultConnectionTransfer;

impl NestedConnectionTransfer for DefaultConnectionTransfer {
    fn transfer(&self, outer: &Extensions, nested: &Extensions) {
        ConnectionReuseTransfer.transfer(outer, nested);
    }
}

/// Carries the outer [`ConnectionReuse`] onto the nested connection as a
/// restriction.
///
/// The outer connector classified the outer endpoint. A nested connection is a
/// different endpoint, so its own connector still has to publish a complete
/// policy, but whatever the transport underneath requires keeps applying on top
/// of that.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionReuseTransfer;

impl NestedConnectionTransfer for ConnectionReuseTransfer {
    fn transfer(&self, outer: &Extensions, nested: &Extensions) {
        if let Some(reuse) = outer.get_ref::<ConnectionReuse>() {
            nested.insert(reuse.clone().into_restriction());
        }
    }
}

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
    /// Nest a new connection on top of `stream`, keeping what `transfer` puts
    /// on it.
    pub fn new(stream: S, transfer: &dyn NestedConnectionTransfer) -> Self {
        let extensions = stream.extensions().fork_nested_connection(transfer);
        AbortIo::front_same_io(stream.extensions(), &extensions);
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
    use crate::client::pool::{ConnectionReusePolicy, ReuseKey};
    use rama_core::extensions::{Extension, NoConnectionTransfer};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Debug)]
    struct AlwaysReusable;

    impl ConnectionReusePolicy for AlwaysReusable {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }

        fn request_key(&self, _input: &Extensions) -> Option<ReuseKey> {
            Some(ReuseKey::of::<Self>())
        }
    }

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

        let nested = NestedConnection::new(proxy, &NoConnectionTransfer);

        assert_eq!(nested.extensions().get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(
            nested.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(3))
        );
    }

    #[test]
    fn a_transfer_carries_what_it_picks_across_the_boundary() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));

        let carry_alpn = |outer: &Extensions, nested: &Extensions| {
            if let Some(alpn) = outer.get_ref::<NegotiatedAlpn>() {
                nested.insert(*alpn);
            }
        };
        let nested = NestedConnection::new(proxy, &carry_alpn);

        assert_eq!(
            nested.extensions().get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(2))
        );
    }

    #[test]
    fn chained_transfers_both_run() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));
        proxy
            .extensions
            .insert(ConnectionReuse::new(AlwaysReusable));

        let carry_alpn = |outer: &Extensions, nested: &Extensions| {
            if let Some(alpn) = outer.get_ref::<NegotiatedAlpn>() {
                nested.insert(*alpn);
            }
        };
        let nested = NestedConnection::new(proxy, &DefaultConnectionTransfer.and(carry_alpn));

        assert_eq!(
            nested.extensions().get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(2))
        );
        let reuse = nested
            .extensions()
            .get_ref::<ConnectionReuse>()
            .expect("reuse restriction");
        assert!(!reuse.is_complete());
    }

    #[test]
    fn into_inner_returns_the_wrapped_stream() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));

        let inner = NestedConnection::new(proxy, &NoConnectionTransfer).into_inner();
        assert_eq!(
            inner.extensions().get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(2))
        );
    }

    #[test]
    fn nested_connection_answers_with_the_wrapped_stream_abort() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        let aborted = Arc::new(AtomicBool::new(false));
        proxy.extensions.insert(AbortIo::new({
            let aborted = aborted.clone();
            move || aborted.store(true, Ordering::Release)
        }));

        let nested = NestedConnection::new(proxy, &NoConnectionTransfer);

        let abort = nested
            .extensions()
            .self_get_arc::<AbortIo>()
            .expect("the nested connection fronts the same stream");
        abort.abort();
        assert!(aborted.load(Ordering::Acquire));
    }
}
