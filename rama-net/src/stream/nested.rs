use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rama_core::extensions::{Extensions, ExtensionsRef, ExtensionsTransfer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::client::{ConnectionAttemptTransfer, pool::ConnectionReuse, proxy_connection_reuse};

/// What a child connection keeps by default, the transfer every site that
/// forks a connection starts from: [`ConnectionReuseTransfer`] and
/// [`ConnectionAttemptTransfer`].
///
/// This is the one that grows as more of the parent connection turns out to
/// still constrain the child, so extend it rather than replace it:
/// `DefaultExtensionsTransfer::new().and(mine)`.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct DefaultExtensionsTransfer;

impl DefaultExtensionsTransfer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ExtensionsTransfer for DefaultExtensionsTransfer {
    fn transfer(&self, parent: &Extensions, child: &Extensions) {
        ConnectionReuseTransfer
            .and(ConnectionAttemptTransfer::new())
            .transfer(parent, child);
    }
}

/// Carries the parent's [`ConnectionReuse`] onto the child connection as a
/// restriction.
///
/// The parent's connector classified the parent endpoint. A child connection is a
/// different endpoint, so its own connector still has to publish a complete
/// policy, but whatever the transport underneath requires keeps applying on top
/// of that.
///
/// A parent that is a connection to a proxy is carried as [`proxy_connection_reuse`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionReuseTransfer;

impl ExtensionsTransfer for ConnectionReuseTransfer {
    fn transfer(&self, parent: &Extensions, child: &Extensions) {
        if let Some(rules) = proxy_connection_reuse(parent) {
            child.insert(rules);
        } else if let Some(reuse) = parent.get_ref::<ConnectionReuse>() {
            child.insert(reuse.clone().into_restriction());
        }
    }
}

pin_project! {
    /// A stream that is a new connection nested on top of the one it wraps.
    ///
    /// Reads and writes go to the wrapped stream, but its [`Extensions`] are a
    /// [`Extensions::fork_connection`] of the wrapped stream's: flow data
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
    pub fn new(stream: S, transfer: &dyn ExtensionsTransfer) -> Self {
        let extensions = stream.extensions().fork_connection(transfer);
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
    use rama_core::{
        extensions::{Extension, NoExtensionsTransfer},
        io::AbortIo,
    };
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

        let nested = NestedConnection::new(proxy, &NoExtensionsTransfer::new());

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

        let carry_alpn = |parent: &Extensions, child: &Extensions| {
            if let Some(alpn) = parent.get_ref::<NegotiatedAlpn>() {
                child.insert(*alpn);
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

        let carry_alpn = |parent: &Extensions, child: &Extensions| {
            if let Some(alpn) = parent.get_ref::<NegotiatedAlpn>() {
                child.insert(*alpn);
            }
        };
        let nested =
            NestedConnection::new(proxy, &DefaultExtensionsTransfer::new().and(carry_alpn));

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    #[extension(scope(connection))]
    struct HopSetting(u8);

    #[derive(Debug)]
    struct SettingReuse(Option<HopSetting>);

    impl SettingReuse {
        fn key(setting: Option<HopSetting>) -> ReuseKey {
            ReuseKey::from_bits::<Self>(setting.map_or(0, |setting| u128::from(setting.0) + 1))
        }
    }

    impl ConnectionReusePolicy for SettingReuse {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            Some(Self::key(self.0))
        }

        fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
            Some(Self::key(input.get_ref::<HopSetting>().copied()))
        }
    }

    fn tunnel_over(hop: Option<HopSetting>) -> Extensions {
        let leg = Extensions::new();
        if let Some(hop) = hop {
            leg.insert(hop);
        }
        leg.insert(ConnectionReuse::new(SettingReuse(hop)));
        leg.fork_connection(&DefaultExtensionsTransfer::new())
    }

    #[test]
    fn a_restriction_keeps_deciding_on_the_requests_it_is_given() {
        let tunnel = tunnel_over(Some(HopSetting(1)));
        let hop = tunnel
            .get_ref::<ConnectionReuse>()
            .expect("the hop's rules cross the boundary");
        assert!(!hop.is_complete());

        let same = Extensions::new();
        same.insert(HopSetting(1));
        assert!(hop.matches(&same));

        let different = Extensions::new();
        different.insert(HopSetting(2));
        assert!(!hop.matches(&different));

        assert!(!hop.matches(&Extensions::new()));
    }

    #[test]
    fn hops_with_different_settings_never_share_a_key() {
        let first = tunnel_over(Some(HopSetting(1)));
        let second = tunnel_over(Some(HopSetting(2)));
        let plain = tunnel_over(None);

        let key = |tunnel: &Extensions| {
            tunnel
                .get_ref::<ConnectionReuse>()
                .and_then(|reuse| reuse.key().cloned())
                .expect("a reusable hop")
        };
        assert_ne!(key(&first), key(&second));
        assert_ne!(key(&first), key(&plain));
    }

    #[test]
    fn into_inner_returns_the_wrapped_stream() {
        let proxy = FakeStream {
            extensions: Extensions::new(),
        };
        proxy.extensions.insert(NegotiatedAlpn(2));

        let inner = NestedConnection::new(proxy, &NoExtensionsTransfer::new()).into_inner();
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

        let nested = NestedConnection::new(proxy, &NoExtensionsTransfer::new());

        let abort = nested
            .extensions()
            .get_arc::<AbortIo>()
            .expect("the nested connection fronts the same stream");
        abort.abort();
        assert!(aborted.load(Ordering::Acquire));
    }
}
