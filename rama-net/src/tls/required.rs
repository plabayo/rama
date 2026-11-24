use rama_core::extensions::Extension;

/// Use TLS on this connection, whatever its protocol.
///
/// A TLS connector in auto mode only secures a protocol that has a secure form,
/// such as `https://`. SOCKS5 has none, so without this it stays plaintext.
///
/// To secure only the connection to a proxy, put it in that route's
/// [`ProxyConnectionExtensions`]. The tunnel through the proxy is not affected.
///
/// A proxy connector without TLS support refuses the connection instead of
/// dialing it in plaintext, see [`PlaintextProxyOnly`].
///
/// [`ProxyConnectionExtensions`]: crate::client::ProxyConnectionExtensions
/// [`PlaintextProxyOnly`]: crate::client::PlaintextProxyOnly
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Extension)]
#[extension(tags(net, tls), scope(connection))]
#[non_exhaustive]
pub struct TlsRequired;

impl TlsRequired {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
