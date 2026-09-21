//! Shared TLS protocol vocabulary and connection requirements.

mod alpn;

#[doc(inline)]
pub use alpn::{ApplicationProtocol, TlsAlpn, default_tls_alpn};

/// Require TLS to the logical destination independently of its application scheme.
///
/// Service discovery can select a TLS endpoint for an `http` origin without
/// changing the HTTP origin or certificate identity. Automatic TLS connectors
/// honor this marker, and HTTP proxies establish a CONNECT tunnel so TLS runs
/// end to end. This does not configure TLS to the proxy itself.
#[derive(Debug, Clone, Copy, Default, rama_core::extensions::Extension)]
#[extension(tags(tls))]
pub struct RequireTls;
