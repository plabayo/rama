//! Protocol-neutral TLS wire vocabulary.

mod alpn;

#[doc(inline)]
pub use alpn::{AlpnPolicy, ApplicationProtocol, TlsAlpn, default_tls_alpn};
