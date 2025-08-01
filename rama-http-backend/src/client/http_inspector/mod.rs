//! [`rama::inspect::RequestInspector`] that ship with this crate,
//! that are especially useful for the http connector service in this crate.

#[cfg(any(feature = "rustls", feature = "boring"))]
mod tls_alpn;
#[cfg(any(feature = "rustls", feature = "boring"))]
pub use tls_alpn::HttpsAlpnModifier;

mod version_adapter;
pub use version_adapter::HttpVersionAdapter;
