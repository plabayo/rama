//! TLS implementation agnostic server types

mod config;
#[doc(inline)]
pub use config::{
    CacheKind, ClientVerifyMode, DynamicCertIssuer, DynamicIssuer, SelfSignedData, ServerAuth,
    ServerAuthData, ServerCertIssuerData, ServerCertIssuerKind, ServerConfig,
};

mod peek;
#[doc(inline)]
pub use peek::{NoTlsRejectError, TlsPeekRouter, TlsPeekStream};
