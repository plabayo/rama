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

mod peek_client_hello;
#[doc(inline)]
pub use peek_client_hello::{
    ClientHelloRequest, PeekTlsClientHelloService, PeekTlsClientHelloStream,
};

mod sni;
#[doc(inline)]
pub use sni::{SniPeekStream, SniRequest, SniRouter};
