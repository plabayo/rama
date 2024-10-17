//! TLS implementation agnostic server types

mod config;
#[doc(inline)]
pub use config::{
    ClientVerifyMode, SelfSignedData, ServerAuth, ServerAuthData, ServerCertIssuerData,
    ServerCertIssuerKind, ServerConfig,
};
