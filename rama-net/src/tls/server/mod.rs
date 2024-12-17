//! TLS implementation agnostic server types

mod config;
#[doc(inline)]
pub use config::{
    ClientVerifyMode, DynamicCertIssuer, DynamicIssuer, SelfSignedData, ServerAuth, ServerAuthData,
    ServerCertIssuerData, ServerCertIssuerKind, ServerConfig,
};
