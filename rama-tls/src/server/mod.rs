//! TLS implementation agnostic server types

mod config;
#[doc(inline)]
pub use config::{
    CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext, CertificateKeyKind,
    CertificateSubject, CertificateValidity, ClientVerifyMode, DynamicCertIssuer,
    GeneratedServerAuthConfig, LeafCertConfig, LeafCertRequest, SelfSignedCaConfig, ServerAuthData,
    TlsClientVerify, TlsServerAuth, TlsServerConfig, TlsStoreClientCertChain,
};

mod peek;
#[doc(inline)]
pub use peek::{NoTlsRejectError, TlsPeekRouter, TlsPrefixedIo};

mod peek_client_hello;
#[doc(inline)]
pub use peek_client_hello::{
    InputWithClientHello, PeekTlsClientHelloService, TlsClientHelloPrefixedIo,
    peek_client_hello_from_input, peek_client_hello_from_input_with_timeout_policy,
};

mod sni;
#[doc(inline)]
pub use sni::{SniPrefixedIo, SniRequest, SniRouter};
