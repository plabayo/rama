//! TLS implementation agnostic server types

use rama_core::extensions::Extension;

use crate::client::ClientHello;

mod config;
#[doc(inline)]
pub use config::{
    CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext, CertificateKeyKind,
    CertificateSubject, CertificateValidity, ClientVerifyMode, DynamicCertIssuer,
    GeneratedServerAuthConfig, LeafCertConfig, LeafCertRequest, SelfSignedCaConfig, ServerAuthData,
    TlsClientVerify, TlsServerAuth, TlsServerConfig, TlsStoreClientCertChain,
};

mod hello;
#[doc(inline)]
pub use hello::{ServerHello, parse_encrypted_extensions};

mod peek;
#[doc(inline)]
pub use peek::{NoTlsRejectError, TlsEgressPredicate, TlsPeekRouter, TlsPrefixedIo};

#[doc(inline)]
pub use crate::client::{ClientHelloPeekStatus, MalformedTlsPolicy};

mod peek_client_hello;
#[doc(inline)]
pub use peek_client_hello::{
    InputWithClientHello, PeekTlsClientHelloService, StoreOuterClientHelloLayer,
    StoreOuterClientHelloService, TlsClientHelloPrefixedIo, peek_client_hello_from_input,
    peek_client_hello_from_input_with_config, peek_client_hello_from_input_with_policies,
};

mod sni;
#[doc(inline)]
pub use sni::{SniPrefixedIo, SniRequest, SniRouter};

/// Diagnostic wire hello for a completed server handshake. When ECH is
/// accepted, `SecureTransport::client_hello()` contains the effective inner
/// instead. Capture consumers can retain both as a matched pair, preserving the
/// wire offer alongside the effective inner.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
#[non_exhaustive]
pub struct EchServerObservation {
    pub outer: ClientHello,
}

impl EchServerObservation {
    #[must_use]
    pub fn new(outer: ClientHello) -> Self {
        Self { outer }
    }
}

/// Actual ECH acceptance on an ingress server handshake. Kept separate from
/// client acceptance so ingress observations cannot satisfy egress pool policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
#[non_exhaustive]
pub struct ServerEchAccepted(pub bool);

impl ServerEchAccepted {
    #[must_use]
    pub const fn new(accepted: bool) -> Self {
        Self(accepted)
    }
}
