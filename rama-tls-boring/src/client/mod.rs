//! TLS (Boring) client support for Rama.

pub mod ech;
pub mod handshake;

mod tls_stream_auto;
pub use tls_stream_auto::AutoTlsStream;

pub use rama_boring_tokio::SslStream as BoringTlsStream;

mod connector;
#[doc(inline)]
pub use connector::{
    ConnectorKindAuto, ConnectorKindSecure, ConnectorKindTunnel, TlsConnectError, TlsConnector,
    TlsConnectorLayer, tls_connect,
};

mod config;
pub(crate) use config::set_alpn_list_with_coupled_alps;
#[cfg(feature = "http")]
pub(crate) use config::{AlpsCoupling, set_alpn_with_coupled_alps};
#[doc(inline)]
pub use config::{
    BoringAlps, BoringCertCompression, BoringCipherSuites, BoringClientConfigExt,
    BoringClientHelloPadding, BoringDelegatedCredentials, BoringExtensionOrder,
    BoringExtensionPresence, BoringGrease, BoringGreaseSignatureSchemes, BoringKeyShares,
    BoringMaxVersion, BoringMinVersion, BoringOcspStapling, BoringPermuteExtensions,
    BoringRecordSizeLimit, BoringServerPaddingRequest, BoringServerVerifyCertStore,
    BoringSignatureSchemes, BoringSignedCertTimestamps, BoringSupportedGroups,
    BoringTls12SessionTickets, BoringTlsConnectorConfig,
};

mod trust_anchors;
#[doc(inline)]
pub use trust_anchors::BoringRequestedTrustAnchors;

mod session;
#[doc(inline)]
pub use session::{
    TlsClientSession, TlsClientSessionCache, TlsClientSessionDomain, TlsClientSessionKey,
    TlsClientSessionStore,
};

mod server_answer;
#[doc(inline)]
pub use server_answer::{AnswerMirror, ServerAnswerRecorder};

mod connector_data;
pub(crate) type BoringServerVerification = rama_core::combinators::Either<
    std::sync::Arc<rama_boring::x509::store::X509Store>,
    std::sync::Arc<rama_crypto::platform_verifier::PlatformVerifier>,
>;

mod verify;
#[doc(inline)]
pub use connector_data::{
    ConnectorConfigClientAuth, TlsConnectorContext, TlsConnectorContextBuilder, TlsConnectorData,
};

#[cfg(feature = "ua")]
pub mod profile;

pub use config::BoringTlsClientConfigProvider;

#[cfg(test)]
pub(crate) mod tests;
