//! The identities and the Rama-side configurations every scenario uses. A peer's own
//! configuration is its adapter's business; what is shared is the identity it presents or
//! trusts, and the protocol both ends must agree on.

use std::net::Ipv4Addr;

use rama::{
    crypto::{
        cert::{CertificateIdentity, CertificateSubject, LeafCertRequest, SelfSignedCaConfig},
        pki_types::CertificateDer,
    },
    net::tls::ApplicationProtocol,
    quic::{ClientConfig, ServerConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::collections::smallvec::smallvec,
};

/// The protocol every shared scenario negotiates. A handshake that settles on anything else is
/// a failure, not a variant.
pub const ALPN: &[u8] = b"rama-quic-interop";

/// One generated identity: whichever side is the server presents it, and the other trusts it.
pub type Identity = ServerAuthData;

#[must_use]
pub fn alpn() -> ApplicationProtocol {
    ApplicationProtocol::from(ALPN)
}

#[must_use]
pub fn server_identity() -> Identity {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("an identity is generated")
}

/// An identity issued by a certificate authority with a name of its own, so a peer trusting
/// another anchor finds no issuer for it.
#[must_use]
pub fn identity_from_a_stranger(issuer: &str) -> Identity {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: SelfSignedCaConfig {
            subject: CertificateSubject {
                organisation_name: Some(issuer.to_owned()),
                common_name: Some(issuer.to_owned()),
            },
            ..Default::default()
        },
        leaf: LeafCertRequest::default(),
    })
    .expect("an identity is generated")
}

/// An identity valid for the loopback address, so a client may name the address it connects to.
#[must_use]
pub fn address_identity() -> Identity {
    ServerAuthData::new_self_signed_leaf(LeafCertRequest::new(CertificateIdentity::Ip(
        Ipv4Addr::LOCALHOST.into(),
    )))
    .expect("an identity is generated")
}

/// The anchor a peer has to trust to accept `identity`.
#[must_use]
pub fn anchor_of(identity: &Identity) -> CertificateDer<'static> {
    identity.cert_chain.last().expect("a chain").clone()
}

#[must_use]
pub fn rama_server_config(identity: &Identity) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![alpn()])
        .with_server_auth(identity.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

#[must_use]
pub fn rama_client_config(anchor: CertificateDer<'static>) -> ClientConfig {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![alpn()])
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the client config is built")
}
