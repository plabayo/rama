//! The identities and the Rama-side configurations every scenario uses. A peer's own
//! configuration is its adapter's business; what is shared is the identity it presents or
//! trusts, and the protocol both ends must agree on.

use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use rama::{
    crypto::{
        cert::{CertificateIdentity, CertificateSubject, LeafCertRequest, SelfSignedCaConfig},
        dep::rcgen,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
    net::{address::Domain, tls::ApplicationProtocol},
    quic::{ClientConfig, ServerConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, fs::TempDir},
};

use crate::scenario::{ANOTHER_NAME, SERVER_NAME};

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

/// An identity for a name that is not the one a case asks for, for the same-type name
/// mismatch.
#[must_use]
pub fn another_named_identity() -> Identity {
    ServerAuthData::new_self_signed_leaf(LeafCertRequest::new(CertificateIdentity::Dns(
        Domain::from_static(ANOTHER_NAME),
    )))
    .expect("an identity is generated")
}

/// An identity for a loopback address that is not the one a peer binds, for the same-type
/// address mismatch.
#[must_use]
pub fn another_address_identity() -> Identity {
    ServerAuthData::new_self_signed_leaf(LeafCertRequest::new(CertificateIdentity::Ip(
        Ipv4Addr::new(127, 0, 0, 2).into(),
    )))
    .expect("an identity is generated")
}

/// An identity valid for the loopback address, so a client may name the address it connects
/// to.
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

/// One identity of an issued pair: the material Rama's own side uses, and the same material on
/// disk for a peer that reads PEM files.
#[derive(Debug)]
pub struct IssuedIdentity {
    pub auth: Identity,
    pub certificate: PathBuf,
    pub key: PathBuf,
}

/// Two identities issued by one authority: one carrying the name, one carrying the loopback
/// address.
///
/// A case that swaps one for the other changes only what identity the certificate carries. The
/// issuer stays the same, so a client's trust configuration is untouched between the two and a
/// refusal cannot be the issuer check in disguise.
#[derive(Debug)]
pub struct IssuedIdentities {
    /// Held so the files live as long as the identities do.
    directory: TempDir,
    /// The authority both identities chain to, in PEM, for a peer that trusts a file.
    pub authority: PathBuf,
    /// The same anchor for a peer configured in memory.
    pub anchor: CertificateDer<'static>,
    pub for_name: IssuedIdentity,
    pub for_address: IssuedIdentity,
    /// A second name and a second address, for the same-type mismatches.
    pub for_another_name: IssuedIdentity,
    pub for_another_address: IssuedIdentity,
}

impl IssuedIdentities {
    /// Generate the authority and both identities.
    #[must_use]
    pub fn generate() -> Self {
        let directory =
            TempDir::with_prefix("rama-quic-interop-issued-").expect("a directory of our own");
        let authority_key = rcgen::KeyPair::generate().expect("a key pair");
        let mut authority = rcgen::CertificateParams::default();
        authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        authority.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        authority.distinguished_name = {
            let mut name = rcgen::DistinguishedName::new();
            name.push(rcgen::DnType::CommonName, "rama quic interop issuer");
            name
        };
        let authority_cert = authority
            .self_signed(&authority_key)
            .expect("the authority is generated");
        let issuer = rcgen::Issuer::from_params(&authority, &authority_key);
        let authority_pem = authority_cert.pem();
        let authority_path = directory.path().join("issuer.pem");
        fs::write(&authority_path, &authority_pem).expect("the authority is written");

        let for_name = Self::issue(
            directory.path(),
            "name",
            rcgen::SanType::DnsName(SERVER_NAME.try_into().expect("the name fits a certificate")),
            &issuer,
            &authority_pem,
            authority_cert.der(),
        );
        let for_address = Self::issue(
            directory.path(),
            "address",
            rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()),
            &issuer,
            &authority_pem,
            authority_cert.der(),
        );
        let for_another_name = Self::issue(
            directory.path(),
            "another-name",
            rcgen::SanType::DnsName(
                ANOTHER_NAME
                    .try_into()
                    .expect("the name fits a certificate"),
            ),
            &issuer,
            &authority_pem,
            authority_cert.der(),
        );
        let for_another_address = Self::issue(
            directory.path(),
            "another-address",
            rcgen::SanType::IpAddress(Ipv4Addr::new(127, 0, 0, 2).into()),
            &issuer,
            &authority_pem,
            authority_cert.der(),
        );
        let issued = Self {
            directory,
            authority: authority_path,
            anchor: authority_cert.der().clone(),
            for_name,
            for_address,
            for_another_name,
            for_another_address,
        };
        for other in [
            &issued.for_address,
            &issued.for_another_name,
            &issued.for_another_address,
        ] {
            assert_eq!(
                anchor_of(&issued.for_name.auth),
                anchor_of(&other.auth),
                "every identity chains to the one authority"
            );
        }
        issued
    }

    /// One leaf under the authority, written out with its chain so a peer that reads the file
    /// serves the authority alongside the leaf.
    fn issue(
        directory: &Path,
        which: &str,
        identity: rcgen::SanType,
        issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
        authority_pem: &str,
        authority_der: &CertificateDer<'static>,
    ) -> IssuedIdentity {
        let key = rcgen::KeyPair::generate().expect("a key pair");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![identity];
        let certificate = params
            .signed_by(&key, issuer)
            .expect("the leaf is issued under the authority");
        let certificate_path = directory.join(format!("{which}.pem"));
        let key_path = directory.join(format!("{which}-key.pem"));
        fs::write(
            &certificate_path,
            format!("{}{authority_pem}", certificate.pem()),
        )
        .expect("the chain is written");
        fs::write(&key_path, key.serialize_pem()).expect("the key is written");
        IssuedIdentity {
            // rcgen serialises the key as PKCS#8, so it is named as such rather than guessed at.
            auth: Identity::new(
                vec![certificate.der().clone(), authority_der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            ),
            certificate: certificate_path,
            key: key_path,
        }
    }

    /// The directory the files are in, for a peer that needs to name it.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
}

/// A path as a peer's own API wants it.
#[must_use]
pub fn path_of(path: &Path) -> &str {
    path.to_str().expect("a printable path")
}
