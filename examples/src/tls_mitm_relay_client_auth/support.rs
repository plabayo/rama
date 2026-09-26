//! Ephemeral PKI and CLI setup for the demo; the policy lives in the main file.

use rama::{
    crypto::{
        cert::{
            LeafCertRequest, SelfSignedCaConfig,
            boring::{generate_certificate_authority_x509, issue_leaf_certificate},
        },
        pki_types::CertificateDer,
    },
    error::BoxError,
    net::address::Host,
    tls::{
        KeyLogIntent,
        boring::{
            client::{ConnectorConfigClientAuth, TlsConnectorData},
            core::{
                asn1::Asn1Time,
                bn::{BigNum, MsbOption},
                ec::{EcGroup, EcKey},
                hash::MessageDigest,
                nid::Nid,
                pkey::{PKey, Private},
                ssl::{SslAcceptor, SslCredential, SslMethod, SslVerifyMode, SslVersion},
                x509::{
                    X509, X509Name,
                    extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
                    store::{X509Store, X509StoreBuilder},
                },
            },
        },
        client::{ServerVerifyMode, TlsClientConfig},
    },
};

use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum Client {
    Trusted,
    Missing,
    Unmapped,
    Untrusted,
}

#[derive(Parser)]
#[command(about = "Map ingress mTLS to an upstream identity in a local TLS exchange")]
pub(super) struct Options {
    /// Use TLS 1.2 instead of TLS 1.3 on both legs.
    #[arg(long)]
    tls12: bool,
    /// Still require ingress authentication when upstream requests none.
    #[arg(long)]
    no_upstream_auth: bool,
    /// Select the client identity; only trusted completes the exchange.
    #[arg(long, value_enum, default_value = "trusted")]
    pub(super) client: Client,
}

impl Options {
    pub(super) fn version(&self) -> SslVersion {
        if self.tls12 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        }
    }

    pub(super) fn upstream_auth(&self) -> bool {
        !self.no_upstream_auth
    }
}

pub(super) struct Identity {
    pub(super) cert: X509,
    pub(super) key: PKey<Private>,
}

impl Identity {
    fn ca() -> Result<Self, BoxError> {
        let (cert, key) = generate_certificate_authority_x509(&SelfSignedCaConfig::default())?;
        Ok(Self { cert, key })
    }

    fn server(ca: &Self) -> Result<Self, BoxError> {
        let (cert, key) = issue_leaf_certificate(&LeafCertRequest::default(), &ca.cert, &ca.key)?;
        Ok(Self { cert, key })
    }

    fn client(name: &str, ca: &Self) -> Result<Self, BoxError> {
        // Rama's leaf issuer generates server-auth certificates; clients need clientAuth EKU.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name_builder = X509Name::builder()?;
        name_builder.append_entry_by_text("CN", name)?;
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
        cert.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
        cert.set_subject_name(&name_builder.build())?;
        cert.set_issuer_name(ca.cert.subject_name())?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        cert.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        cert.append_extension(BasicConstraints::new().critical().build()?.as_ref())?;
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()?
                .as_ref(),
        )?;
        cert.append_extension(ExtendedKeyUsage::new().client_auth().build()?.as_ref())?;
        cert.sign(&ca.key, MessageDigest::sha256())?;
        Ok(Self {
            cert: cert.build(),
            key,
        })
    }

    pub(super) fn credential(&self) -> Result<SslCredential, BoxError> {
        ConnectorConfigClientAuth {
            cert_chain: vec![self.cert.clone()],
            private_key: self.key.clone(),
        }
        .try_into()
    }

    pub(super) fn trust_store(&self) -> Result<X509Store, BoxError> {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(self.cert.clone())?;
        Ok(store.build())
    }
}

pub(super) struct DemoCertificates {
    pub(super) ingress_ca: Identity,
    server_ca: Identity,
    egress_ca: Identity,
    origin: Identity,
    pub(super) relay: Identity,
    pub(super) client: Identity,
    pub(super) mapped: Identity,
}

impl DemoCertificates {
    pub(super) fn new() -> Result<Self, BoxError> {
        let ingress_ca = Identity::ca()?;
        let server_ca = Identity::ca()?;
        let egress_ca = Identity::ca()?;
        Ok(Self {
            origin: Identity::server(&server_ca)?,
            relay: Identity::server(&server_ca)?,
            client: Identity::client("trusted-client", &ingress_ca)?,
            mapped: Identity::client("mapped-client", &egress_ca)?,
            ingress_ca,
            server_ca,
            egress_ca,
        })
    }

    pub(super) fn client_credential(
        &self,
        client: Client,
    ) -> Result<Option<SslCredential>, BoxError> {
        match client {
            Client::Trusted => self.client.credential().map(Some),
            Client::Missing => Ok(None),
            Client::Unmapped => Identity::client("unmapped-client", &self.ingress_ca)?
                .credential()
                .map(Some),
            Client::Untrusted => Identity::client("untrusted-client", &Identity::ca()?)?
                .credential()
                .map(Some),
        }
    }

    pub(super) fn connector(&self, version: SslVersion) -> Result<TlsConnectorData, BoxError> {
        let config = TlsClientConfig::new()
            .with_server_name(Host::from_static("localhost"))
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([CertificateDer::from(self.server_ca.cert.to_der()?)])?
            .with_keylog(KeyLogIntent::Disabled);
        let mut data = TlsConnectorData::try_from(&config)?;
        data.config.set_min_proto_version(Some(version))?;
        data.config.set_max_proto_version(Some(version))?;
        Ok(data)
    }

    pub(super) fn origin_acceptor(&self, options: &Options) -> Result<SslAcceptor, BoxError> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        acceptor.set_min_proto_version(Some(options.version()))?;
        acceptor.set_max_proto_version(Some(options.version()))?;
        acceptor.set_certificate(&self.origin.cert)?;
        acceptor.set_private_key(&self.origin.key)?;
        acceptor.set_cert_store(self.egress_ca.trust_store()?);
        acceptor.set_verify(if options.upstream_auth() {
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            SslVerifyMode::NONE
        });
        Ok(acceptor.build())
    }
}
