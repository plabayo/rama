use crate::core::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama_tls::{client::ClientAuthData, server::SelfSignedCaConfig};

mod e2e;

/// A CA root plus a client identity it issued.
pub(crate) fn client_identity() -> (CertificateDer<'static>, ClientAuthData) {
    let (ca, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
        &SelfSignedCaConfig::default(),
    )
    .unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Rama test client").unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name.build()).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    cert.append_extension(&KeyUsage::new().digital_signature().build().unwrap())
        .unwrap();
    cert.append_extension(&ExtendedKeyUsage::new().client_auth().build().unwrap())
        .unwrap();
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let root = CertificateDer::from(ca.to_der().unwrap());
    (
        root.clone(),
        ClientAuthData {
            cert_chain: vec![CertificateDer::from(cert.build().to_der().unwrap()), root],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                key.private_key_to_der_pkcs8().unwrap(),
            )),
        },
    )
}
