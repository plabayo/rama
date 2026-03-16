use super::*;

use crate::core::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::Id,
    x509::X509NameBuilder,
};
use rama_net::{address::Domain, tls::server::SelfSignedData};

fn sample_data(common_name: &'static str) -> SelfSignedData {
    SelfSignedData {
        common_name: Some(Domain::from_static(common_name)),
        organisation_name: Some("Rama Test".to_owned()),
        ..Default::default()
    }
}

fn ext_by_nid(cert: &X509Ref, nid: Nid) -> Vec<&crate::core::x509::X509ExtensionRef> {
    cert.extensions()
        .filter(|ext| ext.object().nid() == nid)
        .collect()
}

fn build_self_signed_source_with_pkey(
    pkey: &PKey<Private>,
    common_name: &str,
) -> Result<X509, BoxError> {
    let mut x509_name = X509NameBuilder::new().context("create x509 name builder")?;
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .context("append common name to x509 name builder")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().context("create x509 cert builder")?;
    cert_builder
        .set_version(2)
        .context("set version on source cert")?;
    let serial_number = {
        let mut serial = BigNum::new().context("create source serial big num")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("randomise source serial")?;
        serial
            .to_asn1_integer()
            .context("convert source serial to asn1 integer")?
    };
    cert_builder
        .set_serial_number(&serial_number)
        .context("set source serial number")?;
    cert_builder
        .set_subject_name(&x509_name)
        .context("set source subject")?;
    cert_builder
        .set_issuer_name(&x509_name)
        .context("set source issuer")?;
    cert_builder
        .set_pubkey(pkey)
        .context("set source public key")?;
    let not_before = Asn1Time::days_from_now(0).context("source not before")?;
    cert_builder
        .set_not_before(&not_before)
        .context("set source not before")?;
    let not_after = Asn1Time::days_from_now(30).context("source not after")?;
    cert_builder
        .set_not_after(&not_after)
        .context("set source not after")?;

    let san = SubjectAlternativeName::new()
        .dns(common_name)
        .build(&cert_builder.x509v3_context(None, None))
        .context("build source san")?;
    cert_builder
        .append_extension(san.as_ref())
        .context("append source san")?;

    cert_builder
        .sign(pkey, MessageDigest::sha256())
        .context("sign source cert")?;

    Ok(cert_builder.build())
}

#[test]
fn gen_ca_basics() {
    let data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&data).expect("generate CA");

    assert_eq!(ca_key.id(), Id::RSA);
    assert!(ca_cert.verify(&ca_key).expect("verify self-signed ca cert"));
    assert_eq!(
        ca_cert.subject_name().to_der().expect("ca subject der"),
        ca_cert.issuer_name().to_der().expect("ca issuer der")
    );

    let basic_constraints = ext_by_nid(ca_cert.as_ref(), Nid::BASIC_CONSTRAINTS);
    assert_eq!(basic_constraints.len(), 1);
    assert!(basic_constraints[0].critical());
    let key_usage = ext_by_nid(ca_cert.as_ref(), Nid::KEY_USAGE);
    assert_eq!(key_usage.len(), 1);
    assert!(key_usage[0].critical());
}

#[test]
fn gen_leaf_signed_by_ca_and_has_common_name_san() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");

    let leaf_data = sample_data("leaf.rama.test");
    let (leaf_cert, leaf_key) =
        self_signed_server_auth_gen_cert(&leaf_data, &ca_cert, &ca_key).expect("generate leaf");

    assert_eq!(leaf_key.id(), Id::RSA);
    assert_eq!(ca_cert.issued(&leaf_cert), Ok(()));
    assert_eq!(
        leaf_cert.issuer_name().to_der().expect("leaf issuer der"),
        ca_cert.subject_name().to_der().expect("ca subject der")
    );

    let cn = leaf_cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("leaf common name");
    assert_eq!(
        cn.data()
            .as_utf8()
            .expect("leaf common name utf8")
            .to_string(),
        "leaf.rama.test"
    );

    let san = leaf_cert.subject_alt_names().expect("leaf SAN");
    assert!(
        san.iter()
            .any(|name| name.dnsname() == Some("leaf.rama.test"))
    );
}

#[test]
fn mirror_preserves_subject_validity_and_issuer() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");
    let source_data = sample_data("source.rama.test");
    let (source_cert, _) =
        self_signed_server_auth_gen_cert(&source_data, &ca_cert, &ca_key).expect("source cert");

    let (mirrored_cert, mirrored_key) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    assert_eq!(ca_cert.issued(&mirrored_cert), Ok(()));
    assert_eq!(
        source_cert
            .subject_name()
            .to_der()
            .expect("source subject der"),
        mirrored_cert
            .subject_name()
            .to_der()
            .expect("mirrored subject der")
    );
    assert_eq!(source_cert.not_before(), mirrored_cert.not_before());
    assert_eq!(source_cert.not_after(), mirrored_cert.not_after());
    assert_eq!(
        mirrored_cert
            .issuer_name()
            .to_der()
            .expect("mirrored issuer der"),
        ca_cert.subject_name().to_der().expect("ca subject der")
    );
    assert_eq!(mirrored_key.id(), Id::RSA);
}

#[test]
fn mirror_copies_extensions_and_regenerates_key_ids() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");
    let source_data = sample_data("source.rama.test");
    let (source_cert, _) =
        self_signed_server_auth_gen_cert(&source_data, &ca_cert, &ca_key).expect("source cert");
    let (mirrored_cert, _) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    let source_exts: Vec<_> = source_cert.extensions().collect();
    let mirrored_exts: Vec<_> = mirrored_cert.extensions().collect();

    for source_ext in source_exts {
        let nid = source_ext.object().nid();
        if nid == Nid::SUBJECT_KEY_IDENTIFIER || nid == Nid::AUTHORITY_KEY_IDENTIFIER {
            continue;
        }
        let found = mirrored_exts.iter().any(|mirrored_ext| {
            mirrored_ext.object().nid() == nid
                && mirrored_ext.critical() == source_ext.critical()
                && mirrored_ext.data().as_slice() == source_ext.data().as_slice()
        });
        assert!(found, "missing mirrored extension for nid={nid:?}");
    }

    let source_skid = ext_by_nid(source_cert.as_ref(), Nid::SUBJECT_KEY_IDENTIFIER);
    let mirror_skid = ext_by_nid(mirrored_cert.as_ref(), Nid::SUBJECT_KEY_IDENTIFIER);
    assert_eq!(source_skid.len(), 1);
    assert_eq!(mirror_skid.len(), 1);
    assert_ne!(
        source_skid[0].data().as_slice(),
        mirror_skid[0].data().as_slice()
    );

    let source_akid = ext_by_nid(source_cert.as_ref(), Nid::AUTHORITY_KEY_IDENTIFIER);
    let mirror_akid = ext_by_nid(mirrored_cert.as_ref(), Nid::AUTHORITY_KEY_IDENTIFIER);
    assert_eq!(source_akid.len(), 1);
    assert_eq!(mirror_akid.len(), 1);
}

#[test]
fn mirror_uses_ec_key_for_ec_source() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("ec group");
    let ec_key = EcKey::generate(&group).expect("generate ec key");
    let source_key = PKey::from_ec_key(ec_key).expect("pkey from ec key");
    let source_cert = build_self_signed_source_with_pkey(&source_key, "ec-source.rama.test")
        .expect("source cert");

    let (_, mirrored_key) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    assert_eq!(mirrored_key.id(), Id::EC);
}
