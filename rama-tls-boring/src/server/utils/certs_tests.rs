use super::*;

use crate::core::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::Id,
    x509::{
        X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
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

fn build_source_with_ski_only(
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
    common_name: &str,
) -> Result<(X509, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(2048).context("generate source rsa")?;
    let privkey = PKey::from_rsa(rsa).context("source pkey")?;

    let mut x509_name = X509NameBuilder::new().context("source name builder")?;
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .context("source cn")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().context("source builder")?;
    cert_builder.set_version(2).context("source version")?;
    let serial_number = {
        let mut serial = BigNum::new().context("source serial bn")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("source serial rand")?;
        serial.to_asn1_integer().context("source serial asn1")?
    };
    cert_builder
        .set_serial_number(&serial_number)
        .context("source serial")?;
    cert_builder
        .set_subject_name(&x509_name)
        .context("source subject")?;
    cert_builder
        .set_issuer_name(ca_cert.subject_name())
        .context("source issuer")?;
    cert_builder.set_pubkey(&privkey).context("source pubkey")?;
    let not_before = Asn1Time::days_from_now(0).context("source nb")?;
    cert_builder
        .set_not_before(&not_before)
        .context("source set nb")?;
    let not_after = Asn1Time::days_from_now(30).context("source na")?;
    cert_builder
        .set_not_after(&not_after)
        .context("source set na")?;

    let san = SubjectAlternativeName::new()
        .dns(common_name)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("source san")?;
    cert_builder
        .append_extension(san.as_ref())
        .context("append source san")?;

    let ski = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("source ski")?;
    cert_builder
        .append_extension(ski.as_ref())
        .context("append source ski")?;

    cert_builder
        .sign(ca_privkey, MessageDigest::sha256())
        .context("sign source")?;

    Ok((cert_builder.build(), privkey))
}

fn build_ca_without_ski(common_name: &str) -> Result<(X509, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(2048).context("ca rsa")?;
    let privkey = PKey::from_rsa(rsa).context("ca pkey")?;

    let mut x509_name = X509NameBuilder::new().context("ca name builder")?;
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .context("ca cn")?;
    let x509_name = x509_name.build();

    let mut ca_cert_builder = X509::builder().context("ca builder")?;
    ca_cert_builder.set_version(2).context("ca version")?;
    let serial_number = {
        let mut serial = BigNum::new().context("ca serial bn")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("ca serial rand")?;
        serial.to_asn1_integer().context("ca serial asn1")?
    };
    ca_cert_builder
        .set_serial_number(&serial_number)
        .context("ca serial")?;
    ca_cert_builder
        .set_subject_name(&x509_name)
        .context("ca subject")?;
    ca_cert_builder
        .set_issuer_name(&x509_name)
        .context("ca issuer")?;
    ca_cert_builder.set_pubkey(&privkey).context("ca pubkey")?;
    let not_before = Asn1Time::days_from_now(0).context("ca nb")?;
    ca_cert_builder
        .set_not_before(&not_before)
        .context("ca set nb")?;
    let not_after = Asn1Time::days_from_now(365).context("ca na")?;
    ca_cert_builder
        .set_not_after(&not_after)
        .context("ca set na")?;

    ca_cert_builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .context("ca basic constraints")?
                .as_ref(),
        )
        .context("append ca bc")?;
    ca_cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .context("ca key usage")?
                .as_ref(),
        )
        .context("append ca ku")?;

    ca_cert_builder
        .sign(&privkey, MessageDigest::sha256())
        .context("sign ca")?;

    Ok((ca_cert_builder.build(), privkey))
}

#[test]
fn mirror_aki_keyid_matches_ca_ski() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");
    let source_data = sample_data("source.rama.test");
    let (source_cert, _) =
        self_signed_server_auth_gen_cert(&source_data, &ca_cert, &ca_key).expect("source cert");

    let (mirrored_cert, _) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    let ca_ski = ca_cert.subject_key_id().expect("ca has ski");
    let mirror_aki = mirrored_cert.authority_key_id().expect("mirror has aki");
    assert_eq!(mirror_aki.as_slice(), ca_ski.as_slice());
}

#[test]
fn mirror_omits_aki_when_source_has_no_aki() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");

    let (source_cert, _) =
        build_source_with_ski_only(&ca_cert, &ca_key, "ski-only.rama.test").expect("source cert");
    assert!(source_cert.subject_key_id().is_some());
    assert!(source_cert.authority_key_id().is_none());

    let (mirrored_cert, _) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    assert!(mirrored_cert.subject_key_id().is_some());
    assert!(mirrored_cert.authority_key_id().is_none());
}

#[test]
fn mirror_omits_ski_and_aki_when_source_has_neither() {
    let ca_data = sample_data("ca.rama.test");
    let (ca_cert, ca_key) = self_signed_server_auth_gen_ca(&ca_data).expect("generate CA");

    let rsa = Rsa::generate(2048).expect("source rsa");
    let source_pkey = PKey::from_rsa(rsa).expect("source pkey");
    let source_cert = build_self_signed_source_with_pkey(&source_pkey, "no-keyid.rama.test")
        .expect("source cert");
    assert!(source_cert.subject_key_id().is_none());
    assert!(source_cert.authority_key_id().is_none());

    let (mirrored_cert, _) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert");

    assert!(mirrored_cert.subject_key_id().is_none());
    assert!(mirrored_cert.authority_key_id().is_none());
}

#[test]
fn mirror_omits_aki_when_ca_has_no_ski() {
    let (ca_cert, ca_key) = build_ca_without_ski("no-ski-ca.rama.test").expect("ca without ski");
    assert!(ca_cert.subject_key_id().is_none());

    // Source cert (self-signed) with both SKI and AKI present, so mirror would normally re-emit
    // both. The CA-lacks-SKI guard must still kick in and suppress the AKI.
    let rsa = Rsa::generate(2048).expect("source rsa");
    let source_pkey = PKey::from_rsa(rsa).expect("source pkey");
    let mut x509_name = X509NameBuilder::new().expect("source name builder");
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, "with-keyid-source.rama.test")
        .expect("source cn");
    let x509_name = x509_name.build();
    let mut cert_builder = X509::builder().expect("source builder");
    cert_builder.set_version(2).expect("source version");
    let serial = {
        let mut serial = BigNum::new().expect("source serial bn");
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .expect("source serial rand");
        serial.to_asn1_integer().expect("source serial asn1")
    };
    cert_builder
        .set_serial_number(&serial)
        .expect("source serial");
    cert_builder
        .set_subject_name(&x509_name)
        .expect("source subject");
    cert_builder
        .set_issuer_name(&x509_name)
        .expect("source issuer");
    cert_builder
        .set_pubkey(&source_pkey)
        .expect("source pubkey");
    cert_builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("source nb"))
        .expect("source set nb");
    cert_builder
        .set_not_after(&Asn1Time::days_from_now(30).expect("source na"))
        .expect("source set na");
    let ski = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .expect("source ski");
    cert_builder
        .append_extension(ski.as_ref())
        .expect("append source ski");
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&cert_builder.x509v3_context(None, None))
        .expect("source aki");
    cert_builder
        .append_extension(aki.as_ref())
        .expect("append source aki");
    cert_builder
        .sign(&source_pkey, MessageDigest::sha256())
        .expect("sign source");
    let source_cert = cert_builder.build();
    assert!(source_cert.subject_key_id().is_some());
    assert!(source_cert.authority_key_id().is_some());

    let (mirrored_cert, _) =
        self_signed_server_auth_mirror_cert(source_cert.as_ref(), &ca_cert, &ca_key)
            .expect("mirror cert succeeds despite CA lacking SKI");

    assert!(mirrored_cert.subject_key_id().is_some());
    assert!(mirrored_cert.authority_key_id().is_none());
}

#[test]
fn gen_cert_omits_aki_when_ca_has_no_ski() {
    let (ca_cert, ca_key) = build_ca_without_ski("no-ski-ca.rama.test").expect("ca without ski");
    assert!(ca_cert.subject_key_id().is_none());

    let leaf_data = sample_data("leaf.rama.test");
    let (leaf_cert, _) =
        self_signed_server_auth_gen_cert(&leaf_data, &ca_cert, &ca_key).expect("generate leaf");

    assert!(leaf_cert.subject_key_id().is_some());
    assert!(leaf_cert.authority_key_id().is_none());
    assert_eq!(ca_cert.issued(&leaf_cert), Ok(()));
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
