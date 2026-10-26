use crate::harness::{Test, ensure};
use rama_crypto::{
    pki_types::CertificateDer,
    platform_verifier::{PlatformVerifier, PlatformVerifyErrorKind},
};
use rama_net::address::Host;
use rama_tls_boring::{
    core::{pkey::PKey, x509::X509},
    server::utils::{MitmLeafOcspStatus, build_mitm_leaf_ocsp_response},
};
use std::time::SystemTime;

pub(crate) static TESTS: &[Test] = &[
    (
        "trusted_intermediate_with_staples",
        trusted_intermediate_with_staples,
    ),
    (
        "trusted_leaf_is_not_revalidated_as_a_path",
        trusted_leaf_is_not_revalidated_as_a_path,
    ),
];

fn ca_params(name: &str) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
}

fn sdk_level() -> Result<i32, String> {
    let context = ndk_context::android_context();
    // SAFETY: initialized by JNI_OnLoad; Android owns the VM for the process.
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) };
    vm.attach_current_thread(|env| {
        env.get_static_field(
            jni::jni_str!("android/os/Build$VERSION"),
            jni::jni_str!("SDK_INT"),
            jni::jni_sig!("I"),
        )?
        .i()
    })
    .map_err(|e: jni::errors::Error| e.to_string())
}

fn trusted_intermediate_with_staples() -> Result<(), String> {
    let run = || -> Result<(), rama_core::error::BoxError> {
        let root_params = ca_params("Rama test root");
        let root_key = rcgen::KeyPair::generate()?;
        let root = root_params.self_signed(&root_key)?;
        let root_issuer = rcgen::Issuer::new(root_params, root_key);
        let issuer_params = ca_params("Rama trusted intermediate");
        let issuer_key = rcgen::KeyPair::generate()?;
        let intermediate = issuer_params.signed_by(&issuer_key, &root_issuer)?;
        let signing_key = PKey::private_key_from_der(&issuer_key.serialize_der())?;
        let issuer = rcgen::Issuer::new(issuer_params, issuer_key);
        let mut leaf_params = rcgen::CertificateParams::new(vec!["leaf.rama.test".to_owned()])?;
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params.signed_by(&rcgen::KeyPair::generate()?, &issuer)?;
        let leaf_x509 = X509::from_der(leaf.der())?;
        let issuer_x509 = X509::from_der(intermediate.der())?;
        let good = build_mitm_leaf_ocsp_response(
            &leaf_x509,
            &issuer_x509,
            &signing_key,
            MitmLeafOcspStatus::Good,
        )?;
        let revoked = build_mitm_leaf_ocsp_response(
            &leaf_x509,
            &issuer_x509,
            &signing_key,
            MitmLeafOcspStatus::Revoked {
                revocation_time: SystemTime::now() - std::time::Duration::from_hours(2),
            },
        )?;
        let sdk = sdk_level()?;
        for both in [false, true] {
            let mut roots: Vec<CertificateDer<'static>> = vec![intermediate.der().clone()];
            if both {
                roots.push(root.der().clone());
            }
            let verifier = PlatformVerifier::try_with_extra_roots(roots)?;
            let host = Host::from_static("leaf.rama.test");
            verifier.verify_server_chain(leaf.der(), &[], &host, Some(&good), SystemTime::now())?;
            let result = verifier.verify_server_chain(
                leaf.der(),
                &[],
                &host,
                Some(&revoked),
                SystemTime::now(),
            );
            if sdk >= 24 {
                ensure(
                    verifier
                        .verify_server_chain(
                            leaf.der(),
                            &[],
                            &host,
                            Some(&good),
                            SystemTime::now() - std::time::Duration::from_hours(48),
                        )
                        .is_err(),
                    "staple thisUpdate ignored supplied verification time",
                )?;
                ensure(
                    result.is_err_and(|e| e.kind() == PlatformVerifyErrorKind::Revoked),
                    format!(
                        "API {sdk}: revoked staple accepted or misclassified; both anchors={both}"
                    ),
                )?;
                ensure(
                    verifier
                        .verify_server_chain(
                            leaf.der(),
                            &[],
                            &host,
                            Some(&[1, 2, 3]),
                            SystemTime::now(),
                        )
                        .is_err(),
                    "malformed staple accepted",
                )?;
            } else {
                ensure(
                    result.is_ok(),
                    "API 23 should retain its documented lack of supplementary revocation",
                )?;
            }
        }
        Ok(())
    };
    run().map_err(|e| format!("{e:?}"))
}

fn trusted_leaf_is_not_revalidated_as_a_path() -> Result<(), String> {
    let run = || -> Result<(), rama_core::error::BoxError> {
        let params = rcgen::CertificateParams::new(vec!["leaf.rama.test".to_owned()])?;
        let leaf = params.self_signed(&rcgen::KeyPair::generate()?)?;
        let verifier = PlatformVerifier::try_with_extra_roots([leaf.der().clone()])?;
        let chain = verifier.verify_server_chain(
            leaf.der(),
            &[],
            &Host::from_static("leaf.rama.test"),
            Some(&[1, 2, 3]),
            SystemTime::now(),
        )?;
        ensure(
            chain == [leaf.der().clone()],
            "trusted leaf must be the entire path",
        )?;
        Ok(())
    };
    run().map_err(|e| format!("{e:?}"))
}
