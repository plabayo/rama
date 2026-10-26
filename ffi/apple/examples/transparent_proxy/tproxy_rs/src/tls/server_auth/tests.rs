use super::*;
use rama::{
    crypto::cert::{GeneratedServerAuthConfig, generate_server_auth},
    tls::{
        boring::core::x509::X509,
        client::{
            ServerCertChain, ServerCertChainKind, ServerChainCertificate, ServerTrustSource,
            TlsServerTrust, TlsServerVerify,
        },
    },
};

fn check(certificates: &[CertificateDer<'_>], kind: ServerCertChainKind) -> bool {
    let entries: Vec<_> = certificates
        .iter()
        .cloned()
        .map(ServerChainCertificate::certificate)
        .collect();
    DENIED_KEYS
        .check(&ServerCertChain::new(kind, None, &entries))
        .is_ok()
}

#[test]
fn blocks_all_incident_keys_and_cross_signs() {
    // Both files are public certificates from Mozilla bug 2083449, attachments
    // 9664066 and 9664067. No real compromised private key is a test fixture.
    let originals = X509::stack_from_pem(include_bytes!("../../../testdata/emudhra.pem")).unwrap();
    let cross =
        X509::stack_from_pem(include_bytes!("../../../testdata/emudhra-cross-signed.pem")).unwrap();
    assert_eq!(originals.len(), 8);
    assert_eq!(cross.len(), 8);
    let source_fingerprints = [
        "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
        "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
        "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
        "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
        "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",
        "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",
        "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
        "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
    ];
    for ((original, cross), fingerprint) in originals.iter().zip(&cross).zip(source_fingerprints) {
        let original = CertificateDer::from(original.to_der().unwrap());
        assert_eq!(
            rama::utils::fmt::hex(&rama::tls::boring::core::sha::sha256(&original)).to_string(),
            fingerprint
        );
        let cross = CertificateDer::from(cross.to_der().unwrap());
        assert_ne!(original, cross);
        assert_eq!(
            rama::crypto::cert::spki_sha256(&original).unwrap(),
            rama::crypto::cert::spki_sha256(&cross).unwrap()
        );
        for kind in [
            ServerCertChainKind::Presented,
            ServerCertChainKind::Verified,
        ] {
            assert!(!check(std::slice::from_ref(&original), kind));
            assert!(!check(std::slice::from_ref(&cross), kind));
        }
    }
}

#[test]
fn denied_test_ca_is_distinct_from_an_allowed_private_ca() {
    let denied =
        CertificateDer::from_pem_slice(include_bytes!("../../../testdata/denied-ca.pem")).unwrap();
    let (allowed, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    assert!(check(&allowed, ServerCertChainKind::Presented));
    let mut presented = allowed.clone();
    presented.push(denied);
    assert!(!check(&presented, ServerCertChainKind::Presented));
    // Disabled verification cannot discover a withheld issuer.
    assert!(check(&allowed[..1], ServerCertChainKind::Presented));
}

#[test]
fn both_modes_keep_the_chain_policy_and_only_opt_in_uses_the_platform() {
    let mut auth = DemoServerAuth::new(&crate::config::DemoProxyConfig::default()).unwrap();
    assert!(!auth.verify);
    for enabled in [false, true, false] {
        auth.verify = enabled;
        let config = auth.quic(KeyLogIntent::Disabled).unwrap();
        assert!(
            config
                .as_extensions()
                .contains::<DynTlsServerCertChainPolicy>()
        );
        assert_eq!(
            config
                .as_extensions()
                .get_ref::<TlsServerVerify>()
                .unwrap()
                .0,
            if enabled {
                ServerVerifyMode::Auto
            } else {
                ServerVerifyMode::Disable
            }
        );
        if enabled {
            assert!(matches!(
                config
                    .as_extensions()
                    .get_ref::<TlsServerTrust>()
                    .unwrap()
                    .source(),
                ServerTrustSource::Platform
            ));
        }
        auth.tcp().unwrap();
    }
}
