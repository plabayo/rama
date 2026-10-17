use super::*;
use rama_ua::profile::selection::database::UserAgentDatabase;

#[tokio::test]
async fn emulated_profiles_resume_without_changing_their_hello() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    for profile in db.iter() {
        let tls = profile.tls.as_ref().unwrap();
        let mut emulated = TlsClientConfig::new_from_client_hello(&tls.client_hello);
        if tls.permute_extensions {
            emulated.set_permute_extensions(true);
        }
        let server = Server::new(SslVersion::TLS1_3);
        let connector = connector(&server, Some(cache()));
        let request = |extensions: &Extensions| emulated.write_to(extensions);
        let fresh = connect_hello(&connector, &server, request).await;
        let resumed = connect_hello(&connector, &server, request).await;
        assert!(!offers_session(&fresh), "{:?}", profile.ua_str());
        assert!(offers_session(&resumed), "{:?}", profile.ua_str());
        let psk = ExtensionId::PRE_SHARED_KEY;
        assert_eq!(resumed.extensions().last().map(|ext| ext.id()), Some(psk));
        let shape = |hello: &ClientHello| -> Vec<u16> {
            hello
                .extensions()
                .iter()
                .map(|ext| ext.id())
                .filter(|id| !id.is_grease() && *id != psk && *id != ExtensionId::PADDING)
                .map(u16::from)
                .collect()
        };
        let (mut fresh, mut resumed) = (shape(&fresh), shape(&resumed));
        if tls.permute_extensions {
            fresh.sort_unstable();
            resumed.sort_unstable();
        }
        assert_eq!(fresh, resumed, "{:?}", profile.ua_str());
    }
}

#[tokio::test]
async fn different_drawn_orders_resume_within_one_profile_scope() {
    let server = Server::new(SslVersion::TLS1_3);
    let connector = connector(&server, Some(cache()));
    let first_order = vec![
        ExtensionId::SERVER_NAME,
        ExtensionId::SUPPORTED_VERSIONS,
        ExtensionId::SIGNATURE_ALGORITHMS,
        ExtensionId::KEY_SHARE,
        ExtensionId::SUPPORTED_GROUPS,
    ];
    let mut second_order = first_order.clone();
    second_order.reverse();
    for (index, order) in [first_order, second_order].into_iter().enumerate() {
        let hello = connect_hello(&connector, &server, |extensions| {
            extensions.insert(TlsSessionProfileScope("one profile".into()));
            extensions.insert(BoringPermuteExtensions(false));
            extensions.insert(BoringExtensionOrder(order.clone()));
        })
        .await;
        assert_eq!(offers_session(&hello), index != 0);
        let observed: Vec<_> = hello
            .extensions()
            .iter()
            .map(|ext| ext.id())
            .filter(|id| order.contains(id))
            .collect();
        assert_eq!(observed, order);
        if index != 0 {
            assert_eq!(
                hello.extensions().last().map(|ext| ext.id()),
                Some(ExtensionId::PRE_SHARED_KEY)
            );
        }
    }
}

#[tokio::test]
async fn cipher_grease_draws_resume_without_losing_their_wire_values() {
    for version in VERSIONS {
        let server = Server::new(version);
        let connector = connector(&server, Some(cache()));
        for (index, grease) in [0x0a0a, 0x1a1a].into_iter().enumerate() {
            let actual = connect(&connector, &server, "a.test", |extensions| {
                extensions.insert(BoringGreaseValues(GreaseValues::Pinned));
                extensions.insert(BoringCipherSuites(vec![
                    CipherSuite::from(grease),
                    CipherSuite::TLS13_AES_128_GCM_SHA256,
                    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                ]));
            })
            .await;
            assert_eq!(actual, if index == 0 { FULL } else { RESUMED });
        }

        // Native output keeps the next literal GREASE draw while offering the
        // current peer's ticket under the unchanged negotiable cipher policy.
        let hello = connect_hello(&connector, &server, |extensions| {
            extensions.insert(BoringGreaseValues(GreaseValues::Pinned));
            extensions.insert(BoringCipherSuites(vec![
                CipherSuite::from(0x2a2a),
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]));
        })
        .await;
        assert!(offers_session(&hello));
        assert_eq!(u16::from(hello.cipher_suites()[0]), 0x2a2a);
    }
}

#[tokio::test]
async fn profile_scopes_and_security_policies_remain_isolated_across_draws() {
    let server = Server::new(SslVersion::TLS1_3);
    let connector = connector(&server, Some(cache()));
    for (profile, verify, expected) in [
        ("first", ServerVerifyMode::Disable, FULL),
        ("first", ServerVerifyMode::Auto, FULL),
        ("second", ServerVerifyMode::Auto, FULL),
        ("first", ServerVerifyMode::Auto, RESUMED),
        ("second", ServerVerifyMode::Auto, RESUMED),
        ("first", ServerVerifyMode::Disable, RESUMED),
    ] {
        let actual = connect(&connector, &server, "a.test", |extensions| {
            extensions.insert(TlsSessionProfileScope(profile.into()));
            extensions.insert(TlsServerVerify(verify));
            extensions.insert(BoringPermuteExtensions(false));
            extensions.insert(BoringExtensionOrder(vec![
                ExtensionId::SIGNATURE_ALGORITHMS,
                ExtensionId::SERVER_NAME,
                ExtensionId::KEY_SHARE,
                ExtensionId::SUPPORTED_GROUPS,
                ExtensionId::SUPPORTED_VERSIONS,
            ]));
        })
        .await;
        assert_eq!(actual, expected, "{profile}, {verify:?}");
    }
}
