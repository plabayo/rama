use rama_boring_tokio::SslStreamBuilder;

use super::*;

#[tokio::test]
async fn contexts_never_resume_each_others_sessions() {
    let server = Server::new(SslVersion::TLS1_3);
    let config = trusting_config().with_server_name(Host::from_static("a.test"));
    let store = cache();
    let contexts = [(); 2].map(|()| {
        TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .with_session_store(store.clone())
            .build()
    });
    assert!(!handshake(&server, &contexts[0]).await);
    assert!(!handshake(&server, &contexts[1]).await);
    assert!(handshake(&server, &contexts[0]).await);
    assert!(handshake(&server, &contexts[1]).await);
}

#[tokio::test]
async fn sessions_only_resume_on_their_own_context_and_server() {
    let server = Server::new(SslVersion::TLS1_3);
    let config = trusting_config().with_server_name(Host::from_static("a.test"));
    let sessions: Arc<Mutex<Vec<TlsClientSession>>> = Arc::default();
    let remembering = || {
        let sink = sessions.clone();
        TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .with_new_session_callback(move |_, session| sink.lock().push(session))
            .build()
    };
    let (issuing, other) = (remembering(), remembering());
    let plain = TlsConnectorContextBuilder::try_from(&config)
        .unwrap()
        .build();
    assert!(!handshake(&server, &issuing).await);
    let session = sessions.lock().pop().expect("the server issued tickets");
    let ssl_for = |context: &TlsConnectorContext, server: &'static str| {
        let mut data = context.configure().unwrap();
        data.server_name = Some(Host::from_static(server));
        data.into_ssl().unwrap()
    };
    session.resume_on(&mut ssl_for(&issuing, "a.test")).unwrap();
    session
        .resume_on(&mut ssl_for(&issuing, "b.test"))
        .unwrap_err();
    session
        .resume_on(&mut ssl_for(&other, "a.test"))
        .unwrap_err();
    session
        .resume_on(&mut ssl_for(&plain, "a.test"))
        .unwrap_err();
    // Bound to the issuing context, then switched away from it.
    let mut switched = ssl_for(&issuing, "a.test");
    switched
        .set_ssl_context(ssl_for(&other, "a.test").ssl_context())
        .unwrap();
    session.resume_on(&mut switched).unwrap_err();
}

#[tokio::test]
async fn a_generated_client_credential_is_shared_by_the_wire_variants_of_its_policy() {
    let server = Server::new(SslVersion::TLS1_3);
    let connector = connector(&server, Some(cache()));
    for (reversed, expected) in [
        (false, FULL),
        (true, RESUMED),
        (false, RESUMED),
        (true, RESUMED),
    ] {
        let actual = connect(&connector, &server, "a.test", |extensions| {
            extensions.insert(TlsClientAuth(ClientAuth::SelfSigned));
            let mut order = vec![
                ExtensionId::SERVER_NAME,
                ExtensionId::SUPPORTED_VERSIONS,
                ExtensionId::SIGNATURE_ALGORITHMS,
                ExtensionId::KEY_SHARE,
                ExtensionId::SUPPORTED_GROUPS,
            ];
            if reversed {
                order.reverse();
            }
            extensions.insert(BoringExtensionOrder(order));
        })
        .await;
        // Both orders use the one context of this policy, and so its one certificate.
        assert_eq!(actual, expected);
    }
}

/// A pinned session resumes only while its stored chain still verifies; unpinned sessions and
/// pins without chain verification resume without that check.
#[tokio::test]
async fn a_pinned_session_resumes_only_while_its_chain_verifies() {
    // The test certificates live 90 days: a year on they have expired (and fit a 32-bit time_t).
    let later = SystemTime::now() + Duration::from_hours(365 * 24);
    let later = later.duration_since(UNIX_EPOCH).unwrap().as_secs();
    for version in VERSIONS {
        let server = Server::new(version);
        for (pinned, verify, expected_later) in [
            (false, ServerVerifyMode::Auto, Some(true)),
            (true, ServerVerifyMode::Auto, None),
            (true, ServerVerifyMode::Disable, Some(true)),
        ] {
            let mut config = trusting_config().with_server_verify(verify);
            if pinned {
                config.set_server_cert_pins(TlsServerCertPins::new(AUTH.0[0].clone()));
            }
            let store: Arc<dyn TlsClientSessionStore> = cache();
            let mut builder = TlsConnectorContextBuilder::try_from(&config).unwrap();
            builder.set_session_store(store);
            let context = builder.build();
            let mut outcomes = Vec::new();
            for judged_later in [false, false, true] {
                let mut data = context.configure().unwrap();
                data.server_name = Some(Host::from_static("a.test"));
                let mut ssl = data.into_ssl().unwrap();
                if judged_later {
                    ssl.param_mut().set_time(later.try_into().unwrap());
                }
                let (client_io, server_io) = tokio::io::duplex(1024);
                let acceptor = server.acceptor.clone();
                let accepted = tokio::spawn(async move {
                    let mut stream = accept(&acceptor, server_io).await.ok()?;
                    stream.write_all(b"x").await.ok()?;
                    Some(())
                });
                let connected = SslStreamBuilder::new(ssl, client_io).connect().await;
                outcomes.push(match connected {
                    Ok(mut stream) => {
                        stream.read_exact(&mut [0]).await.unwrap();
                        Some(stream.ssl().session_reused())
                    }
                    Err(_) => None,
                });
                drop(accepted.await);
            }
            assert_eq!(
                outcomes,
                [Some(false), Some(true), expected_later],
                "{version:?} pinned: {pinned} verify: {verify:?}"
            );
        }
    }
}

/// Counts its checks and rejects every chain once `reject` is set.
#[derive(Debug, Clone, Default)]
struct SwitchablePolicy {
    reject: Arc<std::sync::atomic::AtomicBool>,
    checks: Arc<AtomicUsize>,
}

impl rama_tls::client::TlsServerCertChainPolicy for SwitchablePolicy {
    fn check(
        &self,
        _chain: &rama_tls::client::ServerCertChain<'_>,
    ) -> Result<(), rama_core::error::BoxError> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        if self.reject.load(Ordering::SeqCst) {
            Err(rama_core::error::BoxError::from_static_str("rejected"))
        } else {
            Ok(())
        }
    }
}

/// A chain policy is checked again whenever a session resumes, with and without
/// chain verification, so a policy that now rejects the chain stops resumption.
#[tokio::test]
async fn a_chain_policy_is_checked_again_on_resumption() {
    for version in VERSIONS {
        let server = Server::new(version);
        for verify in [ServerVerifyMode::Auto, ServerVerifyMode::Disable] {
            let policy = SwitchablePolicy::default();
            let config = trusting_config()
                .with_server_verify(verify)
                .with_server_cert_chain_policy(policy.clone());
            let store: Arc<dyn TlsClientSessionStore> = cache();
            let mut builder = TlsConnectorContextBuilder::try_from(&config).unwrap();
            builder.set_session_store(store);
            let context = builder.build();
            let mut outcomes = Vec::new();
            for reject in [false, false, true] {
                policy.reject.store(reject, Ordering::SeqCst);
                let mut data = context.configure().unwrap();
                data.server_name = Some(Host::from_static("a.test"));
                let ssl = data.into_ssl().unwrap();
                let (client_io, server_io) = tokio::io::duplex(1024);
                let acceptor = server.acceptor.clone();
                let accepted = tokio::spawn(async move {
                    let mut stream = accept(&acceptor, server_io).await.ok()?;
                    stream.write_all(b"x").await.ok()?;
                    Some(())
                });
                let connected = SslStreamBuilder::new(ssl, client_io).connect().await;
                outcomes.push(match connected {
                    Ok(mut stream) => {
                        stream.read_exact(&mut [0]).await.unwrap();
                        Some(stream.ssl().session_reused())
                    }
                    Err(_) => None,
                });
                drop(accepted.await);
            }
            assert_eq!(
                outcomes,
                [Some(false), Some(true), None],
                "{version:?} verify: {verify:?}"
            );
            assert_eq!(
                policy.checks.load(Ordering::SeqCst),
                3,
                "{version:?} verify: {verify:?}: one check per handshake"
            );
        }
    }
}

#[derive(Debug, Default)]
struct CountingKeyLog(AtomicUsize);

impl KeyLogSink for CountingKeyLog {
    fn write_line(&self, _line: &str) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Connections that did not opt into keylogging never share the context of those that did,
/// so their secrets never reach that sink.
#[tokio::test]
async fn keylog_intent_keeps_contexts_apart() {
    let sink = Arc::new(CountingKeyLog::default());
    let logged = trusting_config().with_keylog(KeyLogIntent::Custom(sink.clone()));
    let unlogged = trusting_config().with_keylog(KeyLogIntent::Disabled);
    let server = Server::new(SslVersion::TLS1_3);
    let mut lines = Vec::new();
    for config in [&logged, &unlogged, &logged] {
        let mut data = TlsConnectorData::try_from(config).unwrap();
        data.server_name = Some(Host::from_static("a.test"));
        let ssl = data.into_ssl().unwrap();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let acceptor = server.acceptor.clone();
        let accepted = tokio::spawn(async move {
            let mut stream = accept(&acceptor, server_io).await.ok()?;
            stream.write_all(b"x").await.ok()?;
            Some(())
        });
        let mut stream = SslStreamBuilder::new(ssl, client_io)
            .connect()
            .await
            .unwrap();
        stream.read_exact(&mut [0]).await.unwrap();
        drop(accepted.await);
        lines.push(sink.0.load(Ordering::SeqCst));
    }
    assert!(lines[0] > 0, "the logged connection writes its secrets");
    assert_eq!(
        lines[1], lines[0],
        "the unlogged connection wrote to the sink"
    );
    assert!(lines[2] > lines[1]);
}
