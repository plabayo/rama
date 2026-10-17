//! Native session ownership, engine parameters and failure before connection admission.

use std::sync::atomic::AtomicBool;

use rama_core::error::{BoxError, BoxErrorExt};
use rama_tls::client::ClientHelloExtension;

use super::*;

fn count_initializations(config: &TlsClientConfig) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    config
        .as_extensions()
        .insert(HandshakeInitializer(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })));
    count
}

#[test]
fn prepared_ssl_is_consumed_once_and_retries_keep_fresh_native_state() {
    for version in [Version::V1, Version::V2] {
        let (client, server) = configs();
        let initializations = Arc::new(AtomicUsize::new(0));
        let initialized = initializations.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let finished = completed.clone();
        client
            .as_extensions()
            .insert(HandshakeInitializer(Arc::new(move |ssl| {
                initialized.fetch_add(1, Ordering::SeqCst);
                let finished = finished.clone();
                // This native hook must survive preparation into the actual session.
                // Counting construction alone would miss discarding the prepared SSL.
                on_handshake_completed(ssl, move |_| {
                    finished.fetch_add(1, Ordering::SeqCst);
                })
            })));
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen = observed.clone();
        let client = BoringTlsProvider
            .prepare_fresh_client_config(
                &client,
                rama_net::address::Host::try_from("localhost").unwrap(),
                move |hello, encoded| {
                    let actual = hello
                        .extensions()
                        .iter()
                        .find_map(|extension| match extension {
                            ClientHelloExtension::Opaque { id, data }
                                if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
                            {
                                Some(data)
                            }
                            _ => None,
                        })
                        .expect("native QUIC ClientHello includes transport parameters");
                    assert_eq!(actual.as_slice(), encoded);
                    seen.lock().push(hello.clone());
                    Ok(())
                },
            )
            .unwrap()
            .crypto;
        assert_eq!(initializations.load(Ordering::SeqCst), 1);
        let server = BoringTlsProvider
            .server_config(&server, TlsOptions::default())
            .unwrap()
            .crypto
            .into_fixed();
        for attempt in 0..3 {
            let mut parameters = params(Side::Client);
            parameters.initial_src_cid = Some(ConnectionId::new(&[10 + attempt]));
            let mut c = client
                .clone()
                .start_session(version, "localhost", &parameters)
                .unwrap();
            assert_eq!(
                initializations.load(Ordering::SeqCst),
                usize::from(attempt) + 1
            );
            assert!(c.early_crypto().is_none());
            assert_eq!(client.resumable_version("localhost"), None);
            let mut s = server
                .clone()
                .start_session(version, &params(Side::Server))
                .unwrap();
            // Authentication, ALPN, exporters and packet keys still work; the
            // validation hook must not consume or rewrite native handshake output.
            check_session(&mut *c, &mut *s, false);
            assert_eq!(completed.load(Ordering::SeqCst), usize::from(attempt) + 1);
        }
        let observed = observed.lock();
        assert_eq!(observed.len(), 3);
        for pair in observed.windows(2) {
            let shares = |hello: &rama_tls::client::ClientHello| {
                hello
                    .extensions()
                    .iter()
                    .find_map(|extension| match extension {
                        ClientHelloExtension::Opaque { id, data }
                            if *id == ExtensionId::KEY_SHARE =>
                        {
                            Some(data.clone())
                        }
                        _ => None,
                    })
                    .unwrap()
            };
            assert_ne!(shares(&pair[0]), shares(&pair[1]));
        }
    }
}

#[test]
fn wrong_peer_does_not_consume_the_prepared_ssl() {
    let (client, server) = configs();
    let count = count_initializations(&client);
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = checks.clone();
    let client = BoringTlsProvider
        .prepare_fresh_client_config(
            &client,
            rama_net::address::Host::try_from("localhost").unwrap(),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap()
        .crypto;
    assert!(
        client
            .clone()
            .start_session(Version::V1, "other.invalid", &params(Side::Client))
            .is_err()
    );
    assert_eq!(checks.load(Ordering::SeqCst), 0);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let mut c = client
        .start_session(Version::V1, "localhost", &params(Side::Client))
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    let mut s = BoringTlsProvider
        .server_config(&server, TlsOptions::default())
        .unwrap()
        .crypto
        .into_fixed()
        .start_session(Version::V1, &params(Side::Server))
        .unwrap();
    check_session(&mut *c, &mut *s, false);
}

#[test]
fn failed_native_check_cannot_admit_a_connection_and_retry_can_succeed() {
    let (client, _) = configs();
    let count = count_initializations(&client);
    let reject = Arc::new(AtomicBool::new(true));
    let rejected = reject.clone();
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = checks.clone();
    let client = BoringTlsProvider
        .prepare_fresh_client_config(
            &client,
            rama_net::address::Host::try_from("localhost").unwrap(),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                if rejected.load(Ordering::SeqCst) {
                    Err(BoxError::from_static_str("reject this native first flight"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
    let mut endpoint = crate::proto::Endpoint::new(
        Arc::new(crate::EndpointConfig::try_with_rand_key().unwrap()),
        None,
        true,
        None,
    );
    let remote = "127.0.0.1:443".parse().unwrap();
    let error = endpoint
        .connect(
            crate::proto::Instant::now(),
            client.clone(),
            remote,
            "localhost",
        )
        .unwrap_err();
    assert_matches!(error, crate::ConnectError::Crypto(_));
    assert_eq!(endpoint.open_connections(), 0);
    assert_eq!(endpoint.known_cids(), 0);
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    reject.store(false, Ordering::SeqCst);
    let (_, mut connection) = endpoint
        .connect(crate::proto::Instant::now(), client, remote, "localhost")
        .unwrap();
    assert_eq!(endpoint.open_connections(), 1);
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let mut buffer = Vec::new();
    assert!(
        connection
            .poll_transmit(crate::proto::Instant::now(), 1, &mut buffer)
            .is_some()
    );
    assert!(!buffer.is_empty());
}

#[test]
fn racing_attempts_own_distinct_sessions_and_initialize_each_once() {
    let (client, server) = configs();
    let count = count_initializations(&client);
    let checks = Arc::new(AtomicUsize::new(0));
    let seen = checks.clone();
    let client = BoringTlsProvider
        .prepare_fresh_client_config(
            &client,
            rama_net::address::Host::try_from("localhost").unwrap(),
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap()
        .crypto;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let server = BoringTlsProvider
        .server_config(&server, TlsOptions::default())
        .unwrap()
        .crypto
        .into_fixed();
    std::thread::scope(|scope| {
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let attempts = (0..4)
            .map(|attempt| {
                let client = client.clone();
                let server = server.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    let version = if attempt % 2 == 0 {
                        Version::V1
                    } else {
                        Version::V2
                    };
                    let mut c = client
                        .start_session(version, "localhost", &params(Side::Client))
                        .unwrap();
                    let mut s = server
                        .start_session(version, &params(Side::Server))
                        .unwrap();
                    check_session(&mut *c, &mut *s, false);
                })
            })
            .collect::<Vec<_>>();
        for attempt in attempts {
            attempt.join().unwrap();
        }
    });
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(checks.load(Ordering::SeqCst), 4);
}
