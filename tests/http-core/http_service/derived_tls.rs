//! Native TLS regression coverage for discovery under derived fingerprint settings.
use super::*;
use rama::{
    net::tls::TlsAlpn,
    tls::{boring::client::BoringTlsClientConfigProvider, client::TlsConnectionReuse},
};

fn derive(request: &Request) {
    let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, request.extensions());
    request
        .extensions()
        .insert(TlsAlpn([ApplicationProtocol::HTTP_2].into_iter().collect()));
    request
        .extensions()
        .insert(caller.for_derived_settings(request.extensions()).unwrap());
}

fn advertisement(server: &Server, frame: bool, value: &'static str) -> Reply {
    if frame {
        Reply {
            alt_svc_frame: Some(
                AltSvcFrame::new(
                    StreamId::zero(),
                    Bytes::from(format!("https://localhost:{}", server.address.port())),
                    Bytes::from_static(value.as_bytes()),
                )
                .unwrap(),
            ),
            ..Reply::default()
        }
    } else {
        Reply::advertise(value)
    }
}

async fn expect_port(cache: &AltSvcCache, server: &Server, expected: Option<u16>) {
    timeout(TEST_TIMEOUT, async {
        loop {
            let actual = cache.lookup(&server.origin()).map(|snapshot| {
                assert_eq!(snapshot.len(), 1);
                snapshot.get(0).unwrap().target.port
            });
            if actual == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn derived_tls_learns_headers_and_frames_on_fresh_and_pooled_connections() {
    for first_frame in [false, true] {
        let (auth, tls) = credentials();
        let origin = Server::start(auth, Version::HTTP_2).await;
        let cache = AltSvcCache::default();
        let client = client(tls, cache.clone());
        for (frame, value, expected) in [
            (first_frame, "h3=\":8443\"", Some(8443)),
            (!first_frame, "h3=\":9443\"", Some(9443)),
            (first_frame, "clear", None),
            (!first_frame, "h3=\":8443\"", Some(8443)),
            (!first_frame, "clear", None),
        ] {
            origin.reply(advertisement(&origin, frame, value));
            let request = origin.request();
            derive(&request);
            assert_eq!(complete(&client, request).await.1, Version::HTTP_2);
            expect_port(&cache, &origin, expected).await;
        }
        assert_eq!(
            origin.accepted.load(Ordering::SeqCst),
            1,
            "later responses must use the pooled connection"
        );
        drop(client);
        origin.close().await;
    }
}

#[tokio::test]
async fn derived_tls_caller_overrides_and_stale_tokens_cannot_learn_or_clear() {
    for stale in [false, true] {
        for frame in [false, true] {
            let (auth, tls) = credentials();
            let origin = Server::start(auth, Version::HTTP_2).await;
            let cache = AltSvcCache::default();
            let client = client(tls, cache.clone());
            // An unsupported alternative keeps exchanges on the origin.
            seed(&cache, &origin.origin(), "h3=\":7443\"");
            for value in ["h3=\":8443\"", "clear"] {
                origin.reply(advertisement(&origin, frame, value));
                let request = origin.request();
                if stale {
                    derive(&request);
                    request
                        .extensions()
                        .insert(TlsServerVerify(ServerVerifyMode::Auto));
                } else {
                    request
                        .extensions()
                        .insert(TlsServerVerify(ServerVerifyMode::Auto));
                    derive(&request);
                }
                complete(&client, request).await;
            }
            drop(client);
            // Drain the H2 connection before testing absence of frame updates.
            let key = origin.origin();
            origin.close().await;
            let snapshot = cache.lookup(&key).unwrap();
            assert_eq!(snapshot.get(0).unwrap().target.port, 7443);
        }
    }
}

#[tokio::test]
async fn derived_tls_does_not_authenticate_untrusted_or_unverified_peers() {
    for disabled in [false, true] {
        let (auth, _) = credentials();
        let origin = Server::start(auth, Version::HTTP_2).await;
        let cache = AltSvcCache::default();
        let tls = TlsClientConfig::default_http().with_server_verify(if disabled {
            ServerVerifyMode::Disable
        } else {
            ServerVerifyMode::Auto
        });
        let client = client(tls, cache.clone());
        for frame in [false, true] {
            origin.reply(advertisement(&origin, frame, "h3=\":8443\""));
            let request = origin.request();
            derive(&request);
            if disabled {
                complete(&client, request).await;
            } else {
                assert!(
                    timeout(TEST_TIMEOUT, client.serve(request))
                        .await
                        .unwrap()
                        .is_err()
                );
            }
        }
        assert_eq!(origin.request_count(), if disabled { 2 } else { 0 });
        let key = origin.origin();
        drop(client);
        origin.close().await;
        assert!(cache.lookup(&key).is_none());
    }
}
