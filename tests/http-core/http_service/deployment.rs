//! Deployment sequences through the real easy-client pool, TLS and H1/H2/H3 stacks.
//!
//! RFC 7838 sections 2.2, 3.1 and 6 cover authoritative replacement, network
//! changes, freshness and 421. These tests distinguish discovery state from
//! already established connections: clearing discovery need not close a stream.
//! https://www.rfc-editor.org/rfc/rfc7838.html

use super::{
    Reply, Server, TEST_TIMEOUT, client_with_attempt_timeout, client_with_http3_cache_and_timeout,
    close_client_endpoint, complete, credentials,
};
use rama::{
    Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    futures::{StreamExt as _, stream},
    http::{
        Body, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
        header,
        layer::alt_svc::AltSvcCache,
    },
};
use std::sync::atomic::Ordering;
use tokio::{sync::oneshot, time::timeout};

const ALTERNATIVES: [(&str, Version); 3] = [
    ("http%2F1.1", Version::HTTP_11),
    ("h2", Version::HTTP_2),
    ("h3", Version::HTTP_3),
];

fn assert_origin(alternative: &Server, origin: &Server, requests: usize) {
    let observations = alternative.observations.lock();
    assert_eq!(observations.len(), requests);
    for observation in observations.iter() {
        assert_eq!(
            observation.authority,
            origin.origin().authority().to_string()
        );
        assert_eq!(observation.sni.as_deref(), Some("localhost"));
        assert_eq!(
            observation.alt_used.as_deref(),
            Some(alternative.origin().authority().to_string().as_str())
        );
        assert_eq!(observation.body, "dispatched once");
    }
}

#[tokio::test]
async fn authenticated_alternative_can_replace_then_withdraw_discovery() {
    // Rolling migration works in both directions; an alternative has the same
    // advertisement authority as the original endpoint (RFC 7838 section 2.2).
    for (first_protocol, first_version, next_protocol, next_version) in [
        ("http%2F1.1", Version::HTTP_11, "h3", Version::HTTP_3),
        ("h2", Version::HTTP_2, "h3", Version::HTTP_3),
        ("h3", Version::HTTP_3, "h2", Version::HTTP_2),
    ] {
        for clear in [true, false] {
            let (auth, tls) = credentials();
            let origin = Server::start(auth.clone(), Version::HTTP_2).await;
            let first = Server::start(auth.clone(), first_version).await;
            let next = Server::start(auth, next_version).await;
            origin.reply(Reply::advertise(&format!(
                "{first_protocol}=\":{}\"",
                first.address.port()
            )));
            first.reply(Reply::default());
            first.reply(Reply::advertise(&format!(
                "{next_protocol}=\":{}\"",
                next.address.port()
            )));
            next.reply(Reply::advertise(&if clear {
                "clear".to_owned()
            } else {
                format!("{next_protocol}=\":{}\"; ma=0", next.address.port())
            }));
            let cache = AltSvcCache::default();
            let (client, endpoint) =
                client_with_http3_cache_and_timeout(tls, cache.clone(), Some(TEST_TIMEOUT)).await;

            assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
            assert_eq!(complete(&client, origin.request()).await.1, first_version);
            assert_eq!(complete(&client, origin.request()).await.1, first_version);
            assert_eq!(first.accepted.load(Ordering::SeqCst), 1);
            let snapshot = cache.lookup(&origin.origin()).unwrap();
            assert_eq!(
                snapshot.len(),
                1,
                "replacement must not merge old endpoints"
            );
            assert_eq!(snapshot.get(0).unwrap().target.port, next.address.port());
            assert_eq!(complete(&client, origin.request()).await.1, next_version);
            assert!(cache.lookup(&origin.origin()).is_none());
            assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
            assert_eq!(origin.request_count(), 2);
            assert_origin(&first, &origin, 2);
            assert_origin(&next, &origin, 1);
            assert!(
                origin
                    .observations
                    .lock()
                    .iter()
                    .all(|seen| seen.alt_used.is_none())
            );

            drop(client);
            close_client_endpoint(endpoint).await;
            origin.close().await;
            first.close().await;
            next.close().await;
        }
    }
}

#[tokio::test]
async fn advertisement_age_and_response_cache_control_have_distinct_lifetimes() {
    for (protocol, version) in ALTERNATIVES {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), Version::HTTP_2).await;
        let alternative = Server::start(auth, version).await;
        let mut stale = Reply::advertise(&format!(
            "{protocol}=\":{}\"; ma=60",
            alternative.address.port()
        ));
        stale.headers.insert(header::AGE, "60".parse().unwrap());
        stale
            .headers
            .insert(header::CACHE_CONTROL, "max-age=86400".parse().unwrap());
        origin.reply(stale);
        let mut fresh = Reply::advertise(&format!(
            "{protocol}=\":{}\"; ma=3600",
            alternative.address.port()
        ));
        fresh
            .headers
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        origin.reply(fresh);
        let cache = AltSvcCache::default();
        let (client, endpoint) =
            client_with_http3_cache_and_timeout(tls, cache.clone(), Some(TEST_TIMEOUT)).await;

        // A cached response cannot grant a new full ma lifetime. Conversely,
        // response-cache directives do not control discovery (section 3.1).
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
        assert!(cache.lookup(&origin.origin()).is_none());
        assert_eq!(alternative.accepted.load(Ordering::SeqCst), 0);
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
        assert!(cache.lookup(&origin.origin()).is_some());
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(origin.request_count(), 2);
        assert_origin(&alternative, &origin, 1);

        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
        alternative.close().await;
    }
}

#[tokio::test]
async fn network_change_only_retains_persistent_routes_for_new_connections() {
    for (protocol, version) in ALTERNATIVES {
        let (auth, tls) = credentials();
        let origin = Server::start(auth.clone(), Version::HTTP_2).await;
        let transient = Server::start(auth.clone(), version).await;
        let persistent = Server::start(auth, version).await;
        origin.reply(Reply::advertise(&format!(
            "{protocol}=\":{}\", {protocol}=\":{}\"; persist=1",
            transient.address.port(),
            persistent.address.port()
        )));
        let cache = AltSvcCache::default();
        let (client, endpoint) =
            client_with_http3_cache_and_timeout(tls.clone(), cache.clone(), Some(TEST_TIMEOUT))
                .await;
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_origin(&transient, &origin, 1);
        drop(client);
        close_client_endpoint(endpoint).await;

        // A new pool avoids asserting anything about the RFC-permitted reuse
        // of existing connections after a discovery entry expires or is removed.
        cache.network_changed();
        let (client, endpoint) =
            client_with_http3_cache_and_timeout(tls, cache, Some(TEST_TIMEOUT)).await;
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(complete(&client, origin.request()).await.1, version);
        assert_eq!(transient.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(persistent.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(origin.request_count(), 1);
        assert_origin(&persistent, &origin, 2);

        drop(client);
        close_client_endpoint(endpoint).await;
        origin.close().await;
        transient.close().await;
        persistent.close().await;
    }
}

#[tokio::test]
async fn response_failure_backoff_is_scoped_to_its_network() {
    for (protocol, version) in ALTERNATIVES {
        for changed_network in [false, true] {
            let (auth, tls) = credentials();
            let origin = Server::start(auth.clone(), Version::HTTP_2).await;
            let alternative = Server::start(auth, version).await;
            origin.reply(Reply::advertise(&format!(
                "{protocol}=\":{}\"; persist=1",
                alternative.address.port()
            )));
            let (reset, wait_for_reset) = oneshot::channel();
            let data = stream::once(async {
                Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"before network change")))
            });
            let failure = stream::once(async move {
                wait_for_reset.await.unwrap();
                Err::<Frame<Bytes>, _>(BoxError::from_static_str("old path failed"))
            });
            alternative.reply(Reply {
                body: Some(Body::from_frame_stream(data.chain(failure))),
                ..Reply::default()
            });
            let cache = AltSvcCache::default();
            let (client, endpoint) =
                client_with_http3_cache_and_timeout(tls, cache.clone(), Some(TEST_TIMEOUT)).await;
            complete(&client, origin.request()).await;
            let response = timeout(TEST_TIMEOUT, client.serve(origin.request()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.version(), version);
            let mut body = response.into_body();
            let first = timeout(TEST_TIMEOUT, body.frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(first.into_data().unwrap(), "before network change");

            // Deterministically deliver the old response error after the network
            // notification. Its captured epoch must not suppress the current path.
            if changed_network {
                cache.network_changed();
            }
            let current = cache.lookup(&origin.origin()).unwrap();
            reset.send(()).unwrap();
            timeout(TEST_TIMEOUT, body.collect())
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(cache.is_usable(&current, 0), changed_network);
            let expected_version = if changed_network {
                version
            } else {
                Version::HTTP_2
            };
            assert_eq!(
                complete(&client, origin.request()).await.1,
                expected_version
            );
            assert_eq!(origin.request_count(), if changed_network { 1 } else { 2 });
            assert_origin(&alternative, &origin, if changed_network { 2 } else { 1 });

            drop(client);
            close_client_endpoint(endpoint).await;
            origin.close().await;
            alternative.close().await;
        }
    }
}

#[tokio::test]
async fn misdirected_shared_endpoint_does_not_poison_another_origin() {
    for (protocol, version) in ALTERNATIVES {
        let (auth, tls) = credentials();
        let first = Server::start(auth.clone(), Version::HTTP_2).await;
        let second = Server::start(auth.clone(), Version::HTTP_2).await;
        let alternative = Server::start(auth, version).await;
        let advertisement = format!("{protocol}=\":{}\"", alternative.address.port());
        first.reply(Reply::advertise(&advertisement));
        second.reply(Reply::advertise(&advertisement));
        // A 421's advertisement must be ignored, even if it tries to restore
        // the very endpoint being rejected (RFC 7838 section 6).
        let mut misdirected = Reply::advertise(&advertisement);
        misdirected.status = StatusCode::MISDIRECTED_REQUEST;
        alternative.reply(misdirected);
        let cache = AltSvcCache::default();
        let (client, endpoint) =
            client_with_http3_cache_and_timeout(tls, cache.clone(), Some(TEST_TIMEOUT)).await;
        complete(&client, first.request()).await;
        complete(&client, second.request()).await;
        let first_snapshot = cache.lookup(&first.origin()).unwrap();
        let second_snapshot = cache.lookup(&second.origin()).unwrap();

        assert_eq!(
            complete(&client, first.request()).await.0,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert!(!cache.is_usable(&first_snapshot, 0));
        assert!(cache.is_usable(&second_snapshot, 0));
        assert_eq!(complete(&client, second.request()).await.1, version);
        assert_eq!(complete(&client, first.request()).await.1, Version::HTTP_2);
        assert_eq!(first.request_count(), 2);
        assert_eq!(second.request_count(), 1);
        {
            let observations = alternative.observations.lock();
            assert_eq!(
                observations.len(),
                2,
                "a 421 response must not replay the POST"
            );
            assert_eq!(
                observations[0].authority,
                first.origin().authority().to_string()
            );
            assert_eq!(
                observations[1].authority,
                second.origin().authority().to_string()
            );
        }

        drop(client);
        close_client_endpoint(endpoint).await;
        first.close().await;
        second.close().await;
        alternative.close().await;
    }
}

#[tokio::test]
async fn failed_first_candidate_uses_the_next_supported_service_without_replaying() {
    for (protocol, version) in ALTERNATIVES {
        for authentication_failure in [false, true] {
            let (auth, tls) = credentials();
            let origin = Server::start(auth.clone(), Version::HTTP_2).await;
            let (bad_auth, bad_version) = if authentication_failure {
                (credentials().0, Version::HTTP_2)
            } else {
                // Advertised as h2, but this endpoint only negotiates HTTP/1.1.
                (auth.clone(), Version::HTTP_11)
            };
            let bad = Server::start(bad_auth, bad_version).await;
            let good = Server::start(auth, version).await;
            origin.reply(Reply::advertise(&format!(
                "unknown=\":1\", h2=\":{}\", {protocol}=\":{}\"",
                bad.address.port(),
                good.address.port()
            )));
            let (client, endpoint) = client_with_http3_cache_and_timeout(
                tls,
                AltSvcCache::default(),
                Some(TEST_TIMEOUT),
            )
            .await;
            assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
            assert_eq!(complete(&client, origin.request()).await.1, version);
            let failed_dials = bad.accepted.load(Ordering::SeqCst);
            assert!(
                failed_dials > 0,
                "the preferred supported service was tried"
            );
            assert_eq!(bad.request_count(), 0, "never dispatch before validation");
            assert_eq!(complete(&client, origin.request()).await.1, version);
            assert_eq!(bad.accepted.load(Ordering::SeqCst), failed_dials);
            assert_eq!(good.accepted.load(Ordering::SeqCst), 1);
            assert_eq!(origin.request_count(), 1);
            assert_origin(&good, &origin, 2);

            drop(client);
            close_client_endpoint(endpoint).await;
            origin.close().await;
            bad.close().await;
            good.close().await;
        }
    }
}

#[tokio::test]
async fn stream_only_client_skips_h3_without_dialing_or_suppressing_it() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    // Advertise this listening stream endpoint as H3. A late transport check
    // would dial it before rejecting H3, which the accept counter detects.
    let unsupported = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_2).await;
    origin.reply(Reply::advertise(&format!(
        "h3=\":{}\", h2=\":{}\"",
        unsupported.address.port(),
        alternative.address.port(),
    )));
    let cache = AltSvcCache::default();
    let client = client_with_attempt_timeout(tls, cache.clone(), Some(TEST_TIMEOUT));

    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
    for _ in 0..3 {
        assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_2);
    }
    assert_eq!(origin.request_count(), 1);
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(unsupported.accepted.load(Ordering::SeqCst), 0);
    assert_origin(&alternative, &origin, 3);
    let snapshot = cache.lookup(&origin.origin()).unwrap();
    assert_eq!(snapshot.len(), 2);
    assert!(cache.is_usable(&snapshot, 0), "unsupported is not broken");

    drop(client);
    origin.close().await;
    unsupported.close().await;
    alternative.close().await;
}
