//! Native TLS settings belong to their provider; common trust applies to both.

use super::{Server, TEST_TIMEOUT, close_client_endpoint, complete, credentials, seed};
use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, Version,
        client::{EasyHttpConnectorBuilder, Http3Connector},
        conn::TargetHttpVersion,
        layer::alt_svc::AltSvcCache,
    },
    net::address::SocketAddress,
    quic::{
        Endpoint,
        tls::{BoringTlsProvider, default_tls_provider},
    },
    rt::Executor,
    tls::{
        boring::{
            client::BoringClientConfigExt as _,
            core::x509::{X509, store::X509StoreBuilder},
        },
        client::TlsClientConfig,
        rustls::client::RustlsClientConfigExt as _,
    },
};
use std::{
    fmt::Debug,
    sync::{Arc, atomic::Ordering},
};
use tokio::time::timeout;

async fn check_policy(
    client: impl Service<Request, Output = Response, Error: Debug>,
    endpoint: Endpoint,
    origin: Server,
    alternative: Server,
    fresh: Server,
    restricted: TlsClientConfig,
) {
    let request = origin.request();
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    assert_eq!(complete(&client, request).await.1, Version::HTTP_2);

    // Warm both logical-origin pool keys and the native QUIC configuration cache.
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    assert_eq!(
        complete(&client, alternative.request()).await.1,
        Version::HTTP_3
    );
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 2);

    for request in [alternative.request(), origin.request()] {
        restricted.write_to(request.extensions());
        assert_eq!(complete(&client, request).await.1, Version::HTTP_3);
    }
    assert_eq!(
        alternative.accepted.load(Ordering::SeqCst),
        2,
        "foreign native settings must not prevent connection reuse"
    );

    // The same settings still restrict their owning stream provider, even with a warm pool.
    let request = origin.request();
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    restricted.write_to(request.extensions());
    assert!(
        timeout(TEST_TIMEOUT, client.serve(request))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(origin.request_count(), 1);

    // Check a fresh QUIC handshake as well as reuse of the resulting connection.
    for _ in 0..2 {
        let request = fresh.request();
        restricted.write_to(request.extensions());
        assert_eq!(complete(&client, request).await.1, Version::HTTP_3);
    }
    assert_eq!(fresh.accepted.load(Ordering::SeqCst), 1);

    // Portable trust restrictions apply to both providers and cannot reuse a warm pool.
    let (unrelated, _) = credentials();
    let common = TlsClientConfig::new()
        .try_with_server_trust_anchors(unrelated.cert_chain)
        .unwrap();
    for (request, version) in [
        (origin.request(), Version::HTTP_2),
        (alternative.request(), Version::HTTP_3),
    ] {
        request.extensions().insert(TargetHttpVersion(version));
        common.write_to(request.extensions());
        assert!(
            timeout(TEST_TIMEOUT, client.serve(request))
                .await
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(origin.request_count(), 1);
    assert_eq!(alternative.request_count(), 4);

    // Request-specific restrictions leave shared discovery usable.
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    drop(client);
    close_client_endpoint(endpoint).await;
    origin.close().await;
    alternative.close().await;
    fresh.close().await;
}

#[tokio::test]
async fn boring_stream_policy_is_independent_of_rustls_quic() {
    let (auth, tls) = credentials();
    let (unrelated, _) = credentials();
    let mut store = X509StoreBuilder::new().unwrap();
    for certificate in &unrelated.cert_chain {
        store
            .add_cert(X509::from_der(certificate).unwrap())
            .unwrap();
    }
    let restricted = TlsClientConfig::new().with_server_verify_cert_store(Arc::new(store.build()));
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth.clone(), Version::HTTP_3).await;
    let fresh = Server::start(auth, Version::HTTP_3).await;
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h3=\"{}\"", alternative.address),
    );
    let endpoint = Endpoint::bind_client(Executor::new(), SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let h3 = Http3Connector::builder(Executor::new())
        .with_endpoint(endpoint.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(default_tls_provider().unwrap())
        .build()
        .await
        .unwrap();
    let client = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_http_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector::<Body>(Executor::new())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .with_alt_svc_cache(cache)
        .map_connector(|mut connector| {
            connector
                .get_mut()
                .get_mut()
                .get_mut()
                .set_attempt_timeout(TEST_TIMEOUT);
            connector
        })
        .build_client();
    check_policy(client, endpoint, origin, alternative, fresh, restricted).await;
}

#[tokio::test]
async fn rustls_stream_policy_is_independent_of_boring_quic() {
    let (auth, tls) = credentials();
    let restricted = TlsClientConfig::new().with_modify_rustls_config(|_| {
        Err(BoxError::from_static_str(
            "request TLS policy rejects this connection",
        ))
    });
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth.clone(), Version::HTTP_3).await;
    let fresh = Server::start(auth, Version::HTTP_3).await;
    let cache = AltSvcCache::default();
    seed(
        &cache,
        &origin.origin(),
        &format!("h3=\"{}\"", alternative.address),
    );
    let endpoint = Endpoint::bind_client(Executor::new(), SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let h3 = Http3Connector::builder(Executor::new())
        .with_endpoint(endpoint.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build()
        .await
        .unwrap();
    let client = EasyHttpConnectorBuilder::new()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .with_http_proxy_support()
        .with_tls_support_using_rustls(tls)
        .with_default_http_connector::<Body>(Executor::new())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .with_alt_svc_cache(cache)
        .map_connector(|mut connector| {
            connector
                .get_mut()
                .get_mut()
                .get_mut()
                .set_attempt_timeout(TEST_TIMEOUT);
            connector
        })
        .build_client();
    check_policy(client, endpoint, origin, alternative, fresh, restricted).await;
}
