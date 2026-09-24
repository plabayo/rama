//! Provider-specific trust settings must not disappear when discovery selects H3.

use super::{Server, TEST_TIMEOUT, close_client_endpoint, complete, credentials, seed};
use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    http::{
        Body, Request, Response, Version,
        client::{EasyHttpConnectorBuilder, Http3Connector},
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
    restricted: TlsClientConfig,
) {
    // Warm both logical-origin pool keys and the native configuration cache first.
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    assert_eq!(
        complete(&client, alternative.request()).await.1,
        Version::HTTP_3
    );
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 2);

    for request in [alternative.request(), origin.request()] {
        restricted.write_to(request.extensions());
        assert!(
            timeout(TEST_TIMEOUT, client.serve(request))
                .await
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(
        alternative.request_count(),
        2,
        "neither a pool hit nor a new handshake may ignore the native restriction"
    );
    assert_eq!(
        origin.request_count(),
        0,
        "the stream provider must enforce the restriction after discovery falls back"
    );

    // Request-specific incompatibility must leave shared discovery and pooling usable.
    assert_eq!(complete(&client, origin.request()).await.1, Version::HTTP_3);
    assert_eq!(alternative.accepted.load(Ordering::SeqCst), 2);
    drop(client);
    close_client_endpoint(endpoint).await;
    origin.close().await;
    alternative.close().await;
}

#[tokio::test]
async fn boring_request_trust_cannot_be_bypassed_by_rustls_quic() {
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
    let alternative = Server::start(auth, Version::HTTP_3).await;
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
    check_policy(client, endpoint, origin, alternative, restricted).await;
}

#[tokio::test]
async fn rustls_request_hook_cannot_be_bypassed_by_boring_quic() {
    let (auth, tls) = credentials();
    let restricted = TlsClientConfig::new().with_modify_rustls_config(|_| {
        Err(BoxError::from_static_str(
            "request TLS policy rejects this connection",
        ))
    });
    let origin = Server::start(auth.clone(), Version::HTTP_2).await;
    let alternative = Server::start(auth, Version::HTTP_3).await;
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
    check_policy(client, endpoint, origin, alternative, restricted).await;
}
