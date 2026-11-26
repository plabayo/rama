use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use rama::{
    Service as _,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    http::{
        conn::HttpOrigin,
        layer::{alt_svc::AltSvcCache, http_service::HttpServiceConnector},
    },
    net::{
        Protocol,
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
        },
        tls::ApplicationProtocol,
    },
    quic::{
        client::{ClientEndpoint, QuicConnector},
        tls::BoringTlsProvider,
    },
    service::service_fn,
    tls::client::{EchRequirement, TlsClientConfig},
};

#[tokio::test]
async fn caller_required_ech_failure_does_not_poison_alt_svc() {
    let cache = AltSvcCache::default();
    let input = ConnectRequest::new("127.0.0.1:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    let origin = HttpOrigin::new(Protocol::HTTPS, input.authority.clone()).unwrap();
    cache.record_frame(
        &origin,
        Bytes::from_static(b"h3=\"127.0.0.2:443\""),
        Instant::now(),
    );
    let snapshot = cache.lookup(&origin).unwrap();
    input.extensions().insert(EchRequirement::Required);
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoints = service_fn({
        let calls = calls.clone();
        move |_: ConnectRequest| {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<EstablishedClientConnection<ClientEndpoint, ConnectRequest>, _>(
                    ConnectionError::local(
                        BoxError::from_static_str("unexpected endpoint"),
                        ConnectionErrorKind::InvalidInput,
                    ),
                )
            }
        }
    });
    let connector = QuicConnector::new(
        endpoints,
        TlsClientConfig::new().with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect()),
        Arc::new(BoringTlsProvider::new()),
    );
    let error = HttpServiceConnector::new(connector)
        .with_cache(cache.clone())
        .serve(input)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(cache.is_usable(&snapshot, 0));
}
