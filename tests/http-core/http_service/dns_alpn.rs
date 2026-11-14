//! DNS selects the transport without pinning stream ALPN or losing pool reuse.

use super::*;
use rama::http::conn::{HttpServiceCandidate, HttpServiceCandidates, HttpServiceSource};

#[tokio::test]
async fn dns_stream_negotiates_and_reuses_either_http_version() {
    for (version, offered, advertise_alpn) in [
        (
            Version::HTTP_2,
            vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            true,
        ),
        (
            Version::HTTP_11,
            vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            true,
        ),
        // Request/profile ALPN ordering must survive discovery unchanged.
        (
            Version::HTTP_2,
            vec![ApplicationProtocol::HTTP_11, ApplicationProtocol::HTTP_2],
            true,
        ),
        (
            Version::HTTP_11,
            vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
            false,
        ),
    ] {
        let (auth, tls) = credentials();
        let server = Server::start_with_alpn(auth, version, advertise_alpn).await;
        let builder = EasyHttpConnectorBuilder::new()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .with_http_proxy_support();
        #[cfg(feature = "boring")]
        let builder =
            builder.with_tls_support_using_boringssl_and_default_http_version(tls, Version::HTTP_3);
        #[cfg(not(feature = "boring"))]
        let builder =
            builder.with_tls_support_using_rustls_and_default_http_version(tls, Version::HTTP_3);
        let client = builder
            .with_default_http_connector::<Body>(WeakScope::detached())
            .with_default_connection_pool()
            .build_client();
        for _ in 0..2 {
            let request = server.request();
            if offered[0] == ApplicationProtocol::HTTP_11 {
                TlsClientConfig::new()
                    .with_alpn(offered.iter().cloned().collect())
                    .write_to(request.extensions());
            }
            // Deliberately prefer the opposite protocol: the TLS server decides.
            let preferred = if version == Version::HTTP_2 {
                ApplicationProtocol::HTTP_11
            } else {
                ApplicationProtocol::HTTP_2
            };
            request.extensions().insert(
                HttpServiceCandidates::new(
                    server.origin(),
                    [
                        HttpServiceCandidate::new(preferred, server.origin().authority().clone())
                            .with_source(HttpServiceSource::Https),
                    ],
                )
                .with_origin_fallback(false),
            );
            assert_eq!(complete(&client, request).await.1, version);
        }
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        for observed in server.observations.lock().iter() {
            assert_eq!(observed.alpn, offered);
            assert!(observed.alt_used.is_none());
        }
        drop(client);
        server.close().await;
    }
}
