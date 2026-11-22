//! DNS selects the transport without pinning stream ALPN or losing pool reuse.

use super::*;
use rama::http::conn::{HttpServiceCandidate, HttpServiceCandidates, HttpServiceSource};
use rama::{
    dns::client::{DnsAddressSource, resolver::DnsAddressResolver},
    futures::{Stream, stream},
    net::{address::Domain, client::ConnectorTargetStream, mode::DnsResolveIpMode},
};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
struct CountingResolver(Arc<AtomicUsize>);

impl DnsAddressResolver for CountingResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
        assert_eq!(domain.as_str(), "selected.example");
        self.0.fetch_add(1, Ordering::SeqCst);
        stream::iter([Ok(Ipv4Addr::LOCALHOST)])
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
        panic!("the current request selects IPv4 only");
        #[expect(unreachable_code)]
        stream::empty()
    }
}

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
        let builder = EasyHttpWebClient::connector_builder(WeakScope::detached())
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_proxy_support();
        #[cfg(feature = "boring")]
        let builder =
            builder.with_tls_support_using_boringssl_and_default_http_version(tls, Version::HTTP_3);
        #[cfg(not(feature = "boring"))]
        let builder =
            builder.with_tls_support_using_rustls_and_default_http_version(tls, Version::HTTP_3);
        let client = builder
            .with_default_http_connector()
            .with_default_connection_pool()
            .build_client();
        let resolver = CountingResolver::default();
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
            request.extensions().insert(DnsResolveIpMode::SingleIpV4);
            let candidates = ["selected.example", "unused.example"].map(|name| {
                let domain = Domain::from_static(name);
                let target = HostWithPort::new(domain.clone().into(), server.address.port());
                let extensions = Extensions::new();
                extensions.insert(ConnectorTargetStream::new(
                    target.clone(),
                    DnsAddressSource::new(resolver.clone(), domain),
                ));
                (
                    HttpServiceCandidate::new(preferred.clone(), target)
                        .with_source(HttpServiceSource::Https),
                    extensions,
                )
            });
            request.extensions().insert(
                HttpServiceCandidates::new_with_extensions(server.origin(), candidates)
                    .with_origin_fallback(false),
            );
            assert_eq!(complete(&client, request).await.1, version);
        }
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        // The second request uses the pool; the unused candidate is never resolved.
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
        for observed in server.observations.lock().iter() {
            assert_eq!(observed.alpn, offered);
            assert!(observed.alt_used.is_none());
        }
        drop(client);
        server.close().await;
    }
}
