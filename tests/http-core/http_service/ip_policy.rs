//! Connection family constraints apply after resolution and service selection.

use super::{
    Server, TEST_TIMEOUT, client_with_http3_cache, close_client_endpoint, complete, credentials,
    seed,
};
use rama::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    futures::{
        StreamExt as _,
        stream::{self, BoxStream},
    },
    http::{
        StatusCode, Version, client::Http3Connector, conn::TargetHttpVersion,
        layer::alt_svc::AltSvcCache,
    },
    net::{
        Protocol,
        address::{Domain, Host, HostWithPort, SocketAddress},
        client::{
            AddressCandidates, ConnectRequest, ConnectionErrorDomain, ConnectionErrorKind,
            ConnectorTarget, ConnectorTargetStream,
        },
        mode::ConnectIpMode,
    },
    quic::Endpoint,
    rt::Executor,
};
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::Ordering,
};
use tokio::{net::UdpSocket, time::timeout};
#[cfg(feature = "boring")]
use {rama::quic::tls::BoringTlsProvider, std::sync::Arc};

struct FixedCandidates {
    domain: Domain,
    ip: IpAddr,
}

impl AddressCandidates for FixedCandidates {
    fn domain(&self) -> &Domain {
        &self.domain
    }

    fn stream<'a>(&'a self, _: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
        stream::iter([Ok(self.ip)]).boxed()
    }
}

#[tokio::test]
async fn h3_rejects_disallowed_literal_and_custom_candidates_before_sending() {
    let (_, tls) = credentials();
    for (family, mode) in [
        (SocketAddress::local_ipv4(0), ConnectIpMode::Ipv6),
        (SocketAddress::local_ipv6(0), ConnectIpMode::Ipv4),
    ] {
        let peer = UdpSocket::bind(SocketAddr::from(family)).await.unwrap();
        let address = peer.local_addr().unwrap();
        let endpoint = Endpoint::build(Executor::new())
            .bind_address(family)
            .await
            .unwrap();
        let builder = Http3Connector::builder(Executor::new())
            .with_endpoint(endpoint.clone())
            .with_tls_config(tls.clone());
        #[cfg(feature = "boring")]
        let builder = builder.with_tls_provider(Arc::new(BoringTlsProvider));
        let connector = builder.build().await.unwrap();
        for domain in [false, true] {
            let input = ConnectRequest::new(HostWithPort::example_domain_https())
                .with_application_protocol(Protocol::HTTPS);
            input.extensions().insert(mode);
            let target = if domain {
                let name = Domain::from_static("alt.example");
                input
                    .extensions()
                    .insert(ConnectorTargetStream::new(FixedCandidates {
                        domain: name.clone(),
                        ip: address.ip(),
                    }));
                HostWithPort::new(name.into(), address.port())
            } else {
                address.into()
            };
            input.extensions().insert(ConnectorTarget(target));
            let error = timeout(TEST_TIMEOUT, connector.serve(input))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.domain(), ConnectionErrorDomain::Local);
            assert_eq!(error.kind(), ConnectionErrorKind::InvalidInput);
            assert_eq!(
                peer.try_recv(&mut [0; 1]).unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
        }
        drop(connector);
        close_client_endpoint(endpoint).await;
    }
}

#[tokio::test]
async fn h3_alternatives_honor_connection_family_after_dns_and_literal_selection() {
    let (auth, tls) = credentials();
    let origin = Server::start(auth.clone(), Version::HTTP_3).await;
    let alternative = Server::start(auth, Version::HTTP_3).await;
    for host in [
        Host::from(Domain::from_static("localhost")),
        Host::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Host::from(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())),
    ] {
        for mode in [ConnectIpMode::Ipv4, ConnectIpMode::Ipv6] {
            let target = HostWithPort::new(host.clone(), alternative.address.port());
            let cache = AltSvcCache::default();
            seed(&cache, &origin.origin(), &format!("h3=\"{target}\""));
            let (client, endpoint) = client_with_http3_cache(tls.clone(), cache).await;
            let before = alternative.accepted.load(Ordering::SeqCst);
            let request = origin.request();
            request.extensions().insert(mode);
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            if mode == ConnectIpMode::Ipv4 {
                assert_eq!(
                    complete(&client, request).await,
                    (StatusCode::OK, Version::HTTP_3)
                );
                assert_eq!(alternative.accepted.load(Ordering::SeqCst), before + 1);
            } else {
                assert!(
                    timeout(TEST_TIMEOUT, client.serve(request))
                        .await
                        .unwrap()
                        .is_err()
                );
                assert_eq!(alternative.accepted.load(Ordering::SeqCst), before);
            }
            drop(client);
            close_client_endpoint(endpoint).await;
        }
    }
    origin.close().await;
    alternative.close().await;
}
