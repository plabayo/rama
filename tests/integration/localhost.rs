//! `localhost` reaches a listener bound to 127.0.0.1 only, however often and concurrently it
//! is dialed, also with a resolver overwrite in place.

use rama::{
    Service,
    dns::client::{DnsConnector, EmptyDnsResolver, resolver::DnsAddresssResolverOverwrite},
    extensions::ExtensionsRef as _,
    futures::future::join_all,
    net::{
        address::{Domain, Host, HostWithPort},
        client::{ConnectRequest, EstablishedClientConnection},
        stream::SocketInfo,
    },
    tcp::client::service::TcpConnector,
};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;

async fn dial_localhost(port: u16, overwrite: bool) -> SocketAddr {
    let request = ConnectRequest::new(HostWithPort::new(Host::Name(Domain::tld_localhost()), port));
    if overwrite {
        // Answers nothing: `localhost` stays on loopback without asking any resolver.
        request
            .extensions
            .insert(DnsAddresssResolverOverwrite::new(EmptyDnsResolver::new()));
    }
    let EstablishedClientConnection { conn, .. } = DnsConnector::new(TcpConnector::new())
        .serve(request)
        .await
        .expect("dial localhost");
    conn.extensions()
        .get_ref::<SocketInfo>()
        .expect("socket info")
        .peer_addr()
        .into()
}

#[tokio::test]
async fn localhost_reaches_an_ipv4_only_listener() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        loop {
            drop(listener.accept().await);
        }
    });

    for overwrite in [false, true] {
        for _ in 0..200 {
            assert_eq!(dial_localhost(address.port(), overwrite).await, address);
        }
        let concurrent = join_all((0..32).map(|_| dial_localhost(address.port(), overwrite))).await;
        assert!(
            concurrent.iter().all(|peer| *peer == address),
            "{concurrent:?}"
        );
    }
    accept.abort();
}
