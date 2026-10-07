//! A server carrier may describe its logical peer and also keep metadata of an outbound leg
//! it uses (a reverse tunnel, say); that leg never becomes the HTTP client's address.

use rama_core::{
    ServiceInput,
    extensions::{Egress, Extensions, ExtensionsRef as _},
    service::service_fn,
};
use rama_http::{Body, Request, Response};
use rama_http_core::{server::conn::http1, service::RamaHttpService};
use rama_net::{client_ip::client_ip, stream::SocketInfo};
use std::{convert::Infallible, net::IpAddr, time::Duration};
use tokio::{io::AsyncWriteExt as _, sync::mpsc, time::timeout};

#[tokio::test]
async fn a_carriers_outbound_leg_never_becomes_the_client() {
    for egress_is_newer in [false, true] {
        let (mut client, carrier_io) = tokio::io::duplex(4096);
        let carrier = ServiceInput::new(carrier_io);
        let outbound_leg = Extensions::new();
        outbound_leg.insert(SocketInfo::new(None, "127.0.0.1:9000".parse().unwrap()));
        let logical_peer = SocketInfo::new(None, "203.0.113.5:1000".parse().unwrap());
        if egress_is_newer {
            carrier.extensions().insert(logical_peer);
            carrier.extensions().insert(Egress(outbound_leg));
        } else {
            carrier.extensions().insert(Egress(outbound_leg));
            carrier.extensions().insert(logical_peer);
        }

        let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
        let service = service_fn(move |request: Request| {
            observed_tx.send(client_ip(&request)).unwrap();
            async { Ok::<_, Infallible>(Response::new(Body::empty())) }
        });
        let server = tokio::spawn(async move {
            http1::Builder::new()
                .serve_connection(carrier, RamaHttpService::new(service))
                .await
        });
        timeout(
            Duration::from_secs(5),
            client.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"),
        )
        .await
        .unwrap()
        .unwrap();
        let observed = timeout(Duration::from_secs(5), observed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        server.abort();
        _ = server.await;
        assert_eq!(
            observed,
            Some("203.0.113.5".parse::<IpAddr>().unwrap()),
            "egress_is_newer={egress_is_newer}"
        );
    }
}
