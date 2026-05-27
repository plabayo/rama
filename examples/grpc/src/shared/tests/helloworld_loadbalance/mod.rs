//! Integration test for the gRPC + `DnsLoadBalancerLayer` wiring.
//!
//! This test shows how to plug a custom [`DnsAddressResolver`] under a [`DnsLoadBalancerLayer`]
//! into an [`EasyHttpWebClient`] and use the result as the transport for a
//! [`GreeterClient`]. The transport is mocked via [`MockConnectorService`] and uses the
//! default connection pool.
//!
//! What the test proves:
//! 1. The LB picks a distinct backend per request in round-robin order.
//! 2. The default HTTP connection pool keys on `ConnectorTarget`, so 6 RPCs
//!    across 3 distinct IPs result in 3 transport connects, not 6.
//! 3. Each backend instance answers requests pinned to it for the lifetime of
//!    its pooled connection.

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use parking_lot::Mutex;
use rama::{
    Layer,
    dns::client::{
        lb::{DnsLoadBalancerConfig, DnsLoadBalancerLayer, RoundRobinPicker},
        resolver::DnsAddressResolver,
    },
    futures::{Stream, stream},
    http::{Uri, client::EasyHttpWebClient, server::HttpServer},
    layer::GetInputExtensionRefLayer,
    net::{
        address::{Domain, Host},
        client::ConnectorTarget,
        test_utils::client::MockConnectorService,
    },
    rt::Executor,
};

use crate::hello_world::{
    HelloRequest, RamaGreeter, greeter_client::GreeterClient, greeter_server::GreeterServer,
};

/// Static IPv4 resolver returning the three loopback addresses the LB
/// rotates across used only for this example.
#[derive(Clone)]
struct StaticV4Resolver(Vec<Ipv4Addr>);

impl DnsAddressResolver for StaticV4Resolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(self.0.clone().into_iter().map(Ok))
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn dns_lb_rotates_and_pool_reuses() {
    let ips = [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 0, 0, 2),
        Ipv4Addr::new(127, 0, 0, 3),
    ];

    let created_connections = Arc::new(AtomicU8::new(0));

    let mock = MockConnectorService::new(move || {
        let id = created_connections.fetch_add(1, Ordering::SeqCst);
        HttpServer::auto(Executor::default()).service(GreeterServer::new(RamaGreeter {
            instance_id: Some(id),
        }))
    });

    // capture all the requests we see on the transport connect level
    let captured_on_transport = Arc::new(Mutex::new(Vec::new()));
    let captured_on_transport_cl = captured_on_transport.clone();
    let transport = GetInputExtensionRefLayer::new(move |target: &ConnectorTarget| {
        if let Host::Address(ip) = &target.0.host {
            captured_on_transport_cl.lock().push(*ip);
        }
    })
    .into_layer(mock);

    let http_client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(transport)
        .without_tls_proxy_support()
        .without_proxy_support()
        .without_tls_support()
        .with_default_http_connector(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client();

    // Capture all the ips we see on http request level
    let captured_on_http = Arc::new(Mutex::new(Vec::new()));
    let captured_on_http_cl = captured_on_http.clone();
    let http_client = GetInputExtensionRefLayer::new(move |target: &ConnectorTarget| {
        if let Host::Address(ip) = &target.0.host {
            captured_on_http_cl.lock().push(*ip);
        }
    })
    .into_layer(http_client);

    let lb_config =
        DnsLoadBalancerConfig::from_parts(StaticV4Resolver(ips.to_vec()), RoundRobinPicker::new());
    let lb_http_client = DnsLoadBalancerLayer::new(lb_config).into_layer(http_client);

    let greeter = GreeterClient::new(
        lb_http_client,
        Uri::from_static("http://greeter.local:50051"),
    );

    let mut messages = Vec::new();
    for i in 0..6 {
        let reply = greeter
            .say_hello(HelloRequest {
                name: format!("rama-{i}"),
            })
            .await
            .unwrap()
            .into_inner();
        messages.push(reply.message);
    }

    // Pool reuse should result in only 3 transport connects across 6 calls
    assert_eq!(
        *captured_on_transport.lock(),
        vec![IpAddr::V4(ips[0]), IpAddr::V4(ips[1]), IpAddr::V4(ips[2])],
        "expected one connect per IP, in round-robin pick order",
    );
    assert_eq!(
        *captured_on_http.lock(),
        vec![
            IpAddr::V4(ips[0]),
            IpAddr::V4(ips[1]),
            IpAddr::V4(ips[2]),
            IpAddr::V4(ips[0]),
            IpAddr::V4(ips[1]),
            IpAddr::V4(ips[2])
        ],
        "expected two requests per IP, in round-robin pick order",
    );

    assert_eq!(
        messages,
        vec![
            "[instance=0] Hello rama-0!".to_owned(),
            "[instance=1] Hello rama-1!".to_owned(),
            "[instance=2] Hello rama-2!".to_owned(),
            "[instance=0] Hello rama-3!".to_owned(),
            "[instance=1] Hello rama-4!".to_owned(),
            "[instance=2] Hello rama-5!".to_owned(),
        ],
    );
}
