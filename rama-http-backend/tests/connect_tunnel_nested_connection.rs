//! A server-accepted HTTP CONNECT tunnel is a connection nested on the proxy connection:
//! what is served inside it does not see facts about the proxy connection.

#![cfg(feature = "tls")]
#![expect(
    clippy::unwrap_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{convert::Infallible, time::Duration};

use rama_core::{
    Layer as _, Service as _, ServiceInput,
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef, NestedConnectionTransfer},
    graceful::WeakScope,
    io::BridgeIo,
    service::service_fn,
};
use rama_http::{
    io::upgrade::handle_upgrade,
    layer::upgrade::{
        EagerHttpProxyConnector, LazyHttpProxyConnectReplyService, UpgradeLayer, Upgraded,
    },
    matcher::MethodMatcher,
};
use rama_http_backend::server::HttpServer;
use rama_http_core::client::conn as client_conn;
use rama_http_types::{Body, Method, Request, Response, StatusCode, body::util::BodyExt as _};
use rama_net::{
    ProtocolInputExt as _,
    client::{ConnectRequest, EstablishedClientConnection},
    stream::DefaultConnectionTransfer,
    uri::Uri,
};
use rama_tls::SecureTransport;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Extension)]
#[extension(scope(connection))]
struct ProxyConnFact;

#[derive(Debug, Clone, Copy, Extension)]
struct ProxyFlowFact;

/// What the request served inside the tunnel observed.
fn observe(req: &Request) -> String {
    let ext = req.extensions();
    format!(
        "protocol={} secure={} conn_fact={} flow_fact={}",
        req.protocol().unwrap(),
        ext.contains::<SecureTransport>(),
        ext.contains::<ProxyConnFact>(),
        ext.contains::<ProxyFlowFact>(),
    )
}

fn inner_http_server() -> impl rama_core::Service<Upgraded, Output = (), Error = BoxError> + Clone {
    service_fn(async |upgraded: Upgraded| {
        HttpServer::new_http1(WeakScope::detached())
            .serve(
                upgraded,
                service_fn(async |req: Request| {
                    Ok::<_, Infallible>(Response::new(Body::from(observe(&req))))
                }),
            )
            .await
    })
}

/// A proxy connection accepted on a TLS listener, carrying a connection and a flow fact.
fn tls_proxy_connection(io: tokio::io::DuplexStream) -> ServiceInput<tokio::io::DuplexStream> {
    let io = ServiceInput::new(io);
    io.extensions.insert(SecureTransport::default());
    io.extensions.insert(ProxyConnFact);
    io.extensions.insert(ProxyFlowFact);
    io
}

/// CONNECT through the proxy, then send one cleartext request inside the tunnel.
async fn request_inside_tunnel(client_io: tokio::io::DuplexStream) -> String {
    let (mut sender, conn) = client_conn::http1::handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    tokio::spawn(conn.with_upgrades());
    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri(Uri::parse_authority_form("example.com:80").unwrap())
        .body(Body::empty())
        .unwrap();
    let response = timeout(WAIT, sender.send_request(connect))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tunnel = timeout(WAIT, handle_upgrade(&response))
        .await
        .unwrap()
        .unwrap();

    let (mut sender, conn) = client_conn::http1::handshake(tunnel).await.unwrap();
    tokio::spawn(conn);
    let request = Request::builder()
        .uri("/")
        .header("host", "example.com")
        .body(Body::empty())
        .unwrap();
    let response = timeout(WAIT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

fn serve_lazy_connect_proxy(
    server_io: ServiceInput<tokio::io::DuplexStream>,
    layer: UpgradeLayer<Response>,
) {
    let svc = layer.into_layer(service_fn(async |_req: Request| {
        Ok::<_, Infallible>(Response::new(Body::empty()))
    }));
    tokio::spawn(async move {
        HttpServer::new_http1(WeakScope::detached())
            .serve(server_io, svc)
            .await
    });
}

fn lazy_connect_layer() -> UpgradeLayer<Response> {
    UpgradeLayer::new_with_services(
        WeakScope::detached(),
        MethodMatcher::CONNECT,
        LazyHttpProxyConnectReplyService::new(),
        inner_http_server(),
    )
}

#[tokio::test]
async fn cleartext_request_inside_tunnel_on_tls_listener_is_http() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    serve_lazy_connect_proxy(tls_proxy_connection(server_io), lazy_connect_layer());

    let observed = request_inside_tunnel(client_io).await;

    assert!(observed.contains("protocol=http "), "{observed}");
    assert!(observed.contains("secure=false"), "{observed}");
}

#[tokio::test]
async fn tunnel_keeps_flow_facts_and_drops_connection_facts() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    serve_lazy_connect_proxy(tls_proxy_connection(server_io), lazy_connect_layer());

    let observed = request_inside_tunnel(client_io).await;

    assert!(observed.contains("conn_fact=false"), "{observed}");
    assert!(observed.contains("flow_fact=true"), "{observed}");
}

#[tokio::test]
async fn custom_transfer_carries_a_chosen_fact_into_the_tunnel() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let carry = |outer: &Extensions, nested: &Extensions| {
        if outer.contains::<ProxyConnFact>() {
            nested.insert(ProxyConnFact);
        }
    };
    let layer =
        lazy_connect_layer().with_nested_connection_transfer(DefaultConnectionTransfer.and(carry));
    serve_lazy_connect_proxy(tls_proxy_connection(server_io), layer);

    let observed = request_inside_tunnel(client_io).await;

    assert!(observed.contains("conn_fact=true"), "{observed}");
    assert!(observed.contains("secure=false"), "{observed}");
}

#[tokio::test]
async fn eager_connect_tunnel_is_nested_too() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let egress = service_fn(async |req: ConnectRequest| {
        let (io, _peer) = tokio::io::duplex(1024);
        Ok::<_, BoxError>(EstablishedClientConnection {
            input: req,
            conn: ServiceInput::new(io),
        })
    });
    let relay = service_fn(
        async |BridgeIo(ingress, _egress): BridgeIo<
            Upgraded,
            ServiceInput<tokio::io::DuplexStream>,
        >| { inner_http_server().serve(ingress).await },
    );
    let layer = UpgradeLayer::new(
        WeakScope::detached(),
        MethodMatcher::CONNECT,
        EagerHttpProxyConnector::new(egress, relay),
    );
    serve_lazy_connect_proxy(tls_proxy_connection(server_io), layer);

    let observed = request_inside_tunnel(client_io).await;

    assert!(observed.contains("protocol=http "), "{observed}");
    assert!(observed.contains("conn_fact=false"), "{observed}");
    assert!(observed.contains("flow_fact=true"), "{observed}");
}
