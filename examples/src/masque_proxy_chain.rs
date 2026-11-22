//! A two-hop proxy chain over MASQUE: the client reaches the origin through proxy B, and
//! proxy B through proxy A.
//!
//! Hop A knows who the client is, but only carries an encrypted QUIC connection to hop B.
//! Hop B sees where the client goes, but only that hop A asks for it. Neither knows both.
//! This is the idea behind Apple's iCloud Private Relay.
//!
//! Every tunnel runs inside the one before it:
//!
//! ```text
//! QUIC to hop A
//! └─ CONNECT-UDP to hop B
//!    └─ QUIC to hop B
//!       └─ CONNECT (for TCP) or CONNECT-UDP (for QUIC) to the origin
//!          └─ TLS or QUIC to the origin
//!             └─ HTTP request
//! ```
//!
//! Each hop is the proxy of the `masque_connect_udp_proxy` example.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin masque_proxy_chain --features=http-full,boring
//! ```
//!
//! # Expected output
//!
//! ```text
//! hop a: CONNECT https://127.0.0.1:62051/.well-known/masque/udp/127.0.0.1/62052/ HTTP/3.0
//! hop b: CONNECT 127.0.0.1:62053 HTTP/3.0
//! origin answered over HTTP/2.0: hello through two hops
//! hop a: CONNECT https://127.0.0.1:62051/.well-known/masque/udp/127.0.0.1/62052/ HTTP/3.0
//! hop b: CONNECT https://127.0.0.1:62052/.well-known/masque/udp/127.0.0.1/62053/ HTTP/3.0
//! origin answered over HTTP/3.0: hello through two hops
//! ```

#![recursion_limit = "256"]
#![expect(
    clippy::print_stdout,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer as _, Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    graceful::{Scope, WeakScope},
    http::{
        Body, BodyExtractExt as _, Request, Response, Version,
        client::{
            EasyHttpWebClient, Http3Connector, HttpConnectRequestAdapter, HttpConnector,
            builder::NoTcpConnector, masque_quic_transport,
            proxy::layer::HttpConnectProxyConnector,
        },
        conn::TargetHttpVersion,
        layer::{
            upgrade::{EagerHttpProxyConnector, UpgradeLayer},
            version_adapter::RequestVersionAdapter,
        },
        proxy::{HttpProxyConnectMatcher, ProxyRequestBody},
        server::HttpServer,
        service::web::response::IntoResponse as _,
    },
    layer::MapInputLayer,
    net::{
        address::{ProxyAddress, SocketAddress},
        client::{ProxyConnectionExtensions, ProxyRoute},
        proxy::IoForwardService,
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{
        ConnectUdpService, ConnectUdpSocketConfig, DestinationScopePolicy,
        HttpConnectUdpProxyConnector,
    },
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        client::{QuicEndpointConnector, SharedQuicEndpoint},
        tls::TlsOptions,
    },
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::{
        boring::{client::TlsConnector, server::TlsAcceptorLayer},
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use std::{convert::Infallible, sync::Arc};

const HOP_A: &str = "127.0.0.1:62051";
const HOP_B: &str = "127.0.0.1:62052";
const ORIGIN: &str = "127.0.0.1:62053";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let scope = Scope::new();
    let weak = scope.clone_weak();
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;

    // Hop A and hop B over QUIC, the origin over TCP and over QUIC.
    let hop_a = bind_quic(weak.clone(), HOP_A, auth.clone(), masque_quic_transport()).await?;
    let hop_b = bind_quic(weak.clone(), HOP_B, auth.clone(), masque_quic_transport()).await?;
    let origin = TcpListener::build(weak.clone())
        .bind_address(ORIGIN)
        .await?;
    let origin_quic = bind_quic(
        weak.clone(),
        ORIGIN,
        auth.clone(),
        TransportConfig::default(),
    )
    .await?;
    let hop_a_service = hop_service(weak.clone(), "hop a")?;
    let hop_b_service = hop_service(weak.clone(), "hop b")?;
    scope.spawn_task(serve_hop(weak.clone(), hop_a, hop_a_service));
    scope.spawn_task(serve_hop(weak.clone(), hop_b, hop_b_service));
    scope.spawn_task(serve_origin(weak.clone(), origin, auth));
    scope.spawn_task(serve_origin_over_quic(weak.clone(), origin_quic));

    let client = chain_client(weak)?;

    // HTTP to the origin: TLS end to end, in a CONNECT tunnel through hop B.
    let request = Request::builder()
        .uri(format!("https://{ORIGIN}/"))
        .body(Body::empty())?;
    through_chain(&request, &format!("h3://{HOP_B}"))?;
    print_answer(&client, request).await?;

    // HTTP/3 to the origin: QUIC end to end, in a CONNECT-UDP tunnel through hop B.
    let request = Request::builder()
        .version(Version::HTTP_3)
        .uri(format!("https://{ORIGIN}/"))
        .body(Body::empty())?;
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_3));
    through_chain(&request, &format!("h3+udp://{HOP_B}"))?;
    print_answer(&client, request).await?;

    Ok(())
}

/// Route `request` through hop B at `hop_b`, and its connection to hop B through hop A.
fn through_chain(request: &Request, hop_b: &str) -> Result<(), BoxError> {
    let to_hop_b = Extensions::new();
    to_hop_b.insert(ProxyRoute::Proxy(ProxyAddress::try_from(
        format!("h3+udp://{HOP_A}").as_str(),
    )?));
    request
        .extensions()
        .insert(ProxyRoute::Proxy(ProxyAddress::try_from(hop_b)?));
    request
        .extensions()
        .insert(ProxyConnectionExtensions(to_hop_b));
    Ok(())
}

/// Each hop is the same stack: a transport to the proxy, HTTP over it, and a tunnel
/// method through it. The tunnels of hop A are the transport to hop B, and the tunnels of
/// hop B the transport to the origin.
fn chain_client(
    scope: WeakScope,
) -> Result<impl Service<Request, Output = Response, Error: Into<BoxError>>, BoxError> {
    // The hops and the origin use a generated certificate.
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);

    // Hop A: HTTP/3 over QUIC on UDP; CONNECT-UDP through it. Its QUIC needs room for the
    // QUIC packets it tunnels.
    let h3_to_a = Http3Connector::builder(scope.clone())
        .with_endpoints(SharedQuicEndpoint::managed(scope.clone()))
        .with_tls_config(tls.clone())
        .with_transport(masque_quic_transport())
        .build_lazy()?;
    let http_to_a =
        HttpConnector::<_, ProxyRequestBody<Body>>::new(NoTcpConnector::default(), scope.clone())
            .with_http3_connector(h3_to_a);
    // Hop A sends packets of its QUIC transport's size, which leaves room in the tunnel for
    // the QUIC packets hop B tunnels in turn.
    let udp_through_a = HttpConnectUdpProxyConnector::new(http_to_a, scope.clone())
        .with_socket_config(
            ConnectUdpSocketConfig::default()
                .with_proxy_packet_size(masque_quic_transport().get_initial_mtu()),
        );

    // Hop B: HTTP/3 over QUIC on hop A's CONNECT-UDP tunnels; CONNECT and CONNECT-UDP
    // through it.
    let h3_to_b = Http3Connector::builder(scope.clone())
        .with_endpoints(QuicEndpointConnector::new(udp_through_a, scope.clone()))
        .with_tls_config(tls.clone())
        .with_transport(masque_quic_transport())
        .build_lazy()?;
    let http_to_b =
        HttpConnector::<_, ProxyRequestBody<Body>>::new(NoTcpConnector::default(), scope.clone())
            .with_http3_connector(h3_to_b);
    let tcp_through_b = HttpConnectProxyConnector::new(http_to_b.clone());
    let udp_through_b = HttpConnectUdpProxyConnector::new(http_to_b, scope.clone());

    // The origin: HTTP over TLS on hop B's CONNECT tunnel, or HTTP/3 over QUIC on hop B's
    // CONNECT-UDP tunnels. The request takes the HTTP version its connection speaks.
    let h3_to_origin = Http3Connector::builder(scope.clone())
        .with_endpoints(QuicEndpointConnector::new(udp_through_b, scope.clone()))
        .with_tls_config(tls.clone())
        .build_lazy()?;
    let to_origin = HttpConnector::new(
        TlsConnector::secure(tcp_through_b).with_base_config(tls),
        scope,
    )
    .with_http3_connector(h3_to_origin);
    // The HTTP/3 leg dials a protocol-independent connect request, which the adapter makes
    // of the HTTP request.
    Ok(EasyHttpWebClient::new(RequestVersionAdapter::new(
        HttpConnectRequestAdapter::new(to_origin),
    )))
}

async fn print_answer<S>(client: &S, request: Request) -> Result<(), BoxError>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    let response = client.serve(request).await.map_err(Into::into)?;
    let version = response.version();
    println!(
        "origin answered over {version:?}: {}",
        response.into_body().try_into_string().await?
    );
    Ok(())
}

async fn bind_quic(
    scope: WeakScope,
    address: &str,
    auth: ServerAuthData,
    transport: TransportConfig,
) -> Result<Endpoint, BoxError> {
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut transport = transport;
    HttpServer::new_http3(scope.clone())
        .http3()
        .configure_transport(&mut transport)?;
    let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
    config.set_transport_config(Arc::new(transport));
    Ok(Endpoint::build(scope)
        .with_server_config(config)
        .bind_address(address.parse::<SocketAddress>()?)
        .await?)
}

/// CONNECT-UDP for UDP targets and CONNECT for TCP ones, printing what the hop sees.
fn hop_service(
    scope: WeakScope,
    name: &'static str,
) -> Result<impl Service<Request, Output = Response, Error = Infallible> + Clone, BoxError> {
    let connect_udp = ConnectUdpService::try_new(scope.clone(), None)?
        .with_policy(DestinationScopePolicy::allow_private());
    let service = (
        MapInputLayer::new(move |request: Request| {
            println!(
                "{name}: {} {} {:?}",
                request.method(),
                request.uri(),
                request.version()
            );
            request
        }),
        UpgradeLayer::new(
            scope.clone(),
            HttpProxyConnectMatcher::new(),
            EagerHttpProxyConnector::new(TcpConnector::new(), IoForwardService::new(scope)),
        ),
    )
        .into_layer(connect_udp);
    Ok(Arc::new(service))
}

async fn serve_hop<S>(scope: WeakScope, endpoint: Endpoint, service: S)
where
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let mut h3 = HttpServer::new_http3(scope.clone());
    h3.http3_mut().extended_connect = true;
    endpoint.serve(scope, h3.service(service)).await;
}

async fn serve_origin_over_quic(scope: WeakScope, endpoint: Endpoint) {
    let h3 = HttpServer::new_http3(scope.clone());
    endpoint.serve(scope, h3.service(service_fn(origin))).await;
}

async fn origin(_: Request) -> Result<Response, Infallible> {
    Ok("hello through two hops".into_response())
}

async fn serve_origin(scope: WeakScope, listener: TcpListener, auth: ServerAuthData) {
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn_http_auto();
    let http = HttpServer::auto(scope).service(service_fn(origin));
    listener
        .serve(TlsAcceptorLayer::new(tls).into_layer(http))
        .await;
}
