//! CONNECT-UDP (RFC 9298) between a Rama client and a Rama MASQUE proxy on every carrier:
//! HTTP/1.1, HTTP/2, HTTP/3 with DATAGRAM capsules and HTTP/3 with native QUIC datagrams.
//! Every target is a loopback UDP echo server.

use rama::{
    Layer as _, Service,
    error::extra::OpaqueError,
    extensions::ExtensionsRef as _,
    http::{
        Request, Response, StatusCode, Version,
        client::{EasyHttpWebClient, Http3Connector},
        conn::TargetHttpVersion,
        headers::{HeaderMapExt as _, ProxyErrorType, ProxyStatus},
        proto::ext::HttpDatagrams,
        server::HttpServer,
    },
    layer::AddInputExtensionLayer,
    net::{
        address::{ProxyAddress, ProxyPathTemplate, SocketAddress},
        mode::DnsResolveIpMode,
        tls::ApplicationProtocol,
    },
    proxy::masque::connect_udp::{
        ConnectUdpConnector, ConnectUdpService, ConnectUdpSocket, ConnectUdpTarget,
        DestinationScopePolicy, MAX_UDP_PAYLOAD, connect_udp_request,
    },
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::BoxService,
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    udp::{
        DatagramError, DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _,
        SendDatagram,
    },
};
use std::{io::ErrorKind, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

const DEADLINE: Duration = Duration::from_secs(30);

/// The carriers a tunnel can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    Http1,
    Http2,
    Http3Capsule,
    Http3Datagram,
}

impl Carrier {
    const ALL: [Self; 4] = [
        Self::Http1,
        Self::Http2,
        Self::Http3Capsule,
        Self::Http3Datagram,
    ];

    fn version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
            Self::Http3Capsule | Self::Http3Datagram => Version::HTTP_3,
        }
    }
}

struct Tasks(Vec<JoinHandle<()>>, Option<Endpoint>);

impl Drop for Tasks {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.1 {
            endpoint.close(0u32, b"test fixture dropped");
        }
        for task in &self.0 {
            task.abort();
        }
    }
}

/// A loopback UDP server answering every datagram with the same payload.
async fn udp_echo() -> (SocketAddress, Tasks) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = SocketAddress::from(socket.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            _ = socket.send_to(&buffer[..len], from).await;
        }
    });
    (address, Tasks(vec![task], None))
}

/// A MASQUE proxy on one TCP (HTTP/1.1, HTTP/2) and one UDP (HTTP/3) port.
async fn masque_proxy<P>(
    template: Option<&ProxyPathTemplate>,
    policy: P,
    h3_datagrams: bool,
) -> (SocketAddress, Tasks)
where
    P: rama::proxy::masque::connect_udp::ConnectUdpPolicy,
{
    let exec = Executor::new();
    // The fixtures listen on IPv4 loopback only.
    let service = AddInputExtensionLayer::new(DnsResolveIpMode::SingleIpV4).into_layer(
        ConnectUdpService::try_new(exec.clone(), template)
            .unwrap()
            .with_policy(policy),
    );
    let service = Arc::new(service);
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();

    let tls = TlsServerConfig::new()
        .with_server_auth(auth.clone())
        .with_alpn(
            [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11]
                .into_iter()
                .collect(),
        );
    let mut http = HttpServer::auto(exec.clone());
    http.h2_mut().set_enable_connect_protocol();
    let tcp = TlsAcceptorLayer::new(tls).into_layer(http.service(service.clone()));

    let mut h3 = HttpServer::new_http3(exec.clone());
    h3.http3_mut().extended_connect = true;
    if !h3_datagrams {
        h3.http3_mut().datagrams = None;
    }
    let mut transport = TransportConfig::default();
    h3.http3().configure_transport(&mut transport).unwrap();
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = ServerConfig::try_from_rama_tls_with_provider(
        &tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .unwrap();
    config.set_transport_config(Arc::new(transport));

    // The same port number for TCP and UDP, as clients expect of an HTTP/3 proxy.
    let (listener, endpoint) = loop {
        let listener = TcpListener::bind_address("127.0.0.1:0", exec.clone())
            .await
            .unwrap();
        let address = SocketAddress::from(listener.local_addr().unwrap());
        match Endpoint::build(exec.clone())
            .with_server_config(config.clone())
            .bind_address(address)
            .await
        {
            Ok(endpoint) => break (listener, endpoint),
            Err(DatagramError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                ) => {}
            Err(error) => panic!("{error}"),
        }
    };
    let address = SocketAddress::from(listener.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move { listener.serve(tcp).await });
    let quic_task = tokio::spawn(endpoint.clone().serve(Executor::new(), h3.service(service)));
    (address, Tasks(vec![tcp_task, quic_task], Some(endpoint)))
}

type Client = BoxService<Request, Response, OpaqueError>;

fn http_client(exec: Executor) -> Client {
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()
        .unwrap();
    EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(exec)
        .with_http3_support(h3)
        .with_default_connection_pool()
        .without_alt_svc()
        .build_client()
        .boxed()
}

fn proxy_address(scheme_and_template: &str, proxy: SocketAddress) -> ProxyAddress {
    let (scheme, template) = scheme_and_template
        .split_once("://")
        .unwrap_or((scheme_and_template, ""));
    ProxyAddress::try_from(format!("{scheme}://{proxy}{template}").as_str()).unwrap()
}

async fn echo(socket: &mut ConnectUdpSocket, payload: &[u8]) {
    let peer = rama::net::stream::Socket::peer_addr(socket).unwrap();
    socket
        .create_sender()
        .send(SendDatagram::new(peer, payload))
        .await
        .unwrap();
    let mut buffer = vec![0; 65536];
    let metadata = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
        .await
        .expect("echo within 5s")
        .unwrap();
    assert_eq!(&buffer[..metadata.len], payload);
    assert!(!metadata.truncated);
}

#[tokio::test]
async fn tunnels_relay_udp_on_every_carrier_and_template() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        // Client-side proxy address (scheme, template) and the proxy's own template.
        let templates: [(&str, Option<&str>); 3] = [
            ("masque://", None),
            (
                "https:///masque/{target_host}/{target_port}/",
                Some("/masque/{target_host}/{target_port}/"),
            ),
            (
                "https:///masque{?h,p}",
                Some("/masque?h={target_host}&p={target_port}"),
            ),
        ];
        for (client_template, server_template) in templates {
            for carrier in Carrier::ALL {
                let label = format!("{carrier:?} via {client_template}");
                let server_template =
                    server_template.map(|template| ProxyPathTemplate::try_new(template).unwrap());
                let (proxy, _proxy) = masque_proxy(
                    server_template.as_ref(),
                    DestinationScopePolicy::allow_private(),
                    carrier != Carrier::Http3Capsule,
                )
                .await;
                let client_template = match client_template {
                    "https:///masque{?h,p}" => "https:///masque?h={target_host}&p={target_port}",
                    template => template,
                };
                let proxy = proxy_address(client_template, proxy);
                let exec = Executor::new();
                let connector = ConnectUdpConnector::new(http_client(exec.clone()), exec);
                let mut socket = connector
                    .connect(
                        &proxy,
                        ConnectUdpTarget::new(
                            target.ip_addr.into(),
                            target.port.try_into().unwrap(),
                        ),
                        carrier.version(),
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{label}: {error}"));
                for payload in [&b"hello"[..], b"", &[7; 1000]] {
                    echo(&mut socket, payload).await;
                }
                if carrier == Carrier::Http3Datagram {
                    assert!(socket.max_payload() < 1500, "{label}: native datagrams");
                } else {
                    assert_eq!(socket.max_payload(), MAX_UDP_PAYLOAD, "{label}: capsules");
                    // Capsules carry what native QUIC datagrams cannot.
                    echo(&mut socket, &[9; 4000]).await;
                }
                assert_eq!(
                    socket.stats().received(),
                    if carrier == Carrier::Http3Datagram {
                        3
                    } else {
                        4
                    }
                );
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn names_resolve_at_the_proxy() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let (proxy, _proxy) =
            masque_proxy(None, DestinationScopePolicy::allow_private(), true).await;
        let exec = Executor::new();
        let connector = ConnectUdpConnector::new(http_client(exec.clone()), exec);
        for carrier in Carrier::ALL {
            let target =
                ConnectUdpTarget::from_template_values("localhost", &target.port.to_string())
                    .unwrap();
            let mut socket = connector
                .connect(
                    &proxy_address("masque://", proxy),
                    target,
                    carrier.version(),
                )
                .await
                .unwrap();
            echo(&mut socket, b"by name").await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn the_default_policy_refuses_loopback_with_proxy_status() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let (proxy, _proxy) = masque_proxy(None, DestinationScopePolicy::default(), true).await;
        let client = http_client(Executor::new());
        let proxy = proxy_address("masque://", proxy);
        for carrier in Carrier::ALL {
            let request = connect_udp_request(
                &proxy,
                &ConnectUdpTarget::new(target.ip_addr.into(), target.port.try_into().unwrap()),
                carrier.version(),
            )
            .unwrap();
            request.extensions().insert(HttpDatagrams);
            request
                .extensions()
                .insert(TargetHttpVersion(carrier.version()));
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{carrier:?}");
            let status: ProxyStatus = response.headers().typed_get().unwrap();
            assert_eq!(
                status.entries()[0].error,
                Some(ProxyErrorType::DestinationIpProhibited),
                "{carrier:?}"
            );
            assert_eq!(&*status.entries()[0].proxy, "127.0.0.1", "{carrier:?}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_paths_get_not_found() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let template = ProxyPathTemplate::try_new("/only/{target_host}/{target_port}").unwrap();
        let (proxy, _proxy) = masque_proxy(
            Some(&template),
            DestinationScopePolicy::allow_private(),
            true,
        )
        .await;
        let exec = Executor::new();
        let connector = ConnectUdpConnector::new(http_client(exec.clone()), exec);
        for carrier in Carrier::ALL {
            let error = connector
                .connect(
                    &proxy_address("masque://", proxy),
                    ConnectUdpTarget::new(target.ip_addr.into(), target.port.try_into().unwrap()),
                    carrier.version(),
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("404"), "{carrier:?}: {error}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn an_unreachable_target_closes_the_tunnel() {
    timeout(DEADLINE, async {
        // A port nothing listens on: the proxy's connected socket learns it is refused.
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddress::from(closed.local_addr().unwrap());
        drop(closed);
        let (proxy, _proxy) =
            masque_proxy(None, DestinationScopePolicy::allow_private(), true).await;
        let exec = Executor::new();
        let connector = ConnectUdpConnector::new(http_client(exec.clone()), exec);
        for carrier in Carrier::ALL {
            let mut socket = connector
                .connect(
                    &proxy_address("masque://", proxy),
                    ConnectUdpTarget::new(target.ip_addr.into(), target.port.try_into().unwrap()),
                    carrier.version(),
                )
                .await
                .unwrap();
            let peer = rama::net::stream::Socket::peer_addr(&socket).unwrap();
            let mut buffer = [0; 64];
            let mut sender = socket.create_sender();
            let ended = timeout(Duration::from_secs(10), async {
                loop {
                    // Keep sending until the refusal ends the relay and the tunnel with it.
                    if sender
                        .send(SendDatagram::new(peer, b"anyone?"))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tokio::select! {
                        result = socket.recv(&mut buffer) => {
                            assert!(result.is_err(), "{carrier:?}: unexpected answer");
                            break;
                        }
                        () = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                }
            })
            .await;
            assert!(ended.is_ok(), "{carrier:?}: tunnel stayed open");
        }
    })
    .await
    .unwrap();
}
