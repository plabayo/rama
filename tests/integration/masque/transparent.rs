//! A client's own MASQUE connection crosses a transparent relay before its proxy.
use super::*;
use rama::{
    ServiceInput,
    http::{layer::upgrade::mitm::HttpUpgradeMitmRelayLayer, proxy::mitm::HttpMitmRelay},
    proxy::masque::connect_udp::mitm::{ConnectUdpMitmLayer, ConnectUdpRelayRequestMatcher},
    tls::{boring::proxy::TlsMitmRelay, server::PeekTlsClientHelloService},
};

async fn transparent(proxy: SocketAddress, intercepted: bool) -> (SocketAddress, Tasks) {
    let exec = Executor::new();
    let (ca, key) = generate_certificate_authority_x509(&SelfSignedCaConfig::default()).unwrap();
    let tls = TlsMitmRelay::new_cached_in_memory(ca, key);
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let count = MapInputLayer::new(move |request: Request| {
        counter.fetch_add(1, Ordering::SeqCst);
        request
    });
    let http = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        HttpUpgradeMitmRelayLayer::new(
            exec.clone(),
            ConnectUdpRelayRequestMatcher::default_with_exec(exec.clone()),
        ),
        count.clone(),
        ArcLayer::new(),
    ));
    let tcp = PeekTlsClientHelloService::new(tls.clone().into_layer(http));
    let h3 = Http3MitmRelay::new(exec.clone())
        .with_datagram_relay(rama::proxy::masque::connect_udp::mitm::relay(exec.clone()))
        .with_http_middleware((ConnectUdpMitmLayer::new(), count, ArcLayer::new()));
    let transport = Arc::new(masque_quic_transport());
    let quic = QuicMitmRelay::new(
        tls.issuer().clone(),
        exec.clone(),
        TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        VarInt::from_u32(0x101),
    )
    .with_ingress_transport(transport.clone())
    .with_egress_transport(transport)
    .into_layer(h3);
    type Association =
        BridgeIo<PrefixedDatagramSocket<DemuxedSocket<UdpPacketSender>>, UdpPacketSocket>;
    let forward =
        DatagramForwardService::new(NonZeroUsize::new(kib(64)).unwrap(), EcnPolicy::Discard);
    let route = service_fn(move |input: InputWithQuicClientHello<Association>| {
        let quic = quic.clone();
        async move {
            if intercepted {
                quic.serve(input).await
            } else {
                forward.serve(input.input).await.map_err(BoxError::from)
            }
        }
    });
    let inspect = PeekQuicClientHelloService::new(BoringTlsProvider, route);
    let bridge =
        AddInputExtensionLayer::new(ConnectorTarget(HostWithPort::from(proxy))).into_layer(
            DatagramToProxyBridge::new(inspect, HostWithPort::from(proxy)),
        );
    let (listener, socket) = loop {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        match UdpPacketSocket::bind(SocketAddress::from(listener.local_addr().unwrap())).await {
            Ok(socket) => break (listener, socket),
            Err(DatagramError::Io(error)) if error.kind() == ErrorKind::AddrInUse => {}
            Err(error) => panic!("{error}"),
        }
    };
    let address = SocketAddress::from(listener.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (ingress, _) = accepted.unwrap();
                    let tcp = tcp.clone();
                    connections.spawn(async move {
                        let egress = tokio::net::TcpStream::connect(std::net::SocketAddr::from(proxy)).await.unwrap();
                        if intercepted {
                            tcp.serve(BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress))).await.unwrap();
                        } else {
                            let _outcome = IoForwardService::default().serve(BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress))).await;
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => { result.unwrap(); }
            }
        }
    });
    let udp_task = tokio::spawn(async move {
        DatagramDemux::new(socket, demux_config())
            .serve(exec, bridge)
            .await
            .unwrap();
    });
    let mut tasks = Tasks::new(vec![tcp_task, udp_task], None);
    tasks.requests = requests;
    (address, tasks)
}

#[tokio::test]
async fn own_masque_sessions_survive_transparent_interception_and_passthrough() {
    timeout(Duration::from_secs(120), async {
        let (origin, _origin) = h3_origin().await;
        let template = ProxyPathTemplate::try_new("/custom{?target_host,target_port}").unwrap();
        for carrier in Carrier::ALL {
            let (proxy, proxy_tasks) = masque_proxy_with(
                Some(&template),
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
                ProxyAuth::Basic,
                QuicTls::Boring,
            )
            .await;
            for intercepted in [false, true] {
                let (front, front_tasks) = transparent(proxy, intercepted).await;
                let address = ProxyAddress::try_from(
                    format!("masque://john:secret@{front}/custom{{?target_host,target_port}}")
                        .as_str(),
                )
                .unwrap();
                for run in 0..10 {
                    eprintln!("carrier={carrier:?}, intercepted={intercepted}, run={run}");
                    let client = tunneling_client(Executor::new(), carrier.version());
                    assert_eq!(
                        get_through(&client, &format!("localhost:{}", origin.port), &address).await,
                        "HTTP/3.0 origin"
                    );
                    drop(client);
                    timeout(Duration::from_secs(10), async {
                        while proxy_tasks.proxy.as_ref().unwrap().active() != 0 {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .unwrap_or_else(|_| {
                        panic!("{carrier:?}, intercepted={intercepted}, run={run}: tunnel leaked")
                    });
                }
                assert_eq!(
                    front_tasks.requests.load(Ordering::SeqCst),
                    if intercepted { 10 } else { 0 }
                );
            }
        }
    })
    .await
    .unwrap();
}
