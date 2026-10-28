//! Real UDP H3 relay captures. Only short-header bits are retained.
use super::*;
use parking_lot::Mutex;

struct Capture {
    bits: Arc<Mutex<Vec<(bool, bool)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Capture {
    fn check(&self, enabled: bool) {
        let bits = self.bits.lock();
        for server in [false, true] {
            let direction: Vec<_> = bits
                .iter()
                .filter(|(from_server, _)| *from_server == server)
                .map(|(_, spin)| *spin)
                .collect();
            assert!(direction.len() >= 16);
            if enabled {
                assert!(direction.contains(&false) && direction.contains(&true));
            }
        }
    }
}

async fn captured_hop(allow: [bool; 2]) -> (Endpoint, Endpoint, Connection, Connection, Capture) {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let server_tls = TlsServerConfig::new()
        .with_alpn([b"h3".as_slice().into()].into_iter().collect())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn([b"h3".as_slice().into()].into_iter().collect())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let options = TlsOptions::default().with_early_data(false);
    let server_config = ServerConfig::try_from_rama_tls(&server_tls, options)
        .unwrap()
        .with_transport_config(Arc::new(
            TransportConfig::default().with_allow_spin(allow[1]),
        ));
    let client_config = ClientConfig::try_from_rama_tls(&client_tls, options)
        .unwrap()
        .with_transport_config(Arc::new(
            TransportConfig::default().with_allow_spin(allow[0]),
        ));
    for seed in 0u8..=255 {
        let config = |seed| {
            rama_quic::EndpointConfig::try_with_rand_key()
                .unwrap()
                .with_rng_seed([seed; 32])
        };
        let server_endpoint = Endpoint::build(Executor::new())
            .with_config(config(seed.wrapping_add(64)))
            .with_server_config(server_config.clone())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let client_endpoint = Endpoint::build(Executor::new())
            .with_config(config(seed))
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let origin = server_endpoint.local_addr().unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let bits = Arc::new(Mutex::new(Vec::new()));
        let trace = bits.clone();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut bytes = [0; 65536];
            loop {
                let (len, from) = socket.recv_from(&mut bytes).await.unwrap();
                let from_server = from == origin;
                let to = if from_server {
                    client.unwrap()
                } else {
                    client = Some(from);
                    origin
                };
                // The endpoints assert negotiated v1 below. Exclude entire coalesced
                // long-header datagrams; a short-header packet is always last.
                if len > 0 && bytes[0] & 0x80 == 0 {
                    let mut trace = trace.lock();
                    assert!(trace.len() < 4096, "bounded capture");
                    trace.push((from_server, bytes[0] & 0x20 != 0));
                }
                socket.send_to(&bytes[..len], to).await.unwrap();
            }
        });
        let capture = Capture { bits, task };
        let (client, server) = tokio::join!(
            client_endpoint
                .connect_with(client_config.clone(), address, "localhost")
                .unwrap(),
            async { server_endpoint.accept().await.unwrap().await }
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        if [
            client.spin_enabled_for_test(),
            server.spin_enabled_for_test(),
        ] == allow
        {
            assert_eq!(client.version(), rama_quic_proto::Version::V1);
            assert_eq!(server.version(), rama_quic_proto::Version::V1);
            return (client_endpoint, server_endpoint, client, server, capture);
        }
        client_endpoint.close(0u32, b"select another fixed seed");
        server_endpoint.close(0u32, b"select another fixed seed");
    }
    panic!("fixed seed population has no requested activation");
}

#[tokio::test]
async fn spin_policy_is_independent_across_real_udp_h3_relay_hops() {
    timeout(Duration::from_secs(20), async {
        for ingress_enabled in [true, false] {
            let (browser_endpoint, ingress_endpoint, browser, ingress, downstream) =
                captured_hop([true, ingress_enabled]).await;
            let (egress_endpoint, origin_endpoint, egress, origin, upstream) =
                captured_hop([!ingress_enabled, true]).await;
            let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ordinary_config())
                    .with_egress_config(ordinary_config())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body>(browser, ordinary_config(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            for sequence in 0..16 {
                let payload = format!("public spin test {sequence}");
                let expected = payload.clone();
                let request = Request::builder()
                    .method(Method::POST)
                    .version(Version::HTTP_3)
                    .uri("https://localhost/spin")
                    .body(Body::from(payload))
                    .unwrap();
                let (response, answered) = tokio::join!(browser.send_request(request), async {
                    let (request, response) =
                        origin.accept().await.unwrap().resolve().await.unwrap();
                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(bytes, expected);
                    response
                        .send_response(Response::new(Body::from(bytes)))
                        .await
                });
                answered.unwrap();
                assert_eq!(
                    response
                        .unwrap()
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes(),
                    expected
                );
            }
            downstream.check(ingress_enabled);
            upstream.check(!ingress_enabled);
            origin.shutdown().unwrap();
            browser.closed_or_draining().await;
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"spin test done");
            }
            tokio::join!(
                browser_endpoint.shutdown(),
                ingress_endpoint.shutdown(),
                egress_endpoint.shutdown(),
                origin_endpoint.shutdown()
            );
            let _drivers = tokio::join!(browser_driver, origin_driver);
        }
    })
    .await
    .expect("bounded real UDP H3 relay");
}
