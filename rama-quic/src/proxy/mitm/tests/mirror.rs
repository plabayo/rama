use rama_crypto::dep::boring::ssl::SslContentType;
use rama_quic_proto::{
    capture::{CaptureLimits, RawParameter, transport_parameters_from_hello},
    peek::InitialPeek,
    profile::{ParameterId, TransportLimits},
};
use rama_tls::{
    client::{
        ClientHello, ClientHelloExtension, ClientHelloHandshakePrefix,
        parse_client_hello_message_prefix,
    },
    server::TlsServerConfig,
};

use super::*;
use crate::profile::capture::ProviderKeys;

/// Chrome 153's QUIC ClientHello, from its captured first flight.
fn chrome_client_hello() -> ClientHello {
    let identity = identity();
    let server = crate::test_helpers::server(&identity).crypto.into_fixed();
    let keys = ProviderKeys(server.as_ref());
    let mut peek = InitialPeek::new(
        CaptureLimits::default(),
        std::time::Instant::now() + Duration::from_secs(5),
    );
    for datagram in chrome_flight() {
        if let Some(peeked) = peek
            .inspect(std::time::Instant::now(), &datagram, &keys)
            .unwrap()
        {
            return peeked.client_hello;
        }
    }
    panic!("no ClientHello in Chrome's flight");
}

/// What a hello shows that is not drawn per connection: every list with its GREASE values,
/// and the extensions in order; key shares by group, ECH GREASE and transport parameters by
/// presence (those are compared on their own).
fn shape(hello: &ClientHello) -> Vec<String> {
    let mut shape = vec![format!("{:?}", hello.cipher_suites())];
    for ext in hello.extensions() {
        shape.push(match ext {
            ClientHelloExtension::EncryptedClientHello(_) => "ech".to_owned(),
            ClientHelloExtension::Opaque { id, .. } if *id == rama_tls::ExtensionId::KEY_SHARE => {
                format!("key_share {:?}", hello.ext_key_share_groups())
            }
            ClientHelloExtension::Opaque { id, .. }
                if *id == rama_tls::ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
            {
                "quic_transport_parameters".to_owned()
            }
            other => format!("{other:?}"),
        });
    }
    shape
}

/// Transport parameters without the values every connection draws or a relay sets itself.
fn parameters(hello: &ClientHello) -> Vec<RawParameter> {
    let mut parameters = transport_parameters_from_hello(hello, &CaptureLimits::default()).unwrap();
    for parameter in &mut parameters {
        if matches!(
            parameter.id,
            ParameterId::INITIAL_SOURCE_CONNECTION_ID | ParameterId::VERSION_INFORMATION
        ) {
            parameter.value.clear();
        }
    }
    parameters
}

/// What the client sent and what the origin received through a relay that mirrors (or not).
async fn through_relay(mirror: bool, port: u16) -> (ClientHello, ClientHello) {
    let mitm_identity = identity();
    let origin_identity = untrusted_identity();
    // With GREASE added, which Chrome's QUIC hello lacks: the client draws fresh values
    // per connection, and a mirroring relay must repeat exactly those.
    let chrome = chrome_client_hello();
    let mut ciphers = vec![rama_tls::CipherSuite::from(0x0a0a)];
    ciphers.extend_from_slice(chrome.cipher_suites());
    let mut extensions = vec![ClientHelloExtension::Opaque {
        id: rama_tls::ExtensionId::from(0x1a1a),
        data: Vec::new(),
    }];
    extensions.extend_from_slice(chrome.extensions());
    let captured = ClientHello::new(
        chrome.protocol_version(),
        ciphers,
        chrome.compression_algorithms().to_vec(),
        extensions,
    );
    let address = |offset: u16| SocketAddr::from(([127, 0, 0, 1], port + offset));
    let capacity = NonZeroUsize::new(64).unwrap();
    let (client_socket, ingress) = MemoryDatagramSocket::pair(address(0), address(1), capacity);
    let (egress, origin_socket) = MemoryDatagramSocket::pair(address(2), address(3), capacity);

    let origin_tls = TlsServerConfig::new()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
        .with_server_auth(origin_identity.clone());
    let origin = Endpoint::build(Executor::new())
        .with_server_config(
            ServerConfig::try_from_rama_tls_with_provider(
                &origin_tls,
                TlsOptions::default(),
                &BoringTlsProvider,
            )
            .unwrap(),
        )
        .with_datagram_socket(origin_socket)
        .unwrap();
    let origin_task = tokio::spawn(async move {
        let mut incoming = origin.accept().await.unwrap();
        let hello = incoming.client_hello().await.unwrap().clone();
        let connection = incoming.await.unwrap();
        connection.closed().await;
        (hello, origin)
    });

    let mut mitm = QuicMitmRelay::new(
        issuer(&mitm_identity),
        Executor::new(),
        trusting_with_alpn(&origin_identity, b"h3"),
        VarInt::from_u32(0x0101),
    );
    mitm.set_mirror_client(mirror);
    let service = PeekQuicClientHelloService::new(
        BoringTlsProvider,
        mitm.into_layer(service_fn(
            async |BridgeIo(ingress, egress): BridgeIo<Connection, Connection>| {
                egress.handshake_confirmed().await?;
                ingress.close(VarInt::from_u32(0), b"checked");
                egress.close(VarInt::from_u32(0), b"checked");
                Ok::<_, BoxError>(())
            },
        )),
    );
    let relaying = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });

    let sent = Arc::new(Mutex::new(None));
    let kept = sent.clone();
    let client_tls = TlsClientConfig::new_from_client_hello(&captured)
        .try_with_server_trust_anchors([mitm_identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    client_tls.insert(HandshakeInitializer(Arc::new(move |ssl: &mut SslRef| {
        let kept = kept.clone();
        ssl.set_msg_callback(move |_, message| {
            if message.is_written()
                && message.content_type() == SslContentType::HANDSHAKE
                && message.bytes().first() == Some(&1)
            {
                *kept.lock() = Some(message.bytes().to_vec());
            }
        });
        Ok(())
    })));
    let profile = crate::profile::browsers::chrome_153();
    let mut config = ClientConfig::try_from_rama_tls_with_provider(
        &client_tls,
        TlsOptions::default(),
        &BoringTlsProvider,
    )
    .unwrap();
    config.apply_quic_profile(&profile).unwrap();
    let mut endpoint_config = crate::EndpointConfig::try_with_rand_key().unwrap();
    endpoint_config.apply_quic_profile(&profile).unwrap();
    let client = Endpoint::build(Executor::new())
        .with_config(endpoint_config)
        .with_datagram_socket(client_socket)
        .unwrap();
    let connection = client
        .connect_with(config, address(1), "localhost")
        .unwrap()
        .await
        .unwrap();
    relaying.await.unwrap().unwrap();
    connection.closed().await;
    let (received, _origin) = origin_task.await.unwrap();
    let ClientHelloHandshakePrefix::Complete(sent) =
        parse_client_hello_message_prefix(&sent.lock().clone().unwrap())
    else {
        panic!("the client wrote a complete ClientHello");
    };
    (sent, received)
}

#[tokio::test]
async fn a_mirroring_relay_shows_the_origin_its_clients_first_flight() {
    timeout(LIMIT, async {
        let (sent, received) = through_relay(true, 24900).await;
        assert_eq!(shape(&received), shape(&sent));
        // Datagram support stays the relay's, which (by default) carries none.
        let mut expected = parameters(&sent);
        let datagrams = expected
            .iter()
            .position(|p| p.id == ParameterId::MAX_DATAGRAM_FRAME_SIZE)
            .expect("Chrome advertises datagrams");
        expected.remove(datagrams);
        assert_eq!(parameters(&received), expected);

        // Without mirroring, the origin sees the relay's own configuration.
        let (sent, received) = through_relay(false, 24910).await;
        assert_ne!(shape(&received), shape(&sent));
        assert_ne!(parameters(&received), parameters(&sent));
    })
    .await
    .unwrap();
}

/// `hello` with its transport parameters replaced by `parameters`.
fn with_parameters(hello: &ClientHello, parameters: &[RawParameter]) -> ClientHello {
    let var = |value: u64, out: &mut Vec<u8>| match value {
        0..64 => out.push(value as u8),
        64..16_384 => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        16_384..1_073_741_824 => out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    };
    let mut body = Vec::new();
    for parameter in parameters {
        var(parameter.id.0, &mut body);
        var(parameter.value.len() as u64, &mut body);
        body.extend_from_slice(&parameter.value);
    }
    let extensions = hello
        .extensions()
        .iter()
        .map(|ext| match ext {
            ClientHelloExtension::Opaque { id, .. }
                if *id == rama_tls::ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
            {
                ClientHelloExtension::Opaque {
                    id: *id,
                    data: body.clone(),
                }
            }
            other => other.clone(),
        })
        .collect();
    ClientHello::new(
        hello.protocol_version(),
        hello.cipher_suites().to_vec(),
        hello.compression_algorithms().to_vec(),
        extensions,
    )
}

/// The egress transport a relay with the default configuration builds for `hello`.
fn mirrored_transport(hello: &ClientHello) -> TransportConfig {
    let base = TransportConfig::default();
    let profile = mirrored_profile(&base, &QuicMirrorCeiling::default(), hello).unwrap();
    base.try_with_quic_profile(&profile).unwrap()
}

#[test]
fn a_mirrored_client_cannot_lift_the_relays_egress_limits() {
    let chrome = chrome_client_hello();
    let mut sent = transport_parameters_from_hello(&chrome, &CaptureLimits::default()).unwrap();
    let max = |value: u64| {
        let mut out = Vec::new();
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
        out
    };
    for parameter in &mut sent {
        parameter.value = match parameter.id {
            ParameterId::INITIAL_MAX_DATA
            | ParameterId::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
            | ParameterId::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
            | ParameterId::INITIAL_MAX_STREAM_DATA_UNI => max((1 << 62) - 1),
            ParameterId::INITIAL_MAX_STREAMS_BIDI | ParameterId::INITIAL_MAX_STREAMS_UNI => {
                max(1 << 60)
            }
            ParameterId::MAX_IDLE_TIMEOUT => vec![0],
            _ => continue,
        };
    }
    let base = TransportConfig::default();
    let ceiling = QuicMirrorCeiling::default();
    let greedy = mirrored_transport(&with_parameters(&chrome, &sent));
    assert_eq!(greedy.receive_window.into_inner(), ceiling.max_data);
    for window in [
        Some(greedy.stream_receive_window),
        greedy.stream_receive_window_bidi_remote,
        greedy.stream_receive_window_uni,
    ] {
        assert_eq!(window.unwrap().into_inner(), ceiling.max_stream_data);
    }
    assert_eq!(
        greedy.max_concurrent_bidi_streams.into_inner(),
        ceiling.max_streams
    );
    assert_eq!(
        greedy.max_concurrent_uni_streams.into_inner(),
        ceiling.max_streams
    );
    // A client cannot disable the relay's idle timeout, nor lift it.
    assert_eq!(greedy.max_idle_timeout, base.max_idle_timeout);

    // A client may shorten the idle timeout, never lengthen it past the relay's.
    let base_idle = base.max_idle_timeout.map(VarInt::into_inner);
    for (idle_ms, expected) in [(600_000_u64, base_idle), (10_000, Some(10_000))] {
        let mut sent = transport_parameters_from_hello(&chrome, &CaptureLimits::default()).unwrap();
        for parameter in &mut sent {
            if parameter.id == ParameterId::MAX_IDLE_TIMEOUT {
                parameter.value = max(idle_ms);
            }
        }
        let mirrored = mirrored_transport(&with_parameters(&chrome, &sent));
        assert_eq!(
            mirrored.max_idle_timeout.map(VarInt::into_inner),
            expected,
            "client idle {idle_ms} ms"
        );
    }

    // A browser stays under the ceiling and is mirrored exactly.
    let browser = transport_parameters_from_hello(&chrome, &CaptureLimits::default()).unwrap();
    let limits = TransportLimits::try_from_sent(&browser).unwrap();
    let mirrored = mirrored_transport(&chrome);
    assert_eq!(
        mirrored.receive_window.into_inner(),
        limits.initial_max_data
    );
    assert_eq!(
        mirrored.stream_receive_window.into_inner(),
        limits.initial_max_stream_data_bidi_local
    );
    assert_eq!(
        mirrored.max_concurrent_uni_streams.into_inner(),
        limits.initial_max_streams_uni
    );
    assert_eq!(
        mirrored.max_idle_timeout.map(VarInt::into_inner),
        Some(u64::try_from(limits.max_idle_timeout.as_millis()).unwrap())
    );
}
