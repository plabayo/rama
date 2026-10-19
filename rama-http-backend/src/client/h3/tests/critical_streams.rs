//! Native startup overrides observed directly by an authenticated QUIC peer.

use super::*;
use rama_core::{
    Service as _,
    bytes::Bytes,
    extensions::ExtensionsRef as _,
    rt::{Executor, spawn},
};
use rama_http_core::h3::{
    client,
    connection::Config,
    frame::{FrameDecoder, FrameEvent},
};
use rama_http_types::{
    Body,
    proto::h3::{
        FrameType,
        control::{ClientControlFrame, ClientControlPreferences},
        critical_streams::{Order, Preferences, Startup},
        qpack::EncoderPreferences,
    },
};
use rama_net::{
    Protocol,
    address::{HostWithPort, SocketAddress},
    client::ConnectorTarget,
    tls::ApplicationProtocol,
};
use rama_quic::{Endpoint, ServerConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use std::{collections::BTreeMap, time::Duration};
use tokio::time::timeout;

#[tokio::test]
async fn request_startup_preferences_reach_the_peer_without_ua() {
    timeout(Duration::from_secs(15), async {
        let identity = ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
            .with_server_auth(identity.clone());
        let server = Endpoint::bind_server(
            Executor::new(),
            ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap(),
            SocketAddress::local_ipv4(0),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let tls = TlsClientConfig::new()
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let fixed = Preferences {
            order: Order::DecoderFirst,
            encoder: Startup::OnDemand,
            decoder: Startup::OnDemand,
            ..Preferences::default()
        };
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_config(tls)
            .with_config(Config {
                critical_streams: fixed,
                ..Config::default()
            })
            .build_lazy()
            .unwrap();

        // Expected IDs/types are read from the peer, independently of the
        // engine's stream-allocation logic. Unwritten reserved IDs have no type.
        let cases = [
            (None, vec![(2, 0)]),
            (Some(Preferences::default()), vec![(2, 0), (6, 2), (10, 3)]),
            (
                Some(Preferences {
                    order: Order::DecoderFirst,
                    encoder: Startup::Immediate,
                    decoder: Startup::OnDemand,
                    ..Preferences::default()
                }),
                vec![(2, 0), (10, 2)],
            ),
            (
                Some(Preferences {
                    order: Order::EncoderFirst,
                    encoder: Startup::OnDemand,
                    decoder: Startup::Immediate,
                    ..Preferences::default()
                }),
                vec![(2, 0), (10, 3)],
            ),
        ];
        for (preferences, expected) in cases {
            let input =
                ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(ConnectorTarget(HostWithPort::local_ipv4(address.port())));
            if let Some(preferences) = preferences {
                input.extensions().insert(preferences);
            }
            input.extensions().insert(ClientControlPreferences {
                frames: vec![ClientControlFrame::Ignored {
                    frame_type: FrameType::new(0x21),
                    payload: Bytes::from_static(b"test"),
                }]
                .into(),
            });
            input.extensions().insert(EncoderPreferences {
                target_capacity: Some(128),
                huffman: Some(false),
                defer_dynamic_first_section: Some(true),
                ..EncoderPreferences::default()
            });
            let (transport, peer) = tokio::join!(connector.serve(input), async {
                server
                    .accept()
                    .await
                    .unwrap()
                    .accept()
                    .unwrap()
                    .await
                    .unwrap()
            },);
            let transport = transport.unwrap().conn;
            assert!(transport.config.encoder.defer_dynamic_first_section);
            assert!(!transport.config.encoder.huffman);
            assert_eq!(transport.config.encoder.target_capacity, 128);
            let connection = transport.connection.clone();
            let (_sender, driver) = client::handshake::<Body>(
                transport.connection,
                Arc::unwrap_or_clone(transport.config),
                Executor::new(),
            )
            .unwrap();
            let driver = spawn(driver.run());
            let mut observed = BTreeMap::new();
            let mut streams = Vec::new();
            for _ in 0..3 {
                let Ok(incoming) = timeout(Duration::from_millis(100), peer.accept_uni()).await
                else {
                    break;
                };
                let mut stream = incoming.unwrap();
                let mut prefix = [0];
                if let Ok(result) =
                    timeout(Duration::from_millis(100), stream.read_exact(&mut prefix)).await
                {
                    result.unwrap();
                    observed.insert(u64::from(stream.id()), u64::from(prefix[0]));
                    if prefix[0] == 0 {
                        // Read real peer bytes after the stream type, across any QUIC chunking.
                        let mut frames = FrameDecoder::new(1024).with_reserved_payload_capture(4);
                        let mut found = false;
                        timeout(Duration::from_secs(1), async {
                            while !found {
                                let chunk = stream.read_chunk(1024, true).await.unwrap().unwrap();
                                frames.feed(&chunk.bytes).unwrap();
                                while let Some(event) = frames.poll().unwrap() {
                                    if let FrameEvent::Ignored { ty, payload, .. } = event {
                                        assert_eq!(ty, FrameType::new(0x21));
                                        assert_eq!(payload.as_deref(), Some(b"test".as_slice()));
                                        found = true;
                                    }
                                }
                            }
                        })
                        .await
                        .unwrap();
                    }
                }
                streams.push(stream);
            }
            assert_eq!(observed, expected.into_iter().collect(), "{preferences:?}");
            connection.close(0u32, b"startup verified");
            peer.close(0u32, b"startup verified");
            driver.abort();
            drop(streams);
        }
        server.close(0u32, b"fixture complete");
        server.shutdown().await;
    })
    .await
    .unwrap();
}
