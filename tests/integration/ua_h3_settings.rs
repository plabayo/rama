use std::{num::NonZeroUsize, time::Duration};

use rama::http::{
    Body,
    proto::h3::{SettingId, Settings},
};
use rama::rt::{Executor, spawn};
use rama_http_core::h3::{client, connection::Config, server};
use rama_net::address::SocketAddress;
use rama_quic::{ClientConfig, Endpoint, ServerConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_ua::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    },
    format::canonical::ValueId,
    model::{identity::ConnectionContext, scope::ProfileObservationScope},
    selection::{
        DrawKey, ProfileSeed,
        variants::{ConnectionSelection, PreparedConnectionProfile},
    },
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::octets::{kib, kib_u64};

fn selection(key: u8) -> ConnectionSelection {
    // Chrome 154 loopback capture: values are receive promises, not just labels.
    let fields = [
        (SettingId::QPACK_MAX_TABLE_CAPACITY, kib_u64(64)),
        (SettingId::MAX_FIELD_SECTION_SIZE, kib_u64(256)),
        (SettingId::QPACK_BLOCKED_STREAMS, 100),
        (SettingId::H3_DATAGRAM, 1),
        (SettingId::new(0x1e00490b7), 114_070_958),
    ];
    let settings = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        fields.map(|(id, value)| (id.value(), value.to_be_bytes())),
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http3Settings,
            value: settings,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();
    let mut bucket = rama_ua::profile::evidence::bucket::CountedObservationBucket::new(
        rama_ua::profile::format::canonical::CanonicalDomain::Order,
        ValueId([4; 32]),
        [3; 32],
        rama_ua::profile::evidence::bucket::ProfileBucketLimits::default(),
    )
    .unwrap();
    for index in 0..64_u64 {
        let mut sample = fields;
        if index != 0 {
            sample[4] = (
                SettingId::new(33 + 31 * (u64::from(u32::MAX) / 64 * index)),
                u64::from(u32::MAX) / 64 * index,
            );
        }
        let value = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::Http3Setting,
            sample.map(|(id, value)| (id.value(), value.to_be_bytes())),
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        bucket
            .observe(
                rama_ua::profile::evidence::ingestion::ObservationId {
                    run: [1; 16],
                    sequence: index + 1,
                },
                &value,
            )
            .unwrap();
    }
    let joint = JointCapture::from_canonical(&capture, JointCaptureLimits::default()).unwrap();
    let h3_settings_evidence =
        rama_ua::profile::replay::connection::H3SettingsReplayEvidence::from_analysis(
            &rama_ua::profile::analysis::capture::analyze_capture_bucket(
                &bucket,
                rama_ua::profile::analysis::order::OrderAnalysisConfig::default(),
            )
            .unwrap(),
            &joint.slots[0].value,
        )
        .unwrap();
    ConnectionSelection {
        profile: ValueId([1; 32]),
        variant: capture.id,
        draw: DrawKey([key; 32]),
        analysis_revision: 2,
        effective: PreparedConnectionProfile {
            h3_settings_evidence,
            scope: ValueId([2; 32]),
            capture,
            context: ProfileObservationScope {
                authorized: false,
                profile: ValueId([1; 32]),
                flow: None,
                connection: ConnectionContext::default(),
                structure: ValueId([3; 32]),
            },
        },
    }
}

#[tokio::test(start_paused = true)]
async fn selected_chrome_h3_settings_reach_peer_with_evidenced_generation() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn([b"h3".as_slice().into()].into_iter().collect())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn([b"h3".as_slice().into()].into_iter().collect())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let server_config =
            ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
        let client_config =
            ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap();
        let mut observed = Vec::<Settings>::new();
        for key in [11, 12] {
            let selected = selection(key);
            let prepared = selected.prepare_components().unwrap();
            let settings = prepared
                .h3_client_settings(&mut selected.h3_settings_draw(ProfileSeed([7; 32])))
                .unwrap()
                .unwrap();
            Config::default()
                .try_with_client_settings(settings.0.clone())
                .unwrap_err();
            let config = Config::default()
                .with_browser_emulation_limits()
                .try_with_client_settings(settings.0.clone())
                .unwrap();
            assert_eq!(config.decoder.max_table_capacity, kib_u64(64));
            assert_eq!(config.decoder.max_blocked_streams, 100);
            assert_eq!(config.decoder.max_field_section_size, kib(256));
            assert!(config.observation.is_none());

            let (server_socket, client_socket) = MemoryDatagramSocket::pair(
                SocketAddress::local_ipv4(443),
                SocketAddress::local_ipv4(444),
                NonZeroUsize::MIN,
            );
            let server_endpoint = Endpoint::build(Executor::new())
                .with_server_config(server_config.clone())
                .with_datagram_socket(server_socket)
                .unwrap();
            let client_endpoint = Endpoint::build(Executor::new())
                .with_datagram_socket(client_socket)
                .unwrap();
            let (client_connection, server_connection) = tokio::join!(
                client_endpoint
                    .connect_with(
                        client_config.clone(),
                        server_endpoint.local_addr().unwrap(),
                        "localhost"
                    )
                    .unwrap(),
                async { server_endpoint.accept().await.unwrap().await },
            );
            let (client, client_driver) =
                client::handshake::<Body>(client_connection.unwrap(), config, Executor::new())
                    .unwrap();
            let (server, server_driver) =
                server::handshake(server_connection.unwrap(), Config::default()).unwrap();
            let client_driver = spawn(client_driver.run());
            let server_driver = spawn(server_driver.run());
            let actual = server.peer_settings().await.unwrap();
            assert_eq!(&actual, settings.0.as_ref());
            observed.push(actual);
            drop(client);
            client_endpoint.close(0u32, b"test complete");
            server_endpoint.close(0u32, b"test complete");
            tokio::join!(client_endpoint.shutdown(), server_endpoint.shutdown());
            let _driver_results = tokio::join!(client_driver, server_driver);
        }
        assert_eq!(observed[0].entries()[..4], observed[1].entries()[..4]);
        let first = observed[0].entries()[4];
        let second = observed[1].entries()[4];
        assert!(first.id.is_reserved() && second.id.is_reserved());
        assert_ne!(first.id, second.id);
        assert_ne!(first.value, second.value);
        assert_ne!(first.id.value(), 0x1e00490b7);
        assert_ne!(second.id.value(), 0x1e00490b7);
        assert_ne!(first.value, 114_070_958);
    })
    .await
    .unwrap();
}
