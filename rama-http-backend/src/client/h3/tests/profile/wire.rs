use super::*;
use rama_net::client::ConnectionPolicyScope;
use rama_quic_proto::profile::{
    ConnectionIdProfile, InitialFlightLayout, PacketNumberLength, PacketizationProfile,
    TransportLimits, initial::RecordedInitialFlight,
};
use rama_ua::profile::selection::variants::ConnectionSelection;

#[tokio::test]
async fn captured_tls_reaches_a_rustls_h3_peer_with_the_admitted_selection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        // A different, supported wire order proves the prepared configuration
        // reaches the dial; rebuilding the ordinary default cannot pass.
        fixture.capture.ciphers.reverse();
        let input = fixture.input();
        fixture.install(&input);
        let caller = Extensions::new();
        caller.extend(input.extensions());
        let transport = fixture.serve(input).await.unwrap().conn;
        assert!(
            transport
                .connection
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
        assert!(
            transport
                .connection
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .matches(&caller)
        );
        assert_eq!(
            transport
                .connection
                .extensions()
                .get_ref::<ConnectionPolicyScope>(),
            Some(&ConnectionPolicyScope::Connector)
        );
        assert!(
            transport
                .connection
                .extensions()
                .contains::<ConnectionSelection>()
        );
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_eq!(captures.len(), 2);
        assert_eq!(captures[1].0, fixture.capture);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn captured_parameters_reach_the_h3_peer_without_caller_wire_settings() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let profile = QuicProfile::standard()
            .with_connection_ids(ConnectionIdProfile::standard().try_with_local_len(0).unwrap())
            .with_transport_parameters(TransportParameterProfile::standard().try_with_grease(GreaseParameter::None).unwrap())
            .with_grease_quic_bit(false)
            .try_with_limits(TransportLimits { max_udp_payload_size: 1400, ..TransportLimits::standard() }).unwrap();
        let mut fixture = fixture_with_profile(profile).await;
        let input = fixture.target();
        let (context, _) = selection::selected("native-parameter-tuple", &fixture.capture, Some(&fixture.parameters), None);
        context.publish(input.extensions());
        let caller = Extensions::new();
        caller.extend(input.extensions());
        let transport = fixture.serve(input).await.unwrap().conn;
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_eq!(captures[1].0, fixture.capture);
        assert_eq!(
            captures[1].1.canonical(OrderCaptureLimits::default()).unwrap().bytes,
            fixture.parameters.canonical(OrderCaptureLimits::default()).unwrap().bytes,
            "the peer must observe the correlated parameter tuple, including order and literal versions",
        );
        assert!(!caller.contains::<QuicProfile>(), "producer settings must not change an independent caller snapshot");
    }).await.unwrap();
}

#[tokio::test]
async fn counted_initial_layout_reaches_the_peer_with_fresh_tls() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let packetization = PacketizationProfile::standard()
            .try_with_first_packet_number(1)
            .unwrap()
            .try_with_packet_number_length(PacketNumberLength::AtLeast(2))
            .unwrap()
            .with_layout(InitialFlightLayout::Chaos);
        let profile = QuicProfile::standard()
            .with_packetization(packetization)
            .with_transport_parameters(
                TransportParameterProfile::standard()
                    .try_with_grease(GreaseParameter::None)
                    .unwrap(),
            );
        let mut fixture = fixture_with_profile(profile).await;
        let expected = RecordedInitialFlight::try_from(&fixture.flight.flight).unwrap();
        let input = fixture.target();
        let (context, _) = selection::selected(
            "native-recorded-initial",
            &fixture.capture,
            Some(&fixture.parameters),
            Some(&fixture.flight),
        );
        context.publish(input.extensions());
        let caller = Extensions::new();
        caller.extend(input.extensions());
        let transport = fixture.serve(input).await.unwrap().conn;
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        let actual = RecordedInitialFlight::try_from(&captures[1].2.flight).unwrap();
        assert_eq!(
            actual, expected,
            "the selected native layout, not ordinary defaults, must reach the peer"
        );
        assert_eq!(captures[1].0, fixture.capture);
        assert_eq!(
            captures[1]
                .1
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes,
            fixture
                .parameters
                .canonical(OrderCaptureLimits::default())
                .unwrap()
                .bytes
        );
        assert!(
            !caller.contains::<QuicProfile>(),
            "native layout is installed only on the prepared request"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn replayed_profile_negotiates_its_captured_quic_version() {
    use rama_quic::QuicConnectionInfo;
    use rama_quic_proto::{Version, version::ClientVersionPolicy};
    tokio::time::timeout(Duration::from_secs(15), async {
        // A non-default version catches a replay that silently uses the default policy.
        let profile =
            QuicProfile::standard().with_versions(ClientVersionPolicy::new(Version::V2).unwrap());
        let mut fixture = fixture_with_profile(profile).await;
        assert_eq!(fixture.flight.flight.version, Version::V2);
        let input = fixture.target();
        let (context, _) = selection::selected(
            "native-quic-v2",
            &fixture.capture,
            Some(&fixture.parameters),
            Some(&fixture.flight),
        );
        context.publish(input.extensions());
        let transport = fixture.serve(input).await.unwrap().conn;
        let info = *transport
            .connection
            .extensions()
            .get_ref::<QuicConnectionInfo>()
            .unwrap();
        assert_eq!(info.version, fixture.profile.versions().original());
        assert_eq!(info.original_version, Version::V2);
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_eq!(captures[1].2.flight.version, Version::V2);
    })
    .await
    .unwrap();
}
