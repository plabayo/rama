use super::*;
use rama_quic_proto::profile::{ConnectionIdProfile, TransportLimits};
use rama_ua::profile::selection::variants::ConnectionSelection;

#[tokio::test]
async fn captured_tls_reaches_a_rustls_h3_peer_with_the_admitted_selection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut fixture = fixture().await;
        // A different, supported wire order proves the prepared configuration
        // reaches the dial; rebuilding the ordinary default cannot pass.
        fixture.capture.ciphers.reverse();
        let input = fixture.input();
        let before = fixture.connector.tls_provider().pool_id(input.extensions());
        fixture.install(&input);
        let caller = input.extensions().clone();
        let transport = fixture.connector.serve(input).await.unwrap().conn;
        assert!(
            transport
                .connection
                .extensions()
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
        assert_eq!(before, fixture.connector.tls_provider().pool_id(&caller));
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
        let (context, _) = selection::selected("native-parameter-tuple", &fixture.capture, Some(&fixture.parameters));
        context.publish(input.extensions());
        let before = fixture.connector.tls_provider().pool_id(input.extensions());
        let caller = input.extensions().clone();
        let transport = fixture.connector.serve(input).await.unwrap().conn;
        request(transport).await;
        let captures = fixture.task.take().unwrap().await.unwrap();
        assert_eq!(captures[1].0, fixture.capture);
        assert_eq!(
            captures[1].1.canonical(OrderCaptureLimits::default()).unwrap().bytes,
            fixture.parameters.canonical(OrderCaptureLimits::default()).unwrap().bytes,
            "the peer must observe the correlated parameter tuple, including order and literal versions",
        );
        assert_eq!(fixture.connector.tls_provider().pool_id(&caller), before);
        assert!(!caller.contains::<QuicProfile>(), "compiled wire settings stay local to the consumer");
    }).await.unwrap();
}
