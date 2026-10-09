use super::*;
use rama_core::extensions::Extensions;
use rama_quic_proto::{
    capture::{CaptureLimits, ObservedFrame, QuicObservation},
    version::ClientVersionPolicy,
};
use rama_tls::SecureTransport;

#[test]
fn server_observation_retains_tls_parameters_and_attempt_identity() {
    for version in [Version::V1, Version::V2] {
        let mut server = server_config();
        server.set_capture(CaptureLimits::default());
        let mut pair = Pair::new(
            Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
            server,
        );
        let mut client = client_config();
        client
            .set_versions(ClientVersionPolicy::new(version).unwrap())
            .unwrap();
        let (_, server) = pair.connect_with(client);
        let extensions = Extensions::new();
        let observation = pair.server_conn_mut(server).observation.as_mut().unwrap();
        observation.publish(&extensions, true, false);
        let recorded = extensions.get_ref::<QuicObservation>().unwrap();
        assert!(recorded.completeness.is_complete(), "{recorded:?}");
        assert!(!recorded.transport_parameters.is_empty());
        assert!(!recorded.client_hello_message.is_empty());
        assert!(!recorded.attempt_id.is_empty());
        assert!(recorded.retry_parent.is_none());
        assert_eq!(recorded.first_flight.as_ref().unwrap().version, version);
        assert!(
            extensions
                .get_ref::<SecureTransport>()
                .unwrap()
                .client_hello()
                .is_some()
        );
    }
}

#[test]
fn exhausting_observation_budgets_does_not_reject_the_handshake() {
    for limits in [
        CaptureLimits {
            datagrams: 0,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            bytes: 1,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            packets: 0,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            frames: 0,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            crypto_fragments: 0,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            client_hello_bytes: 1,
            ..CaptureLimits::default()
        },
        CaptureLimits {
            parameters: 0,
            ..CaptureLimits::default()
        },
    ] {
        let mut server = server_config();
        server.set_capture(limits);
        let mut pair = Pair::new(
            Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
            server,
        );
        let (_, server) = pair.connect();
        let extensions = Extensions::new();
        pair.server_conn_mut(server)
            .observation
            .as_mut()
            .unwrap()
            .publish(&extensions, true, false);
        let recorded = extensions.get_ref::<QuicObservation>().unwrap();
        assert!(
            !recorded.completeness.is_complete(),
            "{limits:?}: {recorded:?}"
        );
        assert!(recorded.client_hello_message.len() <= limits.client_hello_bytes);
        assert!(recorded.transport_parameters.len() <= limits.parameters);
        if let Some(flight) = &recorded.first_flight {
            assert!(flight.datagram_sizes.len() <= limits.datagrams);
            assert!(flight.datagram_sizes.iter().sum::<usize>() <= limits.bytes);
            assert!(flight.packet_numbers.len() <= limits.packets);
            assert!(flight.frames.iter().map(Vec::len).sum::<usize>() <= limits.frames);
            assert!(
                flight
                    .frames
                    .iter()
                    .flatten()
                    .filter(|frame| matches!(frame, ObservedFrame::Crypto { .. }))
                    .count()
                    <= limits.crypto_fragments
            );
        }
    }
}

#[test]
fn disabled_capture_has_no_recorder_or_retained_observation() {
    let mut pair = Pair::default();
    let (_, server) = pair.connect();
    assert!(pair.server_conn_mut(server).observation.is_none());
}

#[test]
fn server_observation_reports_retry_lineage_without_claiming_original_flight() {
    let mut server = server_config();
    server.set_capture(CaptureLimits::default());
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (_, server) = pair.connect();
    let extensions = Extensions::new();
    pair.server_conn_mut(server)
        .observation
        .as_mut()
        .unwrap()
        .publish(&extensions, true, false);
    let observed = extensions.get_ref::<QuicObservation>().unwrap();
    assert!(observed.retry_parent.is_some());
    assert_ne!(
        observed.retry_parent.as_deref(),
        Some(observed.attempt_id.as_slice())
    );
    assert!(!observed.completeness.original_attempt);
    assert!(!observed.completeness.is_complete());
    assert!(observed.completeness.client_hello);
}

#[test]
fn server_observation_retains_buffered_retransmissions_before_accept() {
    let mut server = server_config();
    server.set_capture(CaptureLimits::default());
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Wait);
    pair.begin_connect(client_config());
    pair.drive_client();
    let duplicate = pair.server.inbound.front().unwrap().clone();
    pair.server.inbound.push_back(duplicate);
    pair.drive_server();
    let incoming = pair.server.waiting_incoming.pop().unwrap();
    let server = pair.server.try_accept(incoming, pair.time).unwrap();
    let extensions = Extensions::new();
    pair.server_conn_mut(server)
        .observation
        .as_mut()
        .unwrap()
        .publish(&extensions, true, false);
    let observed = extensions.get_ref::<QuicObservation>().unwrap();
    let flight = observed.first_flight.as_ref().unwrap();
    assert_eq!(flight.datagram_sizes.len(), 2);
    assert_eq!(flight.packet_numbers, [0, 0]);
    assert_eq!(flight.frames.len(), 1);
    assert!(observed.completeness.is_complete());
}
