//! Profiles against their captures, and the observer-separation property: a profile changes
//! only what it says at each level of visibility.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test's fixtures fail the test by panicking"
)]

use rama_core::rt::Executor;

use super::browsers::{chrome_153, firefox_156};
use super::capture;
use super::*;
use crate::{ClientConfig, Endpoint};
use rama_quic_proto::{
    capture::{FirstFlight, ObservedFrame, PacketKind, observe},
    version::Version,
};

macro_rules! include_fixture {
    ($name:literal) => {
        include_str!(concat!("fixtures/", $name))
    };
}

fn hex(name: &str) -> Vec<u8> {
    let text = include_fixture(name);
    rama_utils::hex::decode(text.split_whitespace().collect::<String>()).expect("a hex fixture")
}

fn include_fixture(name: &str) -> &'static str {
    match name {
        "chrome-153-initial-1.hex" => include_fixture!("chrome-153-initial-1.hex"),
        "chrome-153-initial-2.hex" => include_fixture!("chrome-153-initial-2.hex"),
        "firefox-156-initial-1.hex" => include_fixture!("firefox-156-initial-1.hex"),
        "firefox-156-initial-2.hex" => include_fixture!("firefox-156-initial-2.hex"),
        other => panic!("unknown fixture {other}"),
    }
}

/// A server-side crypto provider, for reading a first flight back.
fn provider() -> std::sync::Arc<dyn crate::proto::crypto::ServerConfig> {
    let identity = crate::test_helpers::identity();
    let server = crate::test_helpers::server(&identity);
    server.crypto.clone()
}

/// The parameter identifiers a capture carried, in order.
fn observed_parameters(datagrams: &[&[u8]]) -> Vec<ParameterId> {
    let flight = capture::first_flight(datagrams, &*provider()).expect("a readable first flight");
    flight.parameters
}

#[test]
fn a_capture_reads_back_as_the_client_it_was() {
    let one = hex("chrome-153-initial-1.hex");
    let two = hex("chrome-153-initial-2.hex");
    let flight = capture::first_flight(&[&one, &two], &*provider()).expect("chrome's first flight");
    assert_eq!(flight.version, Version::V1);
    assert_eq!(flight.dcid_len, 8);
    assert_eq!(flight.scid_len, 0);
    assert_eq!(flight.token_len, 0);
    assert_eq!(flight.datagram_sizes, vec![1230, 1230]);
    assert_eq!(flight.trailing_bytes, vec![0, 0]);
    assert_eq!(flight.chosen_version, Some(Version::V1));
    // Chrome's version_information: a greased reserved version, then v1.
    assert_eq!(flight.available_versions.len(), 2);
    assert!(flight.available_versions[0].is_reserved());
    assert_eq!(flight.available_versions[1], Version::V1);

    let ff_one = hex("firefox-156-initial-1.hex");
    let ff_two = hex("firefox-156-initial-2.hex");
    let flight =
        capture::first_flight(&[&ff_one, &ff_two], &*provider()).expect("firefox's first flight");
    assert_eq!(flight.dcid_len, 8);
    assert_eq!(flight.scid_len, 3);
    assert_eq!(flight.datagram_sizes, vec![1232, 1232]);
    // Firefox pads with zero bytes after the packet.
    assert_eq!(flight.padding, PaddingPlacement::DatagramTail);
    assert!(flight.trailing_bytes.iter().all(|&tail| tail > 0));
    // Its version_information offers v2 before v1, behind a greased version.
    assert_eq!(flight.chosen_version, Some(Version::V1));
    assert!(flight.available_versions.contains(&Version::V2));
    assert!(flight.available_versions.contains(&Version::V1));
    assert!(flight.available_versions.iter().any(|v| v.is_reserved()));
}

/// The observer split reads only the invariant header (RFC 8999 §5), so it works without keys.
#[test]
fn the_observer_split_needs_no_keys() {
    for name in ["chrome-153-initial-1.hex", "firefox-156-initial-1.hex"] {
        let datagram = hex(name);
        let observed = observe(&datagram).expect("a datagram splits");
        let first = &observed.packets[0];
        assert_eq!(first.kind, PacketKind::Initial);
        assert_eq!(first.version, Some(Version::V1));
        assert_eq!(first.dcid.len(), 8);
    }
}

/// Build a client with a profile, capture its own first flight through an in-memory socket, and
/// return what a server reads from it.
/// Build a client with a profile, capture the datagrams of its own first flight through a
/// loopback socket, and return what a server reads from it, together with whether the client's
/// TLS backend can change version mid-handshake (so the profile's compatible offer stands).
fn rama_first_flight(profile: &QuicProfile) -> (FirstFlight, bool) {
    use std::net::{Ipv4Addr, SocketAddr};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let identity = crate::test_helpers::identity();
        let peer = tokio::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let server_addr = peer.local_addr().unwrap();

        let mut endpoint_config = crate::EndpointConfig::try_with_rand_key().unwrap();
        endpoint_config.apply_quic_profile(profile).unwrap();
        let mut client_config = crate::test_helpers::client(&identity);
        // The round trip exercises packetization and parameters; a backend that cannot change
        // version mid-handshake offers only the first flight's version, which the caller knows.
        let capable = client_config.apply_quic_profile(profile).is_ok();
        if !capable {
            let narrowed = profile
                .clone()
                .with_versions(profile.versions().clone().narrowed_public());
            client_config.apply_quic_profile(&narrowed).unwrap();
        }

        let client = Endpoint::build(Executor::new())
            .with_config(endpoint_config)
            .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let connecting = client
            .connect_with(client_config, server_addr, "localhost")
            .unwrap();

        // Collect datagrams until the ClientHello reassembles into a first flight with its
        // parameters, so a timing-dependent later datagram cannot truncate the read.
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        let flight = loop {
            let mut buf = vec![0u8; 2048];
            let (len, _from) =
                tokio::time::timeout(std::time::Duration::from_secs(5), peer.recv_from(&mut buf))
                    .await
                    .expect("the client sends within the deadline")
                    .unwrap();
            buf.truncate(len);
            datagrams.push(buf);
            let borrowed: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
            match capture::first_flight(&borrowed, &*provider()) {
                Ok(flight) if flight.chosen_version.is_some() => break flight,
                _ if datagrams.len() >= 8 => {
                    panic!("the client hello did not reassemble from its first flight")
                }
                _ => {}
            }
        };
        drop(connecting);
        client.close(0u32.into(), b"done");
        (flight, capable)
    })
}
#[test]
fn the_standard_profile_produces_a_standard_first_flight() {
    let (flight, capable) = rama_first_flight(&QuicProfile::standard());
    assert_eq!(flight.version, Version::V1);
    assert_eq!(flight.dcid_len, 20);
    assert_eq!(flight.datagram_sizes[0], 1200);
    assert_eq!(flight.padding, PaddingPlacement::Frames);
    assert!(flight.available_versions.contains(&Version::V1));
    // The default policy offers v2 as a compatible version; a backend that cannot switch
    // narrows that to v1 only.
    assert_eq!(flight.available_versions.contains(&Version::V2), capable);
}

/// A profile's connection-ID lengths, datagram size, packet-number length, padding placement
/// and coalescing show up in rama's own first flight.
#[test]
fn a_profile_shapes_ramas_first_flight() {
    let profile = QuicProfile::standard()
        .with_connection_ids(
            ConnectionIdProfile::standard()
                .try_with_initial_destination_len(12)
                .unwrap()
                .try_with_local_len(4)
                .unwrap(),
        )
        .with_packetization(
            PacketizationProfile::standard()
                .try_with_initial_datagram_size(1350)
                .unwrap()
                .try_with_packet_number_length(PacketNumberLength::AtLeast(4))
                .unwrap()
                .with_padding(PaddingPlacement::DatagramTail),
        );
    let (flight, _capable_flight) = rama_first_flight(&profile);
    assert_eq!(flight.dcid_len, 12);
    assert_eq!(flight.scid_len, 4);
    assert!(flight.datagram_sizes.iter().all(|&size| size == 1350));
    assert_eq!(flight.packet_number_len, 4);
    assert_eq!(flight.padding, PaddingPlacement::DatagramTail);
    // The zero-byte tail brings the flight's last datagram up to size.
    assert!(flight.trailing_bytes.iter().any(|&tail| tail > 0));
}

/// A fixed transport-parameter order is reproduced on the wire.
#[test]
fn a_fixed_parameter_order_is_reproduced() {
    let order = vec![
        ParameterId::MAX_IDLE_TIMEOUT,
        ParameterId::INITIAL_SOURCE_CONNECTION_ID,
        ParameterId::INITIAL_MAX_DATA,
        ParameterId::VERSION_INFORMATION,
    ];
    let profile = QuicProfile::standard().with_transport_parameters(
        TransportParameterProfile::standard()
            .try_with_order(ParameterOrder::Fixed(order.clone()))
            .unwrap()
            .try_with_grease(GreaseParameter::None)
            .unwrap(),
    );
    let (flight, _capable_flight) = rama_first_flight(&profile);
    // The named parameters lead, in the order given; the rest follow.
    assert_eq!(&flight.parameters[..order.len()], &order[..]);
}

/// An extra vendor parameter is written, and a greased one lands where the order puts it.
#[test]
fn extra_and_greased_parameters_are_written() {
    let profile = QuicProfile::standard().with_transport_parameters(
        TransportParameterProfile::standard()
            .try_with_extra(vec![OpaqueParameter {
                id: ParameterId(0x3128),
                value: b"TEST".to_vec(),
            }])
            .unwrap()
            .try_with_grease(GreaseParameter::Fixed {
                id: ParameterId(27),
                value: vec![1, 2, 3],
            })
            .unwrap(),
    );
    let (flight, _capable_flight) = rama_first_flight(&profile);
    assert!(flight.parameters.contains(&ParameterId(0x3128)));
    assert!(flight.parameters.iter().any(|id| id.is_reserved()));
}

/// The browser profiles reproduce the parameter set their capture carried.
#[test]
fn a_browser_profile_offers_the_parameters_its_capture_did() {
    let chrome_capture = observed_parameters(&[
        &hex("chrome-153-initial-1.hex"),
        &hex("chrome-153-initial-2.hex"),
    ]);
    let (chrome, _capable_chrome) = rama_first_flight(&chrome_153());
    for id in &chrome_capture {
        assert!(
            chrome.parameters.contains(id) || *id == ParameterId(0x13c2_9813_4672_b34f),
            "chrome profile is missing parameter {id}"
        );
    }
    // Chrome's greased four-byte parameter, its google_connection_options and its lack of an
    // Initial source CID (empty SCID) are all reproduced.
    assert!(chrome.parameters.contains(&ParameterId(0x3128)));
    assert!(chrome.parameters.iter().any(|id| id.is_reserved()));

    let firefox_capture = observed_parameters(&[
        &hex("firefox-156-initial-1.hex"),
        &hex("firefox-156-initial-2.hex"),
    ]);
    let (firefox, _capable_firefox) = rama_first_flight(&firefox_156());
    for id in &firefox_capture {
        assert!(
            firefox.parameters.contains(id),
            "firefox profile is missing parameter {id}"
        );
    }
}

/// A browser profile reproduces the wire shape its capture showed: version offer, connection
/// ID lengths, datagram size, packet-number length, padding placement and coalescing.
#[test]
fn a_browser_profile_reproduces_its_captured_shape() {
    // Chrome: v1 only with a greased version first, 8/0 CIDs, 1230-byte datagrams, two-byte
    // packet numbers from one, frame padding, chaos layout, no coalescing.
    let (chrome, _capable_chrome) = rama_first_flight(&chrome_153());
    assert_eq!(chrome.version, Version::V1);
    assert_eq!(chrome.dcid_len, 8);
    assert_eq!(chrome.scid_len, 0);
    assert_eq!(chrome.datagram_sizes[0], 1230);
    assert_eq!(chrome.packet_number_len, 2);
    assert_eq!(chrome.first_packet_number, 1);
    assert_eq!(chrome.padding, PaddingPlacement::Frames);
    assert!(chrome.available_versions[0].is_reserved());
    assert_eq!(chrome.chosen_version, Some(Version::V1));
    assert!(!chrome.coalesced);

    // Firefox: 8/3 CIDs, 1232-byte datagrams padded after the packet, v2 offered before v1.
    let (firefox, capable) = rama_first_flight(&firefox_156());
    assert_eq!(firefox.dcid_len, 8);
    assert_eq!(firefox.scid_len, 3);
    assert!(firefox.datagram_sizes.iter().all(|&size| size == 1232));
    assert_eq!(firefox.padding, PaddingPlacement::DatagramTail);
    assert!(firefox.trailing_bytes.iter().any(|&tail| tail > 0));
    // Firefox offers v2 before v1; a backend that cannot switch offers only v1.
    assert_eq!(firefox.available_versions.contains(&Version::V2), capable);
    assert!(firefox.available_versions.iter().any(|v| v.is_reserved()));
}

/// Chaos layout scatters the CRYPTO frames; ordered layout keeps them in order with padding
/// after them. The reassembled ClientHello is the same either way, which the capture read
/// proves by decoding it at all.
#[test]
fn chaos_layout_scatters_crypto_but_keeps_the_client_hello() {
    let (ordered, _capable_ordered) = rama_first_flight(
        &QuicProfile::standard().with_packetization(PacketizationProfile::standard()),
    );
    let ordered_crypto = ordered.frames[0]
        .iter()
        .filter(|frame| matches!(frame, ObservedFrame::Crypto { .. }))
        .count();
    // One CRYPTO frame, then padding, with the padding trailing.
    assert_eq!(ordered_crypto, 1);

    let (chaos, _capable_chaos) = rama_first_flight(&QuicProfile::standard().with_packetization(
        PacketizationProfile::standard().with_layout(InitialFlightLayout::Chaos),
    ));
    let chaos_frames: usize = chaos
        .frames
        .iter()
        .map(|packet| {
            packet
                .iter()
                .filter(|frame| matches!(frame, ObservedFrame::Crypto { .. } | ObservedFrame::Ping))
                .count()
        })
        .sum();
    // Chaos produces more than one CRYPTO or PING frame; the ClientHello still reassembled,
    // which `first_flight` needs to read the parameters it checked above.
    assert!(chaos_frames > 1, "chaos did not scatter the frames");
    assert!(
        chaos.chosen_version.is_some(),
        "the ClientHello still reassembles"
    );
}

/// Every knob a profile changes is checked; an invalid one is refused, not silently accepted.
#[test]
fn invalid_profiles_are_refused() {
    // A first destination CID must be at least 8 bytes.
    ConnectionIdProfile::standard()
        .try_with_initial_destination_len(4)
        .unwrap_err();
    ConnectionIdProfile::standard()
        .try_with_local_len(21)
        .unwrap_err();
    // An Initial datagram must be at least 1200 bytes.
    PacketizationProfile::standard()
        .try_with_initial_datagram_size(1100)
        .unwrap_err();
    PacketizationProfile::standard()
        .try_with_packet_number_length(PacketNumberLength::AtLeast(5))
        .unwrap_err();
    // An extra parameter may not shadow a known one.
    TransportParameterProfile::standard()
        .try_with_extra(vec![OpaqueParameter {
            id: ParameterId::MAX_IDLE_TIMEOUT,
            value: Vec::new(),
        }])
        .unwrap_err();
    // A greased parameter must use a reserved identifier.
    TransportParameterProfile::standard()
        .try_with_grease(GreaseParameter::Fixed {
            id: ParameterId(0x28),
            value: Vec::new(),
        })
        .unwrap_err();
}

/// A Rustls client cannot offer a compatible version, so the Firefox profile, which offers v2,
/// is refused when applied to a Rustls client. On Boring it is accepted.
#[cfg(feature = "boring")]
#[test]
fn the_firefox_profile_needs_a_switch_capable_backend_on_boring() {
    let identity = crate::test_helpers::identity();
    let mut config = boring_client(&identity);
    config
        .apply_quic_profile(&firefox_156())
        .expect("the firefox profile applies on a switch-capable backend");
}

#[cfg(feature = "boring")]
fn boring_client(identity: &rama_tls::server::ServerAuthData) -> ClientConfig {
    use rama_tls::client::TlsClientConfig;
    let tls = TlsClientConfig::new()
        .with_alpn([b"rama-quic-test".as_slice().into()].into_iter().collect())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    ClientConfig::try_from_rama_tls(
        &tls,
        crate::tls::TlsOptions::default().with_backend(rama_tls::TlsBackend::Boring),
    )
    .unwrap()
}

#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
#[test]
fn the_firefox_profile_is_refused_on_a_rustls_client() {
    use rama_tls::client::TlsClientConfig;
    let identity = crate::test_helpers::identity();
    let tls = TlsClientConfig::new()
        .with_alpn([b"rama-quic-test".as_slice().into()].into_iter().collect())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let mut config = ClientConfig::try_from_rama_tls(
        &tls,
        crate::tls::TlsOptions::default().with_backend(rama_tls::TlsBackend::Rustls),
    )
    .unwrap();
    assert!(matches!(
        config.apply_quic_profile(&firefox_156()),
        Err(crate::ConfigError::VersionPolicy(_))
    ));
}
