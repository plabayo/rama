//! Native recorded layouts: authenticate emitted packets, then complete a real handshake.

use std::sync::Arc;

use rama_core::bytes::Bytes;
use rama_quic_proto::{
    ConnectionId, Version,
    capture::{FirstFlight, ObservedFrame},
    packet::{Header, InitialHeader, PacketNumber},
    profile::{
        GreaseParameter, InitialFlightLayout, PacketizationProfile, QuicProfile,
        initial::{InitialFrame, InitialPacket, RecordedInitialFlight},
    },
    version::ClientVersionPolicy,
};

use super::{
    EndpointConfig, Pair,
    util::{client_config, server_config},
};
use crate::profile::capture;

fn base_profile(version: Version) -> QuicProfile {
    let profile = QuicProfile::standard().with_versions(ClientVersionPolicy::new(version).unwrap());
    // Unconstrained GREASE value length intentionally changes the fresh hello's
    // extent. This test fixes that native policy, rather than guessing or padding TLS.
    profile.clone().with_transport_parameters(
        profile
            .transport_parameters()
            .clone()
            .try_with_grease(GreaseParameter::None)
            .unwrap(),
    )
}

fn pair(profile: &QuicProfile) -> (Pair, crate::proto::ClientConfig) {
    let mut endpoint = EndpointConfig::try_with_rand_key().unwrap();
    endpoint.apply_quic_profile(profile).unwrap();
    let pair = Pair::new(Arc::new(endpoint), server_config());
    let mut client = client_config();
    client.apply_quic_profile(profile).unwrap();
    (pair, client)
}

fn flight(pair: &Pair) -> FirstFlight {
    let buffers: Vec<&[u8]> = pair
        .server
        .inbound
        .iter()
        .map(|datagram| datagram.packet.as_ref())
        .collect();
    capture::first_flight(&buffers, &*server_config().crypto.into_fixed()).unwrap()
}

fn recorded_profile(version: Version) -> QuicProfile {
    // Learn the actual provider's fresh ClientHello extent. The target handshake
    // has different random/key-share bytes but the same configured wire shape.
    let base = base_profile(version);
    let (mut source, client) = pair(&base);
    source.begin_connect(client);
    source.drive_client();
    let source = flight(&source);
    let extent = source
        .frames
        .iter()
        .flatten()
        .filter_map(|frame| match frame {
            ObservedFrame::Crypto { offset, len } => Some(*offset as usize + len),
            _ => None,
        })
        .max()
        .unwrap();
    let split = extent / 2;
    let cid = ConnectionId::try_from_bytes(&vec![0; source.dcid_len]).unwrap();
    let scid = ConnectionId::try_from_bytes(&vec![0; source.scid_len]).unwrap();
    let keys = server_config()
        .crypto
        .into_fixed()
        .initial_keys(version, &cid)
        .unwrap();
    let tag_len = keys.local.packet.tag_len();
    let packets = [(split, extent - split), (0, split)]
        .into_iter()
        .enumerate()
        .map(|(index, (offset, len))| {
            let number = index as u64 + 1;
            let width = index as u8 + 1;
            let mut header = Vec::new();
            Header::Initial(InitialHeader {
                dst_cid: cid,
                src_cid: scid,
                token: Bytes::new(),
                number: PacketNumber::new_at_least(number, 0, width).unwrap(),
                version: version.to_wire().unwrap(),
            })
            .encode_with_max_packet_len(&mut header, 1250);
            let frames = vec![
                InitialFrame::Ping,
                InitialFrame::Crypto {
                    offset: offset as u64,
                    len,
                },
            ];
            let unpadded = InitialPacket::try_new(number, width, 1250, frames.clone()).unwrap();
            let padding = 1250 - header.len() - tag_len - unpadded.payload_len();
            let mut frames = frames;
            frames.insert(1, InitialFrame::Padding { len: padding });
            InitialPacket::try_new(number, width, 1250, frames).unwrap()
        })
        .collect();
    let layout = RecordedInitialFlight::try_new(
        version,
        source.dcid_len as u8,
        source.scid_len as u8,
        packets,
    )
    .unwrap();
    base.with_packetization(
        PacketizationProfile::standard().with_layout(InitialFlightLayout::Recorded(layout)),
    )
}

#[test]
fn recorded_initial_emits_exact_frames_and_widths_then_completes() {
    for version in [Version::V1, Version::V2] {
        let profile = recorded_profile(version);
        let InitialFlightLayout::Recorded(expected) = profile.packetization().layout() else {
            panic!("the test constructs a recorded layout with PADDING then CRYPTO")
        };
        let (mut pair, client) = pair(&profile);
        let client = pair.begin_connect(client);
        pair.drive_client();
        let observed = flight(&pair);
        let actual = RecordedInitialFlight::try_from(&observed).unwrap();
        assert_eq!(&actual, expected);
        assert_eq!(observed.packet_number_lengths, [1, 2]);
        assert_eq!(observed.datagram_sizes, [1250, 1250]);
        assert!(pair.client_sent.iter().all(|sent| sent.packets.len() == 1));
        pair.drive();
        let server = pair.server.assert_accept();
        assert!(!pair.client_conn_mut(client).is_handshaking());
        assert!(!pair.server_conn_mut(server).is_handshaking());
    }
}

#[test]
fn recorded_initial_loss_recovers_through_normal_crypto_retransmission() {
    let profile = recorded_profile(Version::V1);
    let (mut pair, client) = pair(&profile);
    let client = pair.begin_connect(client);
    pair.drive_client();
    // Drop the packet containing the start of ClientHello. The peer cannot
    // complete TLS until recovery retransmits the tracked fresh CRYPTO ranges.
    pair.server.inbound.pop_back().unwrap();
    pair.drive();
    let server = pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client).is_handshaking());
    assert!(!pair.server_conn_mut(server).is_handshaking());
    assert!(pair.client_sent.len() > 2);
}

#[test]
fn recorded_initial_rejects_wrong_fresh_extent_or_geometry_before_output() {
    let valid = recorded_profile(Version::V1);
    let InitialFlightLayout::Recorded(layout) = valid.packetization().layout() else {
        panic!("the test constructs a recorded layout with PADDING then CRYPTO")
    };
    for wrong_extent in [false, true] {
        let mut packets = layout.packets().to_vec();
        let packet = &packets[1];
        let mut frames = packet.frames().to_vec();
        match &mut frames[if wrong_extent { 2 } else { 1 }] {
            InitialFrame::Crypto { len, .. } | InitialFrame::Padding { len } => *len += 1,
            _ => panic!("the test constructs a recorded layout with PADDING then CRYPTO"),
        }
        packets[1] = InitialPacket::try_new(
            packet.number(),
            packet.number_len(),
            packet.datagram_size(),
            frames,
        )
        .unwrap();
        // Increasing the final range also increases the required fresh extent.
        // The second packet carries the beginning, so change the end range instead.
        if wrong_extent {
            let first = &packets[0];
            let mut frames = first.frames().to_vec();
            if let InitialFrame::Crypto { offset, len } = &mut frames[2] {
                *offset += 1;
                *len += 1;
            }
            packets[0] = InitialPacket::try_new(
                first.number(),
                first.number_len(),
                first.datagram_size(),
                frames,
            )
            .unwrap();
        }
        let changed = RecordedInitialFlight::try_new(
            layout.version(),
            layout.destination_cid_len(),
            layout.source_cid_len(),
            packets,
        )
        .unwrap();
        let profile = valid.clone().with_packetization(
            PacketizationProfile::standard().with_layout(InitialFlightLayout::Recorded(changed)),
        );
        let (mut pair, client) = pair(&profile);
        let result = pair
            .client
            .connect(pair.time, client, pair.server.addr, "localhost");
        assert!(
            result.is_err(),
            "incompatible original layout must fail before connection output"
        );
        assert!(pair.client.outbound.is_empty());
        assert_eq!(pair.client.endpoint.open_connections(), 0);
    }
}
