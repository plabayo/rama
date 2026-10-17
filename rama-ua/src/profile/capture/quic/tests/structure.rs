use super::*;

#[test]
fn ten_thousand_flights_share_structures_without_discarding_raw_draws() {
    let limits = QuicFlightCaptureLimits::default();
    let mut first = None;
    let mut first_joint = None;
    let mut raw = BTreeSet::new();
    for index in 0..10_000_u64 {
        let mut captured = capture();
        let flight = &mut captured.flight;
        flight.datagram_sizes[0] += (index % 17) as usize;
        flight.token_len = 1 + (index % 32) as usize;
        flight.first_packet_number = index + 3;
        flight.packet_numbers = vec![index + 3; 1 + (index % 3) as usize];
        flight.packet_number_lengths = vec![flight.packet_number_len; flight.packet_numbers.len()];
        flight.frames[0] = vec![
            ObservedFrame::Crypto {
                offset: 0,
                len: 50 + (index % 50) as usize,
            },
            ObservedFrame::Crypto {
                offset: 50 + index % 50,
                len: 100 + (index % 100) as usize,
            },
            ObservedFrame::Padding {
                len: 700 + (index % 100) as usize,
            },
        ];
        flight.parameters = vec![
            ParameterId(1),
            ParameterId::VERSION_INFORMATION,
            ParameterId(31 * (index + 1) + 27),
        ];
        flight.parameters.rotate_left((index % 3) as usize);
        flight.chosen_version = Some(Version::V1);
        flight.available_versions = vec![Version::V1, Version::V2];
        flight.available_versions.insert(
            (index % 3) as usize,
            Version::from_u32(0x0a0a_0a0a | ((index % 16) as u32 * 0x1010_1010)),
        );
        let value = captured.canonical(limits).unwrap();
        let structure = captured.structural(limits).unwrap();
        structure.validated_domain(limits.bytes).unwrap();
        assert_eq!(*first.get_or_insert(structure.id), structure.id);
        raw.insert(value.id);
        let joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicFirstFlight,
                value,
            }]
            .into(),
        };
        let structure = joint.structural(JointCaptureLimits::default()).unwrap();
        assert_eq!(*first_joint.get_or_insert(structure.id), structure.id);
    }
    assert_eq!(raw.len(), 10_000);
}

#[test]
fn flight_structures_keep_client_choices_and_known_version_preference() {
    let limits = QuicFlightCaptureLimits::default();
    let base = capture();
    let expected = base.structural(limits).unwrap();
    for case in 0..7 {
        let mut changed = base.clone();
        match case {
            0 => changed.flight.version = Version::V2,
            1 => changed.flight.dcid_len = 7,
            2 => changed.flight.scid_len += 1,
            3 => {
                changed.flight.packet_number_len += 1;
                changed.flight.packet_number_lengths[0] += 1;
            }
            4 => changed.flight.token_len = 1,
            5 => changed.flight.coalesced = true,
            _ => changed.flight.frames[0].push(ObservedFrame::Ping),
        }
        assert_ne!(expected.id, changed.structural(limits).unwrap().id);
    }
    let mut versions = base;
    versions
        .flight
        .parameters
        .push(ParameterId::VERSION_INFORMATION);
    versions.flight.chosen_version = Some(Version::V1);
    versions.flight.available_versions = vec![Version::V1, Version::V2];
    let ordered = versions.structural(limits).unwrap();
    versions.flight.available_versions.reverse();
    assert_ne!(ordered.id, versions.structural(limits).unwrap().id);
}

#[test]
fn firefox_connection_id_draws_share_flight_and_joint_structures() {
    // Four Firefox 157.0.1 loopback connections, captured before authentication.
    // The fixture contains flight metadata only, without ClientHello or CID bytes.
    let flights: Vec<FirstFlight> =
        serde_json::from_str(include_str!("fixtures/firefox_flights.json")).unwrap();
    assert_eq!(flights.len(), 4);
    assert_eq!(
        flights
            .iter()
            .map(|flight| flight.dcid_len)
            .collect::<Vec<_>>(),
        [12, 8, 9, 14]
    );
    let limits = QuicFlightCaptureLimits::default();
    let mut literals = BTreeSet::new();
    let mut structures = BTreeSet::new();
    let mut joints = BTreeSet::new();
    for flight in flights {
        let captured = QuicFlightCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            flight,
        };
        let literal = captured.canonical(limits).unwrap();
        let restored = QuicFlightCapture::from_canonical(&literal, limits).unwrap();
        assert_eq!(
            serde_json::to_value(&restored.flight).unwrap(),
            serde_json::to_value(&captured.flight).unwrap()
        );
        literals.insert(literal.id);
        let structure = captured.structural(limits).unwrap();
        QuicFlightCapture::validate_structure(&structure, limits).unwrap();
        structures.insert(structure.id);
        let joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::QuicFirstFlight,
                value: literal,
            }]
            .into(),
        };
        joints.insert(joint.structural(JointCaptureLimits::default()).unwrap().id);
    }
    assert_eq!(literals.len(), 4);
    assert_eq!(structures.len(), 1);
    assert_eq!(joints.len(), 1);
}

#[test]
fn flight_structure_import_rejects_unclassified_cid_lengths() {
    let limits = QuicFlightCaptureLimits::default();
    let value = capture().structural(limits).unwrap();
    // The canonical domain/version prefix is followed by QUIC version and CID classes.
    for (offset, lengths) in [(22, 9..=20u64), (30, 2..=20u64)] {
        for length in lengths {
            let mut bytes = value.bytes.to_vec();
            bytes[offset..offset + 8].copy_from_slice(&length.to_be_bytes());
            QuicFlightCapture::validate_structure(&resign(bytes), limits).unwrap_err();
        }
    }
}

#[test]
fn flight_structure_decoder_checks_bounds_canonicality_and_truncation() {
    let limits = QuicFlightCaptureLimits::default();
    let value = capture().structural(limits).unwrap();
    for end in 0..value.bytes.len() {
        QuicFlightCapture::validate_structure(&resign(value.bytes[..end].to_vec()), limits)
            .unwrap_err();
    }
    let mut bytes = value.bytes.to_vec();
    bytes.push(0);
    QuicFlightCapture::validate_structure(&resign(bytes), limits).unwrap_err();
    for limits in [
        QuicFlightCaptureLimits {
            packets: 0,
            ..limits
        },
        QuicFlightCaptureLimits {
            frames: 1,
            ..limits
        },
        QuicFlightCaptureLimits {
            parameters: 0,
            ..limits
        },
        QuicFlightCaptureLimits {
            bytes: value.bytes.len() - 1,
            ..limits
        },
    ] {
        QuicFlightCapture::validate_structure(&value, limits).unwrap_err();
    }
}

#[test]
fn chromium_chaos_layouts_share_structure_without_losing_frame_evidence() {
    // Chrome 154.0.8037.98: six fresh loopback connections, two Initials each.
    // Only public wire frame types, offsets and lengths are retained here.
    const PACKETS: &[&[(u64, u64, usize)]] = &[
        &[
            (6, 0, 55),
            (6, 1099, 197),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 1011, 88),
            (0, 0, 3),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 9),
            (1, 0, 0),
            (0, 0, 107),
            (1, 0, 0),
            (0, 0, 1),
            (1, 0, 0),
            (0, 0, 1),
            (6, 55, 18),
            (0, 0, 129),
            (1, 0, 0),
            (6, 1296, 576),
        ],
        &[
            (0, 0, 27),
            (1, 0, 0),
            (0, 0, 217),
            (6, 1009, 1),
            (0, 0, 1),
            (6, 897, 112),
            (6, 73, 824),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 5),
            (1, 0, 0),
            (6, 1010, 1),
            (0, 0, 4),
        ],
        &[
            (0, 0, 212),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 47, 9),
            (0, 0, 9),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 1015, 733),
            (6, 0, 9),
            (6, 9, 15),
            (0, 0, 8),
            (1, 0, 0),
            (6, 24, 23),
            (6, 1748, 166),
            (1, 0, 0),
            (1, 0, 0),
        ],
        &[
            (6, 758, 32),
            (0, 0, 62),
            (6, 790, 20),
            (1, 0, 0),
            (0, 0, 2),
            (6, 810, 205),
            (1, 0, 0),
            (0, 0, 11),
            (6, 56, 702),
            (0, 0, 161),
        ],
        &[
            (6, 3, 11),
            (0, 0, 30),
            (6, 82, 1),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 162),
            (1, 0, 0),
            (6, 21, 39),
            (1, 0, 0),
            (6, 65, 16),
            (0, 0, 5),
            (1, 0, 0),
            (1, 0, 0),
            (6, 63, 1),
            (6, 2, 1),
            (6, 0, 2),
            (6, 81, 1),
            (6, 14, 7),
            (0, 0, 16),
            (6, 1040, 869),
            (6, 60, 3),
            (6, 64, 1),
            (1, 0, 0),
            (1, 0, 0),
        ],
        &[
            (0, 0, 131),
            (6, 313, 212),
            (0, 0, 65),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 843, 93),
            (0, 0, 12),
            (6, 525, 256),
            (6, 781, 2),
            (6, 783, 60),
            (6, 83, 230),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 936, 104),
            (0, 0, 9),
        ],
        &[
            (1, 0, 0),
            (1, 0, 0),
            (1, 0, 0),
            (6, 65, 4),
            (6, 62, 1),
            (0, 0, 181),
            (6, 1030, 169),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 5),
            (6, 46, 13),
            (6, 0, 46),
            (1, 0, 0),
            (6, 1199, 711),
            (6, 63, 2),
            (0, 0, 33),
            (6, 59, 3),
            (1, 0, 0),
            (0, 0, 3),
            (6, 69, 4),
        ],
        &[
            (1, 0, 0),
            (0, 0, 4),
            (6, 77, 367),
            (0, 0, 165),
            (1, 0, 0),
            (0, 0, 2),
            (1, 0, 0),
            (0, 0, 39),
            (1, 0, 0),
            (6, 461, 145),
            (1, 0, 0),
            (6, 660, 200),
            (0, 0, 3),
            (1, 0, 0),
            (6, 73, 4),
            (1, 0, 0),
            (6, 444, 17),
            (0, 0, 4),
            (6, 860, 170),
            (1, 0, 0),
            (6, 606, 54),
        ],
        &[
            (0, 0, 36),
            (6, 1310, 429),
            (0, 0, 8),
            (6, 1309, 1),
            (1, 0, 0),
            (0, 0, 130),
            (6, 1039, 99),
            (0, 0, 17),
            (1, 0, 0),
            (6, 1739, 207),
            (0, 0, 18),
            (6, 1186, 123),
            (6, 0, 64),
            (0, 0, 1),
            (6, 1138, 48),
        ],
        &[
            (6, 629, 116),
            (0, 0, 1),
            (6, 745, 294),
            (0, 0, 65),
            (1, 0, 0),
            (6, 219, 230),
            (0, 0, 128),
            (1, 0, 0),
            (6, 64, 24),
            (6, 88, 131),
            (0, 0, 9),
            (6, 539, 90),
            (6, 449, 90),
        ],
        &[
            (0, 0, 198),
            (6, 1065, 810),
            (0, 0, 24),
            (6, 42, 16),
            (1, 0, 0),
            (1, 0, 0),
            (6, 76, 3),
            (6, 8, 4),
            (1, 0, 0),
            (0, 0, 21),
            (6, 0, 8),
            (1, 0, 0),
            (6, 58, 18),
            (6, 1019, 46),
            (1, 0, 0),
            (6, 12, 30),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 2),
        ],
        &[
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 17),
            (6, 714, 305),
            (1, 0, 0),
            (1, 0, 0),
            (0, 0, 10),
            (6, 79, 207),
            (0, 0, 191),
            (1, 0, 0),
            (0, 0, 1),
            (6, 494, 220),
            (6, 286, 208),
            (0, 0, 30),
        ],
    ];
    let limits = QuicFlightCaptureLimits::default();
    let mut structures = BTreeSet::new();
    let mut literals = BTreeSet::new();
    for packets in PACKETS.as_chunks::<2>().0 {
        let mut captured = capture();
        captured.flight.datagram_sizes = vec![1250, 1250];
        captured.flight.trailing_bytes = vec![0, 0];
        captured.flight.first_packet_number = 1;
        captured.flight.packet_numbers = vec![1, 2];
        captured.flight.packet_number_len = 1;
        captured.flight.packet_number_lengths = vec![1, 2];
        captured.flight.frames = packets
            .iter()
            .map(|packet| {
                packet
                    .iter()
                    .map(|&(ty, offset, len)| match ty {
                        0 => ObservedFrame::Padding { len },
                        1 => ObservedFrame::Ping,
                        6 => ObservedFrame::Crypto { offset, len },
                        _ => panic!("unexpected fixture frame"),
                    })
                    .collect()
            })
            .collect();
        let value = captured.canonical(limits).unwrap();
        let restored = QuicFlightCapture::from_canonical(&value, limits).unwrap();
        assert_eq!(
            serde_json::to_value(&restored.flight.frames).unwrap(),
            serde_json::to_value(&captured.flight.frames).unwrap()
        );
        literals.insert(value.id);
        let structure = captured.structural(limits).unwrap();
        QuicFlightCapture::validate_structure(&structure, limits).unwrap();
        structures.insert(structure.id);
    }
    assert_eq!(literals.len(), 6);
    assert_eq!(structures.len(), 1);
    let mut changed = capture();
    let before = changed.structural(limits).unwrap();
    changed.flight.datagram_sizes.push(1200);
    changed.flight.trailing_bytes.push(0);
    assert_ne!(before.id, changed.structural(limits).unwrap().id);
}
