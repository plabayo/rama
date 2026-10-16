use super::*;

#[test]
fn flight_roundtrip_retains_layout_without_connection_secrets() {
    let limits = QuicFlightCaptureLimits::default();
    let capture = capture();
    let canonical = capture.canonical(limits).unwrap();
    assert_eq!(
        QuicFlightCapture::from_canonical(&canonical, limits)
            .unwrap()
            .flight,
        capture.flight
    );
    for secret in [
        b"connection-secret".as_slice(),
        b"attempt-secret",
        b"private-clienthello",
    ] {
        assert!(
            !canonical
                .bytes
                .windows(secret.len())
                .any(|value| value == secret)
        );
        assert!(
            !serde_json::to_vec(&capture)
                .unwrap()
                .windows(secret.len())
                .any(|value| value == secret)
        );
    }
    assert_ne!(canonical.id, capture.structural(limits).unwrap().id);
    let structure = capture.structural(limits).unwrap();
    assert_eq!(
        structure.id.0,
        [
            183, 115, 0, 156, 201, 184, 78, 200, 115, 134, 248, 59, 135, 111, 8, 72, 117, 91, 184,
            108, 172, 227, 189, 222, 189, 255, 186, 158, 49, 21, 190, 61
        ]
    );
    assert_eq!(structure.bytes.as_ref(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x15\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    assert_eq!(canonical.bytes.len(), 172);
    assert_eq!(
        canonical.id.0,
        [
            1, 237, 112, 216, 8, 96, 212, 129, 1, 57, 234, 121, 151, 226, 123, 201, 163, 24, 246,
            91, 51, 192, 149, 123, 247, 200, 75, 154, 252, 75, 85, 179
        ]
    );
}

#[test]
fn flight_capture_requires_all_source_completeness_flags() {
    let limits = QuicFlightCaptureLimits::default();
    for flag in 0..7 {
        let mut source = observation();
        match flag {
            0 => source.completeness.datagrams = false,
            1 => source.completeness.frames = false,
            2 => source.completeness.client_hello = false,
            3 => source.completeness.transport_parameters = false,
            4 => source.completeness.original_attempt = false,
            5 => source.first_flight.as_mut().unwrap().complete = false,
            _ => source.first_flight = None,
        }
        QuicFlightCapture::capture(&source, limits).unwrap_err();
    }
    let mut source = observation();
    source.transport_parameters.clear();
    QuicFlightCapture::capture(&source, limits).unwrap_err();
    let mut capture = capture();
    capture.completeness = ProfileCaptureCompleteness::Incomplete;
    capture.canonical(limits).unwrap_err();
}

#[test]
fn flight_limits_apply_before_retention_to_each_nested_collection() {
    let source = observation();
    let limits = QuicFlightCaptureLimits::default();
    for limits in [
        QuicFlightCaptureLimits {
            observed_bytes: 1199,
            ..limits
        },
        QuicFlightCaptureLimits {
            datagrams: 0,
            ..limits
        },
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
    ] {
        QuicFlightCapture::capture(&source, limits).unwrap_err();
    }
    QuicFlightCapture::capture(
        &source,
        QuicFlightCaptureLimits {
            observed_bytes: 1200,
            ..limits
        },
    )
    .unwrap();
    let mut capture = capture();
    capture.flight.datagram_sizes[0] = kib(32);
    let encoded = capture
        .canonical(QuicFlightCaptureLimits {
            bytes: kib(1),
            ..limits
        })
        .unwrap();
    QuicFlightCapture::from_canonical(
        &encoded,
        QuicFlightCaptureLimits {
            bytes: kib(1),
            ..limits
        },
    )
    .unwrap();
    capture.flight.frames[0].push(ObservedFrame::Ping);
    capture
        .canonical(QuicFlightCaptureLimits {
            frames: 2,
            ..limits
        })
        .unwrap_err();
}

#[test]
fn flight_rejects_inconsistent_lengths_numbers_and_version_context() {
    let limits = QuicFlightCaptureLimits::default();
    for case in 0..14 {
        let mut capture = capture();
        let flight = &mut capture.flight;
        match case {
            0 => flight.trailing_bytes.clear(),
            1 => flight.trailing_bytes[0] = 1201,
            2 => flight.datagram_sizes[0] = 0,
            3 => flight.dcid_len = 21,
            4 => flight.packet_number_len = 0,
            5 => flight.first_packet_number = 4,
            6 => flight.packet_numbers.push(4),
            7 => {
                flight.first_packet_number = 1 << 62;
                flight.packet_numbers[0] = 1 << 62;
            }
            8 => {
                flight.frames[0][0] = ObservedFrame::Crypto {
                    offset: (1 << 62) - 1,
                    len: 1,
                }
            }
            9 => flight.frames[0][0] = ObservedFrame::Other { ty: 1 << 62 },
            10 => flight.frames[0][0] = ObservedFrame::Padding { len: 0 },
            11 => flight.parameters.push(ParameterId(1)),
            12 => flight.parameters[0] = ParameterId(1 << 62),
            _ => flight.chosen_version = Some(Version::V2),
        }
        capture.canonical(limits).unwrap_err();
    }
    let mut capture = capture();
    capture.flight.packet_numbers.push(3);
    let value = capture.canonical(limits).unwrap();
    assert_eq!(
        QuicFlightCapture::from_canonical(&value, limits)
            .unwrap()
            .flight
            .packet_numbers,
        [3, 3]
    );
    capture
        .flight
        .parameters
        .push(ParameterId::VERSION_INFORMATION);
    capture.flight.chosen_version = Some(Version::V1);
    capture.flight.available_versions = vec![Version::V2, Version::V1];
    capture.canonical(limits).unwrap();
    capture.flight.available_versions = vec![Version::V2];
    capture.canonical(limits).unwrap_err();
}

#[test]
fn flight_import_rejects_bad_envelopes_truncation_and_trailers() {
    let limits = QuicFlightCaptureLimits::default();
    let value = capture().canonical(limits).unwrap();
    for end in 0..value.bytes.len() {
        QuicFlightCapture::from_canonical(&resign(value.bytes[..end].to_vec()), limits)
            .unwrap_err();
    }
    let mut bytes = value.bytes.to_vec();
    bytes.push(0);
    QuicFlightCapture::from_canonical(&resign(bytes), limits).unwrap_err();
    let mut bad = value.clone();
    bad.id.0[0] ^= 1;
    QuicFlightCapture::from_canonical(&bad, limits).unwrap_err();
    for index in [14, 16, 17] {
        let mut bytes = value.bytes.to_vec();
        bytes[index] = 255;
        resign(bytes).validated_domain(limits.bytes).unwrap_err();
    }
}

#[test]
fn flight_joint_slot_is_connection_owned() {
    let mut joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: Box::new([CapturedSlot {
            kind: CapturedSlotKind::QuicFirstFlight,
            value: capture()
                .canonical(QuicFlightCaptureLimits::default())
                .unwrap(),
        }]),
    };
    let limits = JointCaptureLimits::default();
    let value = joint.canonical(limits).unwrap();
    JointCapture::from_canonical(&value, limits).unwrap();
    joint
        .structural(limits)
        .unwrap()
        .validated_domain(limits.bytes)
        .unwrap();
    joint.level = CaptureLevel::Request;
    joint.canonical(limits).unwrap_err();
}

#[test]
fn cid_length_classes_preserve_literal_draws_and_routing_choices() {
    let limits = QuicFlightCaptureLimits::default();
    for version in [Version::V1, Version::V2] {
        let mut expected = None;
        for dcid in 8..=20 {
            for scid in 1..=20 {
                let mut captured = capture();
                captured.flight.version = version;
                captured.flight.dcid_len = dcid;
                captured.flight.scid_len = scid;
                let literal = captured.canonical(limits).unwrap();
                let restored = QuicFlightCapture::from_canonical(&literal, limits).unwrap();
                assert_eq!(restored.flight.dcid_len, dcid);
                assert_eq!(restored.flight.scid_len, scid);
                let structure = captured.structural(limits).unwrap();
                QuicFlightCapture::validate_structure(&structure, limits).unwrap();
                assert_eq!(*expected.get_or_insert(structure.id), structure.id);
            }
        }
        let mut captured = capture();
        captured.flight.version = version;
        assert_ne!(expected.unwrap(), captured.structural(limits).unwrap().id);
        captured.flight.scid_len = 1;
        for dcid in 0..8 {
            captured.flight.dcid_len = dcid;
            assert_ne!(expected.unwrap(), captured.structural(limits).unwrap().id);
        }
    }
}
