use super::*;
use crate::profile::capture::{
    joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
    order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
};
use rama_core::bytes::BytesMut;
use rama_http::proto::h2::frame::{
    EarlyFrameStreamContext, Head, Kind, Settings, StreamId, WindowUpdate,
};
use sha2::{Digest as _, Sha256};

fn source(entries: &[(u16, u32)]) -> EarlyFrameCapture {
    let payload: Vec<u8> = entries
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect();
    let settings = Settings::load_observed(
        Head::new(Kind::Settings, 0, StreamId::zero()),
        &payload,
        true,
    )
    .unwrap();
    let mut recorder = EarlyFrameStreamContext::new_recorder();
    recorder.record_settings_frame(&settings);
    recorder.record_windows_update_frame(WindowUpdate::new(StreamId::zero(), 100));
    recorder.freeze_recorder().unwrap()
}
fn captured(entries: &[(u16, u32)]) -> H2Capture {
    H2Capture::capture(&source(entries), H2CaptureLimits::default()).unwrap()
}
fn resign(mut value: CanonicalValue, offset: usize, replacement: u8) -> CanonicalValue {
    value.bytes[offset] = replacement;
    value.id.0 = Sha256::digest(&value.bytes).into();
    value
}

#[test]
fn acknowledgements_do_not_change_h2_structure_or_replay() {
    let limits = H2CaptureLimits::default();
    let plain = captured(&[(1, 4096)]);
    let mut frames = plain.frames.clone().into_vec();
    frames.insert(
        1,
        H2CapturedFrame::Settings {
            ack: true,
            entries: Box::default(),
        },
    );
    let acknowledged = H2Capture {
        frames: frames.into(),
        ..plain
    };
    assert_ne!(
        plain.canonical(limits).unwrap().id,
        acknowledged.canonical(limits).unwrap().id
    );
    assert_eq!(
        plain.structural(limits).unwrap().id,
        acknowledged.structural(limits).unwrap().id
    );
    assert_eq!(
        plain.replay_frames(limits).unwrap(),
        acknowledged.replay_frames(limits).unwrap()
    );
}

#[test]
fn h2_canonical_bytes_match_independent_vectors() {
    let limits = H2CaptureLimits::default();
    let capture = captured(&[(1, 4096), (0xffff, 7)]);
    for (value, expected, digest) in [
        (capture.canonical(limits).unwrap(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x0c\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x00\x10\x00\xff\xff\x00\x00\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x64".as_slice(), [0xce, 0x94, 0x9f, 0x08, 0x46, 0x1c, 0x46, 0x62, 0xf7, 0x98, 0x30, 0xda, 0x69, 0xf6, 0x06, 0x38, 0xa4, 0x88, 0xe5, 0xe6, 0x09, 0x22, 0x27, 0x4a, 0x86, 0x46, 0xab, 0x1d, 0xea, 0x34, 0xa8, 0x22]),
        (capture.structural(limits).unwrap(), b"\x72\x61\x6d\x61\x2d\x70\x72\x6f\x66\x69\x6c\x65\x00\x00\x01\x00\x0d\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x00\x00\x10\x00\xff\xff\x00\x00\x00\x07\x01\x00\x00\x00\x00\x00\x00\x00\x64".as_slice(), [0xd3, 0x79, 0x31, 0x7b, 0x41, 0x2f, 0x0a, 0x2a, 0x91, 0xad, 0x05, 0xf6, 0x69, 0x48, 0xee, 0xed, 0xdb, 0xa9, 0x0e, 0xfb, 0xa0, 0xf2, 0x28, 0x32, 0x7f, 0xac, 0x60, 0x72, 0x7b, 0x39, 0x86, 0xb3]),
    ] {
        assert_eq!(value.bytes.as_ref(), expected);
        assert_eq!(value.id.0, digest);
    }
}

#[test]
fn h2_wire_capture_preserves_unknown_duplicates_and_frame_order() {
    let limits = H2CaptureLimits::default();
    let capture = captured(&[(1, 4096), (0xfefe, 99), (1, 8192)]);
    let value = capture.canonical(limits).unwrap();
    let restored = H2Capture::from_canonical(&value, limits).unwrap();
    assert_eq!(
        serde_json::to_vec(&capture).unwrap(),
        serde_json::to_vec(&restored).unwrap()
    );
    assert!(
        matches!(&restored.frames[0], H2CapturedFrame::Settings { ack: false, entries } if entries.len() == 3 && entries[1].id == 0xfefe && entries[1].value == 99 && entries[2].value == 8192)
    );
    let mut reversed = restored.clone();
    reversed.frames.reverse();
    reversed.canonical(limits).unwrap_err();
    let mut frames = restored.frames.into_vec();
    frames.push(H2CapturedFrame::WindowUpdate {
        stream: 0,
        increment: 200,
    });
    let mut ordered = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: frames.into(),
    };
    let first = ordered.canonical(limits).unwrap();
    let structure = ordered.structural(limits).unwrap();
    ordered.frames.swap(1, 2);
    assert_ne!(first.id, ordered.canonical(limits).unwrap().id);
    assert_ne!(structure.id, ordered.structural(limits).unwrap().id);
}

#[test]
fn h2_replay_compiles_exact_settings_and_early_frame_order() {
    let capture = captured(&[(1, 4_096), (0xfefe, 99), (1, 8_192)]);
    let frames = capture.replay_frames(H2CaptureLimits::default()).unwrap();
    assert_eq!(frames.len(), 2);
    let EarlyFrame::Settings(settings) = &frames[0] else {
        panic!("initial frame must remain SETTINGS");
    };
    let mut encoded = BytesMut::new();
    settings.encode(&mut encoded);
    assert_eq!(
        &encoded[9..],
        &[
            0, 1, 0, 0, 16, 0, 0xfe, 0xfe, 0, 0, 0, 99, 0, 1, 0, 0, 32, 0,
        ]
    );
    assert!(matches!(frames[1], EarlyFrame::WindowUpdate(_)));
}

#[test]
fn h2_structure_keeps_duplicate_setting_semantics() {
    let limits = H2CaptureLimits::default();
    let first = captured(&[(1, 4096), (0xfefe, 99), (1, 8192)]);
    let reordered = captured(&[(0xfefe, 99), (1, 4096), (1, 8192)]);
    let changed = captured(&[(1, 8192), (0xfefe, 99), (1, 4096)]);
    assert_ne!(
        first.canonical(limits).unwrap().id,
        reordered.canonical(limits).unwrap().id
    );
    assert_eq!(
        first.structural(limits).unwrap().id,
        reordered.structural(limits).unwrap().id
    );
    assert_ne!(
        first.structural(limits).unwrap().id,
        changed.structural(limits).unwrap().id
    );
    let value = first.structural(limits).unwrap();
    value
        .validate_content(CanonicalDomain::H2Structure, limits.bytes)
        .unwrap();
}

#[test]
fn h2_incomplete_or_legacy_observations_do_not_gain_profile_capability() {
    let limits = H2CaptureLimits::default();
    let legacy: EarlyFrameCapture =
        serde_json::from_slice(&serde_json::to_vec(&source(&[(1, 1)])).unwrap()).unwrap();
    H2Capture::capture(&legacy, limits).unwrap_err();
    let partial = source(&vec![(0xffff, 1); 257]);
    assert!(partial.is_complete());
    H2Capture::capture(&partial, limits).unwrap_err();
    let mut recorder = EarlyFrameStreamContext::new_recorder();
    for _ in 0..17 {
        recorder.record_windows_update_frame(WindowUpdate::new(StreamId::zero(), 1));
    }
    H2Capture::capture(&recorder.freeze_recorder().unwrap(), limits).unwrap_err();
    let mut capture = captured(&[(1, 1)]);
    let canonical = capture.canonical(limits).unwrap();
    capture.completeness = ProfileCaptureCompleteness::Incomplete;
    capture.canonical(limits).unwrap_err();
    capture.structural(limits).unwrap_err();
    for tag in [0, 2, 255] {
        H2Capture::from_canonical(&resign(canonical.clone(), 17, tag), limits).unwrap_err();
    }
}

#[test]
fn h2_capture_checks_aggregate_budgets_and_canonical_bytes() {
    let base = H2CaptureLimits::default();
    let source = source(&[(1, 4096), (0xffff, 7)]);
    let capture = H2Capture::capture(&source, base).unwrap();
    let value = capture.canonical(base).unwrap();
    let exact = H2CaptureLimits {
        frames: 2,
        settings: 2,
        bytes: value.bytes.len(),
    };
    H2Capture::capture(&source, exact).unwrap();
    H2Capture::from_canonical(&value, exact).unwrap();
    for limits in [
        H2CaptureLimits { frames: 1, ..exact },
        H2CaptureLimits {
            settings: 1,
            ..exact
        },
        H2CaptureLimits {
            bytes: exact.bytes - 1,
            ..exact
        },
    ] {
        H2Capture::capture(&source, limits).unwrap_err();
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
        H2Capture::from_canonical(&value, limits).unwrap_err();
    }
    for end in 0..value.bytes.len() {
        let mut shortened = value.clone();
        shortened.bytes = shortened.bytes[..end].into();
        shortened.id.0 = Sha256::digest(&shortened.bytes).into();
        H2Capture::from_canonical(&shortened, base).unwrap_err();
    }
    let mut corrupt = value.clone();
    corrupt.id.0[0] ^= 1;
    H2Capture::from_canonical(&corrupt, base).unwrap_err();
    H2Capture::from_canonical(&resign(value.clone(), 27, 2), base).unwrap_err();
    H2Capture::from_canonical(&resign(value.clone(), 27, 1), base).unwrap_err(); // ACK with entries
    H2Capture::from_canonical(&resign(value, 26, 255), base).unwrap_err();
}

#[test]
fn h2_hand_built_frames_enforce_protocol_limits() {
    let limits = H2CaptureLimits::default();
    for frame in [
        H2CapturedFrame::WindowUpdate {
            stream: 0,
            increment: 0,
        },
        H2CapturedFrame::WindowUpdate {
            stream: 1 << 31,
            increment: 1,
        },
        H2CapturedFrame::WindowUpdate {
            stream: 0,
            increment: 1 << 31,
        },
        H2CapturedFrame::Priority {
            stream: 0,
            dependency: 1,
            weight: 0,
            exclusive: false,
        },
        H2CapturedFrame::Priority {
            stream: 1,
            dependency: 1,
            weight: 0,
            exclusive: false,
        },
        H2CapturedFrame::Priority {
            stream: 1 << 31,
            dependency: 0,
            weight: 255,
            exclusive: true,
        },
        H2CapturedFrame::Priority {
            stream: 1,
            dependency: 1 << 31,
            weight: 255,
            exclusive: true,
        },
    ] {
        let capture = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: vec![
                H2CapturedFrame::Settings {
                    ack: false,
                    entries: Box::default(),
                },
                frame,
            ]
            .into(),
        };
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
    }
    for (id, value) in [
        (2, 2),
        (8, 2),
        (9, 2),
        (4, 1 << 31),
        (5, (1 << 14) - 1),
        (5, 1 << 24),
    ] {
        let capture = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: vec![H2CapturedFrame::Settings {
                ack: false,
                entries: vec![H2CapturedSetting { id, value }].into(),
            }]
            .into(),
        };
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
    }
}

#[test]
fn h2_capture_requires_initial_non_ack_settings() {
    let limits = H2CaptureLimits::default();
    for frames in [
        vec![],
        vec![H2CapturedFrame::Settings {
            ack: true,
            entries: Box::default(),
        }],
        vec![H2CapturedFrame::WindowUpdate {
            stream: 0,
            increment: 1,
        }],
    ] {
        let capture = H2Capture {
            completeness: ProfileCaptureCompleteness::Complete,
            frames: frames.into(),
        };
        capture.canonical(limits).unwrap_err();
        capture.structural(limits).unwrap_err();
    }
    let capture = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![
            H2CapturedFrame::Settings {
                ack: false,
                entries: Box::default(),
            },
            H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            },
        ]
        .into(),
    };
    let value = capture.canonical(limits).unwrap();
    H2Capture::from_canonical(&value, limits).unwrap();
}

#[test]
fn h2_joint_slots_remain_connection_owned_and_tcp_bound() {
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: captured(&[(1, 4096)])
                .canonical(H2CaptureLimits::default())
                .unwrap(),
        }]
        .into(),
    };
    let value = joint.canonical(limits).unwrap();
    JointCapture::from_canonical(&value, limits).unwrap();
    joint
        .structural(limits)
        .unwrap()
        .validate_content(CanonicalDomain::JointStructure, limits.bytes)
        .unwrap();
    joint.level = CaptureLevel::Request;
    joint.canonical(limits).unwrap_err();
    joint.structural(limits).unwrap_err();
    joint.level = CaptureLevel::Connection;
    let mut slots = joint.slots.into_vec();
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::QuicVersions,
        value: OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicVersion,
            [(1, [])],
            OrderCaptureLimits::default(),
        )
        .unwrap()
        .canonical(OrderCaptureLimits::default())
        .unwrap(),
    });
    joint.slots = slots.into();
    joint.canonical(limits).unwrap_err();
    joint.structural(limits).unwrap_err();
}
