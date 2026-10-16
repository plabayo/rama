use super::*;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        http2::{H2Capture, H2CapturedFrame, H2CapturedSetting},
    },
    compare::{CaptureComparisonLimits, compare_retained_captures},
};

fn h2(ack: Option<usize>, window: u32, setting: u32) -> CanonicalValue {
    let mut frames = vec![
        H2CapturedFrame::Settings {
            ack: false,
            entries: vec![H2CapturedSetting {
                id: 1,
                value: setting,
            }]
            .into(),
        },
        H2CapturedFrame::WindowUpdate {
            stream: 0,
            increment: 100,
        },
        H2CapturedFrame::WindowUpdate {
            stream: 3,
            increment: window,
        },
    ];
    if let Some(index) = ack {
        frames.insert(
            index,
            H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            },
        );
    }
    H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: frames.into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap()
}

fn matches(reference: &[CanonicalValue], actual: &CanonicalValue, mode: ComparisonMode) -> bool {
    compare_retained_captures(reference, actual, mode, CaptureComparisonLimits::default())
        .unwrap()
        .matched
}

#[test]
fn replay_excludes_peer_ack_position_and_presence_but_literal_does_not() {
    let reference = h2(Some(3), 500, 4096);
    for actual in [h2(Some(1), 500, 4096), h2(None, 500, 4096)] {
        assert!(!matches(
            std::slice::from_ref(&reference),
            &actual,
            ComparisonMode::Literal
        ));
        let report = compare_retained_captures(
            std::slice::from_ref(&reference),
            &actual,
            ComparisonMode::Replay,
            CaptureComparisonLimits::default(),
        )
        .unwrap();
        assert!(report.matched);
        assert_eq!(report.reference, reference.id);
        assert_eq!(report.observed, actual.id);
        assert_eq!(report.mode, ComparisonMode::Replay);
        assert!(report.differences.is_empty());
    }
}

#[test]
fn replay_preserves_non_ack_settings_window_values_order_and_correlation() {
    let reference = [h2(Some(3), 500, 4096), h2(None, 700, 8192)];
    for (window, setting) in [(500, 8192), (501, 4096), (500, 4097)] {
        for ack in [None, Some(1)] {
            assert!(!matches(
                &reference,
                &h2(ack, window, setting),
                ComparisonMode::Replay
            ));
        }
    }
    let mut reordered =
        H2Capture::from_canonical(&h2(None, 500, 4096), H2CaptureLimits::default()).unwrap();
    reordered.frames.swap(1, 2);
    assert!(!matches(
        &reference,
        &reordered.canonical(H2CaptureLimits::default()).unwrap(),
        ComparisonMode::Replay
    ));
}

#[test]
fn replay_validates_identity_and_resource_budgets_before_matching() {
    let reference = h2(Some(3), 500, 4096);
    let mut invalid = reference.clone();
    invalid.id.0[0] ^= 1;
    for mode in [ComparisonMode::Literal, ComparisonMode::Replay] {
        compare_retained_captures(
            std::slice::from_ref(&reference),
            &invalid,
            mode,
            CaptureComparisonLimits::default(),
        )
        .unwrap_err();
        for limits in [
            CaptureComparisonLimits {
                work: 0,
                ..Default::default()
            },
            CaptureComparisonLimits {
                bytes: reference.bytes.len() - 1,
                ..Default::default()
            },
        ] {
            compare_retained_captures(std::slice::from_ref(&reference), &reference, mode, limits)
                .unwrap_err();
        }
    }
}

#[cfg(feature = "tls")]
fn joint(cipher: u16, window: u32, ack: Option<usize>) -> CanonicalValue {
    use crate::profile::capture::{
        joint::{CaptureLevel, CapturedSlot, JointCapture},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
    };
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![
            CapturedSlot {
                kind: CapturedSlotKind::TcpTls,
                value: TlsCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    transport: TlsCaptureTransport::Tcp,
                    protocol_version: u16::from(rama_tls::ProtocolVersion::TLSv1_2),
                    ciphers: vec![cipher].into(),
                    compression: vec![0].into(),
                    extensions: Box::default(),
                }
                .canonical(TlsCaptureLimits::default())
                .unwrap(),
            },
            CapturedSlot {
                kind: CapturedSlotKind::Http2EarlyFrames,
                value: h2(ack, window, 4096),
            },
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

#[cfg(feature = "tls")]
#[test]
fn replay_projects_inside_joint_without_combining_other_connection_variants() {
    let reference = [joint(0x1301, 500, Some(3)), joint(0x1302, 700, None)];
    assert!(matches(
        &reference,
        &joint(0x1301, 500, Some(1)),
        ComparisonMode::Replay
    ));
    assert!(!matches(
        &reference,
        &joint(0x1301, 700, Some(1)),
        ComparisonMode::Replay
    ));
    assert!(!matches(
        &reference,
        &joint(0x1303, 500, None),
        ComparisonMode::Replay
    ));
}
