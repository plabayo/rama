use super::*;
use crate::profile::{
    CanonicalValue, CapturedSlot, ConnectionContext, H2CapturedFrame, H2CapturedSetting,
    PreparedConnectionProfile, ProfileCaptureCompleteness, ProfileObservationScope, ValueId,
};
use rama_http::proto::h2::frame::EarlyFrame;

fn order_slot(kind: CapturedSlotKind, namespace: OrderNamespace, id: u64) -> CapturedSlot {
    let value = match namespace {
        OrderNamespace::Http3Setting => 0u64.to_be_bytes().to_vec(),
        OrderNamespace::QuicParameter | OrderNamespace::QuicVersion => Vec::new(),
    };
    let value = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        namespace,
        [(id, value)],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    CapturedSlot { kind, value }
}

fn selection(capture: CanonicalValue) -> ConnectionSelection {
    ConnectionSelection {
        profile: ValueId([1; 32]),
        variant: capture.id,
        draw: crate::profile::DrawKey([2; 32]),
        analysis_revision: 2,
        effective: PreparedConnectionProfile {
            scope: ValueId([3; 32]),
            capture,
            context: ProfileObservationScope {
                authorized: false,
                profile: ValueId([1; 32]),
                flow: None,
                connection: ConnectionContext::default(),
                structure: ValueId([4; 32]),
            },
        },
    }
}

#[test]
fn tcp_connection_components_decode_h2_frames() {
    let h2 = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: vec![H2CapturedFrame::Settings {
            ack: false,
            entries: vec![H2CapturedSetting { id: 1, value: 4096 }].into(),
        }]
        .into(),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: h2,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    let prepared = selection(capture)
        .prepare_components(ProfilePreservationMode::Strict)
        .unwrap();
    let replay = prepared.h2_early_frames.unwrap();
    let EarlyFrame::Settings(settings) = &replay[0] else {
        panic!("initial replay frame must be SETTINGS");
    };
    assert_eq!(settings.config.header_table_size, Some(4_096));
}

#[test]
fn h2_settings_ack_is_regenerated_in_every_preservation_mode() {
    let h2 = H2Capture {
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
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Http2EarlyFrames,
            value: h2,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    for mode in [
        ProfilePreservationMode::Strict,
        ProfilePreservationMode::BestEffort,
    ] {
        let prepared = selection(capture.clone()).prepare_components(mode).unwrap();
        assert_eq!(prepared.h2_early_frames.unwrap().len(), 1);
        assert!(prepared.preservation_report.is_exact());
    }
}

#[test]
fn quic_connection_components_keep_each_order_namespace_separate() {
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![
            order_slot(
                CapturedSlotKind::QuicParameters,
                OrderNamespace::QuicParameter,
                0x04,
            ),
            order_slot(
                CapturedSlotKind::Http3Settings,
                OrderNamespace::Http3Setting,
                0x06,
            ),
            order_slot(
                CapturedSlotKind::QuicVersions,
                OrderNamespace::QuicVersion,
                1,
            ),
        ]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    let prepared = selection(capture)
        .prepare_components(ProfilePreservationMode::Strict)
        .unwrap();
    assert_eq!(prepared.quic_parameters.unwrap().fields[0].id, 0x04);
    assert_eq!(prepared.h3_peer_settings.unwrap().fields[0].id, 0x06);
    assert_eq!(prepared.quic_versions.unwrap().fields[0].id, 1);
    assert!(prepared.h2_early_frames.is_none());
}

#[test]
fn request_capture_cannot_be_prepared_as_connection_components() {
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: Box::default(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();

    assert!(matches!(
        selection(capture).prepare_components(ProfilePreservationMode::Strict),
        Err(ProfileDataError::Invalid(
            "connection profile capture level"
        ))
    ));
}
