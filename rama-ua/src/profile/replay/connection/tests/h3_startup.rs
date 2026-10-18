use super::*;
use crate::profile::{
    capture::http3::{H3CapturedEvent, H3ClientSequenceCapture},
    replay::connection::h3_startup,
};
use rama_core::extensions::Extensions;
use rama_http::proto::h3::control::ClientControlPreferences;

fn priority_prefix(target: u64, length: u64) -> H3ClientSequenceCapture {
    H3ClientSequenceCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        local_settings: OrderedProtocolCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            namespace: OrderNamespace::Http3Setting,
            fields: Box::default(),
        },
        events: vec![
            H3CapturedEvent::Stream {
                stream_id: 2,
                stream_type: 0,
            },
            H3CapturedEvent::Control {
                frame_type: 4,
                length: 0,
                element_id: None,
                value: Box::default(),
            },
            H3CapturedEvent::Control {
                frame_type: 0xf0700,
                length,
                element_id: Some(target),
                value: b"u=0".to_vec().into(),
            },
        ]
        .into(),
        encoder_instructions: Box::default(),
    }
}

#[test]
fn client_priority_targets_survive_compilation_into_native_wire_preferences() {
    for (target, encoded_target) in [(0, vec![0]), (4, vec![4]), (64, vec![0x40, 0x40])] {
        let capture = priority_prefix(target, 3 + encoded_target.len() as u64);
        let extensions = Extensions::new();
        h3_startup::prepare(&extensions, Some(&capture))
            .unwrap()
            .unwrap()
            .apply(&extensions);
        let controls = extensions.get_ref::<ClientControlPreferences>().unwrap();
        assert_eq!(controls.frames.len(), 1);
        let mut actual = Vec::new();
        controls.frames[0].encode(&mut actual).unwrap();
        // Independent RFC9218 frame bytes: type, length, target varint, Priority field.
        let mut expected = vec![0x80, 0x0f, 0x07, 0x00, 3 + encoded_target.len() as u8];
        expected.extend_from_slice(&encoded_target);
        expected.extend_from_slice(b"u=0");
        assert_eq!(actual, expected);
    }
}

#[test]
fn priority_replay_refuses_invalid_stream_roles_and_inconsistent_lengths() {
    for target in [1, 2, 3, 1 << 62] {
        assert!(!h3_startup::supports(Some(&priority_prefix(target, 4))));
    }
    assert!(!h3_startup::supports(Some(&priority_prefix(4, 5))));
}
