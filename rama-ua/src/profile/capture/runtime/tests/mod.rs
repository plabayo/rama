use super::*;
use crate::profile::{
    capture::joint::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
    },
    format::canonical::ValueId,
};
use rama_utils::octets::kib;
use sha2::{Digest as _, Sha256};

fn source() -> UserAgentRuntimeProfile {
    UserAgentRuntimeProfile {
        js_info: None,
        source_info: Some(UserAgentSourceInfo {
            device_name: None,
            os: Some("TestOS".into()),
            os_version: Some("1.2".into()),
            browser_name: None,
            browser_version: None,
        }),
    }
}

fn fixture() -> UserAgentRuntimeProfile {
    serde_json::from_value(serde_json::json!({"source_info":{"device_name":"synthetic","os":"OS","os_version":"1.2","browser_name":"Browser","browser_version":"3.4"},"js_info":{"web_apis":{"navigator":{"app_code_name":"Mozilla","app_name":"Netscape","build_id":"7","cookie_enabled":false,"do_not_track":"1","language":"en-US","languages":["en-US","en","fr"],"oscpu":"test","pdf_viewer_enabled":true,"platform":"platform","product":"Gecko","product_sub":"1","user_agent":"Synthetic/1","vendor":"Vendor","vendor_sub":""},"screen":{"width":1024,"height":768,"avail_width":1000,"avail_height":700,"avail_left":-100,"left":-200,"avail_top":-300,"top":-400,"color_depth":24,"pixel_depth":24,"type":"lcd","moz_orientation":"landscape","moz_brightness":0.5,"lock_orientation":"lock","unlock_orientation":"unlock"}}}})).unwrap()
}

fn resign(bytes: Vec<u8>) -> CanonicalValue {
    CanonicalValue {
        id: ValueId(Sha256::digest(&bytes).into()),
        bytes: bytes.into(),
    }
}

#[test]
fn runtime_metadata_uses_versioned_independent_canonical_bytes() {
    let capture =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &source(), kib(16))
            .unwrap();
    let value = capture.canonical(kib(16)).unwrap();
    assert_eq!(
        value.id.0,
        [
            248, 21, 44, 247, 187, 105, 103, 44, 201, 136, 13, 6, 247, 67, 171, 168, 102, 10, 16,
            251, 252, 191, 178, 35, 232, 149, 161, 55, 133, 193, 173, 193
        ]
    );
    assert_eq!(value.bytes.len(), 50);
    let restored = RuntimeProfileCapture::from_canonical(&value, kib(16)).unwrap();
    assert_eq!(
        serde_json::to_value(&capture.runtime).unwrap(),
        serde_json::to_value(restored.runtime).unwrap()
    );
    assert_eq!(
        capture.structural(kib(16)).unwrap().id.0,
        [
            245, 62, 106, 110, 79, 245, 208, 105, 161, 48, 129, 237, 136, 201, 156, 52, 39, 68,
            172, 161, 64, 199, 29, 142, 224, 175, 145, 171, 57, 149, 103, 223
        ]
    );
}

#[test]
fn runtime_round_trip_preserves_every_typed_field_and_absence() {
    for runtime in [
        source(),
        fixture(),
        UserAgentRuntimeProfile {
            source_info: None,
            js_info: Some(JsProfile { web_apis: None }),
        },
    ] {
        let capture =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        let value = capture.canonical(kib(16)).unwrap();
        let restored = RuntimeProfileCapture::from_canonical(&value, kib(16)).unwrap();
        assert_eq!(
            serde_json::to_value(runtime).unwrap(),
            serde_json::to_value(restored.runtime).unwrap()
        );
        assert_eq!(
            value.validated_domain(kib(16)).unwrap(),
            CanonicalDomain::RuntimeMetadata
        );
        assert_eq!(
            capture
                .structural(kib(16))
                .unwrap()
                .validated_domain(kib(16))
                .unwrap(),
            CanonicalDomain::RuntimeMetadataStructure
        );
    }
}

#[test]
fn runtime_budget_completeness_and_language_limits_precede_retention() {
    let runtime = fixture();
    let value =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap()
            .canonical(kib(16))
            .unwrap();
    for budget in [0, 1, value.bytes.len() - 1] {
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, budget)
            .unwrap_err();
        RuntimeProfileCapture::from_canonical(&value, budget).unwrap_err();
    }
    RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Incomplete, &runtime, kib(16))
        .unwrap_err();
    let mut capture =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap();
    capture.completeness = ProfileCaptureCompleteness::Incomplete;
    capture.canonical(kib(16)).unwrap_err();
    capture.structural(kib(16)).unwrap_err();
    let mut runtime = runtime;
    runtime
        .js_info
        .as_mut()
        .unwrap()
        .web_apis
        .as_mut()
        .unwrap()
        .navigator
        .as_mut()
        .unwrap()
        .languages = Some(vec![String::new(); 65]);
    RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
        .unwrap_err();
    let empty = UserAgentRuntimeProfile {
        source_info: None,
        js_info: None,
    };
    RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &empty, kib(16))
        .unwrap_err();
}

#[test]
fn runtime_floats_are_finite_and_negative_zero_has_one_identity() {
    let mut runtime = fixture();
    for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        runtime
            .js_info
            .as_mut()
            .unwrap()
            .web_apis
            .as_mut()
            .unwrap()
            .screen
            .as_mut()
            .unwrap()
            .moz_brightness = Some(value);
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap_err();
    }
    let mut ids = Vec::new();
    for value in [0.0, -0.0] {
        runtime
            .js_info
            .as_mut()
            .unwrap()
            .web_apis
            .as_mut()
            .unwrap()
            .screen
            .as_mut()
            .unwrap()
            .moz_brightness = Some(value);
        ids.push(
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap()
                .canonical(kib(16))
                .unwrap()
                .id,
        );
    }
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn runtime_structures_group_values_but_preserve_field_presence() {
    let mut runtime = fixture();
    let original =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap();
    let structure = original.structural(kib(16)).unwrap();
    runtime.source_info.as_mut().unwrap().browser_version = Some("different".into());
    runtime
        .js_info
        .as_mut()
        .unwrap()
        .web_apis
        .as_mut()
        .unwrap()
        .screen
        .as_mut()
        .unwrap()
        .width = Some(1920);
    let varied =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap();
    assert_ne!(
        original.canonical(kib(16)).unwrap().id,
        varied.canonical(kib(16)).unwrap().id
    );
    assert_eq!(structure.id, varied.structural(kib(16)).unwrap().id);
    runtime.source_info.as_mut().unwrap().browser_version = None;
    assert_ne!(
        structure.id,
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap()
            .structural(kib(16))
            .unwrap()
            .id
    );
}

#[test]
fn runtime_decode_rejects_bad_envelopes_tags_strings_and_trailing_bytes() {
    let original =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &source(), kib(16))
            .unwrap()
            .canonical(kib(16))
            .unwrap();
    let mut bad = original.clone();
    bad.id.0[0] ^= 1;
    RuntimeProfileCapture::from_canonical(&bad, kib(16)).unwrap_err();
    for (index, byte) in [
        (14, 2),
        (17, 0),
        (17, 2),
        (18, 2),
        (19, 2),
        (20, 2),
        (29, 0xff),
    ] {
        let mut bytes = original.bytes.to_vec();
        bytes[index] = byte;
        resign(bytes).validated_domain(kib(16)).unwrap_err();
    }
    let mut bytes = original.bytes.to_vec();
    bytes.push(0);
    resign(bytes).validated_domain(kib(16)).unwrap_err();
    for length in 0..original.bytes.len() {
        resign(original.bytes[..length].to_vec())
            .validated_domain(kib(16))
            .unwrap_err();
    }
    let structure =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &source(), kib(16))
            .unwrap()
            .structural(kib(16))
            .unwrap();
    let mut bytes = structure.bytes.to_vec();
    bytes[20] = 2;
    resign(bytes).validated_domain(kib(16)).unwrap_err();
}

#[test]
fn runtime_metadata_is_request_owned_in_complete_joint_samples() {
    let value =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &fixture(), kib(16))
            .unwrap()
            .canonical(kib(16))
            .unwrap();
    let mut joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: Box::new([CapturedSlot {
            kind: CapturedSlotKind::RuntimeMetadata,
            value,
        }]),
    };
    let limits = JointCaptureLimits::default();
    let encoded = joint.canonical(limits).unwrap();
    JointCapture::from_canonical(&encoded, limits).unwrap();
    joint
        .structural(limits)
        .unwrap()
        .validated_domain(limits.bytes)
        .unwrap();
    joint.level = CaptureLevel::Connection;
    joint.canonical(limits).unwrap_err();
    joint.structural(limits).unwrap_err();
}

#[test]
fn runtime_report_adapter_checks_budgets_before_cloning_metadata() {
    let runtime = fixture();
    let web = runtime.js_info.as_ref().unwrap().web_apis.as_ref();
    let capture =
        RuntimeProfileCapture::capture_report(runtime.source_info.as_ref(), web, kib(16)).unwrap();
    assert_eq!(
        serde_json::to_value(&capture.runtime).unwrap(),
        serde_json::to_value(&runtime).unwrap()
    );
    for maximum in [0, 1, capture.canonical(kib(16)).unwrap().bytes.len() - 1] {
        RuntimeProfileCapture::capture_report(runtime.source_info.as_ref(), web, maximum)
            .unwrap_err();
    }
    RuntimeProfileCapture::capture_report(None, None, kib(16)).unwrap_err();
}
fn text_paths(value: &serde_json::Value, prefix: &str, paths: &mut Vec<String>) {
    match value {
        serde_json::Value::String(_) => paths.push(prefix.into()),
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                text_paths(value, &format!("{prefix}/{key}"), paths);
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                text_paths(value, &format!("{prefix}/{index}"), paths);
            }
        }
        _ => (),
    }
}

#[test]
fn every_runtime_text_field_has_a_local_bound_and_rejects_controls() {
    let source = serde_json::to_value(fixture()).unwrap();
    let mut paths = Vec::new();
    text_paths(&source, "", &mut paths);
    assert_eq!(paths.len(), 24);
    for path in paths {
        let maximum = if path.ends_with("/user_agent") {
            kib(8)
        } else {
            kib(1)
        };
        for text in [
            "x\0y".to_owned(),
            "x\u{7f}y".to_owned(),
            "x\u{85}y".to_owned(),
            "x".repeat(maximum + 1),
        ] {
            let mut invalid = source.clone();
            *invalid.pointer_mut(&path).unwrap() = text.into();
            let runtime: UserAgentRuntimeProfile = serde_json::from_value(invalid).unwrap();
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap_err();
            RuntimeProfileCapture::capture_report(
                runtime.source_info.as_ref(),
                runtime.js_info.as_ref().and_then(|js| js.web_apis.as_ref()),
                kib(16),
            )
            .unwrap_err();
        }
        let mut valid = source.clone();
        *valid.pointer_mut(&path).unwrap() = "x".repeat(maximum).into();
        let runtime: UserAgentRuntimeProfile = serde_json::from_value(valid).unwrap();
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap();
    }
}

#[test]
fn imported_runtime_text_controls_are_rejected() {
    let value =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &source(), kib(16))
            .unwrap()
            .canonical(kib(16))
            .unwrap();
    let mut bytes = value.bytes.to_vec();
    let start = bytes
        .windows(6)
        .position(|value| value == b"TestOS")
        .unwrap();
    bytes[start] = 0;
    RuntimeProfileCapture::from_canonical(&resign(bytes), kib(16)).unwrap_err();
}

#[test]
fn retained_runtime_numbers_match_their_canonical_zero() {
    let mut runtime = fixture();
    runtime
        .js_info
        .as_mut()
        .unwrap()
        .web_apis
        .as_mut()
        .unwrap()
        .screen
        .as_mut()
        .unwrap()
        .moz_brightness = Some(-0.0);
    let captured =
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap();
    let report = RuntimeProfileCapture::capture_report(
        runtime.source_info.as_ref(),
        runtime.js_info.as_ref().and_then(|js| js.web_apis.as_ref()),
        kib(16),
    )
    .unwrap();
    for captured in [captured, report] {
        let retained = captured
            .runtime
            .js_info
            .as_ref()
            .unwrap()
            .web_apis
            .as_ref()
            .unwrap()
            .screen
            .as_ref()
            .unwrap()
            .moz_brightness
            .unwrap();
        assert_eq!(retained.to_bits(), 0);
        let decoded =
            RuntimeProfileCapture::from_canonical(&captured.canonical(kib(16)).unwrap(), kib(16))
                .unwrap();
        assert_eq!(
            serde_json::to_vec(&captured).unwrap(),
            serde_json::to_vec(&decoded).unwrap()
        );
    }
}
