use super::*;
use crate::profile::ProfileCaptureCompleteness;
use crate::profile::{CapturedSlot, FetchContext, ProfileObservationScope, ResumptionContext};
use rama_http::{HeaderMap, HeaderValue, Method, Version};

fn capture() -> ProfileCapture {
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("application/json"));
    headers.insert("cookie", HeaderValue::from_static("never-retained-secret"));
    let policy = HeaderCapturePolicy::default();
    ProfileCapture {
        profile: ProfileKey::new("application"),
        flow: Some(FlowKey::Http {
            version: Version::HTTP_3,
            method: Method::GET,
            initiator: None,
            fetch: Some(FetchContext::default()),
            connection: ConnectionContext::default(),
        }),
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_3,
                        &headers,
                        None,
                    )
                    .unwrap()
                    .canonical(&policy)
                    .unwrap(),
            }]
            .into(),
        },
    }
}

#[test]
fn counted_capture_resolves_joint_and_leaf_ownership() {
    let capture = capture();
    let limits = JointCaptureLimits::default();
    let prepared = capture.prepare(false, limits).unwrap();
    assert_eq!(prepared.buckets.len(), 2);
    assert_ne!(prepared.buckets[0].scope.id, prepared.buckets[1].scope.id);
    for input in &prepared.buckets {
        let scope = ProfileObservationScope::from_canonical(&input.scope, limits.bytes).unwrap();
        assert!(!scope.authorized);
        assert_eq!(scope.profile, prepared.profile.id);
        assert_eq!(scope.flow, prepared.flow.as_ref().map(|flow| flow.id));
        assert_eq!(scope.structure, input.structure.id);
        input.value.validated_domain(limits.bytes).unwrap();
        input.structure.validated_domain(limits.bytes).unwrap();
        assert!(
            !input
                .value
                .bytes
                .windows(21)
                .any(|bytes| bytes == b"never-retained-secret")
        );
    }
    let authorized = capture.prepare(true, limits).unwrap();
    for (public, private) in prepared.buckets.iter().zip(&authorized.buckets) {
        assert_ne!(public.scope.id, private.scope.id);
    }
}

#[test]
fn counted_capture_rejects_inconsistent_flow_and_context() {
    let limits = JointCaptureLimits::default();
    let mut capture = capture();
    capture.connection.resumption = ResumptionContext::Resumed;
    capture.prepare(false, limits).unwrap_err();
    capture.connection = ConnectionContext::default();
    if let Some(FlowKey::Http { version, .. }) = &mut capture.flow {
        *version = Version::HTTP_2;
    }
    capture.prepare(false, limits).unwrap_err();
    capture.flow = None;
    capture.prepare(false, limits).unwrap_err();
    capture.joint.level = CaptureLevel::Connection;
    capture.prepare(false, limits).unwrap_err();
    capture.joint.slots = Box::default();
    capture.prepare(false, limits).unwrap_err();
}

#[test]
fn canonical_domain_dispatch_preserves_all_content_guards() {
    let limits = JointCaptureLimits::default();
    let prepared = capture().prepare(false, limits).unwrap();
    for value in [
        &prepared.profile,
        prepared.flow.as_ref().unwrap(),
        &prepared.buckets[0].scope,
        &prepared.buckets[0].value,
        &prepared.buckets[0].structure,
        &prepared.buckets[1].value,
    ] {
        value.validated_domain(value.bytes.len()).unwrap();
        value.validated_domain(value.bytes.len() - 1).unwrap_err();
        let mut forged = value.clone();
        forged.id.0[0] ^= 1;
        forged.validated_domain(limits.bytes).unwrap_err();
        for len in 0..17 {
            let mut truncated = value.clone();
            truncated.bytes = truncated.bytes[..len].into();
            truncated.validated_domain(limits.bytes).unwrap_err();
        }
    }
}
