use rama_http::{HeaderMap, HeaderValue, Method, Version};

use super::*;
use crate::profile::{
    capture::{
        CAPTURE_REVISION,
        completeness::ProfileCaptureCompleteness,
        joint::CapturedSlot,
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    },
    evidence::{
        bucket::CountedObservationBucket,
        ingestion::ObservationId,
        transaction::{
            CaptureRunCheckpoint, CaptureRunId, IngestionAttempt, IngestionBatchLimits,
            PendingBucketObservation, PreparedIngestion, StoredObservationBucket,
        },
    },
    model::{
        identity::{FetchContext, ResumptionContext},
        scope::ProfileObservationScope,
    },
};

fn capture() -> ProfileCapture {
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("application/json"));
    headers.insert("cookie", HeaderValue::from_static("never-retained-secret"));
    let policy = HeaderCapturePolicy::default();
    ProfileCapture {
        revision: CAPTURE_REVISION,
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
    capture.joint.completeness = ProfileCaptureCompleteness::Incomplete;
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
            truncated.bytes = truncated.bytes.slice(..len);
            truncated.validated_domain(limits.bytes).unwrap_err();
        }
    }
}

#[test]
fn complete_empty_connection_is_counted_but_empty_requests_are_not() {
    let mut capture = capture();
    capture.flow = None;
    capture.joint.level = CaptureLevel::Connection;
    capture.joint.slots = Box::default();
    let prepared = capture
        .prepare(false, JointCaptureLimits::default())
        .unwrap();
    assert_eq!(prepared.buckets.len(), 1);
    let joint =
        JointCapture::from_canonical(&prepared.buckets[0].value, JointCaptureLimits::default())
            .unwrap();
    assert!(joint.slots.is_empty());
    assert_eq!(joint.level, CaptureLevel::Connection);
    capture.joint.level = CaptureLevel::Request;
    capture.flow = Some(FlowKey::Http {
        version: Version::HTTP_11,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    });
    capture
        .prepare(false, JointCaptureLimits::default())
        .unwrap_err();
}

#[test]
fn incomplete_empty_connections_are_rejected_before_recording() {
    let mut capture = capture();
    capture.flow = None;
    capture.joint.level = CaptureLevel::Connection;
    capture.joint.slots = Box::default();
    capture.joint.completeness = ProfileCaptureCompleteness::Incomplete;
    assert!(matches!(
        capture.prepare(false, JointCaptureLimits::default()),
        Err(ProfileDataError::Incomplete("empty profile capture"))
    ));
}

#[test]
fn reordered_outer_quic_parameters_ingest_once_as_joint_evidence() {
    let mut capture = capture();
    capture.flow = None;
    capture.joint.level = CaptureLevel::Connection;
    let limits = OrderCaptureLimits::default();
    let tuple = |ids: [u64; 2]| {
        OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            ids.map(|id| (id, [1])),
            limits,
        )
        .unwrap()
        .canonical(limits)
        .unwrap()
    };
    capture.joint.slots = Box::new([
        CapturedSlot {
            kind: CapturedSlotKind::QuicParameters,
            value: tuple([1, 4]),
        },
        CapturedSlot {
            kind: CapturedSlotKind::QuicOuterParameters,
            value: tuple([4, 1]),
        },
    ]);
    let prepared = capture
        .prepare(false, JointCaptureLimits::default())
        .unwrap();
    let limits = IngestionBatchLimits::default();
    let run =
        CaptureRunCheckpoint::new(CaptureRunId::new(100, [1; 12]), false, 100, limits).unwrap();
    let buckets: Vec<_> = prepared
        .buckets
        .iter()
        .map(|input| StoredObservationBucket {
            authorized: false,
            day: 100,
            bucket: CountedObservationBucket::new(
                input
                    .value
                    .validated_domain(limits.bucket.input_bytes)
                    .unwrap(),
                input.scope.id,
                [3; 32],
                limits.bucket,
            )
            .unwrap()
            .snapshot(),
        })
        .collect();
    let pending: Vec<_> = prepared
        .buckets
        .iter()
        .zip(&buckets)
        .map(|(input, previous)| PendingBucketObservation {
            expected_scope: &input.scope,
            previous,
            value: &input.value,
        })
        .collect();
    let result = run
        .prepare(
            100,
            IngestionAttempt {
                authorized: false,
                observation_day: 100,
                observation: ObservationId {
                    run: run.run.0,
                    sequence: 1,
                },
            },
            &pending,
            [3; 32],
            limits,
        )
        .unwrap();
    let PreparedIngestion::Commit { buckets, .. } = result else {
        panic!("new observation must commit")
    };
    assert_eq!(buckets.len(), 2);
    assert!(buckets.iter().all(|bucket| bucket.bucket.counts.total == 1));
}
