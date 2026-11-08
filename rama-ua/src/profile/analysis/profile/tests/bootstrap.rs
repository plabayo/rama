use std::{collections::BTreeMap, slice};

use rama_http::{HeaderName, Method, Version, proto::h3::observation::ObservedEncoderBindings};
use rama_utils::octets::kib;

use super::super::*;
use crate::profile::{
    capture::{
        CAPTURE_REVISION,
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource},
        http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        observation::PreparedProfileCapture,
    },
    evidence::{ProfileScopeEvidence, ingestion::ObservationId},
    format::compiled::{decode_compiled_profiles, encode_compiled_profiles},
    model::identity::ConnectionContext,
};

#[test]
fn requests_named_by_an_h3_bootstrap_keep_their_exact_values() {
    let limits = JointCaptureLimits::default();
    let key = ProfileKey::new("bootstrap-hints");
    let flow = FlowKey::Http {
        version: Version::HTTP_3,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let request = |rtt: &str| {
        let headers = HeaderCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            version: Version::HTTP_3,
            fields: [("accept", "*/*"), ("rtt", rtt), ("downlink", "10")]
                .iter()
                .map(|(name, value)| HeaderOccurrence {
                    name: HeaderName::from_static(name),
                    occurrence: 0,
                    sensitive: false,
                    representation: None,
                    value: HeaderValueSource::Profile(value.as_bytes().into()),
                })
                .collect(),
        }
        .canonical(&HeaderCapturePolicy::default())
        .unwrap();
        ProfileCapture {
            revision: CAPTURE_REVISION,
            profile: key.clone(),
            flow: Some(flow.clone()),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Request,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Headers,
                    value: headers,
                }]
                .into(),
            },
        }
        .prepare(false, limits)
        .unwrap()
    };
    let joint_id = |prepared: &PreparedProfileCapture| {
        prepared
            .buckets
            .iter()
            .find(|bucket| {
                bucket.value.validated_domain(kib(64)).unwrap() == CanonicalDomain::Joint
            })
            .unwrap()
            .value
            .id
    };
    let requests = [request("50"), request("100"), request("150")];
    let named = joint_id(&requests[0]);
    let connection = ProfileCapture {
        revision: CAPTURE_REVISION,
        profile: key.clone(),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Http3Bootstrap,
                value: H3BootstrapCapture {
                    request: named,
                    method: Method::GET,
                    fields: 3,
                    bindings: ObservedEncoderBindings {
                        stream_id: 0,
                        complete: true,
                        insertions: Vec::new(),
                    },
                }
                .canonical(H3BootstrapLimits::default())
                .unwrap(),
            }]
            .into(),
        },
    }
    .prepare(false, limits)
    .unwrap();

    let mut windows = BTreeMap::<ValueId, (ProfileScopeEvidence, RetainedBucketWindow)>::new();
    let mut sequence = 0;
    for (prepared, flow) in requests
        .iter()
        .map(|prepared| (prepared, Some(flow.clone())))
        .chain([(&connection, None)])
    {
        for bucket in prepared.buckets.iter() {
            let (_, window) = windows.entry(bucket.scope.id).or_insert_with(|| {
                let window = RetainedBucketWindow::new(
                    bucket.value.validated_domain(kib(64)).unwrap(),
                    bucket.scope.id,
                    [3; 32],
                    ProfileWindowLimits::default(),
                )
                .unwrap();
                let evidence = ProfileScopeEvidence {
                    scope: bucket.scope.clone(),
                    flow: flow.as_ref().map(|flow| flow.canonical(kib(16)).unwrap()),
                    structure: bucket.structure.clone(),
                    window: window.snapshot(),
                };
                (evidence, window)
            });
            sequence += 1;
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence,
                    },
                    &bucket.value,
                )
                .unwrap();
        }
    }
    let evidence = ProfileEvidence {
        format_version: 1,
        profile: connection.profile,
        scopes: windows
            .into_values()
            .map(|(mut evidence, window)| {
                evidence.window = window.snapshot();
                evidence
            })
            .collect(),
    };
    let analyzed = analyze_profile_evidence(
        &evidence,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    let compiled =
        decode_compiled_profiles(&encode_compiled_profiles(slice::from_ref(&analyzed)).unwrap())
            .unwrap()
            .remove(0);
    for profile in [&analyzed, &compiled] {
        let scope = profile
            .scopes
            .iter()
            .find(|scope| {
                scope.flow.is_some() && scope.observations.domain == CanonicalDomain::Joint
            })
            .unwrap();
        // The bootstrap still finds its request, which keeps its own hint values.
        assert!(
            scope
                .observations
                .variants
                .iter()
                .any(|variant| variant.value.id() == named)
        );
        // The other requests read with placeholders and draw from their own values only.
        assert_eq!(scope.observations.variants.len(), 2);
        let drawn: Vec<_> = scope
            .observations
            .network_hints
            .iter()
            .map(|hint| hint.fields[0].1.to_vec())
            .collect();
        assert!(drawn.contains(&b"100".to_vec()) && drawn.contains(&b"150".to_vec()));
        assert!(!drawn.contains(&b"50".to_vec()));
    }
}
