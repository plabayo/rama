use super::*;
use crate::profile::{ConnectionContext, ObservationId, ResumptionContext};

fn setting(number: u64) -> CanonicalValue {
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        [(1, number.to_be_bytes())],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap()
}

fn evidence() -> ProfileEvidence {
    let key = ProfileKey::new("synthetic-library");
    let captured = ProfileCapture {
        profile: key,
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Http3Settings,
                value: setting(1024),
            }]
            .into(),
        },
    }
    .prepare(false, JointCaptureLimits::default())
    .unwrap();
    let scopes = captured
        .buckets
        .into_vec()
        .into_iter()
        .map(|input| {
            let mut window = RetainedBucketWindow::new(
                input.value.validated_domain(kib(64)).unwrap(),
                input.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            for sequence in 1..=40 {
                window
                    .observe(
                        100,
                        if sequence <= 10 { 99 } else { 100 },
                        ObservationId {
                            run: [1; 16],
                            sequence,
                        },
                        &input.value,
                    )
                    .unwrap();
            }
            ProfileScopeEvidence {
                scope: input.scope,
                flow: None,
                structure: input.structure,
                window: window.snapshot(),
            }
        })
        .collect();
    ProfileEvidence {
        format_version: 1,
        profile: captured.profile,
        scopes,
    }
}

#[test]
fn h3_only_library_profile_reanalyzes_stored_counts_without_other_components() {
    let input: ProfileEvidence =
        serde_json::from_slice(&serde_json::to_vec(&evidence()).unwrap()).unwrap();
    let analyzed = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(analyzed.key.client.as_ref(), "synthetic-library");
    assert!(analyzed.key.user_agent.is_none());
    assert_eq!(analyzed.components.h3.as_deref(), Some([0, 1].as_slice()));
    assert!(analyzed.components.h1.is_none());
    assert!(analyzed.components.h2.is_none());
    assert!(analyzed.components.tls_tcp.is_none());
    assert!(analyzed.components.tls_quic.is_none());
    assert!(analyzed.components.quic.is_none());
    assert!(
        analyzed
            .scopes
            .iter()
            .all(|scope| scope.observations.counts.total == 40)
    );
    assert!(
        analyzed
            .scopes
            .iter()
            .all(|scope| scope.context.connection.resumption == ResumptionContext::Unknown)
    );
    let again = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&analyzed).unwrap(),
        serde_json::to_vec(&again).unwrap()
    );
}

#[test]
fn profile_analysis_freshness_excludes_expired_counts_and_capabilities() {
    let input = evidence();
    let today = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        1,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert!(
        today
            .scopes
            .iter()
            .all(|scope| scope.observations.counts.total == 30)
    );
    let expired = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        114,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert!(expired.scopes.is_empty());
    assert!(expired.components.h3.is_none());
    analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        99,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
}

#[test]
fn profile_analysis_checks_authorization_identity_duplicates_and_limits() {
    let input = evidence();
    analyze_profile_evidence(
        &input,
        true,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
    analyze_profile_evidence(
        &input,
        false,
        [4; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
    for limits in [
        ProfileAnalysisLimits {
            scopes: 1,
            ..ProfileAnalysisLimits::default()
        },
        ProfileAnalysisLimits {
            bytes: 1,
            ..ProfileAnalysisLimits::default()
        },
    ] {
        analyze_profile_evidence(&input, false, [3; 32], 100, 14, limits).unwrap_err();
    }
    let mut wrong = input.clone();
    wrong.profile = ProfileKey::new("another-library")
        .canonical(kib(16))
        .unwrap();
    analyze_profile_evidence(
        &wrong,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
    let mut duplicate = input.clone();
    duplicate.scopes = vec![input.scopes[0].clone(), input.scopes[0].clone()].into();
    analyze_profile_evidence(
        &duplicate,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
}

#[test]
fn retained_values_must_match_their_claimed_structure() {
    let mut input = evidence();
    let index = input
        .scopes
        .iter()
        .position(|scope| scope.window.domain == CanonicalDomain::Order)
        .unwrap();
    let scope = &mut input.scopes[index];
    let mut replacement = RetainedBucketWindow::new(
        CanonicalDomain::Order,
        scope.scope.id,
        [3; 32],
        ProfileWindowLimits::default(),
    )
    .unwrap();
    replacement
        .observe(
            100,
            100,
            ObservationId {
                run: [1; 16],
                sequence: 1,
            },
            &setting(2048),
        )
        .unwrap();
    scope.window = replacement.snapshot();
    analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap_err();
}

#[test]
fn empty_observation_set_grants_no_protocol_component() {
    let input = ProfileEvidence {
        format_version: 1,
        profile: ProfileKey::new("metadata-only").canonical(kib(16)).unwrap(),
        scopes: Box::default(),
    };
    let analyzed = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert!(analyzed.scopes.is_empty());
    assert!(analyzed.components.h1.is_none());
    assert!(analyzed.components.h2.is_none());
    assert!(analyzed.components.h3.is_none());
    assert!(analyzed.components.quic.is_none());
    assert!(analyzed.components.tls_tcp.is_none());
    assert!(analyzed.components.tls_quic.is_none());
}
