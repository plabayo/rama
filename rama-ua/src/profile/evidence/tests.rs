use super::*;
use crate::profile::{
    CanonicalDomain, CaptureLevel, CapturedSlot, CapturedSlotKind, ConnectionContext, JointCapture,
    OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProfileCaptureCompleteness,
    analyze_profile_evidence,
};

fn capture(value: u8) -> ProfileCapture {
    let limits = OrderCaptureLimits::default();
    ProfileCapture {
        profile: ProfileKey::new("offline-library"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::Http3Settings,
                value: OrderedProtocolCapture::capture(
                    ProfileCaptureCompleteness::Complete,
                    OrderNamespace::Http3Setting,
                    [(1, u64::from(value).to_be_bytes())],
                    limits,
                )
                .unwrap()
                .canonical(limits)
                .unwrap(),
            }]),
        },
    }
}

fn collector(limits: ProfileAnalysisLimits) -> ProfileEvidenceCollector {
    ProfileEvidenceCollector::new(
        &capture(1).profile,
        false,
        CaptureRunId::new(100, [1; 12]),
        [2; 32],
        100,
        limits,
    )
    .unwrap()
}

fn state(collector: &ProfileEvidenceCollector) -> Vec<u8> {
    serde_json::to_vec(&(
        collector.sequence,
        collector
            .scopes
            .values()
            .map(|scope| scope.window.snapshot())
            .collect::<Vec<_>>(),
    ))
    .unwrap()
}

#[test]
fn offline_evidence_reanalyzes_counts_and_day_expiry_without_synthetic_components() {
    let limits = ProfileAnalysisLimits::default();
    let mut collector = collector(limits);
    for day in [99, 100, 100] {
        collector.observe(day, &capture(1)).unwrap();
    }
    let evidence = collector.finish();
    assert_eq!(evidence.scopes.len(), 2);
    for (horizon, expected) in [(14, 3), (1, 2)] {
        let analysis =
            analyze_profile_evidence(&evidence, false, [2; 32], 100, horizon, limits).unwrap();
        assert!(analysis.components.h3.is_some());
        assert!(analysis.components.h1.is_none());
        assert!(analysis.components.tls_tcp.is_none());
        for scope in &analysis.scopes {
            assert_eq!(scope.observations.counts.total, expected);
        }
        assert_eq!(
            analysis
                .scopes
                .iter()
                .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
                .count(),
            1
        );
    }
}

#[test]
fn offline_evidence_rejects_identity_scope_byte_and_time_errors_atomically() {
    let limits = ProfileAnalysisLimits::default();
    let mut collector = collector(limits);
    collector.observe(100, &capture(1)).unwrap();
    let before = state(&collector);
    let mut wrong = capture(1);
    wrong.profile.client = "different-library".into();
    collector.observe(100, &wrong).unwrap_err();
    assert_eq!(state(&collector), before);
    for day in [0, 86, 101, u32::MAX] {
        collector.observe(day, &capture(1)).unwrap_err();
        assert_eq!(state(&collector), before);
    }
    // The joint scope fits, but adding its leaf exceeds the scope budget.
    collector.limits.scopes = 3;
    collector.observe(100, &capture(2)).unwrap_err();
    assert_eq!(state(&collector), before);
    collector.limits = limits;
    collector.limits.bytes = collector.profile.bytes.len();
    collector.observe(100, &capture(1)).unwrap_err();
    assert_eq!(state(&collector), before);
    collector.limits = limits;
    collector.observe(100, &capture(1)).unwrap();
    let evidence = collector.finish();
    assert!(evidence.scopes.iter().all(|scope| {
        scope.window.buckets.len() == 1 && scope.window.buckets[0].bucket.counts.total == 2
    }));
}
