use super::*;
use crate::profile::{
    CaptureLevel, CapturedSlot, CapturedSlotKind, ConnectionContext, JointCapture,
    JointCaptureLimits, ObservationId, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    ProfileAnalysisLimits, ProfileArchiveEntry, ProfileArchiveLimits, ProfileCapture,
    ProfileCaptureCompleteness, ProfileEvidence, ProfileScopeEvidence, ProfileWindowLimits,
    RetainedBucketWindow,
};
use crate::profile::{Http1Settings, UserAgentDatabase, UserAgentProfileInput};
use rama_utils::octets::kib;

fn profile(version: &str, device: DeviceKind, h1: bool) -> UserAgentProfile {
    let mut row = UserAgentProfileInput::new(format!("library/{version}/{device:?}"));
    if h1 {
        row.h1_settings = Some(Http1Settings::default());
    }
    let mut profile = row.try_into_profile().unwrap();
    profile.key.client = "library".into();
    profile.key.version = Some(version.into());
    profile.key.device = Some(device);
    profile
}

#[test]
fn versions_compare_numerically_and_reject_ambiguous_labels() {
    assert!(ProfileVersion::parse("100") > ProfileVersion::parse("99.12"));
    assert!(ProfileVersion::parse("1.10") > ProfileVersion::parse("1.9"));
    assert_eq!(ProfileVersion::parse("1.0.0"), ProfileVersion::parse("1"));
    for value in [
        "",
        "1.",
        ".1",
        "1..2",
        "1-beta",
        "-1",
        "+1",
        "18446744073709551616",
    ] {
        assert!(ProfileVersion::parse(value).is_none(), "{value}");
    }
}

#[test]
fn latest_three_are_per_device_and_missing_capabilities_do_not_select_old_versions() {
    let database: UserAgentDatabase = [
        profile("99", DeviceKind::Desktop, true),
        profile("100", DeviceKind::Desktop, true),
        profile("101", DeviceKind::Desktop, true),
        profile("102", DeviceKind::Desktop, false),
        profile("200", DeviceKind::Mobile, true),
    ]
    .into_iter()
    .collect();
    let filter = ProfileCandidateFilter {
        client: Some("library"),
        device: Some(DeviceKind::Desktop),
        latest_versions: Some(3),
        capabilities: ProfileCapabilities {
            h1: true,
            ..ProfileCapabilities::default()
        },
        ..ProfileCandidateFilter::default()
    };
    let selected = database.candidates(filter).unwrap();
    let versions: Vec<_> = selected
        .iter()
        .map(|candidate| candidate.profile.key.version.as_deref().unwrap())
        .collect();
    assert_eq!(versions, ["100", "101"]);
    assert!(selected.iter().all(|candidate| matches!(
        candidate.weight,
        ObservationWeight::UnknownHistory {
            observed: 1,
            unassigned: 0
        }
    )));
    let mobile = database
        .candidates(ProfileCandidateFilter {
            device: Some(DeviceKind::Mobile),
            ..filter
        })
        .unwrap();
    assert_eq!(mobile.len(), 1);
    assert_eq!(mobile[0].profile.key.version.as_deref(), Some("200"));
    assert!(
        database
            .candidates(ProfileCandidateFilter {
                capabilities: ProfileCapabilities {
                    h3: true,
                    ..ProfileCapabilities::default()
                },
                ..filter
            })
            .unwrap()
            .is_empty()
    );
}

#[test]
fn h3_only_archives_keep_joint_weights_and_no_synthetic_layers() {
    let limits = JointCaptureLimits::default();
    let value = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::Http3Setting,
        [(1, 1024_u64.to_be_bytes())],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    let prepared = ProfileCapture {
        profile: ProfileKey::new("h3-library"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Http3Settings,
                value,
            }]
            .into(),
        },
    }
    .prepare(false, limits)
    .unwrap();
    let scopes = prepared
        .buckets
        .into_vec()
        .into_iter()
        .map(|input| {
            let domain = input.value.validated_domain(kib(64)).unwrap();
            let mut window = RetainedBucketWindow::new(
                domain,
                input.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            for sequence in 1..=2 {
                window
                    .observe(
                        100,
                        100,
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
                structure: input.structure,
                flow: None,
                window: window.snapshot(),
            }
        })
        .collect();
    let entry = ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: prepared.profile,
            scopes,
        },
        sampler_seed: [3; 32],
    };
    let mut entry = entry;
    entry
        .evidence
        .scopes
        .sort_unstable_by_key(|scope| scope.scope.id);
    let mut unsorted = entry.clone();
    unsorted.evidence.scopes.reverse();
    assert!(unsorted.evidence.scopes.len() > 1);
    unsorted
        .analyze(false, 100, 14, ProfileAnalysisLimits::default())
        .unwrap_err();
    let bytes = serde_json::to_vec(&serde_json::json!({"format_version":1,"generated_day":100,"horizon":14,"profiles":[entry]})).unwrap();
    let database = UserAgentDatabase::try_from_archive(
        &bytes,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    let profile = database.iter().next().unwrap();
    assert!(profile.ua_kind.is_none());
    assert!(profile.ua_str().is_none());
    assert!(profile.http.is_none());
    #[cfg(feature = "tls")]
    assert!(profile.tls.is_none());
    assert!(profile.capabilities().h3);
    assert!(!profile.capabilities().quic);
    assert!(matches!(
        profile.observation_weight().unwrap(),
        ObservationWeight::Exact(2)
    ));
    let mut incomplete = profile.clone();
    let mut analysis = (**incomplete.captured.as_ref().unwrap()).clone();
    analysis.scopes = analysis
        .scopes
        .into_vec()
        .into_iter()
        .filter(|scope| scope.observations.domain != CanonicalDomain::Joint)
        .collect();
    incomplete.captured = Some(analysis.into());
    assert!(matches!(
        incomplete.observation_weight().unwrap(),
        ObservationWeight::UnknownHistory { observed: 2, .. }
    ));
    let h3 = database
        .candidates(ProfileCandidateFilter {
            capabilities: ProfileCapabilities {
                h3: true,
                ..ProfileCapabilities::default()
            },
            ..ProfileCandidateFilter::default()
        })
        .unwrap();
    assert_eq!(h3.len(), 1);
    assert!(
        database
            .candidates(ProfileCandidateFilter {
                capabilities: ProfileCapabilities {
                    h1: true,
                    ..ProfileCapabilities::default()
                },
                ..ProfileCandidateFilter::default()
            })
            .unwrap()
            .is_empty()
    );
    let expired = UserAgentDatabase::try_from_archive(
        &bytes,
        false,
        114,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    assert!(!expired.iter().next().unwrap().capabilities().h3);
    let offline = UserAgentDatabase::try_from_json_slice(&bytes).unwrap();
    assert!(offline.iter().next().unwrap().capabilities().h3);
}

#[test]
fn latest_versions_preserve_each_device_group_without_an_explicit_filter() {
    let database: UserAgentDatabase = [
        profile("1", DeviceKind::Desktop, true),
        profile("2", DeviceKind::Desktop, true),
        profile("99", DeviceKind::Mobile, true),
        profile("100", DeviceKind::Mobile, true),
    ]
    .into_iter()
    .collect();
    let candidates = database
        .candidates(ProfileCandidateFilter {
            latest_versions: Some(1),
            ..ProfileCandidateFilter::default()
        })
        .unwrap();
    let versions: BTreeSet<_> = candidates
        .iter()
        .map(|candidate| candidate.profile.key.version.as_deref().unwrap())
        .collect();
    assert_eq!(versions, ["2", "100"].into_iter().collect());
}
