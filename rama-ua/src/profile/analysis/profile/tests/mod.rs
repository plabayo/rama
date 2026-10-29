use super::*;
use crate::profile::{
    analysis::order::AnalyzedOrderWeight,
    capture::{
        headers::{HeaderCapturePolicy, HeaderValueSource},
        http2::{H2Capture, H2CaptureLimits, H2CapturedFrame, H2CapturedSetting},
    },
    evidence::{ProfileScopeEvidence, counts::ObservationWeight, ingestion::ObservationId},
    format::{archive::ProfileArchiveEntry, canonical::CanonicalWriter},
    model::identity::{ConnectionContext, ResumptionContext},
};
use rama_http::{HeaderMap, HeaderValue, Method};
use std::collections::BTreeMap;

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
    evidence_of(vec![vec![CapturedSlot {
        kind: CapturedSlotKind::Http3Settings,
        value: setting(1024),
    }]])
}

/// One connection capture per slot list, each observed 40 times.
fn evidence_of(connections: Vec<Vec<CapturedSlot>>) -> ProfileEvidence {
    let key = ProfileKey::new("synthetic-library");
    let mut profile = None;
    let mut buckets = BTreeMap::new();
    for slots in connections {
        let captured = ProfileCapture {
            profile: key.clone(),
            flow: None,
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: slots.into(),
            },
        }
        .prepare(false, JointCaptureLimits::default())
        .unwrap();
        profile = Some(captured.profile);
        for input in captured.buckets.into_vec() {
            buckets.insert(input.scope.id, input);
        }
    }
    let scopes = buckets
        .into_values()
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
        profile: profile.unwrap(),
        scopes,
    }
}

#[cfg(feature = "tls")]
fn tls_slot(transport: TlsCaptureTransport, resumed: bool) -> CapturedSlot {
    use crate::profile::capture::tls::{TlsCapturedExtension, TlsCapturedExtensionValue};
    let mut extensions = vec![
        TlsCapturedExtension {
            id: 43,
            value: TlsCapturedExtensionValue::U16List(vec![0x0304].into()),
        },
        TlsCapturedExtension {
            id: 45,
            value: TlsCapturedExtensionValue::U8List(vec![1].into()),
        },
    ];
    if resumed {
        extensions.push(TlsCapturedExtension {
            id: 41,
            value: TlsCapturedExtensionValue::PreSharedKeys {
                identities: vec![32].into(),
                binders: vec![32].into(),
            },
        });
    }
    CapturedSlot {
        kind: match transport {
            TlsCaptureTransport::Tcp => CapturedSlotKind::TcpTls,
            TlsCaptureTransport::Quic => CapturedSlotKind::QuicTls,
        },
        value: TlsCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            transport,
            protocol_version: 0x0303,
            ciphers: vec![0x1301].into(),
            compression: vec![0].into(),
            extensions: extensions.into(),
        }
        .canonical(TlsCaptureLimits::default())
        .unwrap(),
    }
}

#[cfg(feature = "tls")]
fn analyze(connections: Vec<Vec<CapturedSlot>>) -> AnalyzedProfile {
    analyze_profile_evidence(
        &evidence_of(connections),
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap()
}

#[cfg(feature = "tls")]
#[test]
fn tls_counts_only_with_a_full_handshake_on_its_transport() {
    use TlsCaptureTransport::{Quic, Tcp};
    let h3 = |number| CapturedSlot {
        kind: CapturedSlotKind::Http3Settings,
        value: setting(number),
    };
    // QUIC seen only resumed: no TLS/QUIC, and neither QUIC nor HTTP/3 from those connections.
    let analyzed = analyze(vec![
        vec![tls_slot(Tcp, false)],
        vec![tls_slot(Quic, true), h3(2)],
    ]);
    assert!(analyzed.components.tls_tcp.is_some());
    assert!(analyzed.components.tls_quic.is_none());
    assert!(analyzed.components.h3.is_none());
    assert!(analyzed.components.quic.is_none());
    // Next to a full handshake, a resumed one stays as a later-connection variant.
    let analyzed = analyze(vec![
        vec![tls_slot(Quic, false), h3(1)],
        vec![tls_slot(Quic, true), h3(2)],
    ]);
    let tls_quic = analyzed.components.tls_quic.as_deref().unwrap();
    assert_eq!(tls_quic.len(), 4);
    assert!(analyzed.components.h3.is_some());
    // TCP is held to the same rule; components index only the scopes that remain.
    let analyzed = analyze(vec![vec![tls_slot(Tcp, true)], vec![h3(3)]]);
    assert!(analyzed.components.tls_tcp.is_none());
    assert_eq!(analyzed.components.h3.as_deref(), Some([0, 1].as_slice()));
    assert_eq!(analyzed.scopes.len(), 2);
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

#[test]
fn multi_day_literals_retain_counts_beyond_one_day_capacity() {
    let policy = HeaderCapturePolicy::default();
    let limits = JointCaptureLimits::default();
    let mut windows = BTreeMap::new();
    let mut input = None;
    for index in 0..17u64 {
        let mut headers = HeaderMap::new();
        let names = [
            "accept",
            "accept-language",
            "accept-encoding",
            "user-agent",
            "cache-control",
        ];
        let mut order = [0, 1, 2, 3, 4];
        order.rotate_left(index as usize % 5);
        match index / 5 {
            0 => (),
            1 => order.swap(1, 2),
            2 => order.swap(2, 3),
            _ => order.swap(1, 3),
        }
        for slot in order {
            headers.insert(names[slot], HeaderValue::from_static("constant"));
        }
        let value = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers,
                None,
            )
            .unwrap()
            .canonical(&policy)
            .unwrap();
        let prepared = ProfileCapture {
            profile: ProfileKey::new("multi-day"),
            flow: Some(FlowKey::Http {
                version: Version::HTTP_11,
                method: Method::GET,
                initiator: None,
                fetch: None,
                connection: ConnectionContext::default(),
            }),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Request,
                slots: vec![CapturedSlot {
                    kind: CapturedSlotKind::Headers,
                    value,
                }]
                .into(),
            },
        }
        .prepare(false, limits)
        .unwrap();
        let day = if index < 9 { 100 } else { 101 };
        input.get_or_insert_with(|| ProfileEvidence {
            format_version: 1,
            profile: prepared.profile.clone(),
            scopes: Box::default(),
        });
        for bucket in prepared.buckets {
            let (metadata, window) = windows.entry(bucket.scope.id).or_insert_with(|| {
                let window = RetainedBucketWindow::new(
                    bucket.value.validated_domain(kib(64)).unwrap(),
                    bucket.scope.id,
                    [3; 32],
                    ProfileWindowLimits::default(),
                )
                .unwrap();
                (
                    ProfileScopeEvidence {
                        scope: bucket.scope.clone(),
                        flow: prepared.flow.clone(),
                        structure: bucket.structure.clone(),
                        window: window.snapshot(),
                    },
                    window,
                )
            });
            window
                .observe(
                    day,
                    day,
                    ObservationId {
                        run: [1; 16],
                        sequence: index + 1,
                    },
                    &bucket.value,
                )
                .unwrap();
            metadata.window = window.snapshot();
        }
    }
    let mut input = input.unwrap();
    input.scopes = windows
        .into_values()
        .map(|(metadata, _)| metadata)
        .collect();
    let analysis = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        101,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(analysis.scopes.len(), 2);
    for scope in analysis.scopes {
        assert_eq!(scope.observations.variants.len(), 17);
        assert_eq!(scope.observations.counts.total, 17);
        assert_eq!(scope.observations.counts.untracked, 0);
        assert!(scope.observations.variants.iter().all(|variant| matches!(
            variant.weight,
            AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1))
        )));
    }
}

// This is the structural wire format before ACK timing stopped contributing to
// identity. Keep the fixture independent of the current structural encoder.
fn historical_h2_structure(setting_value: u32) -> CanonicalValue {
    let mut writer = CanonicalWriter::new(CanonicalDomain::H2Structure, kib(16)).unwrap();
    writer
        .u8(ProfileCaptureCompleteness::Complete.tag())
        .unwrap();
    writer.u64(2).unwrap();
    writer.u8(0).unwrap(); // SETTINGS frame.
    writer.u8(0).unwrap(); // Not an ACK.
    writer.u64(1).unwrap();
    writer.u16(1).unwrap(); // SETTINGS_HEADER_TABLE_SIZE.
    writer.u32(setting_value).unwrap();
    writer.u8(0).unwrap(); // SETTINGS frame.
    writer.u8(1).unwrap(); // ACK, with an empty payload.
    writer.u64(0).unwrap();
    writer.finish()
}

fn h2_history_evidence(historical: bool, structural_setting: u32) -> ProfileEvidence {
    let limits = JointCaptureLimits::default();
    let value = H2Capture {
        completeness: ProfileCaptureCompleteness::Complete,
        frames: Box::new([
            H2CapturedFrame::Settings {
                ack: false,
                entries: Box::new([H2CapturedSetting { id: 1, value: 1024 }]),
            },
            H2CapturedFrame::Settings {
                ack: true,
                entries: Box::default(),
            },
        ]),
    }
    .canonical(H2CaptureLimits::default())
    .unwrap();
    let prepared = ProfileCapture {
        profile: ProfileKey::new("historical-h2-client"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::Http2EarlyFrames,
                value,
            }]),
        },
    }
    .prepare(false, limits)
    .unwrap();
    let scopes = prepared
        .buckets
        .into_vec()
        .into_iter()
        .map(|bucket| {
            let domain = bucket.value.validated_domain(limits.bytes).unwrap();
            let structure = if historical {
                let leaf = historical_h2_structure(structural_setting);
                if domain == CanonicalDomain::Joint {
                    let mut writer =
                        CanonicalWriter::new(CanonicalDomain::JointStructure, limits.bytes)
                            .unwrap();
                    writer.u8(0).unwrap(); // Connection-level tuple.
                    writer
                        .u8(ProfileCaptureCompleteness::Complete.tag())
                        .unwrap();
                    writer.u64(1).unwrap();
                    writer.u16(6).unwrap(); // Http2EarlyFrames slot.
                    writer.bytes(&leaf.bytes).unwrap();
                    writer.finish()
                } else {
                    leaf
                }
            } else {
                bucket.structure
            };
            let mut context =
                ProfileObservationScope::from_canonical(&bucket.scope, limits.bytes).unwrap();
            context.structure = structure.id;
            let scope = context.canonical(limits.bytes).unwrap();
            let mut window = RetainedBucketWindow::new(
                domain,
                scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            for sequence in 1..=40 {
                window
                    .observe(
                        100,
                        100,
                        ObservationId {
                            run: [if historical { 1 } else { 2 }; 16],
                            sequence,
                        },
                        &bucket.value,
                    )
                    .unwrap();
            }
            ProfileScopeEvidence {
                scope,
                flow: None,
                structure,
                window: window.snapshot(),
            }
        })
        .collect();
    ProfileEvidence {
        format_version: 1,
        profile: prepared.profile,
        scopes,
    }
}

#[test]
fn historical_h2_ack_indices_merge_with_current_scopes() {
    let mut input = h2_history_evidence(true, 1024);
    let current = h2_history_evidence(false, 1024);
    assert_ne!(input.scopes[0].scope.id, current.scopes[0].scope.id);
    let current_ids: Vec<_> = current.scopes.iter().map(|scope| scope.scope.id).collect();
    let mut scopes = input.scopes.into_vec();
    scopes.extend(current.scopes);
    input.scopes = scopes.into();
    let original = serde_json::to_vec(&input).unwrap();
    let result = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(result.components.h2.as_deref(), Some([0, 1].as_slice()));
    let analyzed: Vec<_> = result.scopes.iter().map(|scope| scope.id).collect();
    assert_eq!(analyzed.len(), 2);
    for id in current_ids {
        assert!(analyzed.contains(&id));
    }
    for scope in &result.scopes {
        // Disjoint historical and current observations are counted together.
        assert_eq!(scope.observations.counts.total, 80);
    }
    assert_eq!(serde_json::to_vec(&input).unwrap(), original);
}

#[test]
fn historical_h2_ack_compatibility_preserves_membership_and_authorization() {
    let wrong_setting = h2_history_evidence(true, 4096);
    assert!(matches!(
        analyze_profile_evidence(
            &wrong_setting,
            false,
            [3; 32],
            100,
            14,
            ProfileAnalysisLimits::default()
        ),
        Err(ProfileDataError::Invalid(
            "profile evidence structural membership"
        ))
    ));
    let input = h2_history_evidence(true, 1024);
    assert!(matches!(
        analyze_profile_evidence(
            &input,
            true,
            [3; 32],
            100,
            14,
            ProfileAnalysisLimits::default()
        ),
        Err(ProfileDataError::Invalid("profile evidence ownership"))
    ));
}

/// Stored request scopes as written before volatile header values were classified:
/// every marker value and network hint minted its own structure.
fn polluted_header_evidence(shapes: &[(&str, u32)]) -> ProfileEvidence {
    let policy = HeaderCapturePolicy::default();
    let limits = JointCaptureLimits::default();
    let profile = ProfileKey::new("polluted-browser");
    let flow = FlowKey::Http {
        version: Version::HTTP_2,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let mut scopes = Vec::new();
    let mut identity = None;
    let mut sequence = 0_u64;
    for (accept, requests) in shapes {
        for request in 0..*requests {
            sequence += 1;
            let marker = format!("rama-fp17000000{sequence:05}");
            let rtt = (request * 50).to_string();
            let mut headers = HeaderMap::new();
            headers.insert("accept", HeaderValue::from_str(accept).unwrap());
            headers.insert("rtt", HeaderValue::from_str(&rtt).unwrap());
            headers.insert(
                "x-rama-custom-header-marker",
                HeaderValue::from_str(&marker).unwrap(),
            );
            let mut captured = policy
                .capture(
                    ProfileCaptureCompleteness::Complete,
                    Version::HTTP_2,
                    &headers,
                    None,
                )
                .unwrap();
            captured.fields[2].value = HeaderValueSource::Profile(marker.as_bytes().into());
            let leaf = captured.legacy_structural(&policy).unwrap();
            let prepared = ProfileCapture {
                profile: profile.clone(),
                flow: Some(flow.clone()),
                connection: ConnectionContext::default(),
                joint: JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Request,
                    slots: Box::new([CapturedSlot {
                        kind: CapturedSlotKind::Headers,
                        value: captured.canonical(&policy).unwrap(),
                    }]),
                },
            }
            .prepare(false, limits)
            .unwrap();
            identity = Some(prepared.profile.clone());
            for bucket in &prepared.buckets {
                let domain = bucket.value.validated_domain(limits.bytes).unwrap();
                let structure = if domain == CanonicalDomain::Joint {
                    let mut writer =
                        CanonicalWriter::new(CanonicalDomain::JointStructure, limits.bytes)
                            .unwrap();
                    writer.u8(1).unwrap(); // Request-level tuple.
                    writer
                        .u8(ProfileCaptureCompleteness::Complete.tag())
                        .unwrap();
                    writer.u64(1).unwrap();
                    writer.u16(0).unwrap(); // Headers slot.
                    writer.bytes(&leaf.bytes).unwrap();
                    writer.finish()
                } else {
                    leaf.clone()
                };
                let mut context =
                    ProfileObservationScope::from_canonical(&bucket.scope, limits.bytes).unwrap();
                context.structure = structure.id;
                let scope = context.canonical(limits.bytes).unwrap();
                let mut window = RetainedBucketWindow::new(
                    domain,
                    scope.id,
                    [3; 32],
                    ProfileWindowLimits::default(),
                )
                .unwrap();
                window
                    .observe(
                        100,
                        100,
                        ObservationId {
                            run: [5; 16],
                            sequence,
                        },
                        &bucket.value,
                    )
                    .unwrap();
                scopes.push(ProfileScopeEvidence {
                    scope,
                    flow: prepared.flow.clone(),
                    structure,
                    window: window.snapshot(),
                });
            }
        }
    }
    ProfileEvidence {
        format_version: 1,
        profile: identity.unwrap(),
        scopes: scopes.into(),
    }
}

#[test]
fn stored_scopes_with_volatile_header_literals_merge_into_one_scope() {
    let input = polluted_header_evidence(&[("text/html", 40)]);
    assert_eq!(input.scopes.len(), 80);
    let distinct: BTreeSet<_> = input
        .scopes
        .iter()
        .map(|scope| scope.structure.id)
        .collect();
    assert_eq!(distinct.len(), 80);
    let analyzed = analyze_profile_evidence(
        &input,
        false,
        [3; 32],
        100,
        14,
        ProfileAnalysisLimits {
            scopes: 2,
            ..ProfileAnalysisLimits::default()
        },
    )
    .unwrap();
    assert_eq!(analyzed.scopes.len(), 2);
    for scope in &analyzed.scopes {
        assert_eq!(scope.observations.counts.total, 40);
        // Every stored observation was sampled; the merged scope keeps them all.
        assert_eq!(scope.observations.retained_samples, 40);
    }
    assert_eq!(analyzed.components.h2.as_deref(), Some([0, 1].as_slice()));
}

#[test]
fn normalization_is_charged_to_the_work_budget_and_skips_dropped_windows() {
    let mut input = polluted_header_evidence(&[("text/html", 6), ("*/*", 3), ("image/avif", 2)]);
    let limits = ProfileAnalysisLimits {
        scopes: 4,
        ..ProfileAnalysisLimits::default()
    };
    let normalized = normalize_profile_evidence(&input, false, [3; 32], limits).unwrap();
    assert!(normalized.work_units > 0);
    assert!(matches!(
        normalize_profile_evidence(
            &input,
            false,
            [3; 32],
            ProfileAnalysisLimits {
                maximum_work: normalized.work_units - 1,
                ..limits
            },
        ),
        Err(ProfileDataError::LimitExceeded("profile analysis work"))
    ));
    // Windows of dropped scopes are never decoded.
    let mut scopes = input.scopes.into_vec();
    for scope in scopes.iter_mut().rev().take(4) {
        scope.window.format_version = 2;
    }
    input.scopes = scopes.into();
    let skipped = normalize_profile_evidence(&input, false, [3; 32], limits).unwrap();
    assert_eq!(skipped.dropped_stored_scopes, 4);
    assert_eq!(skipped.work_units, normalized.work_units);
}

#[test]
fn scope_bound_keeps_the_first_listed_scopes_and_reports_the_rest() {
    // Callers list the scopes to keep first.
    let input = polluted_header_evidence(&[("text/html", 6), ("*/*", 3), ("image/avif", 2)]);
    let limits = ProfileAnalysisLimits {
        scopes: 4,
        ..ProfileAnalysisLimits::default()
    };
    let normalized = normalize_profile_evidence(&input, false, [3; 32], limits).unwrap();
    assert_eq!(normalized.stored_scopes, 22);
    assert_eq!(normalized.evidence.scopes.len(), 4);
    assert_eq!(normalized.dropped_scopes, 2);
    assert_eq!(normalized.dropped_stored_scopes, 4);
    let mut totals: Vec<u64> = normalized
        .evidence
        .scopes
        .iter()
        .map(|scope| {
            scope
                .window
                .buckets
                .iter()
                .map(|day| day.bucket.counts.total)
                .sum()
        })
        .collect();
    totals.sort_unstable();
    assert_eq!(totals, [3, 3, 6, 6]);
    // Kept scopes come out in archive order, whatever order ranked them.
    assert!(
        normalized
            .evidence
            .scopes
            .windows(2)
            .all(|pair| pair[0].scope.id < pair[1].scope.id)
    );
    ProfileArchiveEntry {
        evidence: normalized.evidence.clone(),
        sampler_seed: [3; 32],
    }
    .analyze(false, 100, 14, limits)
    .unwrap();
    let analyzed =
        analyze_profile_evidence(&normalized.evidence, false, [3; 32], 100, 14, limits).unwrap();
    assert_eq!(analyzed.scopes.len(), 4);
    // Analysis itself never drops scopes silently.
    assert!(matches!(
        analyze_profile_evidence(&input, false, [3; 32], 100, 14, limits),
        Err(ProfileDataError::LimitExceeded("profile analysis scopes"))
    ));
    for scope in &normalized.evidence.scopes {
        assert_eq!(
            normalized_scope_id(&scope.scope, &scope.structure, kib(16)).unwrap(),
            scope.scope.id
        );
    }
    for scope in &input.scopes {
        let id = normalized_scope_id(&scope.scope, &scope.structure, kib(16)).unwrap();
        assert_ne!(id, scope.scope.id);
    }
}
