use super::*;
use crate::profile::{
    CaptureLevel, CaptureRunId, CapturedSlot, CapturedSlotKind, ConnectionContext,
    CountedObservationBucket, Http1Settings, Http2Settings, JointCapture, JointCaptureLimits,
    JsProfileWebApis, ObservationWeight, ProfileAnalysisLimits, ProfileBucketLimits,
    ProfileCapture, ProfileEvidenceCollector, ProfileKey, UserAgentProfile, UserAgentSourceInfo,
    analyze_profile_evidence,
};
#[cfg(feature = "tls")]
use crate::profile::{TlsCapturedExtensionValue, WsClientConfigOverwrites};
use rama_http::{
    HeaderMap, HeaderValue,
    proto::h2::{PseudoHeader, PseudoHeaderOrder},
};
#[cfg(feature = "tls")]
use rama_net::{address::Domain, tls::ApplicationProtocol};
#[cfg(feature = "tls")]
use rama_tls::{
    CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion,
    client::{ClientHello, ClientHelloExtension},
};
use rama_utils::octets::kib;

fn row() -> UserAgentProfileInput {
    let mut row = UserAgentProfileInput::new("legacy-library/1");
    row.h1_settings = Some(Http1Settings {
        title_case_headers: true,
    });
    let headers: HeaderMap = [("accept", "text/html"), ("cookie", "legacy-cookie-canary")]
        .into_iter()
        .map(|(name, value)| (name.parse().unwrap(), HeaderValue::from_static(value)))
        .collect();
    row.h1_headers_navigate = Some(headers.clone());
    row.h1_headers_fetch = Some(headers.clone());
    row.h1_headers_xhr = Some(headers.clone());
    row.h1_headers_form = Some(headers.clone());
    row.h1_headers_ws = Some(headers.clone());
    row.h2_headers_navigate = Some(headers.clone());
    row.h2_headers_fetch = Some(headers.clone());
    row.h2_headers_xhr = Some(headers.clone());
    row.h2_headers_form = Some(headers.clone());
    row.h2_headers_ws = Some(headers);
    row.h2_settings = Some(Http2Settings {
        http_pseudo_headers: Some(
            [
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ]
            .into_iter()
            .collect::<PseudoHeaderOrder>(),
        ),
        early_frames: None,
    });
    row.js_web_apis = Some(JsProfileWebApis {
        navigator: None,
        screen: None,
    });
    row.source_info = Some(UserAgentSourceInfo {
        device_name: Some("fixture".to_owned()),
        os: None,
        os_version: None,
        browser_name: None,
        browser_version: None,
    });
    row
}

fn capture(field: &LegacyFieldCapture) -> ProfileCapture {
    ProfileCapture {
        profile: ProfileKey::new("legacy-library/1"),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Legacy,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::LegacyField,
                value: field.canonical(kib(16)).unwrap(),
            }]
            .into(),
        },
    }
}

#[test]
fn legacy_fields_keep_missing_facts_and_conventional_unknown_weights() {
    let fields = LegacyFieldCapture::capture_row(&row(), kib(16)).unwrap();
    assert_eq!(fields.len(), 14);
    let mut collected = ProfileEvidenceCollector::new(
        &ProfileKey::new("legacy-library/1"),
        false,
        CaptureRunId::new(100, [3; 12]),
        [4; 32],
        100,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    for field in &fields {
        let value = field.canonical(kib(16)).unwrap();
        assert_eq!(
            value.validated_domain(kib(16)).unwrap(),
            CanonicalDomain::LegacyField
        );
        let restored = LegacyFieldCapture::from_canonical(&value, kib(16)).unwrap();
        assert_eq!(
            serde_json::to_vec(field).unwrap(),
            serde_json::to_vec(&restored).unwrap()
        );
        for end in 0..value.bytes.len() {
            let bytes = &value.bytes[..end];
            LegacyFieldCapture::from_canonical(
                &CanonicalValue {
                    id: ValueId(Sha256::digest(bytes).into()),
                    bytes: bytes.into(),
                },
                kib(16),
            )
            .unwrap_err();
        }
        assert!(
            !value
                .bytes
                .windows(b"legacy-cookie-canary".len())
                .any(|bytes| bytes == b"legacy-cookie-canary")
        );
        if let LegacyFieldValue::Headers(headers) = &field.value {
            let json = serde_json::to_string(headers).unwrap();
            assert!(
                !json.contains("HTTP_11") && !json.contains("method") && !json.contains("version")
            );
        }
        let capture = capture(field);
        assert_eq!(
            capture
                .prepare(false, JointCaptureLimits::default())
                .unwrap()
                .buckets
                .len(),
            1
        );
        collected.observe(100, &capture).unwrap();
    }
    let evidence = collected.finish();
    assert_eq!(evidence.scopes.len(), 14);
    let analysis = analyze_profile_evidence(
        &evidence,
        false,
        [4; 32],
        100,
        14,
        ProfileAnalysisLimits::default(),
    )
    .unwrap();
    assert_eq!(analysis.scopes.len(), 14);
    assert!(analysis.scopes.iter().all(|scope| scope.flow.is_none()
        && scope.observations.domain == CanonicalDomain::LegacyField
        && scope.observations.counts.total == 1
        && !scope.observations.counts.losses.history_known
        && scope.observations.orders.is_empty()));
    let profile = UserAgentProfile::from_captured(analysis);
    assert!(profile.capabilities().h1 && profile.capabilities().h2);
    assert!(matches!(
        profile.observation_weight().unwrap(),
        ObservationWeight::UnknownHistory {
            observed: 1,
            unassigned: 0
        }
    ));
}

#[test]
fn legacy_values_cannot_claim_complete_history_or_joint_correlation() {
    let field = LegacyFieldCapture::capture_row(&row(), kib(16))
        .unwrap()
        .into_vec()
        .remove(0);
    let capture = capture(&field);
    let scope = capture
        .prepare(false, JointCaptureLimits::default())
        .unwrap()
        .buckets[0]
        .scope
        .id;
    let limits = ProfileBucketLimits::default();
    let bucket =
        CountedObservationBucket::new(CanonicalDomain::LegacyField, scope, [4; 32], limits)
            .unwrap();
    for case in 0..2 {
        let mut snapshot = bucket.snapshot();
        if case == 0 {
            snapshot.counts.losses.history_known = true;
        } else {
            snapshot.counts.untracked_distinct.history_known = true;
        }
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::LegacyField,
            scope,
            [4; 32],
            limits,
        )
        .unwrap_err();
    }
    let mut combined = capture.clone();
    combined.joint.slots = vec![
        capture.joint.slots[0].clone(),
        capture.joint.slots[0].clone(),
    ]
    .into();
    combined
        .prepare(false, JointCaptureLimits::default())
        .unwrap_err();
    let mut contextual = capture;
    contextual.connection.token_present = Some(false);
    contextual
        .prepare(false, JointCaptureLimits::default())
        .unwrap_err();
}

#[test]
fn legacy_field_encoding_is_pinned_and_payload_tags_are_checked() {
    let field = LegacyFieldCapture {
        field: LegacyField::H1Settings,
        value: LegacyFieldValue::H1Settings {
            title_case_headers: false,
        },
    };
    let canonical = field.canonical(kib(16)).unwrap();
    assert_eq!(canonical.bytes.as_ref(), b"rama-profile\0\0\x01\0\x17\0\0");
    assert_eq!(
        canonical.id.0,
        [
            46, 225, 140, 242, 30, 147, 131, 200, 213, 154, 22, 177, 133, 181, 100, 231, 146, 108,
            143, 210, 124, 28, 253, 133, 177, 66, 203, 240, 66, 8, 204, 216
        ]
    );
    field.canonical(canonical.bytes.len() - 1).unwrap_err();
    let mut wrong = field;
    wrong.field = LegacyField::SourceInfo;
    wrong.canonical(kib(16)).unwrap_err();
    let mut bytes = canonical.bytes.to_vec();
    bytes.push(0);
    LegacyFieldCapture::from_canonical(
        &CanonicalValue {
            id: ValueId(Sha256::digest(&bytes).into()),
            bytes: bytes.into(),
        },
        kib(16),
    )
    .unwrap_err();
    let mut headers = LegacyFieldCapture::capture_row(&row(), kib(16))
        .unwrap()
        .into_vec()
        .remove(1);
    headers.field = LegacyField::H2Navigate;
    headers.canonical(kib(16)).unwrap_err();
}

#[cfg(feature = "tls")]
#[test]
fn legacy_tls_keeps_transport_and_override_absence_without_connection_secrets() {
    let hello = ClientHello::new(
        ProtocolVersion::TLSv1_2,
        vec![CipherSuite::from(0x1301)],
        vec![CompressionAlgorithm::from(0)],
        vec![
            ClientHelloExtension::ServerName(Some(Domain::try_from("private.example").unwrap())),
            ClientHelloExtension::Opaque {
                id: ExtensionId::from(35),
                data: b"legacy-ticket-canary".to_vec(),
            },
        ],
    );
    let mut row = UserAgentProfileInput::new("legacy-library/1");
    row.tls_client_hello = Some(hello);
    let mut ids = Vec::new();
    for alpn in [
        None,
        Some(Vec::new()),
        Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
    ] {
        row.tls_ws_client_config_overwrites = Some(WsClientConfigOverwrites { alpn });
        let fields = LegacyFieldCapture::capture_row(&row, kib(16)).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(
            matches!(&fields[0].value, LegacyFieldValue::TcpTls(tls) if matches!(tls.transport, TlsCaptureTransport::Tcp) && matches!(tls.extensions[0].value, TlsCapturedExtensionValue::ServerName { present: true }))
        );
        for field in &fields {
            let value = field.canonical(kib(16)).unwrap();
            for secret in [
                b"legacy-ticket-canary".as_slice(),
                b"private.example".as_slice(),
            ] {
                assert!(
                    !value
                        .bytes
                        .windows(secret.len())
                        .any(|bytes| bytes == secret)
                );
            }
            let restored = LegacyFieldCapture::from_canonical(&value, kib(16)).unwrap();
            assert_eq!(
                serde_json::to_vec(field).unwrap(),
                serde_json::to_vec(&restored).unwrap()
            );
        }
        ids.push(fields[1].canonical(kib(16)).unwrap().id);
        let mut tls = fields[0].clone();
        if let LegacyFieldValue::TcpTls(tls) = &mut tls.value {
            tls.transport = TlsCaptureTransport::Quic;
        }
        tls.canonical(kib(16)).unwrap_err();
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
    row.tls_client_hello = None;
    LegacyFieldCapture::capture_row(&row, kib(16)).unwrap_err();
}

#[test]
fn legacy_alpn_overrides_reject_oversized_and_empty_protocol_names() {
    for protocols in [
        vec![Box::<[u8]>::from([])],
        vec![vec![1; 256].into_boxed_slice()],
        vec![Box::<[u8]>::from([1]); 65],
    ] {
        let field = LegacyFieldCapture {
            field: LegacyField::WsTlsAlpn,
            value: LegacyFieldValue::WsTlsAlpn(Some(protocols.into())),
        };
        field.canonical(kib(16)).unwrap_err();
    }
}

#[test]
fn legacy_row_batch_is_atomic_bounded_and_uses_the_live_profile_identity() {
    let row = row();
    let limits = JointCaptureLimits::default();
    let batch = LegacyFieldCapture::prepare_row(&row, false, limits)
        .unwrap()
        .unwrap();
    assert_eq!(batch.buckets.len(), 14);
    assert!(batch.flow.is_none());
    let expected = ProfileKey::from_user_agent(&UserAgent::new(row.uastr.clone()))
        .canonical(limits.value_bytes)
        .unwrap();
    assert_eq!(batch.profile.bytes, expected.bytes);
    assert!(batch.buckets.iter().all(|bucket| {
        bucket.value.validated_domain(limits.value_bytes).unwrap() == CanonicalDomain::LegacyField
    }));
    let exact = batch.profile.bytes.len()
        + batch
            .buckets
            .iter()
            .map(|bucket| {
                bucket.scope.bytes.len() + bucket.structure.bytes.len() + bucket.value.bytes.len()
            })
            .sum::<usize>();
    LegacyFieldCapture::prepare_row(
        &row,
        false,
        JointCaptureLimits {
            bytes: exact,
            ..limits
        },
    )
    .unwrap()
    .unwrap();
    LegacyFieldCapture::prepare_row(
        &row,
        false,
        JointCaptureLimits {
            bytes: exact - 1,
            ..limits
        },
    )
    .unwrap_err();
    assert!(
        LegacyFieldCapture::prepare_row(&UserAgentProfileInput::new("empty/1"), false, limits)
            .unwrap()
            .is_none()
    );
}
