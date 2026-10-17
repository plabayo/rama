use super::*;
use rama_ua::profile::{
    capture::{
        headers::{HeaderCapture, HeaderCapturePolicy},
        joint::{CaptureLevel, CapturedSlot, JointCapture, JointCaptureLimits},
        observation::ProfileCapture,
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    },
    evidence::{
        ProfileEvidence, ProfileScopeEvidence,
        ingestion::ObservationId,
        window::{ProfileWindowLimits, RetainedBucketWindow},
    },
    format::{
        archive::{ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter},
        canonical::ValueId,
    },
    model::identity::{FlowKey, ProfileKey},
    selection::{
        ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{EmulationContext, ProfileSelector, SelectionRequest, VariantPins},
    },
};

// Build real counted evidence and draw through the public archive/selection API.
fn selected(client: &str, capture: &TlsCapture) -> (EmulationContext, ConnectionSelection) {
    let flow = FlowKey::Http {
        version: Version::HTTP_3,
        method: "GET".parse().unwrap(),
        initiator: None,
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let mut scopes = Vec::new();
    for level in [CaptureLevel::Connection, CaptureLevel::Request] {
        let observation = ProfileCapture {
            profile: ProfileKey::new(client),
            flow: (level == CaptureLevel::Request).then(|| flow.clone()),
            connection: ConnectionContext::default(),
            joint: JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level,
                slots: if level == CaptureLevel::Connection {
                    vec![
                        CapturedSlot {
                            kind: CapturedSlotKind::QuicTls,
                            value: capture.canonical(TlsCaptureLimits::default()).unwrap(),
                        },
                        CapturedSlot {
                            kind: CapturedSlotKind::Http3Settings,
                            value: OrderedProtocolCapture {
                                completeness: ProfileCaptureCompleteness::Complete,
                                namespace: OrderNamespace::Http3Setting,
                                fields: Box::default(),
                            }
                            .canonical(OrderCaptureLimits::default())
                            .unwrap(),
                        },
                    ]
                    .into()
                } else {
                    vec![CapturedSlot {
                        kind: CapturedSlotKind::Headers,
                        value: HeaderCapture {
                            completeness: ProfileCaptureCompleteness::Complete,
                            version: Version::HTTP_3,
                            fields: Box::default(),
                        }
                        .canonical(&HeaderCapturePolicy::default())
                        .unwrap(),
                    }]
                    .into()
                },
            },
        };
        let prepared = observation
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
        for bucket in prepared.buckets {
            let mut window = RetainedBucketWindow::new(
                bucket.value.validated_domain(65536).unwrap(),
                bucket.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &bucket.value,
                )
                .unwrap();
            scopes.push(ProfileScopeEvidence {
                scope: bucket.scope,
                flow: prepared.flow.clone(),
                structure: bucket.structure,
                window: window.snapshot(),
            });
        }
    }
    scopes.sort_unstable_by_key(|scope| scope.scope.id);
    let archive =
        ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
            .unwrap()
            .write_profile(ProfileArchiveEntry {
                evidence: ProfileEvidence {
                    format_version: 1,
                    profile: ProfileKey::new(client).canonical(65536).unwrap(),
                    scopes: scopes.into(),
                },
                sampler_seed: [3; 32],
            })
            .unwrap()
            .finish()
            .unwrap();
    let database = UserAgentDatabase::try_from_archive(
        &archive,
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    let selected = Arc::new(
        database
            .select(
                &SelectionRequest {
                    client: ProfileSelector::default(),
                    required: CapabilitySet {
                        h3: true,
                        tls_quic: true,
                        ..CapabilitySet::default()
                    },
                    flow,
                    pins: VariantPins::default(),
                },
                ProfileSeed([4; 32]),
                DrawKey([5; 32]),
            )
            .unwrap(),
    );
    let connection = selected
        .connection(
            &ConnectionContext::default(),
            ProfileSeed([4; 32]),
            DrawKey([6; 32]),
        )
        .unwrap();
    let context =
        selected.emulation_context(ProfileSeed([4; 32]), DrawKey([6; 32]), DrawKey([7; 32]));
    (context, connection)
}

#[tokio::test]
async fn changing_connection_draw_rejects_without_consuming_the_native_plan() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let input = fixture.input();
        let (context, selection) = selected("native-h3-selection", &fixture.capture);
        let mut wrong_draw = context.clone();
        wrong_draw.connection_key = DrawKey([8; 32]);
        let mut wrong_pin = context.clone();
        wrong_pin.pins.connection = Some(ValueId([8; 32]));
        let (wrong_profile, _) = selected("other-native-h3-selection", &fixture.capture);
        for mismatched in [wrong_draw, wrong_pin, wrong_profile] {
            mismatched.publish(input.extensions());
            fixture
                .connector
                .profile_compiler()
                .compile(
                    &input,
                    &selection,
                    &selection.prepare_components().unwrap(),
                    ProfilePreservationMode::Strict,
                )
                .unwrap_err();
        }
        context.clone().publish(input.extensions());
        fixture
            .connector
            .profile_compiler()
            .compile(
                &input,
                &selection,
                &selection.prepare_components().unwrap(),
                ProfilePreservationMode::Strict,
            )
            .unwrap()
            .apply(input.extensions());

        let mut changes = Vec::new();
        let mut changed = context.clone();
        changed.seed = ProfileSeed([8; 32]);
        changes.push(changed);
        let mut changed = context.clone();
        changed.connection_key = DrawKey([8; 32]);
        changes.push(changed);
        let mut changed = context.clone();
        changed.pins.connection = Some(ValueId([8; 32]));
        changes.push(changed);
        let mut changed = context.clone();
        changed.selected = Arc::new((*changed.selected).clone());
        changes.push(changed);
        for changed in changes {
            changed.publish(input.extensions());
            rejected(fixture.connector.prepare_tls(&input));
        }
        // Request draws can change without changing this connection's TLS offer.
        let mut next_request = context;
        next_request.request_key = DrawKey([9; 32]);
        next_request.publish(input.extensions());
        fixture.connector.prepare_tls(&input).unwrap();
        rejected(fixture.connector.prepare_tls(&input));
    })
    .await
    .unwrap();
}
