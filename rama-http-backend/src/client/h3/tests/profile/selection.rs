use super::*;
use rama_quic_proto::{
    capture::version_information, transport_parameters::RawParameter,
    transport_parameters::TransportParameterId,
};
use rama_ua::profile::capture::order::ProtocolValue;
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
        DrawKey, ProfileSeed,
        capabilities::CapabilitySet,
        database::UserAgentDatabase,
        variants::{
            ConnectionSelection, EmulationContext, ProfileSelector, SelectionRequest, VariantPins,
        },
    },
};

// Build real counted evidence and draw through the public archive/selection API.
pub(super) fn selected(
    client: &str,
    capture: &TlsCapture,
    parameters: Option<&OrderedProtocolCapture>,
    flight: Option<&QuicFlightCapture>,
) -> (EmulationContext, ConnectionSelection) {
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
                    let mut slots = vec![
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
                    ];
                    if let Some(parameters) = parameters {
                        slots.push(CapturedSlot {
                            kind: CapturedSlotKind::QuicParameters,
                            value: parameters.canonical(OrderCaptureLimits::default()).unwrap(),
                        });
                        let raw: Vec<_> = parameters
                            .fields
                            .iter()
                            .filter_map(|field| match &field.value {
                                ProtocolValue::Literal(value) => Some(RawParameter {
                                    id: TransportParameterId::from(field.id),
                                    value: value.to_vec(),
                                }),
                                ProtocolValue::ConnectionLength(_) => None,
                            })
                            .collect();
                        let information = version_information(&raw).unwrap();
                        slots.push(CapturedSlot {
                            kind: CapturedSlotKind::QuicVersions,
                            value: OrderedProtocolCapture::capture(
                                ProfileCaptureCompleteness::Complete,
                                OrderNamespace::QuicVersion,
                                information
                                    .available()
                                    .iter()
                                    .map(|version| (u64::from(version.as_u32()), [])),
                                OrderCaptureLimits::default(),
                            )
                            .unwrap()
                            .canonical(OrderCaptureLimits::default())
                            .unwrap(),
                        });
                    }
                    if let Some(flight) = flight {
                        slots.push(CapturedSlot {
                            kind: CapturedSlotKind::QuicFirstFlight,
                            value: flight
                                .canonical(QuicFlightCaptureLimits::default())
                                .unwrap(),
                        });
                    }
                    slots.into()
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
                        quic: parameters.is_some(),
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
async fn current_context_supplies_selection_and_request_draws_share_the_connection_offer() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = fixture().await;
        let input = fixture.input();
        let (context, selected) = selected("native-h3-selection", &fixture.capture, None, None);
        let mut wrong_pin = context.clone();
        wrong_pin.pins.connection = Some(ValueId([8; 32]));
        wrong_pin.publish(input.extensions());
        rejected(fixture.prepare_connection(&input).await);

        // There is no earlier native plan: each preparation reads current context.
        // Changing a request draw must not change the admitted connection variant.
        for key in [DrawKey([7; 32]), DrawKey([9; 32])] {
            let mut context = context.clone();
            context.request_key = key;
            context.publish(input.extensions());
            fixture.prepare_connection(&input).await.unwrap();
            assert_eq!(
                input
                    .extensions()
                    .get_ref::<ConnectionSelection>()
                    .unwrap()
                    .variant,
                selected.variant
            );
        }
    })
    .await
    .unwrap();
}
