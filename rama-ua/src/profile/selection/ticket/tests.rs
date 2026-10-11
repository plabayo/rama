use rama_http::{Method, Version};

use super::*;
use crate::profile::{
    AnalyzedCaptureVariant, AnalyzedProfile, AnalyzedProfileComponents, AnalyzedProfileScope,
    CaptureLevel, CapturedSlot, CapturedSlotKind, CountedCaptureAnalysis, CounterSnapshot,
    JointCapture, JointCaptureLimits, ObservationLosses, OrderCaptureLimits, OrderNamespace,
    OrderedProtocolCapture, ProfileCaptureCompleteness, ProfileKey, ResumptionContext,
    UntrackedDistinctSnapshot,
};

fn flow(context: ConnectionContext, version: Version) -> FlowKey {
    FlowKey::Http {
        version,
        method: Method::GET,
        initiator: None,
        fetch: None,
        connection: context,
    }
}

fn counts(total: u64) -> CounterSnapshot {
    CounterSnapshot {
        total,
        untracked: total,
        values: Box::default(),
        losses: ObservationLosses {
            history_known: true,
            ..ObservationLosses::default()
        },
        untracked_distinct: UntrackedDistinctSnapshot {
            history_known: true,
            ..UntrackedDistinctSnapshot::default()
        },
    }
}

fn connection_variant(version: u64) -> CanonicalValue {
    let value = OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::Complete,
        OrderNamespace::QuicVersion,
        [(version, [])],
        OrderCaptureLimits::default(),
    )
    .unwrap()
    .canonical(OrderCaptureLimits::default())
    .unwrap();
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::QuicVersions,
            value,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn request_variant() -> CanonicalValue {
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: Box::default(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

fn scope(
    tag: u8,
    profile: ValueId,
    flow: Option<ValueId>,
    context: ConnectionContext,
    variants: Vec<(CanonicalValue, u64)>,
) -> AnalyzedProfileScope {
    let total = variants.iter().map(|(_value, weight)| *weight).sum();
    let id = ValueId([tag; 32]);
    AnalyzedProfileScope {
        id,
        context: ProfileObservationScope {
            authorized: false,
            profile,
            flow,
            connection: context,
            structure: ValueId([tag.wrapping_add(100); 32]),
        },
        flow: None,
        structure: request_variant(),
        observations: CountedCaptureAnalysis {
            classifier_revision: 2,
            order_work: 0,
            domain: CanonicalDomain::Joint,
            scope: id,
            counts: counts(total),
            retained_samples: total as usize,
            sample_values: variants.iter().map(|(value, _weight)| value.id).collect(),
            variants: variants
                .into_iter()
                .map(|(value, weight)| AnalyzedCaptureVariant {
                    value,
                    weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(weight)),
                })
                .collect(),
            orders: Box::default(),
            numeric: Box::default(),
        },
    }
}

fn profile(
    client: &str,
    capabilities: CapabilitySet,
    context: ConnectionContext,
) -> UserAgentProfile {
    let mut key = ProfileKey::new(client);
    key.version = Some("1".into());
    let canonical = key.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let version = if capabilities.h3 {
        Version::HTTP_3
    } else if capabilities.h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let request_flow = flow(context.clone(), version)
        .canonical(MAXIMUM_IDENTITY_BYTES)
        .unwrap();
    let connection = scope(
        1,
        canonical.id,
        None,
        context.clone(),
        vec![(connection_variant(1), 1), (connection_variant(2), 3)],
    );
    let request = scope(
        2,
        canonical.id,
        Some(request_flow.id),
        context,
        vec![(request_variant(), 4)],
    );
    let indexes = |enabled: bool| enabled.then(|| vec![0, 1].into_boxed_slice());
    UserAgentProfile::from_captured(AnalyzedProfile {
        work_units: 0,
        format_version: 1,
        classifier_revision: 2,
        id: canonical.id,
        key,
        current_day: 1,
        horizon: 1,
        components: AnalyzedProfileComponents {
            h1: indexes(capabilities.h1),
            h2: indexes(capabilities.h2),
            h3: indexes(capabilities.h3),
            tls_tcp: indexes(capabilities.tls_tcp),
            tls_quic: indexes(capabilities.tls_quic),
            quic: indexes(capabilities.quic),
        },
        scopes: vec![connection, request].into(),
    })
}

fn h3_capabilities() -> CapabilitySet {
    CapabilitySet {
        h3: true,
        tls_quic: true,
        quic: true,
        ..CapabilitySet::default()
    }
}

fn request(context: ConnectionContext) -> SelectionRequest {
    SelectionRequest {
        client: ProfileSelector::default(),
        required: h3_capabilities(),
        flow: flow(context, Version::HTTP_3),
        pins: VariantPins::default(),
    }
}

#[test]
fn advertised_alpn_requires_every_possible_http_outcome() {
    let required =
        CapabilitySet::for_alpn(&TlsAlpn::http_auto(), SelectionTransport::TcpTls).unwrap();
    assert_eq!(
        required,
        CapabilitySet {
            h1: true,
            h2: true,
            tls_tcp: true,
            ..CapabilitySet::default()
        }
    );
    assert!(matches!(
        CapabilitySet::for_alpn(
            &TlsAlpn(vec![ApplicationProtocol::HTTP_3].into()),
            SelectionTransport::TcpTls,
        ),
        Err(SelectionError::IncompatibleTransport)
    ));
}

#[test]
fn selection_requires_flow_and_complete_capability_closure() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [
        profile(
            "incomplete",
            CapabilitySet {
                h3: true,
                ..CapabilitySet::default()
            },
            context.clone(),
        ),
        profile("complete", h3_capabilities(), context.clone()),
    ]
    .into_iter()
    .collect();
    let selected = database
        .select(&request(context), ProfileSeed([3; 32]), DrawKey([4; 32]))
        .unwrap();
    assert_eq!(selected.profile().key.client.as_ref(), "complete");
}

#[test]
fn h1_h2_offer_does_not_admit_an_h2_only_profile() {
    let context = ConnectionContext::default();
    let tcp = CapabilitySet {
        h1: true,
        h2: true,
        tls_tcp: true,
        ..CapabilitySet::default()
    };
    let database: UserAgentDatabase = [
        profile(
            "h2-only",
            CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            context.clone(),
        ),
        profile("complete", tcp, context.clone()),
    ]
    .into_iter()
    .collect();
    let selected = database
        .select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: tcp,
                flow: flow(context.clone(), Version::HTTP_2),
                pins: VariantPins::default(),
            },
            ProfileSeed([41; 32]),
            DrawKey([42; 32]),
        )
        .unwrap();
    assert_eq!(selected.profile().key.client.as_ref(), "complete");

    let incomplete: UserAgentDatabase = [profile(
        "h2-only",
        CapabilitySet {
            h2: true,
            tls_tcp: true,
            ..CapabilitySet::default()
        },
        context.clone(),
    )]
    .into_iter()
    .collect();
    assert!(matches!(
        incomplete.select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: tcp,
                flow: flow(context, Version::HTTP_2),
                pins: VariantPins::default(),
            },
            ProfileSeed([41; 32]),
            DrawKey([42; 32]),
        ),
        Err(SelectionError::MissingCapabilities(required)) if required == tcp
    ));
}

#[test]
fn connection_ticket_matches_exact_context_and_literal_pin() {
    let context = ConnectionContext {
        resumption: ResumptionContext::Resumed,
        early_data: Some(false),
        token_present: Some(true),
        ip_family: None,
    };
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), context.clone())]
        .into_iter()
        .collect();
    let selected = database
        .select(
            &request(context.clone()),
            ProfileSeed([5; 32]),
            DrawKey([6; 32]),
        )
        .unwrap();
    let first = selected
        .connection(&context, ProfileSeed([5; 32]), DrawKey([7; 32]))
        .unwrap();
    let again = selected
        .connection(&context, ProfileSeed([5; 32]), DrawKey([7; 32]))
        .unwrap();
    assert_eq!(first.variant, again.variant);
    assert_eq!(first.effective.scope, again.effective.scope);

    let request_flow = flow(context.clone(), Version::HTTP_3);
    let request_ticket = selected
        .request(
            &first,
            &request_flow,
            ProfileSeed([5; 32]),
            DrawKey([21; 32]),
        )
        .unwrap();
    assert_eq!(request_ticket.profile, first.profile);
    assert_eq!(request_ticket.connection_variant, first.variant);
    assert_eq!(request_ticket.draw, DrawKey([21; 32]));
    assert!(matches!(
        selected.request(
            &first,
            &flow(context.clone(), Version::HTTP_2),
            ProfileSeed([5; 32]),
            DrawKey([21; 32]),
        ),
        Err(SelectionError::IncompatibleNegotiatedProtocol(
            Version::HTTP_2
        ))
    ));

    assert!(matches!(
        selected.connection(
            &ConnectionContext::default(),
            ProfileSeed([5; 32]),
            DrawKey([7; 32]),
        ),
        Err(SelectionError::IncompatibleConnectionContext)
    ));

    let mut pinned_request = request(context.clone());
    pinned_request.pins.connection = Some(first.variant);
    let pinned = database
        .select(&pinned_request, ProfileSeed([8; 32]), DrawKey([9; 32]))
        .unwrap()
        .connection(&context, ProfileSeed([8; 32]), DrawKey([10; 32]))
        .unwrap();
    assert_eq!(pinned.variant, first.variant);

    let mut invalid_request = request(context.clone());
    invalid_request.pins.connection = Some(ValueId([88; 32]));
    let invalid = database
        .select(&invalid_request, ProfileSeed([8; 32]), DrawKey([9; 32]))
        .unwrap();
    assert!(matches!(
        invalid.connection(&context, ProfileSeed([8; 32]), DrawKey([10; 32])),
        Err(SelectionError::IncompatiblePin(pin)) if pin == ValueId([88; 32])
    ));
}

#[test]
fn unrelated_draws_do_not_change_a_logical_connection_draw() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), context.clone())]
        .into_iter()
        .collect();
    let selected = database
        .select(
            &request(context.clone()),
            ProfileSeed([11; 32]),
            DrawKey([12; 32]),
        )
        .unwrap();
    let expected = selected
        .connection(&context, ProfileSeed([11; 32]), DrawKey([13; 32]))
        .unwrap();
    for value in 0..64 {
        selected
            .connection(&context, ProfileSeed([11; 32]), DrawKey([value; 32]))
            .unwrap();
    }
    let actual = selected
        .connection(&context, ProfileSeed([11; 32]), DrawKey([13; 32]))
        .unwrap();
    assert_eq!(actual.variant, expected.variant);
}

#[test]
fn reuse_matches_profile_protocol_and_optional_connection_pin() {
    let context = ConnectionContext::default();
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), context.clone())]
        .into_iter()
        .collect();
    let selected = Arc::new(
        database
            .select(
                &request(context.clone()),
                ProfileSeed([31; 32]),
                DrawKey([32; 32]),
            )
            .unwrap(),
    );
    let ticket = selected
        .connection(&context, ProfileSeed([31; 32]), DrawKey([33; 32]))
        .unwrap();
    let established = Extensions::new();
    ProfileConnectionReuse::new(&ticket, Version::HTTP_3).publish(&established);

    let input = Extensions::new();
    input.insert(selected.clone().emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    ));
    assert!(
        established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut incompatible = (*selected).clone();
    incompatible.pins.connection = Some(ValueId([99; 32]));
    let input = Extensions::new();
    input.insert(Arc::new(incompatible).emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    ));
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut other_profile = (*selected).clone();
    other_profile.id = ValueId([77; 32]);
    let input = Extensions::new();
    input.insert(Arc::new(other_profile).emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    ));
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );
}
