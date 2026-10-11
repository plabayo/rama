use rama_http::{HeaderMap, HeaderName, HeaderValue, Method, Version};

use super::*;
use crate::profile::{
    AnalyzedCaptureVariant, AnalyzedProfile, AnalyzedProfileComponents, AnalyzedProfileScope,
    CaptureLevel, CapturedSlot, CapturedSlotKind, ConnectionIpFamily, CountedCaptureAnalysis,
    CounterSnapshot, FetchContext, HeaderCapture, HeaderCapturePolicy, HeaderOccurrence,
    HeaderValueSource, JointCapture, JointCaptureLimits, ObservationLosses, OrderCaptureLimits,
    OrderNamespace, OrderedProtocolCapture, ProfileCaptureCompleteness, ProfileKey, RequestBinding,
    ResumptionContext, UntrackedDistinctSnapshot,
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

fn request_variant_with_headers(version: Version, fields: Vec<HeaderOccurrence>) -> CanonicalValue {
    let headers = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version,
        fields: fields.into(),
    }
    .canonical(&HeaderCapturePolicy::default())
    .unwrap();

    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: vec![CapturedSlot {
            kind: CapturedSlotKind::Headers,
            value: headers,
        }]
        .into(),
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
    let request_flow = flow(context.clone(), version);
    let canonical_request_flow = request_flow.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let connection = scope(
        1,
        canonical.id,
        None,
        context.clone(),
        vec![(connection_variant(1), 1), (connection_variant(2), 3)],
    );
    let mut request = scope(
        2,
        canonical.id,
        Some(canonical_request_flow.id),
        context,
        vec![(request_variant(), 4)],
    );
    request.flow = Some(request_flow);
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

fn set_request_flow(profile: &mut UserAgentProfile, flow: FlowKey) {
    let canonical = flow.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter_mut()
        .find(|scope| scope.context.flow.is_some())
        .unwrap();
    scope.context.flow = Some(canonical.id);
    scope.flow = Some(flow);
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
fn default_request_selects_fresh_navigation_across_quic_token_states() {
    for token_present in [false, true] {
        let observed_context = ConnectionContext {
            resumption: ResumptionContext::Fresh,
            early_data: Some(false),
            token_present: Some(token_present),
            ip_family: Some(ConnectionIpFamily::V6),
        };
        let mut captured = profile("browser", h3_capabilities(), observed_context.clone());
        set_request_flow(
            &mut captured,
            FlowKey::Http {
                version: Version::HTTP_3,
                method: Method::GET,
                initiator: Some(RequestInitiator::Navigate),
                fetch: Some(FetchContext {
                    mode: Some("navigate".into()),
                    site: Some("none".into()),
                    destination: Some("document".into()),
                    user_activation: Some("?1".into()),
                }),
                connection: observed_context,
            },
        );
        let database: UserAgentDatabase = [captured].into_iter().collect();
        let request = request(ConnectionContext::default());

        let selected = database
            .select(&request, ProfileSeed([50; 32]), DrawKey([51; 32]))
            .unwrap();
        selected
            .connection(
                &ConnectionContext::default(),
                ProfileSeed([50; 32]),
                DrawKey([52; 32]),
            )
            .unwrap();
    }
}

#[test]
fn request_shape_selects_cookie_variant_and_ignores_unobserved_caller_fields() {
    let context = ConnectionContext::default();
    let empty = request_variant();
    let cookie = request_variant_with_headers(
        Version::HTTP_3,
        vec![HeaderOccurrence {
            name: HeaderName::from_static("cookie"),
            occurrence: 0,
            sensitive: true,
            representation: None,
            value: HeaderValueSource::Request(RequestBinding::Cookie),
        }],
    );
    let mut captured = profile("browser", h3_capabilities(), context.clone());
    let analysis = Arc::make_mut(captured.captured.as_mut().unwrap());
    let scope = analysis
        .scopes
        .iter_mut()
        .find(|scope| scope.context.flow.is_some())
        .unwrap();
    scope.observations.counts = counts(2);
    scope.observations.retained_samples = 2;
    scope.observations.sample_values = Box::new([empty.id, cookie.id]);
    scope.observations.variants = Box::new([
        AnalyzedCaptureVariant {
            value: empty.clone(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        },
        AnalyzedCaptureVariant {
            value: cookie.clone(),
            weight: AnalyzedOrderWeight::Counted(ObservationWeight::Exact(1)),
        },
    ]);

    let database: UserAgentDatabase = [captured].into_iter().collect();
    let selected = database
        .select(
            &request(context.clone()),
            ProfileSeed([53; 32]),
            DrawKey([54; 32]),
        )
        .unwrap();
    let connection = selected
        .connection(&context, ProfileSeed([53; 32]), DrawKey([55; 32]))
        .unwrap();
    let flow = flow(context.clone(), Version::HTTP_3);

    let selected_empty = selected
        .request(
            &connection,
            &flow,
            &HeaderMap::new(),
            ProfilePreservationMode::Strict,
            ProfileSeed([53; 32]),
            DrawKey([56; 32]),
        )
        .unwrap();
    assert_eq!(selected_empty.variant, empty.id);

    let mut cookie_headers = HeaderMap::new();
    cookie_headers.insert("cookie", HeaderValue::from_static("session=secret"));
    let selected_cookie = selected
        .request(
            &connection,
            &flow,
            &cookie_headers,
            ProfilePreservationMode::Strict,
            ProfileSeed([53; 32]),
            DrawKey([57; 32]),
        )
        .unwrap();
    assert_eq!(selected_cookie.variant, cookie.id);

    let mut caller_headers = HeaderMap::new();
    caller_headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
    let selected_caller = selected
        .request(
            &connection,
            &flow,
            &caller_headers,
            ProfilePreservationMode::Strict,
            ProfileSeed([53; 32]),
            DrawKey([58; 32]),
        )
        .unwrap();
    assert_eq!(selected_caller.variant, empty.id);

    let mut pinned_request = request(context.clone());
    pinned_request.pins.request = Some(cookie.id);
    let pinned = database
        .select(&pinned_request, ProfileSeed([53; 32]), DrawKey([59; 32]))
        .unwrap();
    let pinned_connection = pinned
        .connection(&context, ProfileSeed([53; 32]), DrawKey([60; 32]))
        .unwrap();
    assert!(matches!(
        pinned.request(
            &pinned_connection,
            &flow,
            &HeaderMap::new(),
            ProfilePreservationMode::Strict,
            ProfileSeed([53; 32]),
            DrawKey([61; 32]),
        ),
        Err(SelectionError::IncompatibleRequestShape)
    ));
}

#[test]
fn h1_h2_offer_draws_only_a_connection_scope_with_h2_state() {
    let context = ConnectionContext::default();
    let tcp = CapabilitySet {
        h1: true,
        h2: true,
        tls_tcp: true,
        ..CapabilitySet::default()
    };
    let mut profile = profile("complete", tcp, context.clone());
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let h1_connection = analysis.scopes[0].clone();
    let mut h2_connection = h1_connection.clone();
    h2_connection.id = ValueId([3; 32]);
    let request_scope = analysis.scopes[1].clone();
    analysis.scopes = vec![h1_connection, h2_connection, request_scope].into();
    analysis.components.h1 = Some(vec![0].into());
    analysis.components.h2 = Some(vec![1, 2].into());
    analysis.components.tls_tcp = Some(vec![0, 1, 2].into());

    let database: UserAgentDatabase = [profile].into_iter().collect();
    let selected = database
        .select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: tcp,
                flow: flow(context.clone(), Version::HTTP_2),
                pins: VariantPins::default(),
            },
            ProfileSeed([43; 32]),
            DrawKey([44; 32]),
        )
        .unwrap();
    let connection = selected
        .connection(&context, ProfileSeed([43; 32]), DrawKey([45; 32]))
        .unwrap();
    assert_eq!(connection.effective.scope, ValueId([3; 32]));
}

#[test]
fn ip_family_does_not_fragment_a_wire_equivalent_selection() {
    let captured = ConnectionContext {
        ip_family: Some(ConnectionIpFamily::V4),
        ..ConnectionContext::default()
    };
    let requested = ConnectionContext {
        ip_family: Some(ConnectionIpFamily::V6),
        ..ConnectionContext::default()
    };
    let database: UserAgentDatabase = [profile("complete", h3_capabilities(), captured.clone())]
        .into_iter()
        .collect();
    let captured_selection = database
        .select(
            &request(captured.clone()),
            ProfileSeed([46; 32]),
            DrawKey([47; 32]),
        )
        .unwrap();
    let selected = database
        .select(
            &request(requested.clone()),
            ProfileSeed([46; 32]),
            DrawKey([47; 32]),
        )
        .unwrap();
    let captured_connection = captured_selection
        .connection(&captured, ProfileSeed([46; 32]), DrawKey([48; 32]))
        .unwrap();
    let connection = selected
        .connection(&requested, ProfileSeed([46; 32]), DrawKey([48; 32]))
        .unwrap();
    assert_eq!(connection.variant, captured_connection.variant);
    assert_eq!(connection.effective.context.connection, captured);
    let request = selected
        .request(
            &connection,
            &flow(requested.clone(), Version::HTTP_3),
            &HeaderMap::new(),
            ProfilePreservationMode::Strict,
            ProfileSeed([46; 32]),
            DrawKey([49; 32]),
        )
        .unwrap();
    assert_eq!(
        request
            .effective
            .flow
            .canonical(MAXIMUM_IDENTITY_BYTES)
            .unwrap()
            .id,
        flow(requested, Version::HTTP_3)
            .canonical(MAXIMUM_IDENTITY_BYTES)
            .unwrap()
            .id
    );

    let incompatible = ConnectionContext {
        resumption: ResumptionContext::Fresh,
        ip_family: Some(ConnectionIpFamily::V6),
        ..ConnectionContext::default()
    };
    assert!(matches!(
        selected.connection(&incompatible, ProfileSeed([46; 32]), DrawKey([48; 32]),),
        Err(SelectionError::IncompatibleConnectionContext)
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
            &HeaderMap::new(),
            ProfilePreservationMode::Strict,
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
            &HeaderMap::new(),
            ProfilePreservationMode::Strict,
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
