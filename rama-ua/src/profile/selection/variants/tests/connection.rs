use super::*;

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
    let emulation = selected.clone().emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    );
    let established = Extensions::new();
    ProfileConnectionReuse::new(&emulation, Version::HTTP_3).publish(&established);

    let input = Extensions::new();
    emulation.publish(&input);
    assert!(
        established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut incompatible = (*selected).clone();
    incompatible.pins.connection = Some(ValueId([99; 32]));
    let input = Extensions::new();
    Arc::new(incompatible)
        .emulation_context(ProfileSeed([31; 32]), DrawKey([34; 32]), DrawKey([35; 32]))
        .publish(&input);
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut other_profile = (*selected).clone();
    other_profile.id = ValueId([77; 32]);
    let input = Extensions::new();
    Arc::new(other_profile)
        .emulation_context(ProfileSeed([31; 32]), DrawKey([34; 32]), DrawKey([35; 32]))
        .publish(&input);
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut pinned = (*selected).clone();
    pinned.pins.connection = Some(ticket.variant);
    let pinned = Arc::new(pinned);
    let pinned_context = pinned.clone().emulation_context(
        ProfileSeed([31; 32]),
        DrawKey([34; 32]),
        DrawKey([35; 32]),
    );
    let established = Extensions::new();
    ProfileConnectionReuse::new(&pinned_context, Version::HTTP_3).publish(&established);

    let input = Extensions::new();
    pinned_context.publish(&input);
    assert!(
        established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    let mut different_pin = (*pinned).clone();
    different_pin.pins.connection = Some(ValueId([55; 32]));
    let input = Extensions::new();
    Arc::new(different_pin)
        .emulation_context(ProfileSeed([31; 32]), DrawKey([34; 32]), DrawKey([35; 32]))
        .publish(&input);
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );
}
