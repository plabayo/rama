#[cfg(feature = "tls")]
use rama_core::extensions::NoExtensionsTransfer;

use super::*;
#[cfg(feature = "tls")]
use crate::profile::{
    analysis::{
        capture::{CaptureOrderAnalysis, CaptureOrderPath},
        order::{DerivedOrderRule, OrderAnalysisDisposition, OrderRuleEvidence},
    },
    capture::tls::{
        TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtension,
        TlsCapturedExtensionValue,
    },
};

/// Joint connection captures: an ordinary offer, a matched ECH pair, an inner without
/// its outer and an ordinary offer whose GREASE ECH differs from the pair's outer.
#[cfg(feature = "tls")]
struct EchCaptures {
    baseline: CanonicalValue,
    pair: CanonicalValue,
    unpaired: CanonicalValue,
    other_grease: CanonicalValue,
}

/// A TCP ClientHello offering `ciphers` and one ECH extension.
#[cfg(feature = "tls")]
fn ech_hello(ciphers: &[u16], value: TlsCapturedExtensionValue) -> CanonicalValue {
    TlsCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        transport: TlsCaptureTransport::Tcp,
        protocol_version: 771,
        ciphers: ciphers.into(),
        compression: vec![0].into(),
        extensions: vec![TlsCapturedExtension { id: 65037, value }].into(),
    }
    .canonical(TlsCaptureLimits::default())
    .unwrap()
}

#[cfg(feature = "tls")]
fn grease_ech(payload: u16) -> TlsCapturedExtensionValue {
    TlsCapturedExtensionValue::EchOuter {
        kdf: 1,
        aead: 1,
        enc: 32,
        payload,
    }
}

#[cfg(feature = "tls")]
fn ech_joint(slots: Vec<(CapturedSlotKind, CanonicalValue)>) -> CanonicalValue {
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Connection,
        slots: slots
            .into_iter()
            .map(|(kind, value)| CapturedSlot { kind, value })
            .collect(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
}

/// An ordinary connection offering `outer`.
#[cfg(feature = "tls")]
fn ordinary_connection(outer: CanonicalValue) -> CanonicalValue {
    ech_joint(vec![(CapturedSlotKind::TcpTls, outer)])
}

/// An accepted ECH pair sending `outer` on the wire.
#[cfg(feature = "tls")]
fn paired_connection(outer: CanonicalValue) -> CanonicalValue {
    ech_joint(vec![
        (
            CapturedSlotKind::TcpTls,
            ech_hello(&[4865], TlsCapturedExtensionValue::EchInner),
        ),
        (CapturedSlotKind::TlsOuter, outer),
    ])
}

#[cfg(feature = "tls")]
fn ech_captures() -> EchCaptures {
    let outer = ech_hello(&[4865], grease_ech(144));
    EchCaptures {
        baseline: ordinary_connection(outer.clone()),
        pair: paired_connection(outer),
        unpaired: ech_joint(vec![(
            CapturedSlotKind::TcpTls,
            ech_hello(&[4865], TlsCapturedExtensionValue::EchInner),
        )]),
        other_grease: ordinary_connection(ech_hello(&[4865], grease_ech(240))),
    }
}

#[cfg(feature = "tls")]
const ECH_REQUIRED: CapabilitySet = CapabilitySet {
    h1: true,
    h2: false,
    h3: false,
    tls_tcp: true,
    tls_quic: false,
    quic: false,
};

/// A TLS profile whose connection scopes hold `connections`, in order, beside its request scope.
#[cfg(feature = "tls")]
fn ech_database(connections: Vec<CanonicalValue>) -> UserAgentDatabase {
    ech_database_in(
        connections
            .into_iter()
            .map(|capture| (capture, ConnectionContext::default()))
            .collect(),
    )
}

/// As [`ech_database`], each connection scope observed in its own context.
#[cfg(feature = "tls")]
fn ech_database_in(connections: Vec<(CanonicalValue, ConnectionContext)>) -> UserAgentDatabase {
    ech_database_of(
        connections
            .into_iter()
            .map(|(capture, context)| (vec![capture], context))
            .collect(),
    )
}

/// As [`ech_database_in`], each connection scope holding every variant in its list.
#[cfg(feature = "tls")]
fn ech_database_of(scopes: Vec<(Vec<CanonicalValue>, ConnectionContext)>) -> UserAgentDatabase {
    [ech_profile("ech", scopes)].into_iter().collect()
}

/// The profile of [`ech_database_of`], named `client`.
#[cfg(feature = "tls")]
fn ech_profile(
    client: &str,
    scopes: Vec<(Vec<CanonicalValue>, ConnectionContext)>,
) -> UserAgentProfile {
    let mut profile = profile(client, ECH_REQUIRED, ConnectionContext::default());
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let request = analysis.scopes[1].clone();
    let count = scopes.len();
    let mut connections = scopes
        .into_iter()
        .zip(1..)
        .map(|((variants, context), tag)| {
            scope(
                tag,
                analysis.id,
                None,
                context,
                variants.into_iter().map(|capture| (capture, 1)).collect(),
            )
        })
        .collect::<Vec<_>>();
    connections.push(request);
    analysis.scopes = connections.into();
    analysis.components.tls_tcp = Some((0..count).collect());
    analysis.components.h1 = Some((0..=count).collect());
    profile
}

#[cfg(feature = "tls")]
fn ech_select(
    database: &UserAgentDatabase,
    pin: Option<ValueId>,
) -> Result<SelectedProfile, SelectionError> {
    database.select(
        &SelectionRequest {
            client: ProfileSelector::default(),
            required: ECH_REQUIRED,
            flow: flow(ConnectionContext::default(), Version::HTTP_11),
            pins: VariantPins {
                connection: pin,
                request: None,
            },
        },
        ProfileSeed([9; 32]),
        DrawKey([10; 32]),
    )
}

#[cfg(feature = "tls")]
#[test]
fn ech_pairs_are_selected_only_for_ready_endpoints_and_pins_still_win() {
    let EchCaptures {
        baseline,
        pair,
        unpaired,
        ..
    } = ech_captures();
    let database = ech_database(vec![baseline.clone(), pair.clone(), unpaired.clone()]);
    let context = ConnectionContext::default();
    let seed = ProfileSeed([9; 32]);
    let key = DrawKey([10; 32]);
    let select = |pin| ech_select(&database, pin).unwrap();
    let selected = select(None);
    for byte in 0..32 {
        let key = DrawKey([byte; 32]);
        assert_eq!(
            selected.connection(&context, seed, key).unwrap().variant,
            baseline.id
        );
        assert_eq!(
            selected
                .connection_with_ech(&context, seed, key, true)
                .unwrap()
                .variant,
            pair.id
        );
    }
    assert_eq!(
        select(Some(baseline.id))
            .connection_with_ech(&context, seed, key, true)
            .unwrap()
            .variant,
        baseline.id
    );
    // Without a ready endpoint a pinned pair is the GREASE offer its baseline shows.
    let (pinned, mode) = select(Some(pair.id))
        .connection_with_offer_mode(&context, seed, key, false)
        .unwrap();
    assert_eq!(mode, ConnectionOfferMode::Grease);
    assert_eq!(pinned.variant, pair.id);
    assert!(!pinned.ech_ready);
    assert!(matches!(
        ech_select(&database, Some(unpaired.id)),
        Err(SelectionError::IncompatiblePin(_))
    ));
}

#[cfg(feature = "tls")]
#[test]
fn paired_only_profile_is_selectable_with_and_without_ech() {
    let EchCaptures { pair, .. } = ech_captures();
    let database = ech_database(vec![pair.clone()]);
    let context = ConnectionContext::default();
    let seed = ProfileSeed([9; 32]);
    let key = DrawKey([10; 32]);
    let selected = ech_select(&database, None).unwrap();
    let connection = selected
        .connection_with_ech(&context, seed, key, true)
        .unwrap();
    assert_eq!(connection.variant, pair.id);
    assert!(connection.ech_ready);
    let (derived, mode) = selected
        .connection_with_offer_mode(&context, seed, key, false)
        .unwrap();
    assert_eq!(mode, ConnectionOfferMode::Derived);
    assert!(!derived.ech_ready);
    let mut components = derived.prepare_components().unwrap();
    components.use_ech_outer_for_replay(false).unwrap();
    assert_eq!(components.tls.unwrap().extensions[0].value, grease_ech(144));
}

#[cfg(feature = "tls")]
#[test]
fn paired_only_context_replays_its_outer_as_grease_when_the_profile_shows_that_hello() {
    let EchCaptures {
        baseline,
        pair,
        other_grease,
        ..
    } = ech_captures();
    let resumed = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let seed = ProfileSeed([9; 32]);
    let key = DrawKey([10; 32]);
    let database = ech_database_in(vec![
        (baseline, ConnectionContext::default()),
        (pair.clone(), resumed.clone()),
    ]);
    let selected = ech_select(&database, None).unwrap();
    let connection = selected.connection(&resumed, seed, key).unwrap();
    assert_eq!(connection.variant, pair.id);
    assert!(!connection.ech_ready);
    // A ready endpoint still draws the pair for real ECH.
    assert!(
        selected
            .connection_with_ech(&resumed, seed, key, true)
            .unwrap()
            .ech_ready
    );

    let database = ech_database_in(vec![
        (other_grease, ConnectionContext::default()),
        (pair, resumed.clone()),
    ]);
    let derived = ech_select(&database, None)
        .unwrap()
        .connection(&resumed, seed, key)
        .unwrap();
    let mut components = derived.prepare_components().unwrap();
    components.use_ech_outer_for_replay(false).unwrap();
    assert_eq!(components.tls.unwrap().extensions[0].value, grease_ech(240));
}

#[cfg(feature = "tls")]
#[test]
fn unpaired_inner_alone_is_never_selectable() {
    let EchCaptures { unpaired, .. } = ech_captures();
    assert!(matches!(
        ech_select(&ech_database(vec![unpaired]), None),
        Err(SelectionError::IncompatibleConnectionContext)
    ));
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

    let mut invalid_request = request(context);
    invalid_request.pins.connection = Some(ValueId([88; 32]));
    let invalid = database.select(&invalid_request, ProfileSeed([8; 32]), DrawKey([9; 32]));
    assert!(matches!(
        invalid,
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
    ProfileConnectionReuse::new(&emulation, Version::HTTP_3, &Extensions::new())
        .publish(&established);

    let input = Extensions::new();
    emulation.clone().publish(&input);
    assert!(
        established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&input)
    );

    // A connection opened with the caller's own HTTP serves only such requests.
    let preserving = Extensions::new();
    preserving.insert(
        UserAgent::new("Mozilla/5.0 Chrome/140.0.0.0").with_http_agent(HttpAgent::Preserve),
    );
    let kept = Extensions::new();
    ProfileConnectionReuse::new(&emulation, Version::HTTP_3, &preserving).publish(&kept);
    assert!(!kept.get_ref::<ConnectionReuse>().unwrap().matches(&input));
    emulation.publish(&preserving);
    assert!(
        kept.get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&preserving)
    );
    assert!(
        !established
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(&preserving)
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
    ProfileConnectionReuse::new(&pinned_context, Version::HTTP_3, &Extensions::new())
        .publish(&established);

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

#[test]
fn cleartext_selection_draws_only_profiles_with_a_cleartext_connection() {
    let context = ConnectionContext::default();
    let cleartext = CapabilitySet {
        h1: true,
        ..CapabilitySet::default()
    };
    let tls = CapabilitySet {
        tls_tcp: true,
        ..cleartext
    };
    let request = |required| SelectionRequest {
        client: ProfileSelector::default(),
        required,
        flow: flow(ConnectionContext::default(), Version::HTTP_11),
        pins: VariantPins::default(),
    };
    // Both admit HTTP/1.1, but only one captured a connection without TLS.
    let tls_only = profile("tls-only", tls, context.clone());
    let database: UserAgentDatabase = [
        tls_only.clone(),
        profile("cleartext", cleartext, context.clone()),
    ]
    .into_iter()
    .collect();
    let mut tls_draws = 0;
    for seed in 0..=u8::MAX {
        let selected = database
            .select(
                &request(cleartext),
                ProfileSeed([seed; 32]),
                DrawKey([seed; 32]),
            )
            .unwrap();
        assert_eq!(selected.profile().key.client.as_ref(), "cleartext");
        selected
            .connection(&context, ProfileSeed([seed; 32]), DrawKey([seed; 32]))
            .unwrap();
        let selected = database
            .select(&request(tls), ProfileSeed([seed; 32]), DrawKey([seed; 32]))
            .unwrap();
        tls_draws += usize::from(selected.profile().key.client.as_ref() == "tls-only");
    }
    assert_eq!(
        tls_draws, 256,
        "TLS draws keep every profile that captured TLS"
    );

    let tls_only: UserAgentDatabase = [tls_only].into_iter().collect();
    assert!(matches!(
        tls_only.select(&request(cleartext), ProfileSeed([1; 32]), DrawKey([2; 32])),
        Err(SelectionError::IncompatibleConnectionContext)
    ));
}

#[cfg(feature = "tls")]
#[test]
fn a_tunnelled_connection_does_not_inherit_the_proxy_legs_selection() {
    let EchCaptures { baseline, .. } = ech_captures();
    let selection = ech_select(&ech_database(vec![baseline]), None)
        .unwrap()
        .connection(
            &ConnectionContext::default(),
            ProfileSeed([9; 32]),
            DrawKey([10; 32]),
        )
        .unwrap();
    let proxy = Extensions::new();
    proxy.insert(selection);
    // Requests on the proxy leg read it; the origin leg is a connection of its own.
    assert!(proxy.fork().contains::<ConnectionSelection>());
    let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
    assert!(origin.get_ref::<ConnectionSelection>().is_none());
}

// The connection draw cannot redraw another profile: request headers already replay the drawn one.
#[cfg(feature = "tls")]
#[test]
fn mixed_database_draws_connect_every_profile_without_ech() {
    let EchCaptures { pair, .. } = ech_captures();
    let database: UserAgentDatabase = [
        ech_profile(
            "pair-only",
            vec![(vec![pair], ConnectionContext::default())],
        ),
        profile("ordinary", ECH_REQUIRED, ConnectionContext::default()),
    ]
    .into_iter()
    .collect();
    let context = ConnectionContext::default();
    let mut pair_only = 0;
    for byte in 0..=u8::MAX {
        let (seed, key) = (ProfileSeed([byte; 32]), DrawKey([byte; 32]));
        let selected = database
            .select(
                &SelectionRequest {
                    client: ProfileSelector::default(),
                    required: ECH_REQUIRED,
                    flow: flow(context.clone(), Version::HTTP_11),
                    pins: VariantPins::default(),
                },
                seed,
                key,
            )
            .unwrap();
        let paired = selected.profile().key.client.as_ref() == "pair-only";
        pair_only += usize::from(paired);
        // An ECH-ready target draws every profile.
        selected
            .connection_with_ech(&context, seed, key, true)
            .unwrap();
        let without_ech = selected.connection(&context, seed, key).unwrap();
        assert!(!without_ech.ech_ready);
        let mut components = without_ech.prepare_components().unwrap();
        components.use_ech_outer_for_replay(false).unwrap();
        if paired {
            assert_eq!(components.tls.unwrap().extensions[0].value, grease_ech(144));
        }
    }
    assert!(pair_only > 0 && pair_only < 256, "{pair_only}");
}

#[cfg(feature = "tls")]
#[test]
fn grease_evidence_compares_whole_offers_with_their_grease_slots() {
    let paired_only = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let draw = |ordinary: CanonicalValue, outer: CanonicalValue| {
        ech_select(
            &ech_database_in(vec![
                (ordinary, ConnectionContext::default()),
                (paired_connection(outer), paired_only.clone()),
            ]),
            None,
        )
        .unwrap()
        .connection(&paired_only, ProfileSeed([9; 32]), DrawKey([10; 32]))
    };
    // An unmatched outer keeps its cipher slots while using ordinary ECH evidence.
    let ordinary = ordinary_connection(ech_hello(&[4865], grease_ech(144)));
    let derived = draw(ordinary, ech_hello(&[0x0a0a, 4865], grease_ech(144))).unwrap();
    let mut components = derived.prepare_components().unwrap();
    components.use_ech_outer_for_replay(false).unwrap();
    assert_eq!(&*components.tls.unwrap().ciphers, &[0x0a0a, 4865]);
    // A GREASE slot is compared as a numbered slot, whichever GREASE value was drawn.
    let ordinary = ordinary_connection(ech_hello(&[0x2a2a, 4865], grease_ech(144)));
    draw(ordinary, ech_hello(&[0x0a0a, 4865], grease_ech(144))).unwrap();
}

#[cfg(feature = "tls")]
#[test]
fn grease_eligibility_is_decided_per_variant_before_pinning_and_drawing() {
    let paired_only = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let shown = paired_connection(ech_hello(&[4865], grease_ech(144)));
    let unshown = paired_connection(ech_hello(&[4865], grease_ech(272)));
    let database = ech_database_of(vec![
        (
            vec![ordinary_connection(ech_hello(&[4865], grease_ech(144)))],
            ConnectionContext::default(),
        ),
        (vec![shown.clone(), unshown.clone()], paired_only.clone()),
    ]);
    let seed = ProfileSeed([9; 32]);
    for byte in 0..32 {
        let connection = ech_select(&database, None)
            .unwrap()
            .connection(&paired_only, seed, DrawKey([byte; 32]))
            .unwrap();
        assert_eq!(connection.variant, shown.id);
    }
    let pinned = |pin| {
        ech_select(&database, Some(pin))
            .unwrap()
            .connection(&paired_only, seed, DrawKey([10; 32]))
    };
    assert_eq!(pinned(shown.id).unwrap().variant, shown.id);
    let derived = pinned(unshown.id).unwrap();
    assert_eq!(derived.variant, unshown.id);
    let mut components = derived.prepare_components().unwrap();
    components.use_ech_outer_for_replay(false).unwrap();
    assert_eq!(components.tls.unwrap().extensions[0].value, grease_ech(144));
}

#[cfg(feature = "tls")]
#[test]
fn readiness_preferences_change_weights_without_excluding_profiles() {
    let captures = ech_captures();
    let database: UserAgentDatabase = [
        ech_profile(
            "paired",
            vec![(vec![captures.pair], ConnectionContext::default())],
        ),
        ech_profile(
            "ordinary",
            vec![(vec![captures.baseline], ConnectionContext::default())],
        ),
    ]
    .into_iter()
    .collect();
    let draws = |readiness| {
        let mut paired = 0;
        for byte in 0..=u8::MAX {
            let selected = database
                .select(
                    &SelectionRequest {
                        client: ProfileSelector {
                            ech_ready: readiness,
                            ..ProfileSelector::default()
                        },
                        required: ECH_REQUIRED,
                        flow: flow(ConnectionContext::default(), Version::HTTP_11),
                        pins: VariantPins::default(),
                    },
                    ProfileSeed([byte; 32]),
                    DrawKey([byte; 32]),
                )
                .unwrap();
            paired += usize::from(selected.profile().key.client.as_ref() == "paired");
            selected
                .connection(
                    &ConnectionContext::default(),
                    ProfileSeed([byte; 32]),
                    DrawKey([byte; 32]),
                )
                .unwrap();
        }
        assert!(paired > 0 && paired < 256);
        paired
    };
    let ordinary = draws(Some(false));
    let unchanged = draws(None);
    let paired = draws(Some(true));
    assert!(
        ordinary < unchanged && unchanged < paired,
        "{ordinary} {unchanged} {paired}"
    );
}

#[cfg(feature = "tls")]
#[test]
fn derived_ech_uses_own_evidence_before_the_nearest_family_version() {
    let captures = ech_captures();
    let profile_at = |version: &str, captures: Vec<CanonicalValue>| {
        let mut profile = ech_profile("family", vec![(captures, ConnectionContext::default())]);
        profile.key.version = Some(version.into());
        profile.key.user_agent = Some(version.into());
        let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
        analysis.key = profile.key.clone();
        analysis.id = profile.key.canonical(MAXIMUM_IDENTITY_BYTES).unwrap().id;
        profile
    };
    let database: UserAgentDatabase = [
        profile_at(
            "9",
            vec![ordinary_connection(ech_hello(&[4865], grease_ech(320)))],
        ),
        profile_at(
            "13",
            vec![ordinary_connection(ech_hello(&[4865], grease_ech(400)))],
        ),
        profile_at("10", vec![captures.pair.clone()]),
        profile_at("12", vec![captures.pair.clone(), captures.other_grease]),
    ]
    .into_iter()
    .collect();
    for (version, expected) in [("10", grease_ech(320)), ("12", grease_ech(240))] {
        let selected = database
            .select(
                &SelectionRequest {
                    client: ProfileSelector {
                        user_agent: Some(version.into()),
                        ..ProfileSelector::default()
                    },
                    required: ECH_REQUIRED,
                    flow: flow(ConnectionContext::default(), Version::HTTP_11),
                    pins: VariantPins {
                        connection: Some(captures.pair.id),
                        request: None,
                    },
                },
                ProfileSeed([9; 32]),
                DrawKey([10; 32]),
            )
            .unwrap();
        let connection = selected
            .connection(
                &ConnectionContext::default(),
                ProfileSeed([9; 32]),
                DrawKey([10; 32]),
            )
            .unwrap();
        let mut components = connection.prepare_components().unwrap();
        components.use_ech_outer_for_replay(false).unwrap();
        assert_eq!(components.tls.unwrap().extensions[0].value, expected);
    }
}

#[cfg(feature = "tls")]
#[test]
fn pins_filter_profiles_before_readiness_weighting() {
    let captures = ech_captures();
    let database: UserAgentDatabase = [
        ech_profile(
            "paired",
            vec![(vec![captures.pair], ConnectionContext::default())],
        ),
        ech_profile(
            "ordinary",
            vec![(
                vec![captures.baseline.clone()],
                ConnectionContext::default(),
            )],
        ),
    ]
    .into_iter()
    .collect();
    for byte in 0..64 {
        for readiness in [None, Some(false), Some(true)] {
            let selected = database
                .select(
                    &SelectionRequest {
                        client: ProfileSelector {
                            ech_ready: readiness,
                            ..ProfileSelector::default()
                        },
                        required: ECH_REQUIRED,
                        flow: flow(ConnectionContext::default(), Version::HTTP_11),
                        pins: VariantPins {
                            connection: Some(captures.baseline.id),
                            request: None,
                        },
                    },
                    ProfileSeed([byte; 32]),
                    DrawKey([byte; 32]),
                )
                .unwrap();
            assert_eq!(selected.profile().key.client.as_ref(), "ordinary");
            assert_eq!(
                selected
                    .connection(
                        &ConnectionContext::default(),
                        ProfileSeed([byte; 32]),
                        DrawKey([byte; 32])
                    )
                    .unwrap()
                    .variant,
                captures.baseline.id
            );
        }
    }
}

#[cfg(feature = "tls")]
#[test]
fn derived_offer_preserves_observed_ech_absence_in_another_context() {
    let captures = ech_captures();
    let mut ordinary = TlsCapture::from_canonical(
        &ech_hello(&[4865], grease_ech(144)),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    ordinary.extensions = Box::default();
    let other_context = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let database = ech_database_in(vec![
        (captures.pair.clone(), ConnectionContext::default()),
        (
            ordinary_connection(ordinary.canonical(TlsCaptureLimits::default()).unwrap()),
            other_context,
        ),
    ]);
    let connection = ech_select(&database, Some(captures.pair.id))
        .unwrap()
        .connection(
            &ConnectionContext::default(),
            ProfileSeed([9; 32]),
            DrawKey([10; 32]),
        )
        .unwrap();
    let mut components = connection.prepare_components().unwrap();
    components.use_ech_outer_for_replay(false).unwrap();
    assert!(
        components
            .tls
            .unwrap()
            .extensions
            .iter()
            .all(|extension| extension.id != 65037)
    );
}

#[test]
fn a_request_pin_restricts_the_connection_draw_to_compatible_scopes() {
    let token = ConnectionContext {
        token_present: Some(true),
        ..ConnectionContext::default()
    };
    let mut profile = profile("client", h3_capabilities(), token);
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    let mut scopes = analysis.scopes.to_vec();
    scopes.push(scope(
        3,
        analysis.id,
        None,
        ConnectionContext {
            token_present: Some(false),
            ..ConnectionContext::default()
        },
        vec![(connection_variant(3), 1)],
    ));
    analysis.scopes = scopes.into();
    analysis.components.quic = Some(vec![0, 2].into());
    analysis.components.tls_quic = Some(vec![0, 2].into());
    analysis.components.h3 = Some(vec![0, 1, 2].into());
    let database: UserAgentDatabase = [profile].into_iter().collect();
    let mut input = request(ConnectionContext::default());
    input.pins.request = Some(request_variant().id);
    for byte in 0..64 {
        let seed = ProfileSeed([byte; 32]);
        let key = DrawKey([byte; 32]);
        let selected = database.select(&input, seed, key).unwrap();
        let connection = selected
            .connection(&ConnectionContext::default(), seed, key)
            .unwrap();
        let request = selected
            .request(&connection, &input.flow, &HeaderMap::new(), seed, key)
            .unwrap();
        assert_eq!(request.variant, request_variant().id);
        assert_eq!(
            connection.effective.context.connection.token_present,
            Some(true)
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn request_pins_keep_readiness_weighting_among_compatible_profiles() {
    let captures = ech_captures();
    let database: UserAgentDatabase = [
        ech_profile(
            "paired",
            vec![(vec![captures.pair], ConnectionContext::default())],
        ),
        ech_profile(
            "ordinary",
            vec![(vec![captures.baseline], ConnectionContext::default())],
        ),
    ]
    .into_iter()
    .collect();
    let draws = |readiness| {
        (0..=u8::MAX)
            .filter(|byte| {
                let selected = database
                    .select(
                        &SelectionRequest {
                            client: ProfileSelector {
                                ech_ready: readiness,
                                ..ProfileSelector::default()
                            },
                            required: ECH_REQUIRED,
                            flow: flow(ConnectionContext::default(), Version::HTTP_11),
                            pins: VariantPins {
                                connection: None,
                                request: Some(request_variant().id),
                            },
                        },
                        ProfileSeed([*byte; 32]),
                        DrawKey([*byte; 32]),
                    )
                    .unwrap();
                selected.profile().key.client.as_ref() == "paired"
            })
            .count()
    };
    assert!(draws(Some(false)) < draws(None));
    assert!(draws(None) < draws(Some(true)));
}

#[cfg(feature = "tls")]
#[test]
fn derived_connection_draw_keeps_the_matching_ordinary_extension_rule() {
    let mut baseline = TlsCapture::from_canonical(
        &ech_hello(&[4865], grease_ech(144)),
        TlsCaptureLimits::default(),
    )
    .unwrap();
    let mut extensions = vec![
        TlsCapturedExtension {
            id: 1000,
            value: TlsCapturedExtensionValue::Literal(Box::new([])),
        },
        TlsCapturedExtension {
            id: 2000,
            value: TlsCapturedExtensionValue::Literal(Box::new([])),
        },
        TlsCapturedExtension {
            id: 3000,
            value: TlsCapturedExtensionValue::Literal(Box::new([])),
        },
    ];
    extensions.extend(baseline.extensions);
    baseline.extensions = extensions.into();
    let mut outer = baseline.clone();
    outer.extensions[..3].rotate_left(1);
    let pair = paired_connection(outer.canonical(TlsCaptureLimits::default()).unwrap());
    let mut profile = ech_profile(
        "client",
        vec![
            (
                vec![ordinary_connection(
                    baseline.canonical(TlsCaptureLimits::default()).unwrap(),
                )],
                ConnectionContext::default(),
            ),
            (vec![pair.clone()], ConnectionContext::default()),
        ],
    );
    let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
    analysis.scopes[1].observations.orders = vec![CaptureOrderAnalysis {
        path: CaptureOrderPath::TlsExtensions,
        dictionary: Box::new([]),
        variants: Box::new([]),
        missing_samples: Box::new([]),
        evidence: OrderRuleEvidence {
            normalized_distinct_orders: 32,
            positions: Box::new([]),
            disposition: OrderAnalysisDisposition::DerivedHeuristic,
            derived: Some(DerivedOrderRule::Shuffled {
                elements: Box::new([]),
                pinned: Box::new([]),
            }),
        },
    }]
    .into();
    let database: UserAgentDatabase = [profile].into_iter().collect();
    let selected = ech_select(&database, Some(pair.id)).unwrap();
    for byte in 0..32 {
        let (selection, mode) = selected
            .connection_with_offer_mode(
                &ConnectionContext::default(),
                ProfileSeed([byte; 32]),
                DrawKey([byte; 32]),
                false,
            )
            .unwrap();
        assert_eq!(mode, ConnectionOfferMode::Derived);
        let mut components = selection.prepare_components().unwrap();
        components.use_ech_outer_for_replay(false).unwrap();
        assert!(
            components
                .tls
                .unwrap()
                .extensions
                .iter()
                .map(|extension| extension.id)
                .eq(baseline.extensions.iter().map(|extension| extension.id))
        );
    }
}
