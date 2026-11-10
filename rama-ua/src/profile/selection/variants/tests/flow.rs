use super::*;

type Fetch = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

const NAVIGATE_TYPED: Fetch = ("navigate", "none", "document", Some("?1"));
const NAVIGATE_LINK: Fetch = ("navigate", "same-origin", "document", Some("?1"));
const STYLE: Fetch = ("no-cors", "same-origin", "style", None);
const FETCH_API: Fetch = ("cors", "same-origin", "empty", None);
const WEBSOCKET: Fetch = ("websocket", "same-origin", "websocket", None);

fn http_flow(method: Method, initiator: Option<RequestInitiator>, fetch: Option<Fetch>) -> FlowKey {
    FlowKey::Http {
        version: Version::HTTP_3,
        method,
        initiator,
        fetch: fetch.map(|(mode, site, destination, user_activation)| FetchContext {
            mode: Some(mode.into()),
            site: Some(site.into()),
            destination: Some(destination.into()),
            user_activation: user_activation.map(Into::into),
        }),
        connection: ConnectionContext::default(),
    }
}

/// Request scopes captured for `flows`, tagged `10 + index`.
fn profile_with_flows(client: &str, flows: &[FlowKey]) -> UserAgentProfile {
    let context = ConnectionContext::default();
    let mut captured = profile(client, h3_capabilities(), context.clone());
    let analysis = Arc::make_mut(captured.captured.as_mut().unwrap());
    let mut scopes = vec![analysis.scopes[0].clone()];
    for (index, flow) in flows.iter().enumerate() {
        let canonical = flow.canonical(MAXIMUM_IDENTITY_BYTES).unwrap();
        let mut request = scope(
            10 + u8::try_from(index).unwrap(),
            analysis.id,
            Some(canonical.id),
            context.clone(),
            vec![(request_variant(), 4)],
        );
        request.flow = Some(flow.clone());
        scopes.push(request);
    }
    let indexes = Some((0..scopes.len()).collect::<Box<[usize]>>());
    analysis.components.h3 = indexes.clone();
    analysis.components.tls_quic = indexes.clone();
    analysis.components.quic = indexes;
    analysis.scopes = scopes.into();
    captured
}

fn scope_tag(index: u8) -> ValueId {
    ValueId([10 + index; 32])
}

/// The profile client, request scope and flow match replayed for `flow`.
fn replay(
    database: &UserAgentDatabase,
    flow: &FlowKey,
    key: u8,
) -> Result<(Box<str>, ValueId, FlowMatch), SelectionError> {
    let context = ConnectionContext::default();
    let selected = database.select(
        &SelectionRequest {
            flow: flow.clone(),
            ..request(context.clone())
        },
        ProfileSeed([key; 32]),
        DrawKey([key; 32]),
    )?;
    let connection = selected.connection(&context, ProfileSeed([key; 32]), DrawKey([key; 32]))?;
    let request = selected.request(
        &connection,
        flow,
        &HeaderMap::new(),
        ProfileSeed([key; 32]),
        DrawKey([key.wrapping_add(1); 32]),
    )?;
    Ok((
        selected.profile().key.client.clone(),
        request.effective.scope,
        request.effective.flow_match,
    ))
}

#[test]
fn request_without_initiator_replays_any_capture_with_its_fetch_metadata() {
    let database: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[
            http_flow(
                Method::GET,
                Some(RequestInitiator::Navigate),
                Some(NAVIGATE_TYPED),
            ),
            http_flow(
                Method::GET,
                Some(RequestInitiator::Form),
                Some(NAVIGATE_LINK),
            ),
            http_flow(Method::POST, Some(RequestInitiator::Xhr), Some(FETCH_API)),
        ],
    )]
    .into_iter()
    .collect();
    for (flow, expected, flow_match) in [
        (
            http_flow(Method::GET, None, Some(NAVIGATE_LINK)),
            scope_tag(1),
            FlowMatch::Exact,
        ),
        (
            http_flow(Method::GET, None, Some(NAVIGATE_TYPED)),
            scope_tag(0),
            FlowMatch::Exact,
        ),
        (
            http_flow(Method::POST, None, Some(FETCH_API)),
            scope_tag(2),
            FlowMatch::Exact,
        ),
        // A link click the caller names still differs from a form submission.
        (
            http_flow(
                Method::GET,
                Some(RequestInitiator::Navigate),
                Some(NAVIGATE_LINK),
            ),
            scope_tag(1),
            FlowMatch::Nearest {
                other_destination: false,
                other_method: false,
            },
        ),
    ] {
        for key in 0..16 {
            assert_eq!(
                replay(&database, &flow, key).unwrap(),
                ("browser".into(), expected, flow_match),
                "{flow:?}"
            );
        }
    }
}

#[test]
fn request_without_context_replays_a_top_level_navigation() {
    let database: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[
            http_flow(
                Method::GET,
                Some(RequestInitiator::Navigate),
                Some(NAVIGATE_TYPED),
            ),
            http_flow(Method::GET, None, Some(STYLE)),
            http_flow(
                Method::GET,
                None,
                Some(("navigate", "same-origin", "iframe", None)),
            ),
        ],
    )]
    .into_iter()
    .collect();
    for key in 0..16 {
        let (_, scope, flow_match) =
            replay(&database, &http_flow(Method::GET, None, None), key).unwrap();
        assert_eq!(scope, scope_tag(0));
        assert_eq!(flow_match, FlowMatch::Exact);
    }
}

#[test]
fn uncaptured_flows_replay_the_closest_capture() {
    let database: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[
            http_flow(
                Method::GET,
                Some(RequestInitiator::Navigate),
                Some(NAVIGATE_TYPED),
            ),
            http_flow(Method::POST, Some(RequestInitiator::Fetch), Some(FETCH_API)),
            http_flow(Method::GET, Some(RequestInitiator::Ws), Some(WEBSOCKET)),
        ],
    )]
    .into_iter()
    .collect();
    for (flow, expected, flow_match) in [
        (
            http_flow(Method::GET, None, Some(STYLE)),
            scope_tag(0),
            FlowMatch::Nearest {
                other_destination: true,
                other_method: false,
            },
        ),
        (
            http_flow(Method::PUT, None, Some(FETCH_API)),
            scope_tag(1),
            FlowMatch::Nearest {
                other_destination: false,
                other_method: true,
            },
        ),
        (
            http_flow(Method::POST, None, None),
            scope_tag(1),
            FlowMatch::Nearest {
                other_destination: false,
                other_method: false,
            },
        ),
    ] {
        for key in 0..8 {
            assert_eq!(
                replay(&database, &flow, key).unwrap(),
                ("browser".into(), expected, flow_match),
                "{flow:?}"
            );
        }
    }
}

#[test]
fn tunnels_and_websockets_never_stand_in_for_other_requests() {
    let websocket_only: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[
            http_flow(Method::GET, Some(RequestInitiator::Ws), None),
            http_flow(Method::CONNECT, Some(RequestInitiator::Ws), Some(WEBSOCKET)),
        ],
    )]
    .into_iter()
    .collect();
    for flow in [
        http_flow(Method::GET, None, None),
        http_flow(Method::GET, None, Some(NAVIGATE_TYPED)),
        http_flow(Method::CONNECT, None, None),
    ] {
        assert!(
            matches!(
                replay(&websocket_only, &flow, 1),
                Err(SelectionError::MissingFlow)
            ),
            "{flow:?}"
        );
    }
    let navigation_only: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[http_flow(
            Method::GET,
            Some(RequestInitiator::Navigate),
            Some(NAVIGATE_TYPED),
        )],
    )]
    .into_iter()
    .collect();
    for flow in [
        http_flow(Method::GET, Some(RequestInitiator::Ws), None),
        http_flow(Method::GET, None, Some(WEBSOCKET)),
        http_flow(Method::CONNECT, Some(RequestInitiator::Ws), None),
    ] {
        assert!(
            matches!(
                replay(&navigation_only, &flow, 1),
                Err(SelectionError::MissingFlow)
            ),
            "{flow:?}"
        );
    }
}

#[test]
fn profiles_that_captured_the_flow_win_over_nearest_matches() {
    let database: UserAgentDatabase = [
        profile_with_flows(
            "nearest",
            &[http_flow(
                Method::GET,
                Some(RequestInitiator::Navigate),
                Some(NAVIGATE_TYPED),
            )],
        ),
        profile_with_flows(
            "exact",
            &[
                http_flow(
                    Method::GET,
                    Some(RequestInitiator::Navigate),
                    Some(NAVIGATE_TYPED),
                ),
                http_flow(Method::GET, None, Some(STYLE)),
            ],
        ),
    ]
    .into_iter()
    .collect();
    for key in 0..16 {
        let (client, scope, flow_match) =
            replay(&database, &http_flow(Method::GET, None, Some(STYLE)), key).unwrap();
        assert_eq!(client.as_ref(), "exact");
        assert_eq!(scope, scope_tag(1));
        assert_eq!(flow_match, FlowMatch::Exact);
    }
}

#[test]
fn closest_capture_follows_the_documented_field_order() {
    const IMAGE: Fetch = ("no-cors", "same-origin", "image", None);
    let fetch = |method, fetch| http_flow(method, Some(RequestInitiator::Fetch), Some(fetch));
    let requested = fetch(Method::GET, IMAGE);
    // Each differs from the request in one field, from least to most significant.
    let ranked = [
        http_flow(Method::GET, Some(RequestInitiator::Xhr), Some(IMAGE)),
        fetch(Method::GET, ("no-cors", "cross-site", "image", None)),
        fetch(Method::GET, ("no-cors", "same-origin", "image", Some("?1"))),
        fetch(Method::POST, IMAGE),
        fetch(Method::GET, STYLE),
        fetch(Method::GET, ("cors", "same-origin", "image", None)),
    ];
    for closest in 0..ranked.len() {
        let database: UserAgentDatabase = [profile_with_flows("browser", &ranked[closest..])]
            .into_iter()
            .collect();
        for key in 0..4 {
            let (_, scope, flow_match) = replay(&database, &requested, key).unwrap();
            assert_eq!(scope, scope_tag(0), "closest is field {closest}");
            assert_eq!(
                flow_match,
                FlowMatch::Nearest {
                    other_destination: closest >= 4,
                    other_method: closest == 3,
                },
                "closest is field {closest}"
            );
        }
    }

    // Any number of less significant differences beat a more significant one.
    let database: UserAgentDatabase = [profile_with_flows(
        "browser",
        &[
            fetch(Method::POST, IMAGE),
            http_flow(
                Method::GET,
                Some(RequestInitiator::Xhr),
                Some(("no-cors", "cross-site", "image", Some("?1"))),
            ),
        ],
    )]
    .into_iter()
    .collect();
    for key in 0..4 {
        let (_, scope, _) = replay(&database, &requested, key).unwrap();
        assert_eq!(scope, scope_tag(1));
    }
}
