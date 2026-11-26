use std::ptr;

use rama_http::{
    HeaderMap, HeaderValue, header,
    headers::{HeaderDecode as _, SecWebSocketKey},
    proto::{ext, h2::PseudoHeaderOrder},
};

use super::{
    parity::{
        embedded, embedded_database, emulate, emulate_alternative, emulate_negotiated,
        emulate_seeded,
    },
    *,
};
use crate::profile::{
    analysis::capture::VariantValue,
    model::identity::{FlowKey, ResumptionContext},
    selection::{
        capabilities::CapabilitySet,
        variants::{ProfileSelector, RequestSelection, SelectionRequest, VariantPins},
    },
};
use crate::{PlatformKind, UserAgentKind, layer::emulate::SelectedUserAgentProfile};

#[tokio::test]
async fn embedded_h3_emulation_prepares_quic_and_h3_components() {
    let database = Arc::new(UserAgentDatabase::try_embedded().unwrap());
    let connector = service_fn(|input: ConnectRequest| async move {
        let prepared = input
            .extensions()
            .get_ref::<PreparedConnectionComponents>()
            .unwrap();
        assert!(prepared.quic_parameters.is_some());
        assert!(prepared.h3_peer_settings.is_some());
        assert!(prepared.tls.is_some());
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_3));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let connector = ProfileEmulateHttpConnectModifier::new(connector);
    let inner = service_fn(move |req: Request<()>| {
        let connector = connector.clone();
        async move {
            let context = EmulationContext::of(req.extensions()).unwrap().clone();
            let captured = context.selected.profile().captured.clone().unwrap();
            assert!(captured.components.h3.is_some());
            assert!(captured.components.quic.is_some());
            let input = ConnectRequest::new("example.com:443".parse().unwrap())
                .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            context.publish(input.extensions());
            connector.serve(input).await.unwrap();
            Ok::<_, Infallible>(())
        }
    });
    let service = ProfileEmulateLayer::new(database)
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(inner);
    // The embedded H3 captures are form submissions.
    let request = Request::builder()
        .uri("https://example.com/")
        .version(Version::HTTP_3)
        .extension(RequestInitiator::Form)
        .body(())
        .unwrap();
    service.serve(request).await.unwrap();
}

#[tokio::test]
async fn optional_emulation_connects_natively_when_preparation_fails() {
    for optional in [true, false] {
        let connector = ProfileEmulateHttpConnectModifier::new(service_fn(
            |input: ConnectRequest| async move {
                assert!(
                    input
                        .extensions()
                        .get_ref::<PreparedConnectionComponents>()
                        .is_none()
                );
                let conn = ServiceInput::new(());
                conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
                Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
            },
        ));
        let inner = service_fn(move |req: Request<()>| {
            let connector = connector.clone();
            async move {
                let input = ConnectRequest::new("example.com:443".parse().unwrap())
                    .with_application_protocol(Protocol::HTTPS);
                EmulationContext::of(req.extensions())
                    .unwrap()
                    .clone()
                    .publish(input.extensions());
                req.extensions()
                    .clone_to_if_absent::<OptionalEmulation>(input.extensions());
                // No embedded connection was captured as a resumption.
                input.extensions().insert(ConnectionContext {
                    resumption: ResumptionContext::Resumed,
                    ..ConnectionContext::default()
                });
                Ok::<_, Infallible>(connector.serve(input).await)
            }
        });
        let connected = embedded()
            .with_is_optional(optional)
            .into_layer(inner)
            .serve(
                Request::builder()
                    .uri("https://example.com/")
                    .version(Version::HTTP_2)
                    .extension(TargetHttpVersion(Version::HTTP_2))
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        if !optional {
            assert_eq!(
                connected.unwrap_err().kind(),
                ConnectionErrorKind::InvalidInput
            );
            continue;
        }
        let established = connected.unwrap();
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .differences
                .contains(&ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::UnemulatedConnection,
                })
        );
        assert!(
            established
                .conn
                .extensions()
                .get_ref::<ConnectionSelection>()
                .is_none()
        );
    }
}

fn caller_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("origin.example"));
    headers.insert(header::USER_AGENT, HeaderValue::from_static("caller/1"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(header::COOKIE, HeaderValue::from_static("a=1; b=2"));
    headers
}

/// Request draws over every captured HTTP version, as emulation makes them.
fn embedded_request_draws(seeds: u8) -> Vec<RequestSelection> {
    request_draws(&embedded_database(), seeds)
}

/// The embedded profiles with every capture rebuilt into canonical form, as
/// archives and the fingerprint database provide them.
fn canonical_profiles() -> UserAgentDatabase {
    embedded_database()
        .iter()
        .cloned()
        .map(|mut profile| {
            let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
            for scope in analysis.scopes.iter_mut() {
                for variant in scope.observations.variants.iter_mut() {
                    variant.value =
                        VariantValue::Canonical(variant.value.canonical().unwrap().into_owned());
                }
            }
            profile
        })
        .collect()
}

fn request_draws(database: &UserAgentDatabase, seeds: u8) -> Vec<RequestSelection> {
    let headers = caller_headers();
    let mut draws = Vec::new();
    for (version, required, initiator) in [
        (
            Version::HTTP_11,
            CapabilitySet {
                h1: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        (
            Version::HTTP_2,
            CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        (
            Version::HTTP_3,
            CapabilitySet {
                h3: true,
                tls_quic: true,
                quic: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Form,
        ),
    ] {
        let flow = FlowKey::Http {
            version,
            method: Method::GET,
            initiator: Some(initiator),
            fetch: None,
            connection: ConnectionContext::default(),
        };
        for seed in 0..seeds {
            let (seed, key) = (ProfileSeed([seed; 32]), DrawKey([seed; 32]));
            let selected = database
                .select(
                    &SelectionRequest {
                        client: ProfileSelector::default(),
                        required,
                        flow: flow.clone(),
                        pins: VariantPins::default(),
                    },
                    seed,
                    key,
                )
                .unwrap();
            let connection = selected
                .connection(&ConnectionContext::default(), seed, key)
                .unwrap();
            draws.push(
                selected
                    .request(&connection, &flow, &headers, seed, key)
                    .unwrap(),
            );
        }
    }
    draws
}

#[test]
fn compact_profiles_draw_and_replay_exactly_what_canonical_profiles_do() {
    let headers = caller_headers();
    let compact = embedded_request_draws(32);
    let canonical = request_draws(&canonical_profiles(), 32);
    assert!(compact.len() >= 96);
    assert_eq!(compact.len(), canonical.len());
    for (compact, canonical) in compact.iter().zip(&canonical) {
        assert!(matches!(
            compact.effective.capture,
            VariantValue::Compact(_)
        ));
        assert!(matches!(
            canonical.effective.capture,
            VariantValue::Canonical(_)
        ));
        assert_eq!(
            (compact.profile, compact.connection_variant, compact.variant),
            (
                canonical.profile,
                canonical.connection_variant,
                canonical.variant
            )
        );
        assert_eq!(
            format!("{:?}", compact.replay_request(&headers)),
            format!("{:?}", canonical.replay_request(&headers)),
            "{:?}",
            compact.effective.flow
        );
        // Without a cached plan, replay decodes the canonical capture itself.
        let mut decoded = canonical.clone();
        decoded.effective.plan = None;
        assert_eq!(
            format!("{:?}", compact.replay_request(&headers)),
            format!("{:?}", decoded.replay_request(&headers)),
        );
    }
}

#[test]
fn compact_profiles_record_the_request_headers_canonical_profiles_do() {
    let canonical = canonical_profiles();
    for (compact, canonical) in embedded_database().iter().zip(canonical.iter()) {
        assert_eq!(compact.ua_str(), canonical.ua_str());
        assert_eq!(
            format!("{:?}", compact.recorded_request_headers()),
            format!("{:?}", canonical.recorded_request_headers())
        );
    }
}

#[test]
fn a_variant_drawn_again_shares_its_plan_and_equal_values_share_a_buffer() {
    let first = embedded_request_draws(8);
    let again = embedded_request_draws(8);
    for (first, again) in first.iter().zip(&again) {
        let (first, first_fields) = first.effective.plan.as_ref().unwrap().resolve().unwrap();
        let (again, again_fields) = again.effective.plan.as_ref().unwrap().resolve().unwrap();
        assert!(ptr::eq(first, again));
        assert!(ptr::eq(first_fields, again_fields));
    }
    // Variants of one profile replay the same User-Agent from one interned buffer.
    let headers = caller_headers();
    let user_agent = |draw: &RequestSelection| {
        draw.replay_request(&headers).unwrap().headers.unwrap()[header::USER_AGENT].clone()
    };
    let draws = embedded_request_draws(32);
    let shared = draws.iter().enumerate().any(|(index, draw)| {
        draws[index + 1..].iter().any(|other| {
            other.profile == draw.profile
                && other.variant != draw.variant
                && user_agent(other).as_bytes().as_ptr() == user_agent(draw).as_bytes().as_ptr()
        })
    });
    assert!(
        shared,
        "two variants of a profile share the interned User-Agent"
    );
}

#[test]
fn replacing_the_capture_replays_it_instead_of_the_cached_plan() {
    let headers = caller_headers();
    let draws = embedded_request_draws(16);
    let replay = |selection: &RequestSelection| format!("{:?}", selection.replay_request(&headers));
    // Replay also uses each draw's network hints; share them so only the capture differs.
    let with_hints_of = |selection: &RequestSelection, hints: &RequestSelection| {
        let mut selection = selection.clone();
        selection.effective.network_hints = hints.effective.network_hints.clone();
        selection
    };
    let (first, other) = draws
        .iter()
        .enumerate()
        .find_map(|(index, first)| {
            draws[index + 1..]
                .iter()
                .find(|other| {
                    format!("{:?}", other.effective.flow) == format!("{:?}", first.effective.flow)
                        && replay(other) != replay(&with_hints_of(first, other))
                })
                .map(|other| (with_hints_of(first, other), other))
        })
        .unwrap();
    assert!(first.effective.plan.is_some());
    let mut swapped = first;
    swapped
        .effective
        .set_capture(other.effective.capture().clone());
    assert!(swapped.effective.plan.is_none());
    assert_eq!(replay(&swapped), replay(other));
}

#[test]
fn replay_into_a_full_header_map_errors_instead_of_panicking() {
    let selection = embedded_request_draws(1).remove(0);
    let mut headers = HeaderMap::new();
    // Distinct caller fields up to the map's capacity leave no room for the capture's fields.
    for index in 0.. {
        let name = HeaderName::from_bytes(format!("x-caller-{index}").as_bytes()).unwrap();
        if headers
            .try_append(name, HeaderValue::from_static("1"))
            .is_err()
        {
            break;
        }
    }
    selection.replay_request(&headers).unwrap_err();
}

/// Requests a Chrome on macOS sends while browsing a page through a MITM proxy.
const BROWSING: [(&str, &str, &str, &str, Option<&str>); 6] = [
    ("GET", "navigate", "none", "document", Some("?1")),
    ("GET", "navigate", "same-origin", "document", Some("?1")),
    ("GET", "no-cors", "same-origin", "style", None),
    ("GET", "no-cors", "cross-site", "image", None),
    ("GET", "no-cors", "same-origin", "script", None),
    ("POST", "cors", "same-origin", "empty", None),
];

#[tokio::test]
async fn embedded_browsing_emulates_every_request_of_a_page() {
    let selector = ProfileSelector {
        client: Some(UserAgentKind::Chromium.as_str().into()),
        platform: Some(PlatformKind::MacOS),
        ..ProfileSelector::default()
    };
    for (method, mode, site, destination, user_activation) in BROWSING {
        for seed in 0..4 {
            let mut request = Request::builder()
                .method(method)
                .uri("https://h2.fp.ramaproxy.org/report")
                .version(Version::HTTP_2)
                .extension(TargetHttpVersion(Version::HTTP_2))
                .header("sec-fetch-mode", mode)
                .header("sec-fetch-site", site)
                .header("sec-fetch-dest", destination)
                .body(())
                .unwrap();
            if let Some(value) = user_activation {
                request
                    .headers_mut()
                    .insert("sec-fetch-user", HeaderValue::from_static(value));
            }
            let emitted = emulate_seeded(
                embedded().with_selector(selector.clone()),
                request,
                [seed; 32],
            )
            .await
            .unwrap_or_else(|error| panic!("{method} {mode} {site} {destination}: {error}"));
            let selected = emitted
                .extensions()
                .get_ref::<SelectedUserAgentProfile>()
                .unwrap();
            assert_eq!(selected.ua_kind, Some(UserAgentKind::Chromium));
            assert_eq!(selected.platform, Some(PlatformKind::MacOS));
            let report = emitted
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap();
            assert!(
                !report
                    .differences
                    .contains(&ProfilePreservationDifference::LoweredProfileItem {
                        item: LoweredProfileItem::NearestFlow,
                    }),
                "{method} {mode} {site} {destination} seed {seed}: {report:?}"
            );
            let headers = emitted.headers();
            assert_eq!(headers["sec-fetch-mode"], mode);
            assert_eq!(headers["sec-fetch-site"], site);
            assert_eq!(headers["sec-fetch-dest"], destination);
            assert_eq!(
                headers
                    .get("sec-fetch-user")
                    .map(|value| value.to_str().unwrap()),
                user_activation,
                "{method} {mode} {site} {destination}"
            );
        }
    }
}

#[tokio::test]
async fn embedded_request_without_context_replays_a_navigation() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        for seed in 0..=u8::MAX {
            let emitted = emulate_seeded(
                embedded(),
                Request::builder()
                    .uri("https://example.com/")
                    .version(version)
                    .extension(TargetHttpVersion(version))
                    .body(())
                    .unwrap(),
                [seed; 32],
            )
            .await
            .unwrap_or_else(|error| panic!("{version:?} seed {seed}: {error}"));
            // Some navigations were captured without Fetch metadata.
            for (name, navigation) in [
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
            ] {
                assert!(
                    emitted
                        .headers()
                        .get(name)
                        .is_none_or(|value| value == navigation),
                    "{version:?} seed {seed}: {name} {:?}",
                    emitted.headers().get(name)
                );
            }
        }
    }
}

/// An embedded User-Agent whose only HTTP/1.1 captures are WebSocket handshakes, beside
/// HTTP/2 navigations.
fn http2_only_page_profile() -> String {
    let database = embedded_database();
    database
        .iter()
        .find_map(|profile| {
            let recorded = profile.recorded_request_headers();
            let http1 = recorded
                .iter()
                .filter(|recorded| recorded.version == Version::HTTP_11);
            let only_ws = http1.clone().count() > 0
                && http1
                    .clone()
                    .all(|recorded| recorded.initiator == Some(RequestInitiator::Ws));
            let navigates = recorded.iter().any(|recorded| {
                recorded.version == Version::HTTP_2
                    && recorded.initiator == Some(RequestInitiator::Navigate)
            });
            (only_ws && navigates)
                .then(|| profile.ua_str().map(str::to_owned))
                .flatten()
        })
        .expect("an embedded profile with only WebSocket captures over HTTP/1.1")
}

fn untargeted_navigation(user_agent: &str) -> Request<()> {
    let request = Request::builder()
        .uri("https://example.com/")
        .extension(RequestInitiator::Navigate)
        .body(())
        .unwrap();
    request
        .extensions()
        .insert(UserAgent::new(user_agent.to_owned()));
    request
}

#[tokio::test]
async fn an_untargeted_request_selects_its_profile_for_the_version_it_negotiates() {
    let user_agent = http2_only_page_profile();
    let emitted = emulate_negotiated(
        embedded(),
        untargeted_navigation(&user_agent),
        Version::HTTP_2,
    )
    .await
    .unwrap();
    let selected = emitted
        .extensions()
        .get_ref::<SelectedUserAgentProfile>()
        .unwrap();
    assert_eq!(
        selected.user_agent_header.as_deref(),
        Some(user_agent.as_str())
    );
    assert_eq!(emitted.headers()["user-agent"], user_agent.as_str());
    assert_eq!(emitted.headers()["sec-fetch-mode"], "navigate");
}

#[tokio::test]
async fn an_untargeted_page_request_offers_only_the_version_holding_page_flows() {
    let user_agent = http2_only_page_profile();
    // Only WebSocket handshakes were captured over HTTP/1.1: the offer holds HTTP/2 alone.
    let (target, selected) =
        selected_target(embedded_database(), untargeted_navigation(&user_agent))
            .await
            .unwrap();
    assert_eq!(target, Some(Version::HTTP_2));
    assert_eq!(selected.as_deref(), Some(user_agent.as_str()));
    // A peer that picks HTTP/1.1 anyway is refused at the handshake, before any request
    // is drawn or sent, and never as a missing flow.
    let error = emulate_negotiated(
        embedded(),
        untargeted_navigation(&user_agent),
        Version::HTTP_11,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("incompatible with negotiated protocol HTTP/1.1"),
        "{error}"
    );
    // A discovered HTTP/1.1 alternative does not widen the selection either.
    let error = emulate_alternative(
        embedded(),
        untargeted_navigation(&user_agent),
        Version::HTTP_11,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("incompatible with negotiated protocol HTTP/1.1"),
        "{error}"
    );
}

#[tokio::test]
async fn a_caller_target_or_alpn_is_not_narrowed_to_the_page_flow_version() {
    let user_agent = http2_only_page_profile();
    // An HTTP/1.1 target fails before connecting instead of drawing another profile.
    let request = untargeted_navigation(&user_agent);
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    let error = emulate(embedded(), request).await.unwrap_err();
    assert!(error.to_string().contains("flow"), "{error}");
    // A caller offer of both versions stays as offered.
    let request = untargeted_navigation(&user_agent);
    request.extensions().insert(TlsAlpn::http_auto());
    let (target, _) = selected_target(embedded_database(), request).await.unwrap();
    assert_eq!(target, None);
}

/// The target selection sets on an untargeted request and the User-Agent it selects.
async fn selected_target(
    database: Arc<UserAgentDatabase>,
    request: Request<()>,
) -> Result<(Option<Version>, Option<String>), BoxError> {
    let service = ProfileEmulateLayer::new(database)
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(service_fn(|request: Request<()>| async move {
            Ok::<_, Infallible>(request)
        }));
    let request = service.serve(request).await?;
    let target = request
        .extensions()
        .get_ref::<TargetHttpVersion>()
        .map(|target| target.0);
    let selected = request
        .extensions()
        .get_ref::<SelectedUserAgentProfile>()
        .and_then(|selected| selected.user_agent_header.as_deref().map(str::to_owned));
    Ok((target, selected))
}

/// An untargeted request of `initiator` naming `user_agent`; a WebSocket is the upgrade
/// request an auto WebSocket client sends.
fn untargeted(user_agent: &str, initiator: RequestInitiator) -> Request<()> {
    let request = if initiator == RequestInitiator::Ws {
        Request::builder()
            .uri("wss://example.com/")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .extension(ext::Protocol::from_static("websocket"))
            .extension(initiator)
            .body(())
            .unwrap()
    } else {
        Request::builder()
            .uri("https://example.com/")
            .extension(initiator)
            .body(())
            .unwrap()
    };
    request
        .extensions()
        .insert(UserAgent::new(user_agent.to_owned()));
    request
}

/// Whether `profile` captured a WebSocket handshake over `version`.
fn websocket_captured(
    profile: &crate::profile::model::ua::UserAgentProfile,
    version: Version,
) -> bool {
    profile
        .captured
        .as_ref()
        .unwrap()
        .scopes
        .iter()
        .any(|scope| {
            matches!(
                &scope.flow,
                Some(FlowKey::Http {
                    version: captured,
                    initiator: Some(RequestInitiator::Ws),
                    ..
                }) if *captured == version
            )
        })
}

/// An embedded profile whose components and WebSocket captures match.
fn embedded_profile(
    h1: bool,
    h2: bool,
    h2_websocket: bool,
) -> crate::profile::model::ua::UserAgentProfile {
    embedded_database()
        .iter()
        .find(|profile| {
            let components = &profile.captured.as_ref().unwrap().components;
            components.h1.is_some() == h1
                && components.h2.is_some() == h2
                && components.tls_tcp.is_some()
                && websocket_captured(profile, Version::HTTP_2) == h2_websocket
        })
        .cloned()
        .expect("an embedded profile of this shape")
}

fn database_of(profile: crate::profile::model::ua::UserAgentProfile) -> Arc<UserAgentDatabase> {
    Arc::new([profile].into_iter().collect())
}

#[tokio::test]
async fn an_untargeted_request_follows_the_versions_its_profile_holds() {
    for (h1, h2, expected) in [
        (true, false, Some(Version::HTTP_11)),
        (true, true, None),
        (false, true, Some(Version::HTTP_2)),
    ] {
        let mut profile = embedded_profile(true, true, false);
        if !h1 || !h2 {
            profile = if h1 {
                embedded_profile(true, false, false)
            } else {
                // No embedded profile lacks HTTP/1.1 data: drop it from one that has both.
                let analysis = Arc::make_mut(profile.captured.as_mut().unwrap());
                analysis.components.h1 = None;
                profile
            };
        }
        let user_agent = profile.ua_str().unwrap().to_owned();
        let (target, selected) = selected_target(
            database_of(profile),
            untargeted(&user_agent, RequestInitiator::Navigate),
        )
        .await
        .unwrap_or_else(|error| panic!("h1 {h1} h2 {h2}: {error}"));
        assert_eq!(target, expected, "h1 {h1} h2 {h2}");
        assert_eq!(selected.as_deref(), Some(user_agent.as_str()));
    }
}

#[tokio::test]
async fn a_caller_target_or_alpn_keeps_selection_strict() {
    let profile = embedded_profile(true, false, false);
    let user_agent = profile.ua_str().unwrap().to_owned();
    let database = database_of(profile);
    let request = untargeted(&user_agent, RequestInitiator::Navigate);
    request.extensions().insert(TlsAlpn::http_auto());
    let error = selected_target(database.clone(), request)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("capabilities"), "{error}");
    let request = untargeted(&user_agent, RequestInitiator::Navigate);
    request
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    selected_target(database, request).await.unwrap_err();
}

#[tokio::test]
async fn an_untargeted_websocket_offers_only_versions_holding_a_websocket_flow() {
    for h2_websocket in [true, false] {
        let profile = embedded_profile(true, true, h2_websocket);
        let user_agent = profile.ua_str().unwrap().to_owned();
        let (target, selected) = selected_target(
            database_of(profile),
            untargeted(&user_agent, RequestInitiator::Ws),
        )
        .await
        .unwrap();
        // With handshakes under both versions ALPN picks; otherwise HTTP/1.1 alone is offered.
        let expected = (!h2_websocket).then_some(Version::HTTP_11);
        assert_eq!(target, expected, "h2 websocket {h2_websocket}");
        assert_eq!(selected.as_deref(), Some(user_agent.as_str()));
    }
}

#[tokio::test]
async fn a_websocket_keeps_its_caller_target() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let request_on = |profile: &crate::profile::model::ua::UserAgentProfile| {
            let request = untargeted(profile.ua_str().unwrap(), RequestInitiator::Ws);
            request.extensions().insert(TargetHttpVersion(version));
            request
        };
        let holds_version = |profile: &&crate::profile::model::ua::UserAgentProfile| {
            let components = &profile.captured.as_ref().unwrap().components;
            match version {
                Version::HTTP_2 => components.h2.is_some(),
                _ => components.h3.is_some(),
            }
        };
        let database = embedded_database();
        // A handshake captured in the version's own form serves the target.
        if let Some(profile) = database
            .iter()
            .filter(holds_version)
            .find(|profile| websocket_captured(profile, version))
        {
            let (target, _) = selected_target(database_of(profile.clone()), request_on(profile))
                .await
                .unwrap_or_else(|error| panic!("{version:?}: {error}"));
            assert_eq!(target, Some(version));
        }
        // Without one the target stays strict rather than replaying another kind of flow.
        let profile = database
            .iter()
            .filter(holds_version)
            .find(|profile| !websocket_captured(profile, version))
            .unwrap();
        let error = selected_target(database_of(profile.clone()), request_on(profile))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("flow"), "{version:?}: {error}");
    }
}

/// An embedded profile holding HTTP/1.1, HTTP/2 data and, when `h3`, HTTP/3 data.
fn alternative_profile(h3: bool) -> crate::profile::model::ua::UserAgentProfile {
    embedded_database()
        .iter()
        .find(|profile| {
            let components = &profile.captured.as_ref().unwrap().components;
            components.h1.is_some()
                && components.h2.is_some()
                && components.tls_tcp.is_some()
                && components.h3.is_some() == h3
                && components.quic.is_some() == h3
                && components.tls_quic.is_some() == h3
        })
        .cloned()
        .expect("an embedded profile of this shape")
}

#[tokio::test]
async fn an_untargeted_request_takes_an_http3_alternative_its_profile_holds() {
    let profile = alternative_profile(true);
    let user_agent = profile.ua_str().unwrap().to_owned();
    let emitted = emulate_alternative(
        ProfileEmulateLayer::new(database_of(profile)),
        untargeted(&user_agent, RequestInitiator::Navigate),
        Version::HTTP_3,
    )
    .await
    .unwrap();
    let selected = emitted
        .extensions()
        .get_ref::<SelectedUserAgentProfile>()
        .unwrap();
    assert_eq!(
        selected.user_agent_header.as_deref(),
        Some(user_agent.as_str())
    );
    assert_eq!(emitted.version(), Version::HTTP_3);
    let prepared = emitted
        .extensions()
        .get_ref::<PreparedConnectionComponents>()
        .unwrap();
    assert!(prepared.quic_first_flight.is_some() || prepared.quic_parameters.is_some());
    assert_eq!(emitted.headers()["sec-fetch-mode"], "navigate");
}

#[tokio::test]
async fn an_http3_alternative_the_profile_lacks_is_refused() {
    let profile = alternative_profile(false);
    let user_agent = profile.ua_str().unwrap().to_owned();
    let error = emulate_alternative(
        ProfileEmulateLayer::new(database_of(profile)),
        untargeted(&user_agent, RequestInitiator::Navigate),
        Version::HTTP_3,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("HTTP/3"), "{error}");
}

#[tokio::test]
async fn an_http2_alternative_serves_an_untargeted_request_with_http2_data() {
    let profile = alternative_profile(false);
    let user_agent = profile.ua_str().unwrap().to_owned();
    let emitted = emulate_alternative(
        ProfileEmulateLayer::new(database_of(profile)),
        untargeted(&user_agent, RequestInitiator::Navigate),
        Version::HTTP_2,
    )
    .await
    .unwrap();
    assert_eq!(emitted.version(), Version::HTTP_2);
    assert!(emitted.extensions().contains::<PseudoHeaderOrder>());
}

#[tokio::test]
async fn a_caller_alpn_keeps_an_alternative_from_switching_the_profile_version() {
    let profile = alternative_profile(true);
    let user_agent = profile.ua_str().unwrap().to_owned();
    let request = untargeted(&user_agent, RequestInitiator::Navigate);
    request.extensions().insert(TlsAlpn::http_auto());
    let error = emulate_alternative(
        ProfileEmulateLayer::new(database_of(profile)),
        request,
        Version::HTTP_3,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("HTTP/3"), "{error}");
}

/// The browser family the layer selects for an untargeted navigation.
async fn selected_family(
    layer: ProfileEmulateLayer,
    request: Request<()>,
) -> Result<Option<UserAgentKind>, BoxError> {
    let service = layer
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(service_fn(|request: Request<()>| async move {
            Ok::<_, Infallible>(request)
        }));
    let request = service.serve(request).await?;
    Ok(request
        .extensions()
        .get_ref::<SelectedUserAgentProfile>()
        .and_then(|selected| selected.ua_kind))
}

const UNKNOWN_FIREFOX: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:999.0) Gecko/20100101 Firefox/999.0";

fn untargeted_navigation_request() -> Request<()> {
    Request::builder()
        .uri("https://example.com/")
        .extension(RequestInitiator::Navigate)
        .body(())
        .unwrap()
}

#[tokio::test]
async fn an_unknown_detected_user_agent_selects_its_browser_family_when_untargeted() {
    let mut request = untargeted_navigation_request();
    request
        .headers_mut()
        .insert("user-agent", UNKNOWN_FIREFOX.parse().unwrap());
    let kind = selected_family(embedded().with_try_auto_detect_user_agent(true), request)
        .await
        .unwrap();
    assert_eq!(kind, Some(UserAgentKind::Firefox));
}

#[tokio::test]
async fn a_configured_unknown_user_agent_is_relaxed_only_by_the_fallback_policy() {
    let configured = || {
        let request = untargeted_navigation_request();
        request
            .extensions()
            .insert(UserAgent::new(UNKNOWN_FIREFOX.to_owned()));
        request
    };
    // The default `Abort` policy keeps a configured User-Agent strict.
    selected_family(
        embedded().with_try_auto_detect_user_agent(true),
        configured(),
    )
    .await
    .unwrap_err();
    let kind = selected_family(
        embedded().with_select_fallback(ProfileSelectFallback::SameClient),
        configured(),
    )
    .await
    .unwrap();
    assert_eq!(kind, Some(UserAgentKind::Firefox));
}

/// An embedded profile whose every Extended CONNECT handshake over HTTP/2 carried a key.
fn keyed_extended_connect_profile() -> crate::profile::model::ua::UserAgentProfile {
    embedded_database()
        .iter()
        .find(|profile| {
            let recorded = profile.recorded_request_headers();
            let mut handshakes = recorded.iter().filter(|recorded| {
                recorded.version == Version::HTTP_2
                    && recorded.initiator == Some(RequestInitiator::Ws)
            });
            handshakes.clone().next().is_some()
                && handshakes
                    .all(|recorded| recorded.headers.contains_key(header::SEC_WEBSOCKET_KEY))
        })
        .cloned()
        .expect("an embedded profile whose HTTP/2 WebSocket handshakes carry a key")
}

/// A WebSocket handshake of `user_agent` in the form of `version`, without a key.
fn websocket_handshake(user_agent: &str, version: Version) -> Request<()> {
    let request = untargeted(user_agent, RequestInitiator::Ws);
    request.extensions().insert(TargetHttpVersion(version));
    if version == Version::HTTP_2 {
        let (mut parts, body) = request.into_parts();
        parts.method = Method::CONNECT;
        parts.version = version;
        parts.headers.remove(header::UPGRADE);
        parts.headers.remove(header::CONNECTION);
        return Request::from_parts(parts, body);
    }
    request
}

#[tokio::test]
async fn an_extended_connect_fills_the_captured_websocket_key_slot() {
    let profile = keyed_extended_connect_profile();
    let user_agent = profile.ua_str().unwrap().to_owned();
    let recorded = profile.recorded_request_headers();
    let emitted = emulate(
        ProfileEmulateLayer::new(database_of(profile.clone())),
        websocket_handshake(&user_agent, Version::HTTP_2),
    )
    .await
    .unwrap();
    assert!(
        SecWebSocketKey::decode(&mut emitted.headers().get_all(header::SEC_WEBSOCKET_KEY).iter())
            .is_ok(),
        "a WebSocket key in the key format"
    );
    let names = emitted.headers().keys().cloned().collect::<Vec<_>>();
    // At its captured position: the emitted list is a recorded one less unsupplied fields.
    assert!(
        recorded
            .iter()
            .filter(|recorded| recorded.version == Version::HTTP_2
                && recorded.initiator == Some(RequestInitiator::Ws))
            .any(|recorded| recorded
                .headers
                .keys()
                .filter(|name| names.contains(name))
                .eq(names.iter())),
        "{names:?}"
    );
    // Each handshake draws a fresh key.
    let again = emulate(
        ProfileEmulateLayer::new(database_of(profile.clone())),
        websocket_handshake(&user_agent, Version::HTTP_2),
    )
    .await
    .unwrap();
    assert_ne!(
        again.headers().get(header::SEC_WEBSOCKET_KEY),
        emitted.headers().get(header::SEC_WEBSOCKET_KEY)
    );
    // An HTTP/1.1 upgrade without its client's key gets none invented.
    let emitted = emulate(
        ProfileEmulateLayer::new(database_of(profile)),
        websocket_handshake(&user_agent, Version::HTTP_11),
    )
    .await
    .unwrap();
    assert!(!emitted.headers().contains_key(header::SEC_WEBSOCKET_KEY));
}
