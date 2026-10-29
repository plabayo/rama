use std::ptr;

use rama_http::{HeaderMap, HeaderValue, header};

use super::{
    parity::{embedded, embedded_database},
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
    let (first, other) = draws
        .iter()
        .enumerate()
        .find_map(|(index, first)| {
            draws[index + 1..]
                .iter()
                .find(|other| {
                    format!("{:?}", other.effective.flow) == format!("{:?}", first.effective.flow)
                        && replay(other) != replay(first)
                })
                .map(|other| (first, other))
        })
        .unwrap();
    assert!(first.effective.plan.is_some());
    let mut swapped = first.clone();
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
