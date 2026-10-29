use std::ptr;

use rama_http::{HeaderMap, HeaderValue, header};

use super::{
    parity::{embedded, embedded_database},
    *,
};
use crate::profile::{
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
    let database = embedded_database();
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
fn cached_replay_plans_replay_exactly_what_decoding_the_capture_does() {
    let headers = caller_headers();
    let draws = embedded_request_draws(32);
    assert!(draws.len() >= 96);
    for cached in draws {
        assert!(cached.effective.plan.is_some(), "embedded captures decode");
        let mut decoded = cached.clone();
        decoded.effective.plan = None;
        assert_eq!(
            format!("{:?}", cached.replay_request(&headers)),
            format!("{:?}", decoded.replay_request(&headers)),
            "{:?}",
            cached.effective.flow
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
