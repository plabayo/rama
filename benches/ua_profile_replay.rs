//! User-Agent profile emulation: selecting a profile and replaying a captured browser
//! request, the work done for every emulated request, and loading the embedded database.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{Bencher, black_box};
use rama::{
    Layer, Service,
    extensions::ExtensionsRef as _,
    http::{HeaderMap, HeaderValue, Method, Request, Version, conn::TargetHttpVersion, header},
    service::service_fn,
    ua::{
        UserAgent,
        layer::emulate::ProfileEmulateLayer,
        profile::{
            model::{
                identity::{ConnectionContext, FlowKey},
                runtime_hints::RequestInitiator,
                ua::UserAgentProfile,
            },
            selection::{
                DrawKey, ProfileSeed,
                capabilities::CapabilitySet,
                database::UserAgentDatabase,
                variants::{ProfileSelector, RequestSelection, SelectionRequest, VariantPins},
            },
        },
    },
};
use std::{
    convert::Infallible,
    pin::pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll, Waker},
};

mod bench_alloc;

fn main() {
    divan::main();
}

static DATABASE: LazyLock<UserAgentDatabase> =
    LazyLock::new(|| UserAgentDatabase::try_embedded().unwrap());

/// `client/version` pairs covering every browser family and HTTP version captured.
const CASES: &[&str] = &[
    "Chromium/h1",
    "Chromium/h2",
    "Chromium/h3",
    "Firefox/h1",
    "Firefox/h2",
    "Firefox/h3",
    "Safari/h1",
    "Safari/h2",
];

fn caller_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("origin.example"));
    headers.insert(header::USER_AGENT, HeaderValue::from_static("rama"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("session=abc123; theme=dark"),
    );
    headers
}

/// Draw the profile, connection and request variant once, as emulation does per request.
fn selection(case: &str) -> (RequestSelection, HeaderMap) {
    let (client, version) = case.split_once('/').unwrap();
    let (version, required, initiator) = match version {
        "h1" => (
            Version::HTTP_11,
            CapabilitySet {
                h1: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        "h2" => (
            Version::HTTP_2,
            CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        _ => (
            Version::HTTP_3,
            CapabilitySet {
                h3: true,
                tls_quic: true,
                quic: true,
                ..CapabilitySet::default()
            },
            // The embedded HTTP/3 captures are form submissions.
            RequestInitiator::Form,
        ),
    };
    let flow = FlowKey::Http {
        version,
        method: Method::GET,
        initiator: Some(initiator),
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let headers = caller_headers();
    let (seed, key) = (ProfileSeed([1; 32]), DrawKey([2; 32]));
    let selected = DATABASE
        .select(
            &SelectionRequest {
                client: ProfileSelector {
                    client: Some(client.into()),
                    ..ProfileSelector::default()
                },
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
    let request = selected
        .request(&connection, &flow, &headers, seed, key)
        .unwrap();
    (request, headers)
}

/// Draw the request variant for an established connection, as each request does.
#[divan::bench(args = CASES)]
fn draw_request(bencher: Bencher<'_, '_>, case: &str) {
    let (client, version) = case.split_once('/').unwrap();
    let (version, required, initiator) = match version {
        "h1" => (
            Version::HTTP_11,
            CapabilitySet {
                h1: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        "h2" => (
            Version::HTTP_2,
            CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Navigate,
        ),
        _ => (
            Version::HTTP_3,
            CapabilitySet {
                h3: true,
                tls_quic: true,
                quic: true,
                ..CapabilitySet::default()
            },
            RequestInitiator::Form,
        ),
    };
    let flow = FlowKey::Http {
        version,
        method: Method::GET,
        initiator: Some(initiator),
        fetch: None,
        connection: ConnectionContext::default(),
    };
    let headers = caller_headers();
    let (seed, key) = (ProfileSeed([1; 32]), DrawKey([2; 32]));
    let selected = DATABASE
        .select(
            &SelectionRequest {
                client: ProfileSelector {
                    client: Some(client.into()),
                    ..ProfileSelector::default()
                },
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
    bencher.bench_local(|| {
        black_box(
            selected
                .request(&connection, black_box(&flow), &headers, seed, key)
                .unwrap(),
        )
    });
}

/// Rebuild the request headers from the drawn capture.
#[divan::bench(args = CASES)]
fn replay_request(bencher: Bencher<'_, '_>, case: &str) {
    let (selection, headers) = selection(case);
    bencher.bench_local(|| black_box(selection.replay_request(black_box(&headers)).unwrap()));
}

/// Decode the embedded profiles and index them, as a process does at startup.
#[divan::bench(sample_count = 5, sample_size = 1)]
fn load_embedded_database() -> UserAgentDatabase {
    UserAgentDatabase::try_embedded().unwrap()
}

/// Selection cases: the request kind and the shape of the profile its exact User-Agent names.
const SELECT_CASES: &[&str] = &[
    "page/targeted-h2",
    "page/untargeted",
    "page/untargeted-h1-only",
    "websocket/h2-capture",
    "websocket/h1-capture",
];

static SHARED: LazyLock<Arc<UserAgentDatabase>> =
    LazyLock::new(|| Arc::new(UserAgentDatabase::try_embedded().unwrap()));

/// Whether `profile` captured a WebSocket handshake over HTTP/2.
fn h2_websocket(profile: &UserAgentProfile) -> bool {
    profile.captured.as_ref().is_some_and(|analysis| {
        analysis.scopes.iter().any(|scope| {
            matches!(
                &scope.flow,
                Some(FlowKey::Http {
                    version: Version::HTTP_2,
                    initiator: Some(RequestInitiator::Ws),
                    ..
                })
            )
        })
    })
}

/// The exact User-Agent of the first embedded profile of this shape.
fn user_agent(h2: bool, websocket_h2: bool) -> String {
    SHARED
        .iter()
        .find(|profile| {
            let components = &profile.captured.as_ref().unwrap().components;
            components.h1.is_some()
                && components.h2.is_some() == h2
                && components.tls_tcp.is_some()
                && h2_websocket(profile) == websocket_h2
        })
        .and_then(|profile| profile.ua_str())
        .unwrap()
        .to_owned()
}

/// Select a profile for one request through the emulate layer, as each request does.
#[divan::bench(args = SELECT_CASES)]
fn select_profile(bencher: Bencher<'_, '_>, case: &str) {
    let (kind, shape) = case.split_once('/').unwrap();
    let (initiator, uri, user_agent) = match (kind, shape) {
        ("websocket", "h2-capture") => (
            RequestInitiator::Ws,
            "wss://origin.example/",
            user_agent(true, true),
        ),
        ("websocket", _) => (
            RequestInitiator::Ws,
            "wss://origin.example/",
            user_agent(true, false),
        ),
        (_, "untargeted-h1-only") => (
            RequestInitiator::Navigate,
            "https://origin.example/",
            user_agent(false, false),
        ),
        _ => (
            RequestInitiator::Navigate,
            "https://origin.example/",
            user_agent(true, false),
        ),
    };
    let service = ProfileEmulateLayer::new(SHARED.clone())
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(service_fn(|request: Request<()>| async move {
            Ok::<_, Infallible>(request)
        }));
    let targeted = shape == "targeted-h2";
    // The User-Agent is parsed once, as the classifier does before emulation.
    let user_agent = UserAgent::new(user_agent);
    bencher.bench_local(|| {
        let request = Request::builder()
            .uri(uri)
            .extension(initiator)
            .body(())
            .unwrap();
        request.extensions().insert(user_agent.clone());
        if targeted {
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_2));
        }
        // Selection never waits: the future completes on its first poll.
        let mut future = pin!(service.serve(request));
        let polled = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        black_box(matches!(polled, Poll::Ready(Ok(_))))
    });
}
