//! User-Agent profile emulation: replaying a captured browser request, the work
//! done for every emulated request, and loading the embedded profile database.

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::{Bencher, black_box};
use rama::{
    http::{HeaderMap, HeaderValue, Method, Version, header},
    ua::profile::{
        model::{
            identity::{ConnectionContext, FlowKey},
            runtime_hints::RequestInitiator,
        },
        selection::{
            DrawKey, ProfileSeed,
            capabilities::CapabilitySet,
            database::UserAgentDatabase,
            variants::{ProfileSelector, RequestSelection, SelectionRequest, VariantPins},
        },
    },
};
use std::sync::LazyLock;

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
