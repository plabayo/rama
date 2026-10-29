use rama_core::error::BoxError;
use rama_http::proto::h2::PseudoHeaderOrder;

use super::*;
use crate::{
    PlatformKind, UserAgentKind,
    layer::emulate::{
        ProfileEmulateRelayRequestModifier, ProfileSelectFallback, SelectedUserAgentProfile,
    },
};

const LEGACY_PROFILES: &[u8] =
    include_bytes!("../../../../profile/format/legacy/tests/browser_profiles.json");

#[derive(Debug)]
struct Sink(Extensions);

impl ExtensionsRef for Sink {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

impl rama_core::Service<Request<()>> for Sink {
    type Output = Request<()>;
    type Error = Infallible;

    async fn serve(&self, req: Request<()>) -> Result<Self::Output, Self::Error> {
        Ok(req)
    }
}

/// Run a request through selection, a mock connection and request replay.
pub(super) async fn emulate(
    layer: ProfileEmulateLayer,
    request: Request<()>,
) -> Result<Request<()>, BoxError> {
    emulate_drawn(layer, request, [3; 32]).await
}

/// [`emulate`] with an explicit request draw key.
pub(super) async fn emulate_drawn(
    layer: ProfileEmulateLayer,
    request: Request<()>,
    request_key: [u8; 32],
) -> Result<Request<()>, BoxError> {
    let inner = service_fn(|request: Request<()>| async move {
        let Some(context) = EmulationContext::of(request.extensions()).cloned() else {
            return Ok::<_, BoxError>(request);
        };
        let version = request.version();
        let transport = service_fn(move |input: ConnectRequest| async move {
            let conn = Sink(Extensions::new());
            conn.extensions().insert(TargetHttpVersion(version));
            Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
        });
        let input = ConnectRequest::new("example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        input.extensions().insert(TargetHttpVersion(version));
        context.publish(input.extensions());
        // Connectors see the request's extensions, including its preservation choices.
        request
            .extensions()
            .clone_to_if_absent::<UserAgent>(input.extensions());
        let established = ProfileEmulateHttpConnectModifier::new(transport)
            .serve(input)
            .await?;
        established
            .input
            .extensions()
            .clone_to_if_absent::<ProfilePreservationReport>(request.extensions());
        established
            .input
            .extensions()
            .clone_to_if_absent::<PreparedConnectionComponents>(request.extensions());
        ProfileEmulateHttpRequestModifier::new(established.conn)
            .serve(request)
            .await
    });
    layer
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey(request_key))
        .into_layer(inner)
        .serve(request)
        .await
}

pub(super) fn navigate(version: Version) -> Request<()> {
    Request::builder()
        .uri("https://example.com/")
        .version(version)
        .extension(TargetHttpVersion(version))
        .body(())
        .unwrap()
}

pub(super) fn client(kind: UserAgentKind) -> ProfileSelector {
    ProfileSelector {
        client: Some(kind.as_str().into()),
        ..ProfileSelector::default()
    }
}

pub(super) fn embedded() -> ProfileEmulateLayer {
    ProfileEmulateLayer::new(Arc::new(UserAgentDatabase::try_embedded().unwrap()))
}

fn assert_emulated(emitted: &Request<()>, kind: UserAgentKind) {
    let selected = emitted
        .extensions()
        .get_ref::<SelectedUserAgentProfile>()
        .unwrap();
    assert_eq!(selected.ua_kind, Some(kind));
    assert!(emitted.extensions().contains::<RequestSelection>());
    assert_eq!(
        emitted.headers()["user-agent"],
        selected.user_agent_header.as_deref().unwrap()
    );
    if emitted.version() == Version::HTTP_2 {
        assert!(emitted.extensions().contains::<PseudoHeaderOrder>());
    }
}

#[tokio::test]
async fn embedded_profiles_emulate_navigation_over_h1_and_h2_with_tls() {
    for kind in [
        UserAgentKind::Chromium,
        UserAgentKind::Firefox,
        UserAgentKind::Safari,
    ] {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let emitted = emulate(embedded().with_selector(client(kind)), navigate(version))
                .await
                .unwrap_or_else(|error| panic!("{kind} {version:?}: {error}"));
            assert_emulated(&emitted, kind);
            assert!(
                emitted
                    .extensions()
                    .get_ref::<PreparedConnectionComponents>()
                    .is_some_and(|prepared| prepared.tls.is_some()),
                "{kind} {version:?} prepares the captured ClientHello"
            );
        }
    }
}

#[tokio::test]
async fn embedded_desktop_browsers_emulate_http3_with_quic_and_settings() {
    for kind in [UserAgentKind::Chromium, UserAgentKind::Firefox] {
        let emitted = emulate(
            embedded().with_selector(client(kind)),
            navigate(Version::HTTP_3),
        )
        .await
        .unwrap_or_else(|error| panic!("{kind} HTTP/3: {error}"));
        assert_emulated(&emitted, kind);
        let prepared = emitted
            .extensions()
            .get_ref::<PreparedConnectionComponents>()
            .unwrap_or_else(|| panic!("{kind} HTTP/3 prepares its connection"));
        assert!(prepared.quic_parameters.is_some(), "{kind} QUIC parameters");
        assert!(
            prepared.quic_first_flight.is_some(),
            "{kind} QUIC first flight"
        );
        assert!(
            prepared.h3_peer_settings.is_some(),
            "{kind} HTTP/3 SETTINGS"
        );
        #[cfg(feature = "tls")]
        assert!(prepared.tls.is_some(), "{kind} ClientHello over QUIC");
    }
}

#[tokio::test]
async fn embedded_h3_without_a_matching_flow_is_optional_pass_through() {
    // A known User-Agent whose every embedded profile lacks HTTP/3, so only the missing
    // flow can fail selection.
    let database = UserAgentDatabase::try_embedded().unwrap();
    let user_agent: Box<str> = database
        .iter_ua_str()
        .find(|ua| {
            database
                .get_exact_header_str(ua)
                .all(|profile| !profile.capabilities().h3)
        })
        .expect("an embedded User-Agent without HTTP/3")
        .into();
    let request = || {
        let mut request = navigate(Version::HTTP_3);
        request
            .headers_mut()
            .insert("user-agent", "caller/1".parse().unwrap());
        request
    };
    let without_h3 = || {
        embedded().with_selector(ProfileSelector {
            user_agent: Some(user_agent.clone()),
            ..ProfileSelector::default()
        })
    };
    let Err(error) = emulate(without_h3(), request()).await else {
        panic!("{user_agent} has no embedded HTTP/3 navigation flow");
    };
    assert!(
        error.to_string().contains("flow") || error.to_string().contains("capabilities"),
        "{error}"
    );
    let emitted = emulate(without_h3().with_is_optional(true), request())
        .await
        .unwrap();
    assert!(!emitted.extensions().contains::<RequestSelection>());
    assert!(EmulationContext::of(emitted.extensions()).is_none());
    assert_eq!(emitted.headers()["user-agent"], "caller/1");
}

#[tokio::test]
async fn auto_detected_non_browser_with_same_client_fallback_is_an_error() {
    let mut request = navigate(Version::HTTP_2);
    request
        .headers_mut()
        .insert("user-agent", "curl/8".parse().unwrap());
    let layer = embedded()
        .with_try_auto_detect_user_agent(true)
        .with_select_fallback(ProfileSelectFallback::SameClient);
    emulate(layer, request).await.unwrap_err();
}

#[tokio::test]
async fn auto_detection_emulates_the_callers_own_browser() {
    for (header, kind, platform) in [
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
            UserAgentKind::Firefox,
            PlatformKind::Windows,
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
            UserAgentKind::Safari,
            PlatformKind::IOS,
        ),
        (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
            UserAgentKind::Chromium,
            PlatformKind::Android,
        ),
    ] {
        let mut request = navigate(Version::HTTP_2);
        request
            .headers_mut()
            .insert("user-agent", header.parse().unwrap());
        let emitted = emulate(embedded().with_try_auto_detect_user_agent(true), request)
            .await
            .unwrap();
        assert_emulated(&emitted, kind);
        let selected = emitted
            .extensions()
            .get_ref::<SelectedUserAgentProfile>()
            .unwrap();
        assert_eq!(selected.platform, Some(platform), "{header}");
    }
}

#[tokio::test]
async fn auto_detection_prefers_the_exact_user_agent_over_its_browser_family() {
    let database = UserAgentDatabase::try_embedded().unwrap();
    let chromium: Vec<_> = database
        .iter_ua_str()
        .filter(|ua| ua.contains("Windows") && ua.contains("Chrome/") && !ua.contains("Edg/"))
        .map(str::to_owned)
        .collect();
    assert!(chromium.len() > 1, "siblings of the same browser family");
    for header in chromium {
        let mut request = navigate(Version::HTTP_2);
        request
            .headers_mut()
            .insert("user-agent", header.parse().unwrap());
        let emitted = emulate(embedded().with_try_auto_detect_user_agent(true), request)
            .await
            .unwrap_or_else(|error| panic!("{header}: {error}"));
        assert_eq!(emitted.headers()["user-agent"], header.as_str());
    }
    // A loose description has no exact profile and selects its browser family.
    let mut request = navigate(Version::HTTP_2);
    request
        .headers_mut()
        .insert("user-agent", "desktop firefox".parse().unwrap());
    let emitted = emulate(embedded().with_try_auto_detect_user_agent(true), request)
        .await
        .unwrap();
    assert_emulated(&emitted, UserAgentKind::Firefox);
}

#[tokio::test]
async fn tls_requests_never_draw_a_plaintext_request_shape() {
    // Chrome 114 on Android was captured over plaintext HTTP/1.1 too, without fetch metadata.
    let database = UserAgentDatabase::try_embedded().unwrap();
    let header = database
        .iter_ua_str()
        .find(|ua| ua.contains("Chrome/114"))
        .unwrap()
        .to_owned();
    for draw in 0..32u8 {
        let mut request = navigate(Version::HTTP_11);
        request
            .headers_mut()
            .insert("user-agent", header.parse().unwrap());
        let emitted = emulate_drawn(
            embedded().with_try_auto_detect_user_agent(true),
            request,
            [draw; 32],
        )
        .await
        .unwrap();
        assert!(
            emitted.headers().contains_key("sec-fetch-mode"),
            "draw {draw} sent a plaintext request shape over TLS"
        );
    }
}

#[tokio::test]
async fn caller_request_fields_select_the_shape_that_carries_them() {
    // Firefox navigations over HTTP/3 were captured with and without `alt-used`.
    let header = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";
    for draw in 0..32u8 {
        let mut request = navigate(Version::HTTP_3);
        let headers = request.headers_mut();
        headers.insert("user-agent", header.parse().unwrap());
        headers.insert("cookie", "c0=1; c1=1".parse().unwrap());
        headers.insert("alt-used", "example.com".parse().unwrap());
        let emitted = emulate_drawn(
            embedded().with_try_auto_detect_user_agent(true),
            request,
            [draw; 32],
        )
        .await
        .unwrap();
        let names: Vec<_> = emitted
            .headers()
            .ordered_iter()
            .map(|(name, _value)| name.as_str().to_owned())
            .collect();
        let position = |name| names.iter().position(|field| field == name);
        assert!(
            position("alt-used") < position("cookie"),
            "draw {draw} appended alt-used outside its captured position: {names:?}"
        );
    }
}

#[tokio::test]
async fn a_configured_user_agent_is_relaxed_only_by_the_fallback_policy() {
    let unknown = ProfileSelector {
        user_agent: Some(
            "Mozilla/5.0 (X11; Linux x86_64; rv:1.0) Gecko/20100101 Firefox/1.0".into(),
        ),
        ..client(UserAgentKind::Firefox)
    };
    emulate(
        embedded().with_selector(unknown.clone()),
        navigate(Version::HTTP_2),
    )
    .await
    .unwrap_err();
    let emitted = emulate(
        embedded()
            .with_selector(unknown)
            .with_select_fallback(ProfileSelectFallback::SameClient),
        navigate(Version::HTTP_2),
    )
    .await
    .unwrap();
    assert_emulated(&emitted, UserAgentKind::Firefox);
}

#[tokio::test]
async fn fallback_relaxes_an_unmatched_selector() {
    let firefox_on_ios = ProfileSelector {
        platform: Some(PlatformKind::IOS),
        ..client(UserAgentKind::Firefox)
    };
    emulate(
        embedded().with_selector(firefox_on_ios.clone()),
        navigate(Version::HTTP_2),
    )
    .await
    .unwrap_err();
    let emitted = emulate(
        embedded()
            .with_selector(firefox_on_ios)
            .with_select_fallback(ProfileSelectFallback::SameClient),
        navigate(Version::HTTP_2),
    )
    .await
    .unwrap();
    assert_emulated(&emitted, UserAgentKind::Firefox);

    let unknown = ProfileSelector {
        client: Some("unknown-browser".into()),
        ..ProfileSelector::default()
    };
    let same_client = embedded()
        .with_selector(unknown.clone())
        .with_select_fallback(ProfileSelectFallback::SameClient);
    emulate(same_client, navigate(Version::HTTP_2))
        .await
        .unwrap_err();
    // A request extension overrides the configured fallback.
    let request = navigate(Version::HTTP_2);
    request.extensions().insert(ProfileSelectFallback::Any);
    let emitted = emulate(embedded().with_selector(unknown), request)
        .await
        .unwrap();
    assert!(emitted.extensions().contains::<RequestSelection>());
}

#[tokio::test]
async fn input_header_order_orders_caller_headers_and_is_removed() {
    let order = HeaderName::from_static("x-header-order");
    let mut request = navigate(Version::HTTP_2);
    let headers = request.headers_mut();
    headers.insert("x-second", "2".parse().unwrap());
    headers.insert("x-first", "1".parse().unwrap());
    headers.insert(&order, "x-first, x-second".parse().unwrap());
    let emitted = emulate(
        embedded()
            .with_selector(client(UserAgentKind::Firefox))
            .with_input_header_order(order.clone()),
        request,
    )
    .await
    .unwrap();
    assert!(!emitted.headers().contains_key(&order));
    let names = emitted
        .headers()
        .ordered_iter()
        .map(|(name, _value)| name.as_str().to_owned())
        .collect::<Vec<_>>();
    let first = names.iter().position(|name| name == "x-first").unwrap();
    let second = names.iter().position(|name| name == "x-second").unwrap();
    assert!(first < second, "{names:?}");
}

#[tokio::test]
async fn legacy_profile_files_are_emulated_as_captured_profiles() {
    let database = Arc::new(UserAgentDatabase::try_from_json_slice(LEGACY_PROFILES).unwrap());
    assert!(database.iter().all(|profile| profile.captured.is_some()));
    for kind in [
        UserAgentKind::Chromium,
        UserAgentKind::Firefox,
        UserAgentKind::Safari,
    ] {
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let emitted = emulate(
                ProfileEmulateLayer::new(database.clone()).with_selector(client(kind)),
                navigate(version),
            )
            .await
            .unwrap_or_else(|error| panic!("{kind} {version:?}: {error}"));
            assert_emulated(&emitted, kind);
            // Legacy H2 frame arrays cannot prove completeness, so their SETTINGS stay native.
            let lowered = emitted
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .unwrap()
                .differences
                .contains(&ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::Http2Settings,
                });
            assert_eq!(lowered, version == Version::HTTP_2, "{kind} {version:?}");
        }
    }
}

#[tokio::test]
async fn relayed_requests_replay_against_a_drawn_connection() {
    let inner = service_fn(|request: Request<()>| async move {
        ProfileEmulateRelayRequestModifier::new(service_fn(async |request: Request<()>| {
            Ok::<_, Infallible>(request)
        }))
        .serve(request)
        .await
    });
    let emitted = embedded()
        .with_selector(client(UserAgentKind::Firefox))
        .into_layer(inner)
        .serve(navigate(Version::HTTP_2))
        .await
        .unwrap();
    assert_emulated(&emitted, UserAgentKind::Firefox);
    assert!(
        emitted
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .unwrap()
            .differences
            .contains(&ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::UnemulatedConnection,
            })
    );
}
