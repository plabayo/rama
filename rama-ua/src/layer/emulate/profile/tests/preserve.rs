use super::*;
use crate::{
    HttpAgent, UserAgentKind,
    layer::emulate::{
        PreserveClientHints, PreserveHeaderUserAgent, ProfileEmulateRelayRequestModifier,
    },
};

#[cfg(all(feature = "tls", feature = "embed-profiles"))]
use {
    super::parity::{client, embedded, emulate, navigate},
    crate::TlsAgent,
};

const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

fn hinted_database() -> Arc<UserAgentDatabase> {
    database_with(&["test-browser"], || {
        request_variant(vec![
            profile_header("user-agent", "captured-browser"),
            profile_header("sec-ch-ua", "\"captured\";v=\"1\""),
            profile_header("sec-ch-ua-platform", "\"captured-os\""),
        ])
    })
}

/// Select a hinted profile and replay the request without a profile connection.
async fn relay(request: Request<()>) -> Request<()> {
    let inner = service_fn(|request: Request<()>| async move {
        ProfileEmulateRelayRequestModifier::new(service_fn(async |request: Request<()>| {
            Ok::<_, Infallible>(request)
        }))
        .serve(request)
        .await
    });
    ProfileEmulateLayer::new(hinted_database())
        .with_selector(ProfileSelector {
            client: Some("test-browser".into()),
            ..ProfileSelector::default()
        })
        .with_seed(ProfileSeed([1; 32]))
        .with_connection_key(DrawKey([2; 32]))
        .with_request_key(DrawKey([3; 32]))
        .into_layer(inner)
        .serve(request)
        .await
        .unwrap()
}

fn caller_request() -> Request<()> {
    let mut request = h2_request();
    let headers = request.headers_mut();
    headers.insert("user-agent", "caller/1".parse().unwrap());
    headers.insert("sec-ch-ua", "\"caller\";v=\"2\"".parse().unwrap());
    request
}

fn differences(request: &Request<()>) -> Box<[ProfilePreservationDifference]> {
    request
        .extensions()
        .get_ref::<ProfilePreservationReport>()
        .unwrap()
        .differences
        .clone()
}

fn lowered(item: LoweredProfileItem) -> ProfilePreservationDifference {
    ProfilePreservationDifference::LoweredProfileItem { item }
}

fn replaced(name: &'static str) -> ProfilePreservationDifference {
    ProfilePreservationDifference::CallerValueReplaced {
        name: HeaderName::from_static(name),
        occurrence: 0,
    }
}

fn header_names(request: &Request<()>) -> Vec<&str> {
    request
        .headers()
        .ordered_iter()
        .map(|(name, _value)| name.as_str())
        .collect()
}

#[tokio::test]
async fn without_preservation_the_profile_replaces_caller_values() {
    let emitted = relay(caller_request()).await;
    assert_eq!(emitted.headers()["user-agent"], "captured-browser");
    assert_eq!(emitted.headers()["sec-ch-ua"], "\"captured\";v=\"1\"");
    let differences = differences(&emitted);
    assert!(differences.contains(&replaced("user-agent")));
    assert!(differences.contains(&replaced("sec-ch-ua")));
}

#[tokio::test]
async fn preserved_user_agent_keeps_the_caller_value_in_captured_position() {
    let request = caller_request();
    request.extensions().insert(PreserveHeaderUserAgent::new());
    let emitted = relay(request).await;
    assert_eq!(emitted.headers()["user-agent"], "caller/1");
    assert_eq!(emitted.headers()["sec-ch-ua"], "\"captured\";v=\"1\"");
    assert_eq!(
        header_names(&emitted),
        ["user-agent", "sec-ch-ua", "sec-ch-ua-platform"]
    );
    let differences = differences(&emitted);
    assert!(differences.contains(&lowered(LoweredProfileItem::CallerUserAgent)));
    assert!(!differences.contains(&replaced("user-agent")));
    assert!(differences.contains(&replaced("sec-ch-ua")));
    assert!(emitted.extensions().contains::<RequestSelection>());
}

#[tokio::test]
async fn preserved_user_agent_without_a_caller_value_sends_the_profile_value() {
    let request = h2_request();
    request.extensions().insert(PreserveHeaderUserAgent::new());
    let emitted = relay(request).await;
    assert_eq!(emitted.headers()["user-agent"], "captured-browser");
    assert!(!differences(&emitted).contains(&lowered(LoweredProfileItem::CallerUserAgent)));
}

#[tokio::test]
async fn preserved_client_hints_keep_caller_hints_and_fill_missing_ones() {
    let request = caller_request();
    request.extensions().insert(PreserveClientHints::new());
    let emitted = relay(request).await;
    assert_eq!(emitted.headers()["sec-ch-ua"], "\"caller\";v=\"2\"");
    assert_eq!(emitted.headers()["sec-ch-ua-platform"], "\"captured-os\"");
    assert_eq!(emitted.headers()["user-agent"], "captured-browser");
    let differences = differences(&emitted);
    assert!(differences.contains(&lowered(LoweredProfileItem::CallerClientHints)));
    assert!(!differences.contains(&replaced("sec-ch-ua")));
    assert!(differences.contains(&replaced("user-agent")));
}

#[tokio::test]
async fn preserved_http_sends_the_caller_request_unchanged() {
    let mut request = caller_request();
    request
        .headers_mut()
        .insert("x-custom", "1".parse().unwrap());
    request
        .extensions()
        .insert(UserAgent::new("caller/1").with_http_agent(HttpAgent::Preserve));
    let emitted = relay(request).await;
    assert_eq!(
        header_names(&emitted),
        ["user-agent", "sec-ch-ua", "x-custom"]
    );
    assert_eq!(emitted.headers()["user-agent"], "caller/1");
    assert!(EmulationContext::of(emitted.extensions()).is_some());
    assert!(!emitted.extensions().contains::<RequestSelection>());
    assert_eq!(
        differences(&emitted).as_ref(),
        [lowered(LoweredProfileItem::CallerHttp)]
    );
}

#[tokio::test]
async fn preserved_http_skips_captured_connection_settings() {
    let inner = service_fn(|input: ConnectRequest| async move {
        assert!(!input.extensions().contains::<H2ClientContextParams>());
        let conn = ServiceInput::new(());
        conn.extensions().insert(TargetHttpVersion(Version::HTTP_2));
        Ok::<_, ConnectionError>(EstablishedClientConnection { input, conn })
    });
    let input = ConnectRequest::new("example.com:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    input
        .extensions()
        .insert(UserAgent::new("caller/1").with_http_agent(HttpAgent::Preserve));
    emulation_context().publish(input.extensions());

    let established = ProfileEmulateHttpConnectModifier::new(inner)
        .serve(input)
        .await
        .unwrap();
    let report = established
        .conn
        .extensions()
        .get_ref::<ProfilePreservationReport>()
        .unwrap();
    assert!(
        report
            .differences
            .contains(&lowered(LoweredProfileItem::CallerHttp))
    );
    assert!(
        established
            .conn
            .extensions()
            .get_ref::<ConnectionReuse>()
            .unwrap()
            .matches(established.input.extensions())
    );

    // Requests on that connection carry the item once.
    let request = h2_request();
    request
        .extensions()
        .insert(UserAgent::new("caller/1").with_http_agent(HttpAgent::Preserve));
    emulation_context().publish(request.extensions());
    let emitted =
        ProfileEmulateHttpRequestModifier::new(Sink(established.conn.extensions().clone()))
            .serve(request)
            .await
            .unwrap();
    let kept = differences(&emitted)
        .iter()
        .filter(|difference| **difference == lowered(LoweredProfileItem::CallerHttp))
        .count();
    assert_eq!(kept, 1);
}

#[test]
fn preserved_http_still_selects_the_parsed_browser() {
    let agent = UserAgent::new(CHROME).with_http_agent(HttpAgent::Preserve);
    let selector = effective_selector(&ProfileSelector::default(), Some(&agent));
    assert_eq!(
        selector.client.as_deref(),
        Some(UserAgentKind::Chromium.as_str())
    );
}

#[cfg(all(feature = "tls", feature = "embed-profiles"))]
#[tokio::test]
async fn preserved_tls_leaves_the_captured_offer_unapplied() {
    let request = navigate(Version::HTTP_2);
    request
        .extensions()
        .insert(UserAgent::new("caller/1").with_tls_agent(TlsAgent::Preserve));
    let emitted = emulate(
        embedded().with_selector(client(UserAgentKind::Chromium)),
        request,
    )
    .await
    .unwrap();
    assert!(
        emitted
            .extensions()
            .get_ref::<PreparedConnectionComponents>()
            .is_some_and(|prepared| prepared.tls.is_none())
    );
    assert!(differences(&emitted).contains(&lowered(LoweredProfileItem::CallerTls)));
    // HTTP is still emulated.
    assert!(emitted.extensions().contains::<RequestSelection>());
}

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
