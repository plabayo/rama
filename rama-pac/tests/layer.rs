//! The layer that turns a script verdict into `ProxyRoutes`.

#![cfg(feature = "http")]

use std::sync::{Arc, RwLock};

use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_core::{Layer, Service, service::service_fn};
use rama_http::{Body, Request, Response};
use rama_net::address::ProxyAddress;
use rama_net::client::{ProxyRoute, ProxyRoutes};
use rama_net::uri::Uri;
use rama_pac::{PacFailurePolicy, PacProxyRoutesLayer, PacResolver};

const SCRIPT: &str = r#"
    function FindProxyForURL(url, host) {
        if (host === "internal.example") { return "DIRECT"; }
        if (host === "many.example") { return "PROXY a:1; SOCKS5 b:2; DIRECT"; }
        if (host === "broken.example") { return 42; }
        return "PROXY edge:3128";
    }
"#;

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn uri(raw: &str) -> Uri {
    raw.parse().expect("test uri must parse")
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn resolver() -> Arc<PacResolver> {
    Arc::new(
        PacResolver::builder()
            .build_static(SCRIPT)
            .expect("build resolver"),
    )
}

/// Records the routes each request carried when it reached the client.
#[derive(Debug, Clone, Default)]
struct Seen(Arc<RwLock<Vec<Option<ProxyRoutes>>>>);

impl Seen {
    fn record(&self, req: &Request) {
        let routes = req.extensions().get_ref::<ProxyRoutes>().cloned();
        if let Ok(mut guard) = self.0.write() {
            guard.push(routes);
        }
    }

    fn last(&self) -> Option<ProxyRoutes> {
        self.0.read().ok().and_then(|guard| guard.last().cloned())?
    }
}

fn stack(
    layer: PacProxyRoutesLayer,
    seen: Seen,
) -> impl Service<Request, Output = Response, Error = BoxError> {
    layer.into_layer(service_fn(move |req: Request| {
        let seen = seen.clone();
        async move {
            seen.record(&req);
            Ok::<_, BoxError>(Response::new(Body::empty()))
        }
    }))
}

async fn serve(
    svc: &impl Service<Request, Output = Response, Error = BoxError>,
    req: Request,
) -> Result<Response, BoxError> {
    svc.serve(req).await
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn request(url: &str) -> Request {
    Request::get(uri(url))
        .body(Body::empty())
        .expect("build request")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_verdict_becomes_proxy_routes() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(resolver()), seen.clone());

    serve(&svc, request("http://other.example/"))
        .await
        .expect("serve");

    let routes = seen.last().expect("routes inserted");
    assert_eq!(routes.as_slice().len(), 1);
    let address = routes.as_slice()[0]
        .proxy_address()
        .expect("a proxied route");
    assert_eq!(address.address.to_string(), "edge:3128");
    // the default must not claim precedence over a configured route
    assert!(!routes.overwrite());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_verdict_becomes_a_direct_route() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(resolver()), seen.clone());

    serve(&svc, request("http://internal.example/"))
        .await
        .expect("serve");

    let routes = seen.last().expect("routes inserted");
    assert_eq!(routes.as_slice(), [ProxyRoute::Direct]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_whole_fallback_list_is_preserved_in_order() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(resolver()), seen.clone());

    serve(&svc, request("http://many.example/"))
        .await
        .expect("serve");

    let routes = seen.last().expect("routes inserted");
    let slice = routes.as_slice();
    assert_eq!(slice.len(), 3, "{slice:?}");
    assert_eq!(
        slice[0].proxy_address().map(|a| a.address.to_string()),
        Some("a:1".to_owned()),
    );
    // a socks5 directive lets the proxy resolve the name
    assert_eq!(
        slice[1]
            .proxy_address()
            .and_then(|a| a.protocol.as_ref().map(ToString::to_string)),
        Some("socks5h".to_owned()),
    );
    assert_eq!(slice[2], ProxyRoute::Direct);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_already_routed_request_is_left_alone() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(resolver()), seen.clone());

    // a pre-set singular route wins, and the script is not consulted
    let req = request("http://other.example/");
    let preset = ProxyAddress::try_from("http://preset:9999").expect("parse proxy address");
    req.extensions().insert(ProxyRoute::Proxy(preset));
    serve(&svc, req).await.expect("serve");
    assert!(
        seen.last().is_none(),
        "no ProxyRoutes should have been inserted",
    );

    // ... and a pre-set collection is equally untouched
    let req = request("http://other.example/");
    req.extensions()
        .insert(ProxyRoutes::new([ProxyRoute::Direct]));
    serve(&svc, req).await.expect("serve");
    assert_eq!(
        seen.last().map(|routes| routes.as_slice().to_vec()),
        Some(vec![ProxyRoute::Direct]),
        "the pre-set collection must survive",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overwrite_lets_the_script_win() {
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(resolver()).with_overwrite(true),
        seen.clone(),
    );

    let req = request("http://other.example/");
    let preset = ProxyAddress::try_from("http://preset:9999").expect("parse proxy address");
    req.extensions().insert(ProxyRoute::Proxy(preset));
    serve(&svc, req).await.expect("serve");

    let routes = seen.last().expect("routes inserted");
    assert_eq!(
        routes.as_slice()[0]
            .proxy_address()
            .map(|a| a.address.to_string()),
        Some("edge:3128".to_owned()),
    );
    // and it tells the connector to prefer them over the singular route
    assert!(routes.overwrite());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_script_fails_the_request_by_default() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(resolver()), seen.clone());

    let err = serve(&svc, request("http://broken.example/"))
        .await
        .expect_err("a non-string verdict must fail the request");
    assert!(format!("{err}").contains("pac"), "{err}");
    assert!(
        seen.last().is_none(),
        "the request must not have been served"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_policy_can_go_direct() {
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(resolver()).with_failure_policy(PacFailurePolicy::Direct),
        seen.clone(),
    );

    serve(&svc, request("http://broken.example/"))
        .await
        .expect("serve");
    assert_eq!(
        seen.last().map(|routes| routes.as_slice().to_vec()),
        Some(vec![ProxyRoute::Direct]),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_policy_can_name_fallback_routes() {
    let fallback = ProxyAddress::try_from("http://fallback:8080").expect("parse proxy address");
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(resolver()).with_failure_policy(PacFailurePolicy::Routes(
            ProxyRoutes::new([ProxyRoute::Proxy(fallback), ProxyRoute::Direct]),
        )),
        seen.clone(),
    );

    serve(&svc, request("http://broken.example/"))
        .await
        .expect("serve");

    let routes = seen.last().expect("routes inserted");
    assert_eq!(
        routes.as_slice()[0]
            .proxy_address()
            .map(|a| a.address.to_string()),
        Some("fallback:8080".to_owned()),
    );
    assert_eq!(routes.as_slice()[1], ProxyRoute::Direct);
}
