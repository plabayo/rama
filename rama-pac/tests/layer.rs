//! The layer that turns a script verdict into `ProxyRoutes`.

#![cfg(feature = "http")]

use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_core::{Layer, Service, service::service_fn};
use rama_http::{Body, Request, Response, header::HOST};
use rama_net::address::ProxyAddress;
use rama_net::client::{ProxyRoute, ProxyRoutes};
use rama_net::uri::Uri;
use rama_pac::{DEFAULT_PAC_MAX_ROUTES, PacFailurePolicy, PacProxyRoutesLayer, PacResolver};

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

/// Verdicts keyed on the exact `(url, host)` pair the script is handed, so
/// a wrongly synthesized url shows up as a missing route.
const URL_SCRIPT: &str = r#"
    function FindProxyForURL(url, host) {
        if (host !== "origin.example") { return "DIRECT"; }
        if (url === "http://origin.example/some/path?q=1") { return "PROXY path:1"; }
        if (url === "http://origin.example/") { return "PROXY root:1"; }
        return "PROXY other:1";
    }
"#;

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn url_resolver() -> Arc<PacResolver> {
    Arc::new(
        PacResolver::builder()
            .build_static(URL_SCRIPT)
            .expect("build resolver"),
    )
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn request_with_host(target: &str, host: &str) -> Request {
    Request::get(uri(target))
        .header(HOST, host)
        .body(Body::empty())
        .expect("build request")
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn selected_proxy(seen: &Seen) -> String {
    seen.last()
        .expect("routes inserted")
        .as_slice()
        .first()
        .expect("at least one route")
        .proxy_address()
        .expect("a proxied route")
        .address
        .to_string()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_origin_form_request_is_routed_like_its_absolute_form() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(url_resolver()), seen.clone());

    // the shape a proxy or mitm hands to a client stack: no host in the uri,
    // the target only in the `Host` header
    serve(&svc, request_with_host("/some/path?q=1", "origin.example"))
        .await
        .expect("serve");
    assert_eq!(selected_proxy(&seen), "path:1");

    // ... and the absolute-form control resolves to the very same verdict
    serve(&svc, request("http://origin.example/some/path?q=1"))
        .await
        .expect("serve");
    assert_eq!(selected_proxy(&seen), "path:1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_header_default_port_is_not_shown_to_the_script() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(url_resolver()), seen.clone());

    serve(&svc, request_with_host("/", "origin.example:80"))
        .await
        .expect("serve");
    assert_eq!(selected_proxy(&seen), "root:1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_asterisk_form_request_is_routed_on_its_host() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(url_resolver()), seen.clone());

    let req = Request::options(uri("*"))
        .header(HOST, "origin.example")
        .body(Body::empty())
        .expect("build request");
    serve(&svc, req).await.expect("serve");
    // `*` is no path, so the script sees the origin's root
    assert_eq!(selected_proxy(&seen), "root:1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_without_any_authority_fails_cleanly() {
    let seen = Seen::default();
    let svc = stack(PacProxyRoutesLayer::new(url_resolver()), seen.clone());

    let req = Request::get(uri("/some/path"))
        .body(Body::empty())
        .expect("build request");
    let err = serve(&svc, req)
        .await
        .expect_err("a request with no resolvable authority must fail");
    assert!(format!("{err}").contains("authority"), "{err}");
    assert!(
        seen.last().is_none(),
        "the request must not have been served"
    );

    // ... and the failure policy still governs it
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(url_resolver()).with_failure_policy(PacFailurePolicy::Direct),
        seen.clone(),
    );
    let req = Request::get(uri("/some/path"))
        .body(Body::empty())
        .expect("build request");
    serve(&svc, req).await.expect("serve");
    assert_eq!(
        seen.last().map(|routes| routes.as_slice().to_vec()),
        Some(vec![ProxyRoute::Direct]),
    );
}

const MANY_ROUTES_SCRIPT: &str = r#"
    function FindProxyForURL(url, host) {
        var out = [];
        for (var i = 0; i < 40; i++) { out.push("PROXY p" + i + ":8080"); }
        return out.join("; ");
    }
"#;

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn many_routes_resolver() -> Arc<PacResolver> {
    Arc::new(
        PacResolver::builder()
            .build_static(MANY_ROUTES_SCRIPT)
            .expect("build resolver"),
    )
}

fn proxy_addresses(routes: &ProxyRoutes) -> Vec<String> {
    routes
        .iter()
        .filter_map(|route| route.proxy_address().map(|a| a.address.to_string()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_verdict_is_truncated_to_the_route_cap() {
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(many_routes_resolver()),
        seen.clone(),
    );

    serve(&svc, request("http://other.example/"))
        .await
        .expect("serve");

    let routes = seen.last().expect("routes inserted");
    // one verdict must not become an unbounded number of connect attempts
    assert_eq!(routes.as_slice().len(), DEFAULT_PAC_MAX_ROUTES.get());
    // and the kept routes are the first ones, in order
    let expected: Vec<String> = (0..DEFAULT_PAC_MAX_ROUTES.get())
        .map(|i| format!("p{i}:8080"))
        .collect();
    assert_eq!(proxy_addresses(&routes), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_route_cap_is_configurable() {
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(many_routes_resolver())
            .with_max_routes(NonZeroUsize::new(2).expect("non-zero")),
        seen.clone(),
    );

    serve(&svc, request("http://other.example/"))
        .await
        .expect("serve");
    let routes = seen.last().expect("routes inserted");
    assert_eq!(
        proxy_addresses(&routes),
        vec!["p0:8080".to_owned(), "p1:8080".to_owned()],
    );

    // ... and it can be lifted for a script that is trusted with the list
    let seen = Seen::default();
    let svc = stack(
        PacProxyRoutesLayer::new(many_routes_resolver()).without_max_routes(),
        seen.clone(),
    );
    serve(&svc, request("http://other.example/"))
        .await
        .expect("serve");
    assert_eq!(seen.last().expect("routes inserted").as_slice().len(), 40);
}
