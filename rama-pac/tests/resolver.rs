//! Script providers and the resolver that drives them.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rama_core::error::{ErrorExt as _, extra::OpaqueError};
use rama_core::{Layer, Service, service::service_fn};
use rama_js::JsRuntime;
use rama_net::uri::Uri;
use rama_pac::{
    PacDirective, PacResolver, PacScript, PacScriptCacheLayer, PacUrlSanitize, StaticPacScript,
};

const SCRIPT_URI: &str = "http://config.example/proxy.pac";

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn uri(raw: &str) -> Uri {
    raw.parse().expect("test uri must parse")
}

/// Provider counting how often it is really asked for a script.
#[derive(Debug, Clone, Default)]
struct CountingProvider {
    calls: Arc<AtomicUsize>,
    script: Arc<RwLock<String>>,
}

impl CountingProvider {
    fn new(script: &str) -> Self {
        let provider = Self::default();
        provider.set_script(script);
        provider
    }

    fn set_script(&self, script: &str) {
        if let Ok(mut guard) = self.script.write() {
            *guard = script.to_owned();
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Service<Uri> for CountingProvider {
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let script = self
            .script
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        Ok(PacScript::from(script))
    }
}

const DIRECT_SCRIPT: &str = r#"function FindProxyForURL(url, host) { return "DIRECT"; }"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_provider_resolves() {
    let resolver = PacResolver::builder()
        .build_static(DIRECT_SCRIPT)
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://example.com/x"))
        .await
        .expect("resolve");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_is_asked_every_lookup() {
    let provider = CountingProvider::new(DIRECT_SCRIPT);
    let resolver = PacResolver::builder()
        .build(provider.clone(), uri(SCRIPT_URI))
        .expect("build resolver");

    for _ in 0..3 {
        resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect("resolve");
    }
    assert_eq!(provider.calls(), 3, "always-fetch is the default");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_bounds_the_provider_calls() {
    let provider = CountingProvider::new(DIRECT_SCRIPT);
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::from_secs(60))
        .into_layer(provider.clone());
    let resolver = PacResolver::builder()
        .build(cached, uri(SCRIPT_URI))
        .expect("build resolver");

    for _ in 0..3 {
        resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect("resolve");
    }
    assert_eq!(provider.calls(), 1, "ttl not elapsed: one real fetch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_refetches_once_the_ttl_elapsed() {
    let provider = CountingProvider::new(DIRECT_SCRIPT);
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::ZERO)
        .into_layer(provider.clone());
    let resolver = PacResolver::builder()
        .build(cached, uri(SCRIPT_URI))
        .expect("build resolver");

    for _ in 0..2 {
        resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect("resolve");
    }
    assert_eq!(provider.calls(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_serves_stale_when_a_refresh_fails() {
    let failing = AtomicUsize::new(0);
    let flaky = service_fn(move |_uri: Uri| {
        let attempt = failing.fetch_add(1, Ordering::SeqCst);
        async move {
            if attempt == 0 {
                Ok(PacScript::from(DIRECT_SCRIPT))
            } else {
                Err(std::io::Error::other("boom").into_opaque_error())
            }
        }
    });
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::ZERO)
        .with_serve_stale(true)
        .into_layer(flaky);

    let first = cached.serve(uri(SCRIPT_URI)).await.expect("first fetch");
    let second = cached
        .serve(uri(SCRIPT_URI))
        .await
        .expect("stale answer served");
    assert_eq!(first, second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_can_propagate_the_failure_instead() {
    let failing = AtomicUsize::new(0);
    let flaky = service_fn(move |_uri: Uri| {
        let attempt = failing.fetch_add(1, Ordering::SeqCst);
        async move {
            if attempt == 0 {
                Ok(PacScript::from(DIRECT_SCRIPT))
            } else {
                Err(std::io::Error::other("boom").into_opaque_error())
            }
        }
    });
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::ZERO)
        .with_serve_stale(false)
        .into_layer(flaky);

    let _first = cached.serve(uri(SCRIPT_URI)).await.expect("first fetch");
    let _err = cached
        .serve(uri(SCRIPT_URI))
        .await
        .expect_err("refresh failure propagates");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_script_takes_effect() {
    let provider = CountingProvider::new(DIRECT_SCRIPT);
    let resolver = PacResolver::builder()
        .build(provider.clone(), uri(SCRIPT_URI))
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("resolve");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);

    provider.set_script(r#"function FindProxyForURL(u, h) { return "PROXY edge:3128; DIRECT"; }"#);

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("resolve after swap");
    assert_eq!(directives.len(), 2);
    assert!(matches!(directives.first(), Some(PacDirective::Proxy(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runaway_script_is_bounded_and_the_worker_recovers() {
    let provider = CountingProvider::new(
        r#"
        function FindProxyForURL(url, host) {
            if (host === "slow.example") {
                function spin() { while (true) {} }
                spin();
            }
            return "DIRECT";
        }
        "#,
    );
    let resolver = PacResolver::builder()
        .with_execution_time_limit(Duration::from_millis(200))
        .build(provider, uri(SCRIPT_URI))
        .expect("build resolver");

    // the runaway call is cut short rather than wedging the worker
    let _err = resolver
        .find_proxy(&uri("http://slow.example/"))
        .await
        .expect_err("runaway script must fail");

    // and the next lookup works again: the poisoned worker was rebuilt
    let directives = resolver
        .find_proxy(&uri("http://fast.example/"))
        .await
        .expect("resolver recovered");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn find_proxy_for_url_ex_is_preferred() {
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) { return "PROXY classic:1"; }
            function FindProxyForURLEx(url, host) { return "PROXY ex:2"; }
            "#,
        )
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("resolve");
    assert_eq!(directives.to_string(), "PROXY ex:2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_script_is_not_loaded_again_until_it_changes() {
    // the script body calls a host fn, so every real load is counted:
    // it then defines no entry point, so the load is rejected
    let loads = Arc::new(AtomicUsize::new(0));
    let counter = loads.clone();
    let runtime = JsRuntime::builder().with_fn("countLoad", move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });

    let provider = CountingProvider::new("countLoad(); var notAnEntryPoint = 1;");
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .build(provider.clone(), uri(SCRIPT_URI))
        .expect("build resolver");

    for _ in 0..3 {
        let _err = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("script defines no entry point");
    }
    assert_eq!(provider.calls(), 3, "the provider is still consulted");
    assert_eq!(
        loads.load(Ordering::SeqCst),
        1,
        "a rejected script must not be built again",
    );

    // a changed script bypasses the rejection at once, no backoff
    provider.set_script("countLoad(); function FindProxyForURL(u, h) { return \"DIRECT\"; }");
    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("fixed script loads");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    assert_eq!(loads.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_without_an_entry_point_fails_to_load() {
    let resolver = PacResolver::builder()
        .build_static("var notAnEntryPoint = 1;")
        .expect("build resolver");

    let err = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect_err("missing entry point");
    assert!(
        err.to_string().contains("FindProxyForURL")
            || format!("{err:?}").contains("FindProxyForURL"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sanitize_controls_what_the_script_sees() {
    let script = r#"
        function FindProxyForURL(url, host) {
            // encode the url into a host label so it survives parsing
            return url.indexOf("/secret") === -1 ? "DIRECT" : "PROXY leaked:1";
        }
    "#;

    for (sanitize, uri_str, expected_direct) in [
        (
            PacUrlSanitize::HttpsOnly,
            "https://example.com/secret",
            true,
        ),
        // http keeps its path under the browser-parity default
        (
            PacUrlSanitize::HttpsOnly,
            "http://example.com/secret",
            false,
        ),
        (PacUrlSanitize::All, "http://example.com/secret", true),
        (PacUrlSanitize::None, "https://example.com/secret", false),
    ] {
        let resolver = PacResolver::builder()
            .with_sanitize(sanitize)
            .build_static(script)
            .expect("build resolver");
        let directives = resolver.find_proxy(&uri(uri_str)).await.expect("resolve");
        assert_eq!(
            directives.as_slice() == [PacDirective::Direct],
            expected_direct,
            "{sanitize:?} {uri_str}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_never_reach_the_script() {
    let script = r#"
        function FindProxyForURL(url, host) {
            return url.indexOf("hunter2") === -1 ? "DIRECT" : "PROXY leaked:1";
        }
    "#;
    let resolver = PacResolver::builder()
        .with_sanitize(PacUrlSanitize::None)
        .build_static(script)
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://user:hunter2@example.com/x"))
        .await
        .expect("resolve");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_string_result_is_an_error() {
    let resolver = PacResolver::builder()
        .build_static("function FindProxyForURL(url, host) { return 42; }")
        .expect("build resolver");

    let _err = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect_err("numeric result is not a pac directive list");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_pac_script_provider_serves_its_script_for_any_uri() {
    let provider = StaticPacScript::new(DIRECT_SCRIPT);
    for request in ["http://a/", "http://b/pac.js", "file:///tmp/x"] {
        let script = provider.serve(uri(request)).await.expect("serve");
        assert_eq!(script.as_str(), DIRECT_SCRIPT, "{request}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sanitized_url_keeps_its_root_path() {
    // the common pac idiom is `shExpMatch(url, "https://*.corp/*")`,
    // which needs the slash a bare origin would not have
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                return shExpMatch(url, "https://*.example.com/*") ? "PROXY m:1" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("https://www.example.com/deep/path?q=1"))
        .await
        .expect("resolve");
    assert_eq!(directives.to_string(), "PROXY m:1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_treats_a_new_uri_as_a_miss() {
    let provider = CountingProvider::new(DIRECT_SCRIPT);
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::from_secs(60))
        .into_layer(provider.clone());

    let _ = cached.serve(uri("http://a/pac")).await.expect("serve a");
    let _ = cached.serve(uri("http://a/pac")).await.expect("serve a");
    let _ = cached.serve(uri("http://b/pac")).await.expect("serve b");
    assert_eq!(provider.calls(), 2, "a different uri is a different policy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_generated_script_routes_as_specified() {
    use rama_net::address::Domain;
    use rama_pac::PacGenerator;

    let internal = "PROXY internal:8080; DIRECT"
        .parse::<rama_pac::PacDirectives>()
        .expect("parse route");
    let script = PacGenerator::new()
        .with_route(
            internal,
            [
                Domain::from_static("example.com"),
                Domain::from_static("aikido.gent"),
            ],
        )
        .generate();

    let resolver = PacResolver::builder()
        .build_static(script.as_str())
        .expect("build resolver");

    for (request, expected) in [
        // exact host and subdomain both match the route
        ("http://example.com/", "PROXY internal:8080; DIRECT"),
        ("http://www.example.com/", "PROXY internal:8080; DIRECT"),
        ("http://aikido.gent/", "PROXY internal:8080; DIRECT"),
        // a trailing dot is normalised away by the generated script
        ("http://example.com./", "PROXY internal:8080; DIRECT"),
        // and anything else falls through to the default route
        ("http://other.example/", "DIRECT"),
        // a suffix that is not a label boundary must not match
        ("http://notexample.com/", "DIRECT"),
    ] {
        let directives = resolver
            .find_proxy(&uri(request))
            .await
            .unwrap_or_else(|err| panic!("resolve {request}: {err}"));
        assert_eq!(directives.to_string(), expected, "{request}");
    }
}
