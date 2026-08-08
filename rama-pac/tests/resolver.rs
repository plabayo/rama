//! Script providers and the resolver that drives them.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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

/// A spinning script poisons its worker on the execution time limit; the
/// loop-iteration limit is off so nothing else cuts the call short first.
fn spinning_resolver_builder(loads: &Arc<AtomicUsize>, limit: Duration) -> rama_pac::PacResolver {
    let counter = loads.clone();
    let runtime = JsRuntime::builder()
        .maybe_with_loop_iteration_limit(None)
        .with_fn("countLoad", move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
    #[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
    PacResolver::builder()
        .with_runtime(runtime)
        .with_execution_time_limit(limit)
        .build_static("countLoad(); function FindProxyForURL(u, h) { while (true) {} }")
        .expect("build resolver")
}

/// A script whose top level stalls in a host fn for as long as `stalling`
/// says so: every load abandons a worker thread mid-load, until the flag
/// is cleared and the very same script loads fine.
fn stalling_load_resolver(
    builds: &Arc<AtomicUsize>,
    stalling: &Arc<AtomicBool>,
    cooldown: Duration,
) -> rama_pac::PacResolver {
    let counter = builds.clone();
    let flag = stalling.clone();
    let runtime = JsRuntime::builder().with_fn("maybeStall", move || {
        counter.fetch_add(1, Ordering::SeqCst);
        if flag.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(600));
        }
    });
    #[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
    PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(150))
        .with_wedge_cooldown(cooldown)
        .build_static("maybeStall(); function FindProxyForURL(u, h) { return \"DIRECT\"; }")
        .expect("build resolver")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_lookups_share_one_respawned_worker() {
    let loads = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(spinning_resolver_builder(
        &loads,
        Duration::from_millis(200),
    ));

    let mut tasks = Vec::new();
    for _ in 0..4 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let _err = resolver
                .find_proxy(&uri("http://example.com/"))
                .await
                .expect_err("a script that never returns cannot resolve");
        }));
    }
    for task in tasks {
        task.await.expect("lookup task");
    }

    let loads = loads.load(Ordering::SeqCst);
    assert!(
        loads <= 2,
        "concurrent callers must share one respawned worker, got {loads} worker builds",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_that_keeps_killing_its_worker_is_never_rejected() {
    let loads = Arc::new(AtomicUsize::new(0));
    let resolver = spinning_resolver_builder(&loads, Duration::from_millis(100));

    let lookups = PacResolver::MAX_CONSECUTIVE_WEDGES + 4;
    for _ in 0..lookups {
        let err = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("a script that never returns cannot resolve");
        let err = format!("{err} {err:?}");
        // a lost worker is no verdict about the script: memoizing it would
        // fail every host, including the ones the script handles fine
        assert!(!err.contains("rejected"), "{err}");
    }

    // ... and a wedged worker leaks its thread, so the cost of one that
    // keeps dying is capped per cooldown window rather than paid per lookup
    let loads = loads.load(Ordering::SeqCst);
    assert!(
        loads <= PacResolver::MAX_CONSECUTIVE_WEDGES,
        "{lookups} lookups cost {loads} leaked worker threads",
    );
    assert!(loads > 0, "the script was never given a worker at all");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_wedging_every_load_stops_costing_workers() {
    let builds = Arc::new(AtomicUsize::new(0));
    let stalling = Arc::new(AtomicBool::new(true));
    // long enough that the whole loop below runs inside one cooldown window
    let resolver = stalling_load_resolver(&builds, &stalling, Duration::from_secs(5));

    let mut last = String::new();
    for _ in 0..(PacResolver::MAX_CONSECUTIVE_WEDGES + 4) {
        let err = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("a script that never finishes loading cannot resolve");
        last = format!("{err} {err:?}");
        assert!(!last.contains("rejected"), "{last}");
    }
    assert!(
        last.contains("cooling down"),
        "the error must say what actually happened: {last}",
    );

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_CONSECUTIVE_WEDGES,
        "abandoned worker threads must be bounded, got {builds} load attempts",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wedge_cooldown_lets_go_on_its_own() {
    let builds = Arc::new(AtomicUsize::new(0));
    let stalling = Arc::new(AtomicBool::new(true));
    let cooldown = Duration::from_millis(200);
    let resolver = stalling_load_resolver(&builds, &stalling, cooldown);

    for _ in 0..(PacResolver::MAX_CONSECUTIVE_WEDGES + 1) {
        let _err = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("a script that never finishes loading cannot resolve");
    }
    let wedged_builds = builds.load(Ordering::SeqCst);

    // the same script, no longer stalling: the cap must not have written
    // this script off for the process' lifetime
    stalling.store(false, Ordering::SeqCst);
    tokio::time::sleep(cooldown * 2).await;

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("the resolver recovers once the cooldown elapsed");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    assert!(
        builds.load(Ordering::SeqCst) > wedged_builds,
        "a fresh attempt must actually build a worker",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_good_script_is_never_rejected_for_what_the_previous_one_cost() {
    // every load of the deployed script abandons a worker mid-load
    let builds = Arc::new(AtomicUsize::new(0));
    let counter = builds.clone();
    let runtime = JsRuntime::builder().with_fn("stall", move || {
        counter.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(600));
    });
    let cooldown = Duration::from_millis(200);
    let provider = CountingProvider::new("stall(); function FindProxyForURL(u, h) { return 1; }");
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(150))
        .with_wedge_cooldown(cooldown)
        .build(provider.clone(), uri(SCRIPT_URI))
        .expect("build resolver");

    // one more lookup than the cap, so the cooldown has started before the
    // fixed script is served
    for _ in 0..(PacResolver::MAX_CONSECUTIVE_WEDGES + 1) {
        let _err = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("a script that never finishes loading cannot resolve");
    }

    // the operator fixes the deploy: nothing about these bytes was ever
    // tried, so they must not inherit the old script's verdict
    provider.set_script(DIRECT_SCRIPT);
    tokio::time::sleep(cooldown * 2).await;

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("a fixed deploy must load");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    assert_eq!(
        builds.load(Ordering::SeqCst),
        PacResolver::MAX_CONSECUTIVE_WEDGES,
        "the good script does not call stall(), so no extra load attempts",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runaway_host_does_not_take_the_other_hosts_down_with_it() {
    // one host is chosen to burn the execution limit; picking it is within
    // reach of anyone who can aim a request at the proxy
    let runtime = JsRuntime::builder().maybe_with_loop_iteration_limit(None);
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_execution_time_limit(Duration::from_millis(150))
        .with_wedge_cooldown(Duration::from_millis(200))
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "bad.example") { while (true) {} }
                return "PROXY gw:8080";
            }
            "#,
        )
        .expect("build resolver");

    for _ in 0..(PacResolver::MAX_CONSECUTIVE_WEDGES + 2) {
        let err = resolver
            .find_proxy(&uri("http://bad.example/"))
            .await
            .expect_err("the runaway host cannot resolve");
        let err = format!("{err} {err:?}");
        assert!(!err.contains("rejected"), "{err}");
    }

    // every other host keeps resolving: a per-request cpu cost must not
    // become a total, lasting outage
    tokio::time::sleep(Duration::from_millis(400)).await;
    let directives = resolver
        .find_proxy(&uri("http://good.example/"))
        .await
        .expect("an unrelated host still resolves");
    assert_eq!(directives.to_string(), "PROXY gw:8080");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_wedged_in_a_host_fn_fails_the_lookup_instead_of_hanging() {
    // a host fn is uninterruptible: no javascript limit cuts it short, so
    // only the lookup timeout keeps the caller from waiting on it
    let runtime = JsRuntime::builder().with_fn("wedge", || {
        std::thread::sleep(Duration::from_secs(2));
    });
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_execution_time_limit(Duration::from_millis(100))
        .build_static("function FindProxyForURL(u, h) { wedge(); return \"DIRECT\"; }")
        .expect("build resolver");

    let start = Instant::now();
    let _err = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect_err("a wedged worker cannot answer");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "the lookup must fail promptly rather than wait for the wedge: {elapsed:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transient_load_timeout_stays_retryable() {
    // only the very first load stalls: a slow, cold or oversized first
    // load is not a verdict about the script, so it must not be memoized
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let runtime = JsRuntime::builder().with_fn("maybeStall", move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(800));
        }
    });

    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(200))
        .build_static("maybeStall(); function FindProxyForURL(u, h) { return \"DIRECT\"; }")
        .expect("build resolver");

    let _err = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect_err("the first load times out");

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("a timed-out load must stay retryable");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "the script was retried");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_script_sees_a_case_folded_host() {
    // shExpMatch is case-sensitive by spec, so a rule written in lowercase
    // must not be escapable by shouting the host
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                return shExpMatch(host, "*.corp.example") ? "PROXY gw:8080" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    for request in ["http://www.corp.example/x", "http://WWW.CORP.EXAMPLE/x"] {
        let directives = resolver.find_proxy(&uri(request)).await.expect("resolve");
        assert_eq!(directives.to_string(), "PROXY gw:8080", "{request}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rooted_host_reaches_the_script_intact_in_both_arguments() {
    // the two arguments must tell the same story about the name: a rule on
    // the url and a rule on the host may not disagree
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                if (host !== "intranet.") { return "PROXY host-lost-the-dot:1"; }
                if (url.indexOf("http://intranet./x") !== 0) { return "PROXY url-differs:2"; }
                return "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://Intranet./x"))
        .await
        .expect("resolve");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_script_sees_the_path_it_was_given() {
    // an operator rule is written against the spelling that arrives, so a
    // pct-escape or a dot segment may not be rewritten under it
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                return url.indexOf("/Path/A%6Db/./c") === -1 ? "DIRECT" : "PROXY verbatim:1";
            }
            "#,
        )
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://example.com/Path/A%6Db/./c"))
        .await
        .expect("resolve");
    assert_eq!(directives.to_string(), "PROXY verbatim:1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_script_sees_a_case_folded_url() {
    let resolver = PacResolver::builder()
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                return shExpMatch(url, "http://*.corp.example/*") ? "PROXY gw:8081" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    for request in ["http://a.corp.example/x", "http://A.CORP.EXAMPLE/x"] {
        let directives = resolver.find_proxy(&uri(request)).await.expect("resolve");
        assert_eq!(directives.to_string(), "PROXY gw:8081", "{request}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_does_not_serialize_callers_behind_a_failed_fetch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let flaky = service_fn(move |_uri: Uri| {
        let attempt = counter.fetch_add(1, Ordering::SeqCst);
        async move {
            if attempt == 0 {
                Ok(PacScript::from(DIRECT_SCRIPT))
            } else {
                // a blackholed origin only answers once the fetch budget ran out
                tokio::time::sleep(Duration::from_millis(300)).await;
                Err(std::io::Error::other("boom").into_opaque_error())
            }
        }
    });
    let cached = PacScriptCacheLayer::new()
        .with_ttl(Duration::ZERO)
        .into_layer(flaky);

    let _first = cached.serve(uri(SCRIPT_URI)).await.expect("first fetch");

    let start = Instant::now();
    let (a, b, c, d) = tokio::join!(
        cached.serve(uri(SCRIPT_URI)),
        cached.serve(uri(SCRIPT_URI)),
        cached.serve(uri(SCRIPT_URI)),
        cached.serve(uri(SCRIPT_URI)),
    );
    let elapsed = start.elapsed();

    for result in [a, b, c, d] {
        assert_eq!(result.expect("stale script served").as_str(), DIRECT_SCRIPT,);
    }
    assert!(
        elapsed < Duration::from_millis(900),
        "a failing refresh must not queue callers behind each other: {elapsed:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_layer_backs_off_before_refetching_after_a_failure() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let flaky = service_fn(move |_uri: Uri| {
        let attempt = counter.fetch_add(1, Ordering::SeqCst);
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
        .into_layer(flaky);

    for _ in 0..4 {
        let script = cached.serve(uri(SCRIPT_URI)).await.expect("script served");
        assert_eq!(script.as_str(), DIRECT_SCRIPT);
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one failed attempt per backoff window, not one per caller",
    );
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

    let internal = rama_pac::PacDirectives::new([
        rama_pac::PacDirective::proxy((Domain::from_static("internal"), 8080)),
        rama_pac::PacDirective::Direct,
    ]);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exact_route_does_not_match_subdomains() {
    use rama_net::address::Domain;
    use rama_pac::{PacDirective, PacDirectives, PacGenerator};

    let script = PacGenerator::new()
        .with_exact_route(
            PacDirectives::new([PacDirective::proxy((Domain::from_static("internal"), 8080))]),
            [Domain::from_static("example.com")],
        )
        .generate();

    let resolver = PacResolver::builder()
        .build_static(script.as_str())
        .expect("build resolver");

    for (request, expected) in [
        ("http://example.com/", "PROXY internal:8080"),
        // ... but the subdomain that `with_route` would have matched does not
        ("http://www.example.com/", "DIRECT"),
    ] {
        let directives = resolver
            .find_proxy(&uri(request))
            .await
            .unwrap_or_else(|err| panic!("resolve {request}: {err}"));
        assert_eq!(directives.to_string(), expected, "{request}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_route_matches_its_parent_and_subdomains() {
    use rama_net::address::Domain;
    use rama_pac::{PacDirective, PacDirectives, PacGenerator};

    let script = PacGenerator::new()
        .with_route(
            PacDirectives::new([PacDirective::proxy((Domain::from_static("gw"), 8080))]),
            [Domain::from_static("*.corp.example")],
        )
        .generate();

    let resolver = PacResolver::builder()
        .build_static(script.as_str())
        .expect("build resolver");

    for (request, expected) in [
        // `*.x` reads as "x and everything under it", as it does everywhere
        // else in rama — a literal `*` rule would have matched nothing at all
        ("http://corp.example/", "PROXY gw:8080"),
        ("http://www.corp.example/", "PROXY gw:8080"),
        ("http://a.b.corp.example/", "PROXY gw:8080"),
        ("http://notcorp.example/", "DIRECT"),
    ] {
        let directives = resolver
            .find_proxy(&uri(request))
            .await
            .unwrap_or_else(|err| panic!("resolve {request}: {err}"));
        assert_eq!(directives.to_string(), expected, "{request}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_exact_routes_survive_prototype_named_hosts() {
    use rama_net::address::Domain;
    use rama_pac::{PacDirective, PacDirectives, PacGenerator};

    let script = PacGenerator::new()
        .with_exact_route(
            PacDirectives::new([PacDirective::proxy((Domain::from_static("gw"), 8080))]),
            [
                Domain::from_static("__proto__"),
                Domain::from_static("_dmarc"),
            ],
        )
        .generate();

    let resolver = PacResolver::builder()
        .build_static(script.as_str())
        .expect("build resolver");

    for (request, expected) in [
        // `__proto__` is a valid host name, and must not vanish into the
        // object prototype on either the store or the lookup side
        ("http://__proto__/", "PROXY gw:8080"),
        ("http://_dmarc/", "PROXY gw:8080"),
        // ... while inherited members are still no match
        ("http://constructor/", "DIRECT"),
        ("http://hasownproperty/", "DIRECT"),
        ("http://tostring/", "DIRECT"),
    ] {
        let directives = resolver
            .find_proxy(&uri(request))
            .await
            .unwrap_or_else(|err| panic!("resolve {request}: {err}"));
        assert_eq!(directives.to_string(), expected, "{request}");
    }
}
