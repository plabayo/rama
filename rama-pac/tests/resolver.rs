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

    let lookups = PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 4;
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

    // this runaway is bytecode, so the execution limit stops it and the
    // worker exits: nothing accumulates, and rebuilding per lookup is the
    // right answer — the leak cap covers the workers that cannot be stopped
    // (see `a_script_wedging_every_load_stops_costing_workers`)
    let loads = loads.load(Ordering::SeqCst);
    assert!(loads > 0, "the script was never given a worker at all");
    assert!(
        resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .is_err(),
        "the resolver must still be answering, not cooling down",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_wedging_every_load_stops_costing_workers() {
    let builds = Arc::new(AtomicUsize::new(0));
    let stalling = Arc::new(AtomicBool::new(true));
    // long enough that the whole loop below runs inside one cooldown window
    let resolver = stalling_load_resolver(&builds, &stalling, Duration::from_secs(5));

    let mut last = String::new();
    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 4) {
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
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "abandoned worker threads must be bounded, got {builds} load attempts",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wedged_replacement_is_charged_independently() {
    let builds = Arc::new(AtomicUsize::new(0));
    let load_builds = builds.clone();
    let runtime = JsRuntime::builder()
        .with_fn("maybeWedgeLoad", move || {
            if load_builds.fetch_add(1, Ordering::SeqCst) != 0 {
                std::thread::sleep(Duration::from_millis(800));
            }
        })
        .with_fn("wedgeCall", || {
            std::thread::sleep(Duration::from_millis(800));
        });
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(100))
        .with_wedge_cooldown(Duration::from_secs(5))
        .build_static(
            "maybeWedgeLoad(); function FindProxyForURL(u, h) { wedgeCall(); return 'DIRECT' }",
        )
        .expect("build resolver");

    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 3) {
        let _error = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("every available worker wedges");
    }

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "a replacement wedge escaped its own charge: {builds} workers",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changing_script_bytes_cannot_hide_wedged_workers() {
    #[derive(Clone)]
    struct ChangingProvider(Arc<AtomicUsize>);

    impl Service<Uri> for ChangingProvider {
        type Output = PacScript;
        type Error = OpaqueError;

        async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
            let revision = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(PacScript::from(format!(
                "countLoad(); function FindProxyForURL(u, h) {{ wedgeCall(); return 'DIRECT' }} // {revision}"
            )))
        }
    }

    let builds = Arc::new(AtomicUsize::new(0));
    let load_builds = builds.clone();
    let runtime = JsRuntime::builder()
        .with_fn("countLoad", move || {
            load_builds.fetch_add(1, Ordering::SeqCst);
        })
        .with_fn("wedgeCall", || {
            std::thread::sleep(Duration::from_millis(800));
        });
    let resolver = Arc::new(
        PacResolver::builder()
            .with_runtime(runtime)
            .with_timeout(Duration::from_millis(100))
            .with_wedge_cooldown(Duration::from_secs(5))
            .build(
                ChangingProvider(Arc::new(AtomicUsize::new(0))),
                uri(SCRIPT_URI),
            )
            .expect("build resolver"),
    );

    let mut lookups = Vec::new();
    for _ in 0..12 {
        let resolver = resolver.clone();
        lookups.push(tokio::spawn(async move {
            let _result = resolver.find_proxy(&uri("http://example.com/")).await;
        }));
    }
    for lookup in lookups {
        lookup.await.expect("join lookup");
    }

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "changing bytes hid wedged workers: {builds} builds",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_healthy_worker_is_charged_when_its_call_wedges() {
    let builds = Arc::new(AtomicUsize::new(0));
    let wedging = Arc::new(AtomicBool::new(false));
    let load_builds = builds.clone();
    let wedge_calls = wedging.clone();
    let runtime = JsRuntime::builder()
        .with_fn("countLoad", move || {
            load_builds.fetch_add(1, Ordering::SeqCst);
        })
        .with_fn("wedgeCall", move || {
            if wedge_calls.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(800));
            }
        });
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(50))
        .with_wedge_cooldown(Duration::from_millis(500))
        .build_static(
            "countLoad(); function FindProxyForURL(u, h) { wedgeCall(); return 'DIRECT' }",
        )
        .expect("build resolver");

    let directives = resolver
        .find_proxy(&uri("http://example.com/"))
        .await
        .expect("prime a healthy worker");
    assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    wedging.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(550)).await;
    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 3) {
        let _error = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("every available worker wedges");
    }

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "a long-lived worker's wedge used its old spawn time: {builds} workers",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wedge_cooldown_lets_go_on_its_own() {
    let builds = Arc::new(AtomicUsize::new(0));
    let stalling = Arc::new(AtomicBool::new(true));
    let cooldown = Duration::from_millis(200);
    let resolver = stalling_load_resolver(&builds, &stalling, cooldown);

    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 1) {
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
    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 1) {
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
    // the good script never calls stall(), so every build counted here was
    // spent on the broken deploy; the window slides, so a loop spanning more
    // than one of them may fit an extra build
    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 1,
        "the broken deploy cost {builds} worker threads",
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

    for _ in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 2) {
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
async fn distinct_rejected_scripts_do_not_spend_the_spawn_window() {
    let provider = CountingProvider::new("throw new Error('initial rejection')");
    let resolver = PacResolver::builder()
        .with_wedge_cooldown(Duration::from_secs(30))
        .build(provider.clone(), uri(SCRIPT_URI))
        .expect("build resolver");

    for revision in 0..(PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW + 2) {
        provider.set_script(&format!("throw new Error('rejection {revision}')"));
        let rejected = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .expect_err("script throws while loading");
        assert!(!format!("{rejected:?}").contains("cooling down"));

        provider.set_script(&format!(
            "function FindProxyForURL(u, h) {{ return 'DIRECT' }} // {revision}"
        ));
        let directives = resolver
            .find_proxy(&uri("http://example.com/"))
            .await
            .unwrap_or_else(|error| panic!("valid revision {revision} was refused: {error:?}"));
        assert_eq!(directives.as_slice(), [PacDirective::Direct]);
    }
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

/// A script that wedges only for some hosts must not buy itself more workers
/// by answering the others: each build leaks a thread that cannot be
/// interrupted, so what is bounded is the building, not the dying.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answering_some_requests_does_not_buy_more_workers() {
    let builds = Arc::new(AtomicUsize::new(0));
    let counter = builds.clone();
    let runtime = JsRuntime::builder().with_fn("countLoad", move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_millis(120))
        .with_wedge_cooldown(Duration::from_secs(30))
        .build_static(
            "countLoad(); function FindProxyForURL(u, h) { \
             if (h === 'spin.example') { while (true) {} } return 'DIRECT' }",
        )
        .expect("build resolver");

    // alternate hostile and benign, which used to reset the budget every time
    for _ in 0..6 {
        let _wedged = resolver.find_proxy(&uri("http://spin.example/")).await;
        let _fine = resolver.find_proxy(&uri("http://ok.example/")).await;
    }

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "12 lookups cost {builds} worker threads",
    );
}

/// The script's own top level is script code: it may not spend what the
/// entry point is denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_script_top_level_is_budgeted_too() {
    let queries = Arc::new(AtomicUsize::new(0));
    let resolver = counting_dns_resolver(
        &queries,
        "for (var i = 0; i < 500; i++) { dnsResolve('h' + i + '.example') } \
         function FindProxyForURL(u, h) { return 'DIRECT' }",
        4,
    );

    // whether the evaluation survives its exhausted budget is beside the
    // point here: what matters is that the top level could not outspend it
    drop(resolver.find_proxy(&uri("http://target.example/")).await);
    let spent = queries.load(Ordering::SeqCst);
    assert!(spent <= 4, "the script's top level spent {spent} lookups");
}

/// Resolving the same host twice within one evaluation is free, so a policy
/// testing one host against many subnets does not exhaust its budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeat_lookups_within_an_evaluation_are_free() {
    let queries = Arc::new(AtomicUsize::new(0));
    let resolver = counting_dns_resolver(
        &queries,
        "function FindProxyForURL(url, host) { \
         for (var i = 0; i < 50; i++) { if (isInNet(host, '10.' + i + '.0.0', '255.255.0.0')) { \
         return 'PROXY gw:8080' } } return 'DIRECT' }",
        4,
    );

    let verdict = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect("50 subnet tests of one host must not exhaust a 4-host budget");
    assert_eq!(verdict.to_string(), "DIRECT");
    assert_eq!(queries.load(Ordering::SeqCst), 1, "one host, one lookup");
}

/// Spending the dns budget must fail the evaluation, never quietly answer
/// "unresolvable" — that would let a script turn off the rule that follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exhausted_dns_budget_fails_the_evaluation() {
    let queries = Arc::new(AtomicUsize::new(0));
    let resolver = counting_dns_resolver(
        &queries,
        "function FindProxyForURL(url, host) { \
         for (var i = 0; i < 20; i++) { dnsResolve('pad' + i + '.example') } \
         if (isInNet(host, '10.0.0.0', '255.0.0.0')) { return 'PROXY inspector:8080' } \
         return 'DIRECT' }",
        4,
    );

    let err = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect_err("padding the budget must not answer DIRECT");
    assert!(format!("{err}").contains("pac"), "{err}");
}

/// A script that deletes its own entry point mid-call gets a fresh runtime,
/// which still has it: one poisoned request, not a permanent outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_that_deletes_its_entry_point_recovers() {
    let resolver = PacResolver::builder()
        .build_static(
            "function FindProxyForURL(u, h) { globalThis.FindProxyForURL = 1; return 'DIRECT' }",
        )
        .expect("build resolver");

    for round in 1..=3 {
        let verdict = resolver
            .find_proxy(&uri("http://target.example/"))
            .await
            .unwrap_or_else(|err| panic!("round {round}: {err}"));
        assert_eq!(verdict.to_string(), "DIRECT", "round {round}");
    }
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn counting_dns_resolver(
    queries: &Arc<AtomicUsize>,
    script: &str,
    lookups: u32,
) -> rama_pac::PacResolver {
    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;
    use rama_net::address::Domain;

    #[derive(Debug, Clone)]
    struct Counting(Arc<AtomicUsize>);

    impl DnsAddressResolver for Counting {
        type Error = rama_core::error::BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
            self.0.fetch_add(1, Ordering::SeqCst);
            stream::iter([Ok(std::net::Ipv4Addr::new(203, 0, 113, 1))])
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            stream::iter([])
        }
    }

    PacResolver::builder()
        .with_env(
            rama_pac::PacEnv::new()
                .with_dns_resolver(Counting(queries.clone()))
                .with_max_lookups_per_evaluation(lookups),
        )
        .build_static(script)
        .expect("build resolver")
}

/// A log is not a channel a script may fill: past the cap the lines are
/// dropped, and the evaluation still answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_are_bounded_per_evaluation() {
    let resolver = PacResolver::builder()
        .with_env(rama_pac::PacEnv::new().with_max_alerts_per_evaluation(2))
        .build_static(
            "function FindProxyForURL(u, h) { \
             for (var i = 0; i < 5000; i++) { alert('x'.repeat(1024)) } return 'DIRECT' }",
        )
        .expect("build resolver");

    let started = std::time::Instant::now();
    let verdict = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect("resolve");
    assert_eq!(verdict.to_string(), "DIRECT");
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// Host functions block the worker where no javascript deadline reaches, so
/// the wall clock they may spend is bounded on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_function_blocking_is_bounded_in_wall_clock() {
    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;
    use rama_net::address::Domain;

    /// A resolver that never answers, so every lookup costs its full timeout.
    #[derive(Debug, Clone)]
    struct Blackhole;

    impl DnsAddressResolver for Blackhole {
        type Error = rama_core::error::BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
            stream::pending()
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            stream::pending()
        }
    }

    let resolver = PacResolver::builder()
        .with_env(
            rama_pac::PacEnv::new()
                .with_dns_resolver(Blackhole)
                .with_dns_timeout(Duration::from_millis(200))
                .with_max_lookups_per_evaluation(64)
                .with_max_blocking_per_evaluation(Duration::from_millis(600)),
        )
        .with_timeout(Duration::from_secs(30))
        .build_static(
            "function FindProxyForURL(u, h) { \
             for (var i = 0; i < 64; i++) { dnsResolve('h' + i + '.example') } return 'DIRECT' }",
        )
        .expect("build resolver");

    // 64 lookups x 200ms would hold the worker for 12.8s without the bound
    let started = std::time::Instant::now();
    let _result: Result<_, _> = resolver.find_proxy(&uri("http://target.example/")).await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "blocked for {elapsed:?}");
}

/// A lookup cancelled while its worker is still loading may leave that
/// worker's thread stuck, so it has to be paid for like any other build.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_load_still_costs_its_worker() {
    let builds = Arc::new(AtomicUsize::new(0));
    let counter = builds.clone();
    let runtime = JsRuntime::builder().with_fn("stall", move || {
        counter.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(30));
    });
    let resolver = PacResolver::builder()
        .with_runtime(runtime)
        .with_timeout(Duration::from_secs(20))
        .with_wedge_cooldown(Duration::from_secs(30))
        .build_static("stall(); function FindProxyForURL(u, h) { return 'DIRECT' }")
        .expect("build resolver");

    // each caller goes away long before the worker timeout would fire
    let target = uri("http://example.com/");
    for _ in 0..8 {
        tokio::select! {
            _ = resolver.find_proxy(&target) => {}
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    let builds = builds.load(Ordering::SeqCst);
    assert!(
        builds <= PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW,
        "8 cancelled lookups cost {builds} worker threads",
    );
}

/// A rule ladder compiles once for the runtime, not once per request: the
/// patterns come from the script, which does not change under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_ladder_is_not_recompiled_every_request() {
    let mut script = String::from("function FindProxyForURL(url, host) {\n");
    for rule in 0..200 {
        script.push_str(&format!(
            "  if (shExpMatch(host, \"*.r{rule}.corp.example\")) {{ return \"PROXY gw:8080\" }}\n"
        ));
    }
    script.push_str("  return \"DIRECT\";\n}\n");

    let resolver = PacResolver::builder()
        .build_static(script.as_str())
        .expect("build resolver");
    let target = uri("http://target.example/");

    let first = std::time::Instant::now();
    resolver.find_proxy(&target).await.expect("first lookup");
    let first = first.elapsed();

    let steady = std::time::Instant::now();
    for _ in 0..20 {
        resolver.find_proxy(&target).await.expect("steady lookup");
    }
    let steady = steady.elapsed() / 20;

    // generous: recompiling all 200 rules costs the first request's work again
    assert!(
        steady * 4 < first,
        "steady {steady:?} vs first {first:?}: the ladder looks recompiled",
    );
}

/// An ipv4-only lookup asked nothing about ipv6, so it must not answer for
/// the `*Ex` call that follows it in the same evaluation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_classic_lookup_does_not_answer_for_an_ex_one() {
    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;
    use rama_net::address::Domain;

    /// A host that exists only over ipv6, as plenty of internal names do.
    #[derive(Debug, Clone)]
    struct Ipv6Only;

    impl DnsAddressResolver for Ipv6Only {
        type Error = rama_core::error::BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter([])
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            stream::iter([Ok(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))])
        }
    }

    let resolver = PacResolver::builder()
        .with_env(rama_pac::PacEnv::new().with_dns_resolver(Ipv6Only))
        .build_static(
            "function FindProxyForURL(url, host) { \
             var classic = isResolvable(host); \
             var ex = isResolvableEx(host); \
             return 'PROXY ' + classic + '.' + ex + ':1' }",
        )
        .expect("build resolver");

    let verdict = resolver
        .find_proxy(&uri("http://v6only.example/"))
        .await
        .expect("resolve")
        .to_string();
    assert_eq!(
        verdict, "PROXY false.true:1",
        "the ipv4 answer was reused for the ipv6 question",
    );
}

/// Turning the extensions off must also stop `FindProxyForURLEx` from being
/// chosen: an environment that does not offer the `*Ex` half cannot serve a
/// script written against it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ex_entry_point_follows_the_extensions_setting() {
    const BOTH: &str = "function FindProxyForURL(u, h) { return 'PROXY classic:1' } \
                        function FindProxyForURLEx(u, h) { return 'PROXY extended:1' }";

    let preferred = PacResolver::builder()
        .build_static(BOTH)
        .expect("build resolver");
    assert_eq!(
        preferred
            .find_proxy(&uri("http://target.example/"))
            .await
            .expect("resolve")
            .to_string(),
        "PROXY extended:1",
    );

    let classic_only = PacResolver::builder()
        .with_env(rama_pac::PacEnv::new().with_ipv6_extensions(false))
        .build_static(BOTH)
        .expect("build resolver");
    assert_eq!(
        classic_only
            .find_proxy(&uri("http://target.example/"))
            .await
            .expect("resolve")
            .to_string(),
        "PROXY classic:1",
    );

    // ... and a script that only has the Ex half has no entry point at all
    let ex_only = PacResolver::builder()
        .with_env(rama_pac::PacEnv::new().with_ipv6_extensions(false))
        .build_static("function FindProxyForURLEx(u, h) { return 'PROXY extended:1' }")
        .expect("build resolver");
    let err = ex_only
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect_err("no entry point this environment can call");
    assert!(format!("{err}").contains("pac"), "{err}");
}
