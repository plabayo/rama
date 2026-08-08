//! Deliberately hostile PAC scripts: what a script must never be able to do
//! to the host serving it.
//!
//! A PAC file is configuration, but configuration that arrives over the
//! network from somewhere a user does not fully control. So each case here
//! asserts the same two things: the answer is a refusal rather than a wrong
//! route, and the resolver still serves the next request.

use std::time::{Duration, Instant};

use rama_net::uri::Uri;
use rama_pac::PacResolver;

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn uri(raw: &str) -> Uri {
    raw.parse().expect("test uri must parse")
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn resolver(script: &str) -> PacResolver {
    PacResolver::builder()
        .build_static(script)
        .expect("build resolver")
}

const ENTRY: &str = "function FindProxyForURL(u, h) { return 'DIRECT' }";

/// Every one of these tampers with machinery the host relies on; none may
/// change, redirect, or break the verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampering_with_the_host_dispatch_changes_nothing() {
    for tamper in [
        "globalThis = 1;",
        "var globalThis = 1;",
        "globalThis = { FindProxyForURL: function() { return 'PROXY attacker.example:8080' } };",
        "Array.prototype[Symbol.iterator] = function() { throw new Error('hijacked') };",
        "Object.prototype.f = function() { return 'PROXY attacker.example:8080' };",
        "Object.defineProperty(Object.prototype, 'a0', { get: function() { throw new Error('x') } });",
        "Function.prototype.call = function() { return 'PROXY attacker.example:8080' };",
        "Function.prototype.apply = function() { return 'PROXY attacker.example:8080' };",
        "delete globalThis.__rama_js_call__; globalThis.__rama_js_call__ = function() { return 0 };",
    ] {
        let resolver = resolver(&format!("{ENTRY} {tamper}"));
        for round in 1..=2 {
            let directives = resolver
                .find_proxy(&uri("http://target.example/"))
                .await
                .unwrap_or_else(|err| panic!("`{tamper}` round {round}: {err}"));
            assert_eq!(directives.to_string(), "DIRECT", "`{tamper}` round {round}");
        }
    }
}

/// A getter cannot be invoked under any deadline, so it must never be
/// invoked at all — not for the entry point, and not while probing for one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_point_getter_is_never_invoked() {
    let started = Instant::now();
    let resolver = resolver(&format!(
        "{ENTRY} Object.defineProperty(globalThis, 'FindProxyForURLEx', \
         {{ get: function() {{ while (true) {{}} }} }});"
    ));
    let directives = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect("resolve");

    assert_eq!(directives.to_string(), "DIRECT");
    assert!(started.elapsed() < Duration::from_secs(5), "the getter ran");
}

/// Nonsense arguments are a false predicate, never a panic: a panicking host
/// function takes the whole worker down with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absurd_host_function_arguments_are_survivable() {
    let script = r#"
        function FindProxyForURL(url, host) {
            var probes = [
                function() { return timeRange(2000000000, 0, 2000000000, 0) },
                function() { return timeRange(0, 0, 0, 2000000000, 0, 0) },
                function() { return timeRange(-2000000000, -2000000000) },
                function() { return dateRange(2000000000, 2000000000) },
                function() { return weekdayRange("SAT", undefined) },
                function() { return dnsDomainIs("aé.com", "6.com") },
                function() { return dnsDomainIs("", "") },
                function() { return isPlainHostName("") },
                function() { return dnsDomainLevels("") },
                function() { return localHostOrDomainIs("", ".") },
                function() { return shExpMatch("", "") },
                function() { return shExpMatch("bücher.de", "b?cher.de") },
                function() { return isInNet("10.1.2.3", "10.99.2.99", "255.0.255.0") },
                function() { return isInNet(null, undefined, NaN) },
                function() { return isInNetEx("not an ip", "nonsense") },
                function() { return sortIpAddressList("") },
                function() { return myIpAddress() },
                function() { return dnsDomainLevels(null) }
            ];
            for (var i = 0; i < probes.length; i++) {
                try { probes[i](); } catch (e) { return "PROXY threw" + i + ":1" }
            }
            return "DIRECT";
        }
    "#;
    let resolver = resolver(script);

    let directives = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect("resolve");
    assert_eq!(
        directives.to_string(),
        "DIRECT",
        "a host function threw where the pac contract wants false",
    );
    // ... and the worker is still there for the next request
    assert_eq!(
        resolver
            .find_proxy(&uri("http://second.example/"))
            .await
            .expect("second resolve")
            .to_string(),
        "DIRECT",
    );
}

/// Quadratic native matching cannot be interrupted by any deadline, so the
/// matcher has to refuse the input instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pathological_glob_cannot_wedge_the_worker() {
    let script = r#"
        function FindProxyForURL(url, host) {
            var haystack = "a".repeat(2000000);
            var needle = "*" + "a".repeat(500000) + "b";
            shExpMatch(haystack, needle);
            return "DIRECT";
        }
    "#;
    let resolver = resolver(script);

    let started = Instant::now();
    let result = resolver.find_proxy(&uri("http://target.example/")).await;
    let elapsed = started.elapsed();

    // either answer is fine; taking minutes is not
    assert!(result.is_ok() || result.is_err());
    assert!(elapsed < Duration::from_secs(20), "took {elapsed:?}");
}

/// A runaway entry point must be cut off, and must not take the resolver
/// with it: the next request gets a fresh worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runaway_script_does_not_end_the_service() {
    let script = "function FindProxyForURL(u, h) { if (h === 'spin.example') { while (true) {} } return 'DIRECT' }";
    let resolver = PacResolver::builder()
        .with_execution_time_limit(Duration::from_millis(200))
        .build_static(script)
        .expect("build resolver");

    let err = resolver
        .find_proxy(&uri("http://spin.example/"))
        .await
        .expect_err("a runaway script must fail its request");
    assert!(!format!("{err}").is_empty());

    assert_eq!(
        resolver
            .find_proxy(&uri("http://target.example/"))
            .await
            .expect("the resolver must recover")
            .to_string(),
        "DIRECT",
    );
}

/// A script cannot decide how much dialling one request is worth.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_enormous_directive_list_is_bounded() {
    let script = r#"
        function FindProxyForURL(url, host) {
            var out = [];
            for (var i = 0; i < 20000; i++) { out.push("PROXY p" + i + ".example:8080") }
            return out.join("; ");
        }
    "#;
    let resolver = resolver(script);

    let directives = resolver
        .find_proxy(&uri("http://target.example/"))
        .await
        .expect("resolve");
    let routes = directives.into_proxy_routes();
    assert!(
        routes.as_slice().len() < 20000,
        "one verdict bought {} dial attempts",
        routes.as_slice().len(),
    );
}

/// Credentials in a request url are the host's business, never the script's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_and_paths_never_reach_a_script() {
    let script = r#"
        function FindProxyForURL(url, host) {
            if (url.indexOf("secret") !== -1) { return "PROXY leaked.example:1" }
            if (url.indexOf("hunter2") !== -1) { return "PROXY leaked.example:2" }
            if (host.indexOf("hunter2") !== -1) { return "PROXY leaked.example:3" }
            return "DIRECT";
        }
    "#;
    let resolver = resolver(script);

    for raw in [
        "https://user:hunter2@target.example/secret/path?token=secret",
        "http://user:hunter2@target.example/",
    ] {
        let directives = resolver.find_proxy(&uri(raw)).await.expect("resolve");
        assert_eq!(directives.to_string(), "DIRECT", "{raw}");
    }
}

/// One request must not become an unbounded burst of dns queries: the proxy
/// would be an amplifier pointed at whatever resolver it is configured with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_cannot_spend_unbounded_dns_queries_on_one_request() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rama_core::error::BoxError;
    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;
    use rama_net::address::Domain;
    use rama_pac::PacEnv;

    /// Counts what a script actually spends.
    #[derive(Debug, Clone, Default)]
    struct CountingResolver(Arc<AtomicUsize>);

    impl DnsAddressResolver for CountingResolver {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
            self.0.fetch_add(1, Ordering::Relaxed);
            stream::iter([Ok(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            stream::iter([])
        }
    }

    const BUDGET: u32 = 8;
    let queries = Arc::new(AtomicUsize::new(0));
    let script = r#"
        function FindProxyForURL(url, host) {
            for (var i = 0; i < 500; i++) { dnsResolve("h" + i + ".example") }
            return "DIRECT";
        }
    "#;
    let resolver = PacResolver::builder()
        .with_env(
            PacEnv::new()
                .with_dns_resolver(CountingResolver(queries.clone()))
                .with_max_lookups_per_evaluation(BUDGET),
        )
        .build_static(script)
        .expect("build resolver");

    for _ in 0..3 {
        resolver
            .find_proxy(&uri("http://target.example/"))
            .await
            .expect("resolve");
    }

    let spent = queries.load(Ordering::Relaxed);
    // each evaluation gets its own budget back, and no more
    assert!(
        spent <= 3 * BUDGET as usize,
        "500 lookups per request became {spent} queries",
    );
    assert!(spent >= BUDGET as usize, "the budget was never spendable");
}
