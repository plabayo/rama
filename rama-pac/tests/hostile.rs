//! Deliberately hostile PAC scripts: what a script must never be able to do
//! to the host serving it.
//!
//! A PAC file is configuration, but configuration that arrives over the
//! network from somewhere a user does not fully control. So each case here
//! asserts the same two things: the answer is a refusal rather than a wrong
//! route, and the resolver still serves the next request.

use std::time::{Duration, Instant};

use rama_core::error::BoxError;
use rama_core::futures::{Stream, stream};
use rama_dns::client::resolver::DnsAddressResolver;
use rama_net::address::Domain;
use rama_net::uri::Uri;
use rama_pac::{PacEnv, PacResolver, PacUrlSanitize};
use rama_utils::octets::kib;

/// Answers every name the same way, so no test depends on the host resolver.
#[derive(Debug, Clone)]
struct OfflineResolver;

impl DnsAddressResolver for OfflineResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter([Ok(std::net::Ipv4Addr::new(203, 0, 113, 1))])
    }

    fn lookup_ipv6(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter([])
    }
}

#[expect(clippy::expect_used, reason = "test helper outside a #[test] fn")]
fn uri(raw: &str) -> Uri {
    raw.parse().expect("test uri must parse")
}

/// The longest any single lookup here may take.
///
/// Generous next to what these tests measure, and it turns a property that
/// broke completely into a failure rather than a run that never ends.
const LOOKUP_CEILING: Duration = Duration::from_secs(60);

/// Resolve, or fail loudly rather than block the suite forever.
#[expect(clippy::panic, reason = "test helper outside a #[test] fn")]
async fn find_proxy(
    resolver: &PacResolver,
    target: &str,
) -> Result<rama_pac::PacDirectives, rama_core::error::BoxError> {
    match tokio::time::timeout(LOOKUP_CEILING, resolver.find_proxy(&uri(target))).await {
        Ok(result) => result,
        Err(_elapsed) => panic!("`{target}` did not finish within {LOOKUP_CEILING:?}"),
    }
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
        // the dispatch payload's own property names, from every angle
        "Object.defineProperty(Object.prototype, 'f', \
         { get: function() { return function() { return 'PROXY attacker.example:8080' } } });",
        "Object.defineProperty(Object.prototype, 'a1', { get: function() { return 'attacker.example' } });",
        "Object.prototype.a0 = 'http://attacker.example/';",
        // the global object's own shape
        "Object.setPrototypeOf(globalThis, new Proxy({}, \
         { get: function() { return function() { return 'PROXY attacker.example:8080' } } }));",
        "globalThis.__proto__ = null;",
        "Object.freeze(globalThis); Object.seal(globalThis);",
        "Object.preventExtensions(globalThis);",
        // the reserved call slot, by every means of redefining a global
        "try { Object.defineProperty(globalThis, '__rama_js_call__', \
         { value: function() { return { f: function() { return 'PROXY attacker.example:8080' } } } }) \
         } catch (e) {}",
        "try { Reflect.defineProperty(globalThis, '__rama_js_call__', { value: 1 }) } catch (e) {}",
        // reflection and the builtins a dispatch might lean on
        "Reflect.apply = function() { return 'PROXY attacker.example:8080' };",
        "Reflect.get = function() { return function() { return 'PROXY attacker.example:8080' } };",
        "Reflect.ownKeys = function() { throw new Error('x') };",
        "Function.prototype.bind = function() { return function() { return 'PROXY attacker.example:8080' } };",
        "Object.getOwnPropertyDescriptor = function() \
         { return { value: function() { return 'PROXY attacker.example:8080' } } };",
        "Object.getPrototypeOf = function() { throw new Error('x') };",
        "Object.keys = function() { throw new Error('x') };",
        "JSON.stringify = function() { return 'PROXY attacker.example:8080' };",
        // coercion hooks a host that stringified anything would run
        "String.prototype.toString = function() { return 'PROXY attacker.example:8080' };",
        "String.prototype.valueOf = function() { return 'PROXY attacker.example:8080' };",
        "Object.prototype.toString = function() { return 'PROXY attacker.example:8080' };",
        "Object.prototype.valueOf = function() { return 'PROXY attacker.example:8080' };",
        "globalThis.toString = function() { return 'PROXY attacker.example:8080' };",
        "Symbol.toPrimitive = 'not a symbol';",
        // an entry point that is not callable, and one hidden behind a getter,
        // must both read as absent rather than as the one to call
        "Object.defineProperty(globalThis, 'FindProxyForURLEx', { value: 42 });",
        "var FindProxyForURLEx = 'PROXY attacker.example:8080';",
        "Object.defineProperty(globalThis, 'FindProxyForURLEx', \
         { get: function() { return function() { return 'PROXY attacker.example:8080' } } });",
    ] {
        let resolver = resolver(&format!("{ENTRY} {tamper}"));
        for round in 1..=2 {
            let directives = find_proxy(&resolver, "http://target.example/")
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
    let directives = find_proxy(&resolver, "http://target.example/")
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

    let directives = find_proxy(&resolver, "http://target.example/")
        .await
        .expect("resolve");
    assert_eq!(
        directives.to_string(),
        "DIRECT",
        "a host function threw where the pac contract wants false",
    );
    // ... and the worker is still there for the next request
    assert_eq!(
        find_proxy(&resolver, "http://second.example/")
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
    let result = find_proxy(&resolver, "http://target.example/").await;
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

    let err = find_proxy(&resolver, "http://spin.example/")
        .await
        .expect_err("a runaway script must fail its request");
    assert!(!format!("{err}").is_empty());

    assert_eq!(
        find_proxy(&resolver, "http://target.example/")
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

    let directives = find_proxy(&resolver, "http://target.example/")
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
            if (url.indexOf("@") !== -1) { return "PROXY leaked.example:4" }
            return "DIRECT";
        }
    "#;
    let resolver = resolver(script);

    for raw in [
        "https://user:hunter2@target.example/secret/path?token=secret",
        "http://user:hunter2@target.example/",
        // a password is still a password when it is pct-escaped, when the
        // username is, when either half is missing, and when the authority
        // carries a port or an ipv6 literal
        "http://us%3Aer:hunter2@target.example/",
        "http://user:hunter%32@target.example/",
        "http://user:hunter2@target.example:8443/",
        "http://:hunter2@target.example/",
        "http://hunter2@target.example/",
        "https://user:hunter2@[2001:db8::1]:8443/secret",
        // and the tail of a url is never the script's business either
        "https://target.example/a?q=secret&t=hunter2#secret",
        "https://target.example/#hunter2",
        // an idn host must not smuggle the path in through the other argument
        "https://user:hunter2@bücher.example/secret",
    ] {
        let directives = find_proxy(&resolver, raw).await.expect("resolve");
        assert_eq!(directives.to_string(), "DIRECT", "{raw}");
    }
}

/// A script that only misbehaves for `evil.example`, so every case can also
/// ask an ordinary host whether the resolver still works.
fn split_brain(body: &str) -> String {
    format!(
        "function FindProxyForURL(url, host) {{ \
         if (host === 'evil.example') {{ {body} }} return 'DIRECT' }}"
    )
}

const EVIL: &str = "http://evil.example/";
const GOOD: &str = "http://good.example/";

/// Uninterruptible native work: a javascript deadline can only stop
/// bytecode, and a callback invoked by a native builtin is not bytecode the
/// deadline gets to look at.
const SHIELDED_SPIN: &str = "var t = 0; for (var i = 0; i < 900000; i++) { t += i } return t";

/// The host requires a real string; every way of pretending to be one is a
/// refusal, because coercing would run script code the host cannot bound and
/// would let a script pick a route it never returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_result_that_is_not_a_string_is_never_a_route() {
    for expr in [
        "42",
        "null",
        "undefined",
        "true",
        "NaN",
        "Infinity",
        "-0",
        "Symbol('PROXY evil.example:1')",
        // a String object, a boxed one, and every coercion hook
        "new String('PROXY evil.example:1')",
        "Object('PROXY evil.example:1')",
        "({ toString: function() { return 'PROXY evil.example:1' } })",
        "({ valueOf: function() { return 'PROXY evil.example:1' } })",
        "(function() { var o = {}; o[Symbol.toPrimitive] = \
         function() { return 'PROXY evil.example:1' }; return o })()",
        // a proxy pretending to be a string, and one whose traps throw
        "new Proxy({}, { get: function() { return 'PROXY evil.example:1' }, \
         ownKeys: function() { return ['0', 'length'] } })",
        "new Proxy({}, { ownKeys: function() { throw new Error('x') } })",
        "new Proxy(Object('PROXY evil.example:1'), {})",
        // containers, promises and functions are not verdicts either
        "['PROXY evil.example:1']",
        "({ 0: 'PROXY evil.example:1', length: 1 })",
        "Promise.resolve('PROXY evil.example:1')",
        "new Promise(function() {})",
        "function() { return 'PROXY evil.example:1' }",
        // and a throw is a refusal, however it is dressed up
        "(function() { throw 'PROXY evil.example:1' })()",
        "(function() { throw { toString: function() { return 'PROXY evil.example:1' } } })()",
    ] {
        let resolver = resolver(&split_brain(&format!("return {expr}")));

        let result = find_proxy(&resolver, EVIL).await;
        assert!(
            result.is_err(),
            "`{expr}` became the verdict {:?}",
            result.map(|directives| directives.to_string()),
        );
        // ... and the worker is still there for the next request
        let directives = find_proxy(&resolver, GOOD)
            .await
            .unwrap_or_else(|err| panic!("`{expr}`: {err}"));
        assert_eq!(directives.to_string(), "DIRECT", "`{expr}`");
    }
}

/// A verdict string is either something rama can act on exactly as written,
/// or a refusal: never a route to a host the script did not name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_verdict_never_becomes_another_route() {
    for (literal, expected) in [
        // nothing usable at all
        ("''", None),
        ("'   '", None),
        ("';'", None),
        ("';;; ;'", None),
        ("'PROXY'", None),
        ("'PROXY :8080'", None),
        ("'SOCKS4 legacy.example:1080'", None),
        ("'GARBAGE'", None),
        // ports that are not ports
        ("'PROXY p.example:99999'", None),
        ("'PROXY p.example:-1'", None),
        ("'PROXY p.example:8o80'", None),
        ("'PROXY p.example: 8080'", None),
        // a second address, however it is separated, is not a directive
        ("'DIRECT p.example:8080'", None),
        ("'PROXY a.example:1 b.example:2'", None),
        ("'PROXY a.example:1\\nDIRECT'", None),
        ("'PROXY a.example:1\\tDIRECT'", None),
        // authority syntax that means something else entirely
        ("'PROXY user:pass@p.example:8080'", None),
        ("'PROXY http://p.example:8080'", None),
        ("'PROXY //p.example:8080'", None),
        ("'PROXY p.example:8080/x'", None),
        ("'PROXY p.example:8080?a=b'", None),
        ("'PROXY p.example:8080#@evil.example:80'", None),
        ("'PROXY [p.example]:8080'", None),
        // control characters never quietly disappear from a host
        ("'\\u0000DIRECT'", None),
        ("'DIRECT\\u0000'", None),
        ("'DIRECT\\u0007'", None),
        ("'\\ud800'", None),
        ("'PROXY p.example:8080\\u0000; DIRECT'", None),
        // ... and what is accepted is accepted exactly as written
        ("'direct'", Some("DIRECT")),
        ("'PrOxY p.example:8080'", Some("PROXY p.example:8080")),
        ("'PROXY  p.example:8080  '", Some("PROXY p.example:8080")),
        ("'PROXY p.example:080'", Some("PROXY p.example:80")),
        ("'PROXY [::1]:8080'", Some("PROXY [::1]:8080")),
        ("'PROXY [::1]'", Some("PROXY [::1]:80")),
        ("'PROXY 127.0.0.1:8080'", Some("PROXY 127.0.0.1:8080")),
        ("'PROXY p.example:8080;;;;'", Some("PROXY p.example:8080")),
        ("'SOCKS4 legacy.example:1080; DIRECT'", Some("DIRECT")),
        (
            "'PROXY a.example:1 ; DIRECT'",
            Some("PROXY a.example:1; DIRECT"),
        ),
    ] {
        let resolver = resolver(&split_brain(&format!("return {literal}")));

        let result = find_proxy(&resolver, EVIL).await;
        match expected {
            Some(expected) => assert_eq!(
                result
                    .unwrap_or_else(|err| panic!("`{literal}` should route: {err}"))
                    .to_string(),
                expected,
                "`{literal}`",
            ),
            None => assert!(
                result.is_err(),
                "`{literal}` became the verdict {:?}",
                result.map(|directives| directives.to_string()),
            ),
        }
        assert_eq!(
            find_proxy(&resolver, GOOD)
                .await
                .unwrap_or_else(|err| panic!("`{literal}`: {err}"))
                .to_string(),
            "DIRECT",
            "`{literal}`",
        );
    }
}

/// A script names the proxy; it does not get to choose how much of a name
/// rama carries around, resolves, or writes to a log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verdict_cannot_name_a_host_no_name_could_be() {
    let resolver = resolver(&split_brain(
        "return 'PROXY ' + 'a'.repeat(100000) + '.example:8080'",
    ));

    // refusing it is fine; routing to a name no resolver could ever answer,
    // and carrying it through every log and connect attempt, is not
    let routed = match find_proxy(&resolver, EVIL).await {
        Ok(directives) => directives.to_string().len(),
        Err(_refused) => 0,
    };
    assert!(
        routed < kib(4),
        "a 100k-character host became a {routed} byte route"
    );

    assert_eq!(
        find_proxy(&resolver, GOOD)
            .await
            .expect("resolve")
            .to_string(),
        "DIRECT",
    );
}

/// A refused verdict must not let the script pick what rama writes down:
/// not the size of it, and not where a log record starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_verdict_cannot_forge_or_flood_the_error() {
    for literal in [
        "'GARBAGE\\nERROR rama: pac disabled, all traffic now DIRECT'",
        "'GARBAGE\\u001b[2K\\rDIRECT'",
        "'x'.repeat(6 * 1024 * 1024)",
        "'PROXY a.example:1 ' + 'b'.repeat(1024 * 1024)",
        "'DIRECT ' + 'c'.repeat(1024 * 1024)",
    ] {
        let resolver = resolver(&split_brain(&format!("return {literal}")));

        let started = Instant::now();
        let err = find_proxy(&resolver, EVIL)
            .await
            .err()
            .unwrap_or_else(|| panic!("`{literal}` should be refused"));
        let elapsed = started.elapsed();
        let rendered = format!("{err} {err:?}");

        assert!(
            rendered.len() < kib(4),
            "`{literal}` bought a {} byte error",
            rendered.len(),
        );
        assert!(
            !rendered.chars().any(char::is_control),
            "`{literal}` forged a log record: {rendered}",
        );
        assert!(elapsed < Duration::from_secs(5), "`{literal}`: {elapsed:?}");

        assert_eq!(
            find_proxy(&resolver, GOOD)
                .await
                .unwrap_or_else(|err| panic!("`{literal}`: {err}"))
                .to_string(),
            "DIRECT",
            "`{literal}`",
        );
    }
}

/// A result larger than the boundary allows is a refusal, not a wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_result_is_refused_promptly() {
    let resolver = resolver(&split_brain("return 'x'.repeat(9 * 1024 * 1024)"));

    let started = Instant::now();
    let _err = find_proxy(&resolver, EVIL)
        .await
        .expect_err("a result past the value boundary cannot be a verdict");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

    assert_eq!(
        find_proxy(&resolver, GOOD)
            .await
            .expect("resolve")
            .to_string(),
        "DIRECT",
    );
}

/// Work smuggled into a native builtin's callback is work no javascript
/// deadline can interrupt, so what has to hold is the caller's clock: the
/// lookup fails within its own deadline and the next one gets a live worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn work_hidden_in_a_native_builtin_still_ends_the_lookup() {
    let limit = Duration::from_millis(20);
    for (name, body) in [
        (
            "map",
            format!("new Array(40).fill(0).map(function() {{ {SHIELDED_SPIN} }});"),
        ),
        (
            "every",
            format!("new Array(40).fill(0).every(function() {{ {SHIELDED_SPIN}; return true }});"),
        ),
        (
            "sort",
            format!("new Array(40).fill(0).sort(function() {{ {SHIELDED_SPIN}; return 0 }});"),
        ),
        (
            "reduce",
            format!(
                "new Array(40).fill(0).reduce(function(a) {{ {SHIELDED_SPIN}; return a }}, 0);"
            ),
        ),
        (
            "replace",
            format!("'a'.repeat(40).replace(/a/g, function() {{ {SHIELDED_SPIN}; return 'b' }});"),
        ),
        (
            "stringify",
            format!(
                "JSON.stringify(new Array(40).fill(0), function(k, v) {{ {SHIELDED_SPIN}; return v }});"
            ),
        ),
        (
            "toJSON",
            format!("JSON.stringify({{ toJSON: function() {{ {SHIELDED_SPIN}; return 1 }} }});"),
        ),
        (
            "getter",
            format!(
                "var o = {{}}; Object.defineProperty(o, 'x', \
                 {{ get: function() {{ {SHIELDED_SPIN} }} }}); o.x;"
            ),
        ),
        (
            "proxy trap",
            format!("(new Proxy({{}}, {{ get: function() {{ {SHIELDED_SPIN} }} }})).x;"),
        ),
        (
            "coercion",
            format!(
                "var o = {{}}; o[Symbol.toPrimitive] = function() {{ {SHIELDED_SPIN} }}; '' + o;"
            ),
        ),
        (
            "regex backtracking",
            "/(a+)+$/.test('a'.repeat(25) + 'b');".to_owned(),
        ),
    ] {
        let resolver = PacResolver::builder()
            .with_execution_time_limit(limit)
            // the spawn window has to clear between the cases, or the second
            // one would be refused for what the first one cost
            .with_wedge_cooldown(Duration::from_millis(1))
            .build_static(split_brain(&body).as_str())
            .expect("build resolver");

        let started = Instant::now();
        let result = find_proxy(&resolver, EVIL).await;
        let elapsed = started.elapsed();

        if let Ok(directives) = &result {
            assert_eq!(directives.to_string(), "DIRECT", "{name}");
        }
        assert!(
            elapsed < Duration::from_secs(3),
            "{name}: the caller waited {elapsed:?} on a {limit:?} deadline",
        );

        let started = Instant::now();
        let directives = find_proxy(&resolver, GOOD)
            .await
            .unwrap_or_else(|err| panic!("{name}: the resolver must recover: {err}"));
        assert_eq!(directives.to_string(), "DIRECT", "{name}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{name}: recovery took {:?}",
            started.elapsed(),
        );
    }
}

/// Recursion that grows native frames per javascript frame must hit a limit,
/// not the bottom of the worker's stack: a stack overflow is a process abort,
/// which no failure policy can catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recursion_through_native_frames_is_an_error_not_a_crash() {
    for body in [
        "function f(n) { return n <= 0 ? 0 : f(n - 1) + 1 } return 'PROXY p:' + f(1000000);",
        "function d(n) { return n <= 0 ? 'x' : \
         JSON.stringify({ toJSON: function() { return d(n - 1) } }) } return d(1000000);",
        "function m(n) { return n <= 0 ? [] : [0].map(function() { return m(n - 1) }) } \
         return String(m(1000000));",
        "var o = {}; Object.defineProperty(o, 'x', { get: function() { return o.x } }); return o.x;",
        "var a = []; a.push(a); return JSON.stringify(a);",
    ] {
        let resolver = resolver(&split_brain(body));

        let started = Instant::now();
        let _err = find_proxy(&resolver, EVIL)
            .await
            .expect_err("runaway recursion cannot be a verdict");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{body}: {:?}",
            started.elapsed(),
        );

        assert_eq!(
            find_proxy(&resolver, GOOD)
                .await
                .unwrap_or_else(|err| panic!("{body}: {err}"))
                .to_string(),
            "DIRECT",
        );
    }
}

/// Jobs a script queues are still work it chose; the deadline owns it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_microtask_flood_is_cut_off() {
    let limit = Duration::from_millis(100);
    let resolver = PacResolver::builder()
        .with_execution_time_limit(limit)
        .with_wedge_cooldown(Duration::from_millis(1))
        .build_static(
            split_brain(
                "for (var i = 0; i < 5000000; i++) { Promise.resolve(i).then(function() {}) }",
            )
            .as_str(),
        )
        .expect("build resolver");

    let started = Instant::now();
    let _err = find_proxy(&resolver, EVIL)
        .await
        .expect_err("a flood of queued jobs cannot be a verdict");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");

    assert_eq!(
        find_proxy(&resolver, GOOD)
            .await
            .expect("the resolver must recover")
            .to_string(),
        "DIRECT",
    );
}

/// The rule says these hosts go through the gateway. A client that can pad
/// its own url must not be able to spend the match budget until the rule
/// stops matching and its traffic goes direct instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_padded_url_cannot_stop_a_rule_from_matching() {
    let resolver = PacResolver::builder()
        .with_sanitize(PacUrlSanitize::None)
        .with_env(PacEnv::new().with_max_glob_steps_per_evaluation(2_000))
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                return shExpMatch(url, "*secret.corp.example*") ? "PROXY gw:8080" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    let padded = format!("http://secret.corp.example/{}", "a".repeat(50_000));
    let result = find_proxy(&resolver, &padded).await;
    assert!(
        result
            .as_ref()
            .is_ok_and(|directives| directives.to_string() == "PROXY gw:8080")
            || result.is_err(),
        "padding the url turned the rule off: {:?}",
        result.map(|directives| directives.to_string()),
    );

    // and the budget is per evaluation, so the next request still matches
    assert_eq!(
        find_proxy(&resolver, "http://secret.corp.example/x")
            .await
            .expect("resolve")
            .to_string(),
        "PROXY gw:8080",
    );
    assert_eq!(
        find_proxy(&resolver, "http://other.example/x")
            .await
            .expect("resolve")
            .to_string(),
        "DIRECT",
    );
}

/// The slot backing deadline-bounded calls is host machinery: calling it
/// hands a script nothing, and cannot leave the next call without a payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reserved_call_slot_hands_a_script_nothing() {
    let resolver = resolver(
        r#"
        function FindProxyForURL(url, host) {
            var seen = [];
            for (var i = 0; i < 4; i++) {
                try { seen.push(String(__rama_js_call__())) } catch (e) { seen.push("threw") }
            }
            for (var i = 0; i < seen.length; i++) {
                if (seen[i] !== "threw") { return "PROXY leaked.example:" + (i + 1) }
            }
            return "DIRECT";
        }
        "#,
    );

    for round in 1..=3 {
        assert_eq!(
            find_proxy(&resolver, GOOD)
                .await
                .unwrap_or_else(|err| panic!("round {round}: {err}"))
                .to_string(),
            "DIRECT",
            "round {round}",
        );
    }
}

/// `alert` is the one host function whose whole job is to write somewhere a
/// script does not own; none of its inputs may become the host's problem.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_cannot_make_the_host_work_without_end() {
    let resolver = PacResolver::builder()
        .with_execution_time_limit(Duration::from_millis(150))
        .with_wedge_cooldown(Duration::from_millis(1))
        .build_static(
            split_brain(
                r#"
                var deep = {};
                for (var i = 0; i < 200; i++) { deep = { next: deep } }
                var throwing = {};
                Object.defineProperty(throwing, 'x', {
                    enumerable: true, get: function() { throw new Error('boom') }
                });
                try { alert(throwing) } catch (e) {}
                try { alert.apply(null, new Array(100000).fill('x')) } catch (e) {}
                for (var i = 0; i < 100000; i++) {
                    alert(deep, 'x'.repeat(4096), '\n[2K ERROR rama: forged', i);
                }
                "#,
            )
            .as_str(),
        )
        .expect("build resolver");

    let started = Instant::now();
    let result = find_proxy(&resolver, EVIL).await;
    let elapsed = started.elapsed();
    if let Ok(directives) = &result {
        assert_eq!(directives.to_string(), "DIRECT");
    }
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

    assert_eq!(
        find_proxy(&resolver, GOOD)
            .await
            .expect("the resolver must recover")
            .to_string(),
        "DIRECT",
    );
}

/// A script that throws its own entry point away costs a fresh worker on
/// every request. Nothing was wedged and no thread leaked, so the resolver
/// has to keep serving rather than spend the window it keeps for real wedges.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_that_discards_its_entry_point_keeps_being_served() {
    let resolver = resolver(
        "function FindProxyForURL(url, host) { globalThis.FindProxyForURL = 42; return 'DIRECT' }",
    );

    for round in 1..=8 {
        let directives = find_proxy(&resolver, GOOD)
            .await
            .unwrap_or_else(|err| panic!("round {round}: {err}"));
        assert_eq!(directives.to_string(), "DIRECT", "round {round}");
    }
}

/// One host chosen to wedge the worker is within reach of anyone who can aim
/// a request at the proxy. It must not become an outage for every other host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_wedging_host_is_not_an_outage_for_every_host() {
    // the default worker spawn window: what an operator actually deploys
    let resolver = PacResolver::builder()
        .with_execution_time_limit(Duration::from_millis(100))
        .build_static(
            split_brain(&format!(
                "new Array(100).fill(0).map(function() {{ {SHIELDED_SPIN} }});"
            ))
            .as_str(),
        )
        .expect("build resolver");

    for round in 1..=2 {
        let _wedged = find_proxy(&resolver, EVIL).await;

        let directives = find_proxy(&resolver, GOOD).await.unwrap_or_else(|err| {
            panic!("round {round}: an unrelated host must still route: {err}")
        });
        assert_eq!(directives.to_string(), "DIRECT", "round {round}");
    }
}

/// Damage a script cannot do inside one request, it will try to accumulate
/// across many: budgets have to come back per evaluation and state a script
/// keeps must not decide what the next request costs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_hostile_sequence_leaves_the_resolver_healthy() {
    let resolver = PacResolver::builder()
        .with_env(
            PacEnv::new()
                .with_dns_resolver(OfflineResolver)
                .with_max_glob_steps_per_evaluation(20_000)
                .with_max_lookups_per_evaluation(8)
                .with_dns_timeout(Duration::from_millis(1)),
        )
        .with_wedge_cooldown(Duration::from_millis(1))
        .build_static(
            r#"
            var hoard = [];
            function FindProxyForURL(url, host) {
                if (host.indexOf("burn.") === 0) {
                    try { shExpMatch(url + "a".repeat(30000), "*zzz*") } catch (e) {}
                }
                if (host.indexOf("hoard.") === 0) {
                    hoard.push(new Array(4000).join("x"));
                }
                if (host.indexOf("dns.") === 0) {
                    for (var i = 0; i < 200; i++) {
                        try { dnsResolve("h" + i + ".invalid") } catch (e) {}
                    }
                }
                if (host.indexOf("alert.") === 0) {
                    for (var i = 0; i < 200; i++) { alert("x".repeat(1024)) }
                }
                return shExpMatch(host, "*.corp.example") ? "PROXY gw:8080" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    let started = Instant::now();
    for round in 0..12 {
        for host in [
            "burn.example",
            "hoard.example",
            "dns.example",
            "alert.example",
        ] {
            // whatever these cost, they may not cost the next host anything
            let _result = find_proxy(&resolver, &format!("http://{host}/{round}")).await;

            let directives = find_proxy(&resolver, "http://desk.corp.example/")
                .await
                .unwrap_or_else(|err| panic!("round {round} after {host}: {err}"));
            assert_eq!(
                directives.to_string(),
                "PROXY gw:8080",
                "round {round} after {host}",
            );
        }
    }
    let elapsed = started.elapsed();

    // a hostile sequence must not make the ordinary case slower and slower
    assert!(elapsed < Duration::from_secs(60), "{elapsed:?}");
    assert_eq!(
        find_proxy(&resolver, "http://desk.corp.example/")
            .await
            .expect("resolve")
            .to_string(),
        "PROXY gw:8080",
    );
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
    // running out is an error, so a script hiding it from itself is the
    // shape that keeps asking: it must not get more queries for that
    let script = r#"
        function FindProxyForURL(url, host) {
            for (var i = 0; i < 500; i++) {
                try { dnsResolve("h" + i + ".example") } catch (e) {}
            }
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
        assert_eq!(
            find_proxy(&resolver, "http://target.example/")
                .await
                .expect("resolve")
                .to_string(),
            "DIRECT",
        );
    }

    let spent = queries.load(Ordering::Relaxed);
    // each evaluation gets its own budget back, and no more
    assert!(
        spent <= 3 * BUDGET as usize,
        "500 lookups per request became {spent} queries",
    );
    assert!(spent >= BUDGET as usize, "the budget was never spendable");
}

/// A request that spends the whole dns budget must not leave the next one
/// unable to resolve anything: the budget is per evaluation, and a rule that
/// needs one lookup has to keep working however the last request behaved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spending_the_dns_budget_does_not_disarm_the_next_request() {
    use rama_core::error::BoxError;
    use rama_core::futures::{Stream, stream};
    use rama_dns::client::resolver::DnsAddressResolver;
    use rama_net::address::Domain;

    #[derive(Debug, Clone)]
    struct FixedResolver;

    impl DnsAddressResolver for FixedResolver {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter([Ok(std::net::Ipv4Addr::new(10, 0, 0, 1))])
        }

        fn lookup_ipv6(
            &self,
            _domain: Domain,
        ) -> impl Stream<Item = Result<std::net::Ipv6Addr, Self::Error>> + Send + '_ {
            stream::iter([])
        }
    }

    let resolver = PacResolver::builder()
        .with_env(
            PacEnv::new()
                .with_dns_resolver(FixedResolver)
                .with_max_lookups_per_evaluation(4),
        )
        .with_wedge_cooldown(Duration::from_millis(1))
        .build_static(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "evil.example") {
                    for (var i = 0; i < 500; i++) {
                        try { dnsResolve("h" + i + ".example") } catch (e) {}
                    }
                }
                return isInNet(host, "10.0.0.0", "255.0.0.0") ? "PROXY gw:8080" : "DIRECT";
            }
            "#,
        )
        .expect("build resolver");

    for round in 1..=5 {
        let _burnt = find_proxy(&resolver, EVIL).await;
        assert_eq!(
            find_proxy(&resolver, GOOD)
                .await
                .unwrap_or_else(|err| panic!("round {round}: {err}"))
                .to_string(),
            "PROXY gw:8080",
            "round {round}",
        );
    }
}
