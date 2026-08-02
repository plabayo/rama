//! The PAC host functions, exercised from inside a real js runtime.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use jiff::{Timestamp, Zoned, civil, tz::TimeZone};
use rama_core::error::BoxError;
use rama_core::futures::{Stream, stream};
use rama_dns::client::resolver::DnsAddressResolver;
use rama_js::{JsRuntime, JsValue, JsWorker};
use rama_net::address::Domain;
use rama_pac::PacEnv;

/// Resolver with a fixed answer, so tests never touch the network.
#[derive(Debug, Clone, Default)]
struct StaticResolver {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl DnsAddressResolver for StaticResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::iter(self.ipv4.map(Ok))
    }

    fn lookup_ipv6(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter(self.ipv6.map(Ok))
    }
}

const RESOLVED_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);

/// Saturday 2026-08-01, 12:30:45 UTC — pinned so the date and time
/// predicates are deterministic.
fn pinned_now() -> Zoned {
    // a fixed civil timestamp in UTC always converts
    civil::date(2026, 8, 1)
        .at(12, 30, 45, 0)
        .to_zoned(TimeZone::UTC)
        .unwrap_or_else(|_| Timestamp::UNIX_EPOCH.to_zoned(TimeZone::UTC))
}

fn env() -> PacEnv {
    PacEnv::new()
        .with_dns_resolver(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            ipv6: Some(RESOLVED_IPV6),
        })
        .with_my_ip(Ipv4Addr::new(192, 168, 1, 10).into())
        .with_clock(Arc::new(pinned_now))
}

#[expect(clippy::unwrap_used, reason = "test helper outside a #[test] fn")]
async fn worker() -> JsWorker {
    let builder = env().register(JsRuntime::builder()).unwrap();
    JsWorker::spawn(builder).unwrap()
}

#[expect(clippy::unwrap_used, reason = "test helper outside a #[test] fn")]
async fn eval(worker: &JsWorker, script: &'static str) -> JsValue {
    worker.eval(script).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pure_predicates_are_callable_from_script() {
    let worker = worker().await;

    for (script, expected) in [
        (r#"isPlainHostName("www")"#, true),
        (r#"isPlainHostName("www.example.com")"#, false),
        (r#"dnsDomainIs("www.example.com", ".example.com")"#, true),
        (r#"dnsDomainIs("www.example.org", ".example.com")"#, false),
        (r#"localHostOrDomainIs("www", "www.example.com")"#, true),
        (r#"shExpMatch("http://x/people/y", "*/people/*")"#, true),
        (r#"shExpMatch("www.example.org", "*.example.com")"#, false),
        // an ipv6 literal has no dots but is not an unqualified name
        (r#"isPlainHostName("2001:db8::1")"#, false),
        (r#"isPlainHostName("192.168.0.1")"#, false),
        // a partially qualified host still matches its search domain
        (
            r#"localHostOrDomainIs("www.example", "www.example.com")"#,
            true,
        ),
        // non-ascii input must not kill the worker
        (r#"dnsDomainIs("aé.com", "6.com")"#, false),
    ] {
        assert_eq!(
            eval(&worker, script).await,
            JsValue::Bool(expected),
            "{script}"
        );
    }

    assert_eq!(
        eval(&worker, r#"dnsDomainLevels("www.example.com")"#).await,
        JsValue::Number(2.0),
    );
    assert_eq!(
        eval(&worker, r#"getClientVersion()"#).await.as_str(),
        Some("1.0"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_host_functions_use_the_configured_resolver() {
    let worker = worker().await;

    assert_eq!(
        eval(&worker, r#"dnsResolve("example.com")"#).await.as_str(),
        Some("10.1.2.3"),
    );
    assert_eq!(
        eval(&worker, r#"isResolvable("example.com")"#).await,
        JsValue::Bool(true),
    );
    // the Ex variants add the ipv6 answer
    assert_eq!(
        eval(&worker, r#"dnsResolveEx("example.com")"#)
            .await
            .as_str(),
        Some("10.1.2.3;2001:db8::1"),
    );
    // ip literals never hit the resolver
    assert_eq!(
        eval(&worker, r#"dnsResolve("8.8.4.4")"#).await.as_str(),
        Some("8.8.4.4"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolvable_hosts_yield_null_not_a_throw() {
    let builder = PacEnv::new()
        .with_dns_resolver(StaticResolver::default())
        .register(JsRuntime::builder())
        .unwrap();
    let worker = JsWorker::spawn(builder).unwrap();

    assert_eq!(
        eval(&worker, r#"dnsResolve("nope.example")"#).await,
        JsValue::Null,
    );
    assert_eq!(
        eval(&worker, r#"isResolvable("nope.example")"#).await,
        JsValue::Bool(false),
    );
    // the script keeps running: a failed lookup is a value, not an error
    assert_eq!(
        eval(
            &worker,
            r#"dnsResolve("nope.example") === null ? "ok" : "bad""#
        )
        .await
        .as_str(),
        Some("ok"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_membership_predicates() {
    let worker = worker().await;

    for (script, expected) in [
        // example.com resolves to 10.1.2.3
        (r#"isInNet("example.com", "10.1.0.0", "255.255.0.0")"#, true),
        (
            r#"isInNet("example.com", "10.2.0.0", "255.255.0.0")"#,
            false,
        ),
        (
            r#"isInNet("10.1.2.3", "10.1.2.3", "255.255.255.255")"#,
            true,
        ),
        (r#"isInNetEx("example.com", "10.1.0.0/16")"#, true),
        (r#"isInNetEx("example.com", "2001:db8::/32")"#, true),
        (r#"isInNetEx("example.com", "2001:dba::/32")"#, false),
        // malformed arguments are false, never a throw
        (r#"isInNet("example.com", "nonsense", "255.0.0.0")"#, false),
        (r#"isInNetEx("example.com", "not-a-prefix")"#, false),
    ] {
        assert_eq!(
            eval(&worker, script).await,
            JsValue::Bool(expected),
            "{script}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_address_and_sorting() {
    let worker = worker().await;

    assert_eq!(
        eval(&worker, "myIpAddress()").await.as_str(),
        Some("192.168.1.10"),
    );
    assert_eq!(
        eval(&worker, "myIpAddressEx()").await.as_str(),
        Some("192.168.1.10"),
    );
    assert_eq!(
        eval(&worker, r#"sortIpAddressList("10.2.3.9;::1;127.0.0.1")"#)
            .await
            .as_str(),
        Some("::1;10.2.3.9;127.0.0.1"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn time_predicates_read_the_injected_clock() {
    let worker = worker().await;

    for (script, expected) in [
        // pinned to saturday 2026-08-01 12:30:45 UTC
        (r#"weekdayRange("SAT", "GMT")"#, true),
        (r#"weekdayRange("MON", "FRI", "GMT")"#, false),
        (r#"dateRange(1, "AUG", "GMT")"#, false),
        (r#"dateRange("AUG", "GMT")"#, true),
        (r#"dateRange(2026, "GMT")"#, true),
        (r#"timeRange(12, "GMT")"#, true),
        (r#"timeRange(0, 6, "GMT")"#, false),
        (r#"timeRange(12, 0, 13, 0, "GMT")"#, true),
    ] {
        assert_eq!(
            eval(&worker, script).await,
            JsValue::Bool(expected),
            "{script}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_realistic_pac_script_routes_requests() {
    let worker = worker().await;
    worker
        .exec(
            r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host) || dnsDomainIs(host, ".internal")) {
                    return "DIRECT";
                }
                if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) {
                    return "PROXY internal:8080; DIRECT";
                }
                if (shExpMatch(url, "https://*")) {
                    return "HTTPS secure:443";
                }
                return "PROXY edge:3128; DIRECT";
            }
            "#,
        )
        .await
        .unwrap();

    for (url, host, expected) in [
        ("http://intranet/", "intranet", "DIRECT"),
        ("http://db.internal/x", "db.internal", "DIRECT"),
        // resolves to 10.1.2.3 through the static resolver
        (
            "http://example.com/",
            "example.com",
            "PROXY internal:8080; DIRECT",
        ),
    ] {
        let value = worker.call("FindProxyForURL", [url, host]).await.unwrap();
        assert_eq!(value.as_str(), Some(expected), "{url}");
    }

    // and the returned string parses into typed directives
    let value = worker
        .call("FindProxyForURL", ["http://example.com/", "example.com"])
        .await
        .unwrap();
    let directives: rama_pac::PacDirectives = value.as_str().unwrap().parse().unwrap();
    assert_eq!(directives.len(), 2);
    assert_eq!(
        directives
            .proxy_addresses(rama_pac::PacSocks5Dns::default())
            .count(),
        1,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alert_does_not_break_a_script() {
    let worker = worker().await;
    assert_eq!(
        eval(&worker, r#"alert("hello from pac"); "done""#)
            .await
            .as_str(),
        Some("done"),
    );
    // control characters are escaped rather than forging log lines
    assert_eq!(
        eval(&worker, "alert(\"a\\r\\nforged\"); \"done\"")
            .await
            .as_str(),
        Some("done"),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_resolve_ex_returns_every_address() {
    let worker = worker().await;
    // the static resolver answers one address per family
    assert_eq!(
        eval(&worker, r#"dnsResolveEx("example.com")"#)
            .await
            .as_str(),
        Some("10.1.2.3;2001:db8::1"),
    );
}

#[test]
fn register_without_a_runtime_fails_loudly() {
    let err = PacEnv::new().register(JsRuntime::builder()).unwrap_err();
    assert!(err.to_string().contains("tokio runtime"), "{err}");
}
