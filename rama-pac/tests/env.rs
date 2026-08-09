//! The PAC host functions, exercised from inside a real js runtime.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use jiff::{Timestamp, Zoned, civil, tz::TimeZone};
use rama_core::error::BoxError;
use rama_core::futures::{Stream, stream};
use rama_dns::client::resolver::DnsAddressResolver;
use rama_js::{JsRuntime, JsValue, JsWorker};
use rama_net::address::Domain;
use rama_pac::{PacEnv, PacLocalAddresses};

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
        .with_local_addresses(PacLocalAddresses::Fixed(vec![
            Ipv4Addr::new(192, 168, 1, 10).into(),
            RESOLVED_IPV6.into(),
        ]))
        .with_clock(Arc::new(pinned_now))
}

#[expect(clippy::unwrap_used, reason = "test helper outside a #[test] fn")]
async fn worker() -> JsWorker {
    env()
        .register(JsRuntime::builder())
        .unwrap()
        .spawn()
        .unwrap()
        .0
}

#[expect(clippy::unwrap_used, reason = "test helper outside a #[test] fn")]
async fn eval(worker: &JsWorker, script: impl Into<String>) -> JsValue {
    worker.eval(script.into()).await.unwrap()
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
    assert_eq!(
        eval(&worker, r#"wdays.join(",") + ";" + months.join(",")"#)
            .await
            .as_str(),
        Some("SUN,MON,TUE,WED,THU,FRI,SAT;JAN,FEB,MAR,APR,MAY,JUN,JUL,AUG,SEP,OCT,NOV,DEC"),
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
    assert_eq!(
        eval(&worker, r#"isResolvableEx("example.com")"#).await,
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
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver::default())
        .register(JsRuntime::builder())
        .unwrap()
        .spawn()
        .unwrap();

    assert_eq!(
        eval(&worker, r#"dnsResolve("nope.example")"#).await,
        JsValue::Null,
    );
    assert_eq!(
        eval(&worker, r#"isResolvable("nope.example")"#).await,
        JsValue::Bool(false),
    );
    assert_eq!(
        eval(&worker, r#"isResolvableEx("nope.example")"#).await,
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
async fn an_ipv6_only_host_is_resolvable_to_the_ex_variant_only() {
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver {
            ipv4: None,
            ipv6: Some(RESOLVED_IPV6),
        })
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    // the classic variants are ipv4 only, the Ex ones see every family
    assert_eq!(
        eval(&worker, r#"isResolvable("example.com")"#).await,
        JsValue::Bool(false),
    );
    assert_eq!(
        eval(&worker, r#"isResolvableEx("example.com")"#).await,
        JsValue::Bool(true),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ipv4_mapped_answer_belongs_to_its_ipv4_network() {
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver {
            ipv4: None,
            // ::ffff:10.1.2.3
            ipv6: Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a01, 0x0203)),
        })
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    assert_eq!(
        eval(&worker, r#"isInNetEx("example.com", "10.1.0.0/16")"#).await,
        JsValue::Bool(true),
    );
    assert_eq!(
        eval(&worker, r#"isInNetEx("example.com", "10.2.0.0/16")"#).await,
        JsValue::Bool(false),
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
        // an ipv4 answer is compared against an ipv6 prefix as its
        // v4-mapped form, as browsers do
        (r#"isInNetEx("example.com", "::ffff:10.1.0.0/112")"#, true),
        (r#"isInNetEx("example.com", "::ffff:10.2.0.0/112")"#, false),
        // ... and an ipv4 catch-all in ipv6 form matches too
        (r#"isInNetEx("10.1.2.3", "::/0")"#, true),
        // malformed arguments are false, never a throw
        (r#"isInNet("example.com", "nonsense", "255.0.0.0")"#, false),
        (r#"isInNetEx("example.com", "not-a-prefix")"#, false),
        // a non-contiguous mask is applied bitwise, as browsers do
        (
            r#"isInNet("example.com", "10.99.2.99", "255.0.255.0")"#,
            true,
        ),
        (r#"isInNet("10.1.2.3", "10.1.2.3", "255.0.255.0")"#, true),
        (
            r#"isInNet("example.com", "10.99.9.99", "255.0.255.0")"#,
            false,
        ),
        // isInNetEx stays prefix-based: a dotted quad is not a prefix
        (r#"isInNetEx("example.com", "255.0.255.0")"#, false),
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
    // the Ex variant lists every configured address
    assert_eq!(
        eval(&worker, "myIpAddressEx()").await.as_str(),
        Some("192.168.1.10;2001:db8::1"),
    );
    // ipv6 before ipv4, and within a family the narrower scope first — the
    // rule the reference's own example demonstrates
    assert_eq!(
        eval(&worker, r#"sortIpAddressList("10.2.3.9;::1;127.0.0.1")"#)
            .await
            .as_str(),
        Some("::1;127.0.0.1;10.2.3.9"),
    );
    // a malformed list is an empty string, as the reference specifies
    for script in [
        r#"sortIpAddressList("")"#,
        r#"sortIpAddressList("nope")"#,
        r#"sortIpAddressList("10.0.0.1;nope")"#,
    ] {
        assert_eq!(
            eval(&worker, script).await,
            JsValue::String(String::new().into()),
            "{script}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn my_ip_address_reports_real_interfaces_by_default() {
    // the default enumerates this host's interfaces
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver::default())
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    let classic = eval(&worker, "myIpAddress()").await;
    let classic = classic.as_str().expect("a string");
    assert!(
        classic.parse::<std::net::Ipv4Addr>().is_ok(),
        "classic callers expect a dotted quad, got {classic:?}",
    );

    // every Ex entry is an ip address, and the classic one is among them
    let listed = eval(&worker, "myIpAddressEx()").await;
    let listed = listed.as_str().expect("a string");
    assert!(!listed.is_empty());
    for entry in listed.split(';') {
        assert!(
            entry.parse::<std::net::IpAddr>().is_ok(),
            "{entry:?} of {listed:?}",
        );
    }

    // loopback mode discloses nothing about the host
    let (worker, _budget) = PacEnv::new()
        .with_local_addresses(PacLocalAddresses::Loopback)
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");
    assert_eq!(
        eval(&worker, "myIpAddressEx()").await.as_str(),
        Some("127.0.0.1"),
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
async fn a_missing_bound_never_matches_a_shorter_range() {
    let worker = worker().await;

    // pinned to saturday 2026-08-01 12:30:45 UTC, so every one of these
    // would be true if the absent bound collapsed the call to a shorter form
    for script in [
        r#"weekdayRange("SAT", undefined)"#,
        r#"weekdayRange("SAT", undefined, "GMT")"#,
        r#"weekdayRange("SAT", null, "GMT")"#,
        r#"weekdayRange(null, "SAT", "GMT")"#,
        r#"timeRange(12, undefined)"#,
        r#"timeRange(12, undefined, "GMT")"#,
        r#"timeRange(12, 0, null, 13, 0, 0, "GMT")"#,
        r#"dateRange(1, 15, undefined, "GMT")"#,
        r#"dateRange(undefined, "AUG", "GMT")"#,
        // an over-long call matches no form either, including one whose
        // widest form is exactly what dropping the extra argument leaves
        r#"timeRange(12, 0, 0, 13, 0, 0, 0, "GMT")"#,
        r#"timeRange(12, 0, 0, 13, 0, 0, "GMT", 0)"#,
    ] {
        assert_eq!(
            eval(&worker, script).await,
            JsValue::Bool(false),
            "{script}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absurd_time_arguments_do_not_kill_the_worker() {
    let worker = worker().await;

    assert_eq!(
        eval(&worker, r#"timeRange(2000000000, 0, 2000000000, 0, "GMT")"#).await,
        JsValue::Bool(false),
    );
    assert_eq!(
        eval(&worker, r#"timeRange(0, 0, 0, 2000000000, 0, 1, "GMT")"#).await,
        JsValue::Bool(true),
    );
    // the worker is still alive afterwards
    assert_eq!(
        eval(&worker, r#"timeRange(12, "GMT")"#).await,
        JsValue::Bool(true),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn glob_matching_is_bounded_and_character_based() {
    let worker = worker().await;

    // one `?` is one character, not one utf-8 byte
    assert_eq!(
        eval(&worker, r#"shExpMatch("bücher.de", "b?cher.de")"#).await,
        JsValue::Bool(true),
    );
    assert_eq!(
        eval(&worker, r#"shExpMatch("bü", "b??")"#).await,
        JsValue::Bool(false),
    );

    // a backtracking pattern over a huge input cannot stall the worker: the
    // js deadline cannot interrupt native matching, so the match bounds
    // itself and *throws* — answering `false` would let a client pad its own
    // url until a rule stops matching
    let started = std::time::Instant::now();
    let err = worker
        .eval(r#"shExpMatch("a".repeat(7000000), "*" + "a".repeat(900000) + "b")"#)
        .await
        .expect_err("an exhausted match budget must not answer");
    assert!(format!("{err}").contains("budget"), "{err}");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "shExpMatch took {elapsed:?}",
    );

    // ... and the worker keeps serving
    assert_eq!(
        eval(&worker, r#"shExpMatch("a.example", "*.example")"#).await,
        JsValue::Bool(true),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_arguments_are_bounded_not_processed() {
    let worker = worker().await;

    // an address list far beyond any real one is refused, not a sort of a
    // few hundred thousand entries
    assert_eq!(
        eval(&worker, r#"sortIpAddressList(("::1;").repeat(100000))"#).await,
        JsValue::String(String::new().into()),
    );
    // and a huge alert message is truncated rather than logged whole
    assert_eq!(
        eval(&worker, r#"alert("x".repeat(2000000)); "done""#)
            .await
            .as_str(),
        Some("done"),
    );
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
    assert_eq!(directives.proxy_addresses().count(), 1,);
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
async fn ipv4_promotion_can_be_disabled() {
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver {
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            ipv6: None,
        })
        .with_promote_ipv4_in_net(false)
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    // strict families: an ipv4 answer never matches an ipv6 prefix
    assert_eq!(
        eval(&worker, r#"isInNetEx("example.com", "::/0")"#).await,
        JsValue::Bool(false),
    );
    assert_eq!(
        eval(&worker, r#"isInNetEx("example.com", "10.1.0.0/16")"#).await,
        JsValue::Bool(true),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn convert_addr_matches_the_reference_arithmetic() {
    let worker = worker().await;

    // the reference builds a *signed* 32-bit int, so the top bit wraps
    for (input, expected) in [
        ("10.1.2.3", 167_838_211.0),
        ("0.0.0.0", 0.0),
        ("127.0.0.1", 2_130_706_433.0),
        ("255.255.255.255", -1.0),
        ("192.168.1.1", -1_062_731_519.0),
        // javascript coercion, verified against the reference definition:
        // what is not a number contributes nothing, a missing group likewise,
        // and a radix prefix is read as the number it spells
        ("not.an.address.at.all", 0.0),
        ("10.1", 167_837_696.0),
        ("", 0.0),
        ("1.2.3.4.5", 16_909_060.0),
        ("256.1.2.3", 66_051.0),
        (" 10 . 1 . 2 . 3 ", 167_838_211.0),
        ("0x10.1.2.3", 268_501_507.0),
        ("10.1.2.-3", 167_838_461.0),
        ("1e2.1.2.3", 1_677_787_651.0),
        // ToInt32 wraps modulo 2^32 instead of saturating through a Rust
        // integer conversion.
        ("9223372036854775808.0.0.0", 0.0),
        ("1e19.0.0.0", 0.0),
        // ECMAScript trims the BOM but not NEXT LINE (U+0085).
        ("\u{FEFF}1.2.3.4", 16_909_060.0),
        ("\u{0085}1.2.3.4", 131_844.0),
    ] {
        assert_eq!(
            eval(&worker, format!(r#"convert_addr("{input}")"#)).await,
            JsValue::Number(expected),
            "{input}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn is_valid_ip_address_is_the_reference_regex() {
    let worker = worker().await;

    for (input, expected) in [
        ("10.1.2.3", true),
        ("255.255.255.255", true),
        // the reference accepts a leading zero, and rejects everything that
        // is not four groups of one to three digits
        ("010.1.2.3", true),
        ("256.1.2.3", false),
        ("10.1.2", false),
        ("10.1.2.3.4", false),
        ("10.1.2.x", false),
        ("2001:db8::1", false),
        ("", false),
    ] {
        assert_eq!(
            eval(&worker, format!(r#"isValidIpAddress("{input}")"#)).await,
            JsValue::Bool(expected),
            "{input}",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sort_ip_address_list_follows_the_reference_example() {
    let worker = worker().await;

    // the reference's own published example: ipv6 before ipv4, and a
    // link-local address ahead of a global one
    assert_eq!(
        eval(
            &worker,
            r#"sortIpAddressList("2001:4898:28:3:201:2ff:feea:fc14;157.59.139.22;fe80::5efe:157.59.139.22")"#,
        )
        .await,
        JsValue::String(
            "fe80::5efe:157.59.139.22;2001:4898:28:3:201:2ff:feea:fc14;157.59.139.22".into()
        ),
    );

    // a list it cannot sort is an empty string, not `false`
    assert_eq!(
        eval(&worker, r#"sortIpAddressList("nonsense")"#).await,
        JsValue::String(String::new().into()),
    );
    assert_eq!(
        eval(&worker, r#"typeof sortIpAddressList("nonsense")"#).await,
        JsValue::String("string".into()),
    );
}

/// The environment handed out publicly must be armable, or its advertised
/// per-evaluation budgets are a promise nobody can keep.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publicly_registered_env_can_arm_its_budgets() {
    let (worker, budget) = env()
        .with_max_lookups_per_evaluation(2)
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    // unarmed, the budget bounds nothing across calls
    let unarmed = worker
        .eval("var n = 0; for (var i = 0; i < 10; i++) { if (dnsResolve('h' + i + '.example')) n++ } n")
        .await
        .expect("unarmed eval");
    assert_eq!(unarmed, JsValue::Number(10.0));

    // armed by the handle the caller was given, it bounds them
    let armed = budget.clone();
    let spent = worker
        .run(move |runtime| {
            armed.arm();
            runtime.eval(
                "var n = 0; for (var i = 0; i < 10; i++) { \
                 try { if (dnsResolve('h' + i + '.example')) n++ } catch (e) { break } } n",
            )
        })
        .await
        .expect("armed eval");
    assert_eq!(spent, JsValue::Number(2.0), "the budget was not armed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_env_can_build_one_direct_runtime() {
    let bound = env().register(JsRuntime::builder()).expect("register env");
    let value = std::thread::spawn(move || {
        let (mut runtime, budget) = bound.build().expect("build runtime");
        budget.arm();
        runtime.eval(r#"wdays[0] + months[11]"#)
    })
    .join()
    .expect("join runtime thread")
    .expect("evaluate runtime");
    assert_eq!(value.as_str(), Some("SUNDEC"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duration_max_leaves_blocking_host_functions_unbounded() {
    let (worker, budget) = env()
        .with_max_blocking_per_evaluation(std::time::Duration::MAX)
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    let value = worker
        .run(move |runtime| {
            budget.arm();
            runtime.eval(r#"dnsResolve("example.com")"#)
        })
        .await
        .expect("an unbounded blocking budget must allow the first lookup");
    assert_eq!(value.as_str(), Some("10.1.2.3"));
}

/// The classic helpers answer "in the dot-separated format", so a host that
/// exists only over ipv6 is unresolvable to them and resolvable to the `*Ex`
/// helpers that were added to carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_v6_only_host_is_reachable_only_through_the_ex_helpers() {
    let (worker, _budget) = PacEnv::new()
        .with_dns_resolver(StaticResolver {
            ipv4: None,
            ipv6: Some(RESOLVED_IPV6),
        })
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");

    assert_eq!(
        eval(&worker, r#"dnsResolve("v6only.example")"#).await,
        JsValue::Null,
    );
    assert_eq!(
        eval(&worker, r#"isResolvable("v6only.example")"#).await,
        JsValue::Bool(false),
    );
    assert_eq!(
        eval(
            &worker,
            r#"isInNet("v6only.example", "10.0.0.0", "255.0.0.0")"#
        )
        .await,
        JsValue::Bool(false),
    );

    assert_eq!(
        eval(&worker, r#"dnsResolveEx("v6only.example")"#)
            .await
            .as_str(),
        Some("2001:db8::1"),
    );
    assert_eq!(
        eval(&worker, r#"isResolvableEx("v6only.example")"#).await,
        JsValue::Bool(true),
    );
    assert_eq!(
        eval(&worker, r#"isInNetEx("v6only.example", "2001:db8::/32")"#).await,
        JsValue::Bool(true),
    );
}

/// The ipv6-aware extensions are Microsoft's. Chromium omits
/// `getClientVersion` and Firefox omits the set, so deployments may want only
/// the classic surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ipv6_extensions_can_be_left_undefined() {
    const EXTENSIONS: [&str; 6] = [
        "dnsResolveEx",
        "isResolvableEx",
        "isInNetEx",
        "myIpAddressEx",
        "sortIpAddressList",
        "getClientVersion",
    ];
    const CLASSIC: [&str; 8] = [
        "dnsResolve",
        "isResolvable",
        "isInNet",
        "myIpAddress",
        "isPlainHostName",
        "dnsDomainIs",
        "shExpMatch",
        "convert_addr",
    ];

    // the full Microsoft set is defined by default
    let worker = worker().await;
    for name in EXTENSIONS.into_iter().chain(CLASSIC) {
        assert_eq!(
            eval(&worker, format!("typeof {name}")).await.as_str(),
            Some("function"),
            "{name} must be defined by default",
        );
    }

    // ... and absent, not broken, when turned off
    let (worker, _budget) = env()
        .with_ipv6_extensions(false)
        .register(JsRuntime::builder())
        .expect("register env")
        .spawn()
        .expect("spawn worker");
    for name in EXTENSIONS {
        assert_eq!(
            eval(&worker, format!("typeof {name}")).await.as_str(),
            Some("undefined"),
            "{name} must be undefined",
        );
    }
    // the classic half is untouched
    for name in CLASSIC {
        assert_eq!(
            eval(&worker, format!("typeof {name}")).await.as_str(),
            Some("function"),
            "{name} must survive",
        );
    }
    assert_eq!(
        eval(&worker, r#"dnsResolve("example.com")"#).await.as_str(),
        Some("10.1.2.3"),
    );
}
