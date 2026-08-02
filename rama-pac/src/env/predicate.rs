//! The PAC host functions that are pure: host/string shape tests.

use std::net::IpAddr;

use rama_js::JsValue;
use rama_utils::thirdparty::wildcard::Wildcard;

/// Coerce a script argument to a string the way a PAC script expects:
/// `null`/`undefined` are absent, everything else renders.
pub(super) fn arg_str(value: &JsValue) -> Option<String> {
    (!value.is_null_or_undefined()).then(|| value.to_string())
}

/// `isPlainHostName(host)`: true when the host carries no domain part.
pub(super) fn is_plain_host_name(host: &str) -> bool {
    // an ipv6 literal has no dots either, yet is not an unqualified name
    !host.contains('.')
        && host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .parse::<IpAddr>()
            .is_err()
}

/// `dnsDomainIs(host, domain)`: true when `host` sits in `domain`.
///
/// Classic semantics are a plain suffix test, so `dnsDomainIs("xexample.com",
/// ".example.com")` is false while `dnsDomainIs("www.example.com",
/// ".example.com")` is true.
pub(super) fn dns_domain_is(host: &str, domain: &str) -> bool {
    // compared as bytes: slicing a `str` at a computed offset panics when
    // it lands inside a multi-byte character
    let host = host.trim_end_matches('.').as_bytes();
    let domain = domain.trim_end_matches('.').as_bytes();
    host.len() >= domain.len() && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
}

/// `localHostOrDomainIs(host, hostdom)`: true for an exact match, or when
/// `host` is the unqualified form of `hostdom`.
pub(super) fn local_host_or_domain_is(host: &str, hostdom: &str) -> bool {
    if host.eq_ignore_ascii_case(hostdom) {
        return true;
    }
    // `hostdom` starts with `host` plus a label separator
    let (host, hostdom) = (host.as_bytes(), hostdom.as_bytes());
    hostdom.len() > host.len()
        && hostdom[host.len()] == b'.'
        && hostdom[..host.len()].eq_ignore_ascii_case(host)
}

/// `dnsDomainLevels(host)`: the number of dots in the host.
pub(super) fn dns_domain_levels(host: &str) -> u32 {
    u32::try_from(host.matches('.').count()).unwrap_or(u32::MAX)
}

/// `shExpMatch(str, shexp)`: shell-glob match (`*` and `?`).
pub(super) fn sh_exp_match(input: &str, pattern: &str) -> bool {
    match Wildcard::new(pattern.as_bytes()) {
        Ok(wildcard) => wildcard.is_match(input.as_bytes()),
        // an invalid glob matches nothing, mirroring a failed script test
        Err(_) => false,
    }
}

/// `sortIpAddressList(list)`: sort a `;`-separated address list, IPv6
/// before IPv4, each family ascending. Invalid entries drop out.
pub(super) fn sort_ip_address_list(list: &str) -> String {
    let mut addresses: Vec<IpAddr> = list
        .split(';')
        .filter_map(|entry| entry.trim().parse().ok())
        .collect();
    addresses.sort_by(|left, right| match (left, right) {
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Less,
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Greater,
        _ => left.cmp(right),
    });
    join_addresses(addresses)
}

/// Render addresses the way PAC's `*Ex` functions return them.
pub(super) fn join_addresses(addresses: impl IntoIterator<Item = IpAddr>) -> String {
    let mut out = String::new();
    for address in addresses {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&address.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_host_name() {
        assert!(is_plain_host_name("www"));
        assert!(is_plain_host_name("intranet"));
        assert!(!is_plain_host_name("www.example.com"));
        // ip literals are never plain host names, dots or not
        assert!(!is_plain_host_name("192.168.0.1"));
        assert!(!is_plain_host_name("2001:db8::1"));
        assert!(!is_plain_host_name("::1"));
        assert!(!is_plain_host_name("[2001:db8::1]"));
    }

    #[test]
    fn domain_is() {
        assert!(dns_domain_is("www.example.com", ".example.com"));
        assert!(dns_domain_is("www.example.com", "example.com"));
        assert!(dns_domain_is("example.com", "example.com"));
        // suffix test, not label-aware: classic PAC behaviour
        assert!(!dns_domain_is("xexample.com", ".example.com"));
        assert!(!dns_domain_is("www.example.org", ".example.com"));
        assert!(!dns_domain_is("com", "example.com"));
        // trailing dots and case do not matter
        assert!(dns_domain_is("WWW.Example.COM.", ".example.com"));
        // a non-ascii host must not panic on the byte-offset compare
        assert!(!dns_domain_is("aé.com", "6.com"));
        assert!(dns_domain_is("wéb.example.com", ".example.com"));
    }

    #[test]
    fn local_host_or_domain() {
        assert!(local_host_or_domain_is(
            "www.example.com",
            "www.example.com"
        ));
        assert!(local_host_or_domain_is("www", "www.example.com"));
        // a partially qualified host is a prefix too
        assert!(local_host_or_domain_is("www.example", "www.example.com"));
        assert!(!local_host_or_domain_is(
            "www.example.org",
            "www.example.com"
        ));
        // a prefix that is not on a label boundary does not match
        assert!(!local_host_or_domain_is("ww", "www.example.com"));
        assert!(!local_host_or_domain_is(
            "home.example.com",
            "www.example.com"
        ));
    }

    #[test]
    fn domain_levels() {
        assert_eq!(dns_domain_levels("www"), 0);
        assert_eq!(dns_domain_levels("www.example.com"), 2);
    }

    #[test]
    fn glob_match() {
        assert!(sh_exp_match(
            "http://home.example.com/people/",
            "*/people/*"
        ));
        assert!(sh_exp_match("vpn1.example.com", "vpn?.example.com"));
        assert!(!sh_exp_match("vpn10.example.com", "vpn?.example.com"));
        assert!(!sh_exp_match("www.example.org", "*.example.com"));
    }

    #[test]
    fn sort_addresses_v6_first() {
        assert_eq!(
            sort_ip_address_list("10.2.3.9;2001:4898:28:3:201:2ff:feea:fc14;::1;127.0.0.1"),
            "::1;2001:4898:28:3:201:2ff:feea:fc14;10.2.3.9;127.0.0.1",
        );
        // junk entries are dropped rather than failing the whole call
        assert_eq!(sort_ip_address_list("not-an-ip;10.0.0.1"), "10.0.0.1");
        assert_eq!(sort_ip_address_list(""), "");
    }
}
