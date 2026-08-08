//! The PAC host functions that are pure: host/string shape tests.

use std::net::IpAddr;

use rama_utils::octets::kib;

/// Longest list `sortIpAddressList` accepts; a real address list is a
/// handful of entries, so anything larger is script-driven work.
const MAX_ADDRESS_LIST_BYTES: usize = kib(64);

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
///
/// Matching is native work no deadline can interrupt, so it is charged
/// against the evaluation's [glob budget][crate::env::budget]. Running out
/// is an error rather than a `false`: answering `false` would let a client
/// pad its own url until a rule stops matching.
pub(super) fn sh_exp_match(input: &str, pattern: &str) -> Result<bool, GlobBudgetExhausted> {
    let budget = super::budget::glob_steps_left();
    let mut steps = 0_u64;
    let matched = glob_match(input, pattern, budget, &mut steps);
    super::budget::charge_glob_steps(steps);
    matched.ok_or(GlobBudgetExhausted)
}

/// The evaluation spent its whole glob budget.
#[derive(Debug)]
pub(super) struct GlobBudgetExhausted;

impl std::fmt::Display for GlobBudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("shExpMatch exhausted this evaluation's match budget")
    }
}

impl std::error::Error for GlobBudgetExhausted {}

/// Glob match where `?` is exactly one character and `*` any run of them;
/// nothing else is special, matching the reference regex transform.
///
/// Walks both strings by byte offset so a match costs no allocation, however
/// many rules a script tests per request. `None` once `budget` steps are
/// spent, with `steps` reporting what was used either way.
fn glob_match(input: &str, pattern: &str, budget: u64, steps: &mut u64) -> Option<bool> {
    let (mut index, mut cursor) = (0, 0);
    // the last `*` seen, and how much of the input it swallowed so far
    let mut star: Option<(usize, usize)> = None;

    while index < input.len() {
        *steps += 1;
        if *steps > budget {
            return None;
        }
        let actual = input[index..].chars().next();
        match pattern[cursor..].chars().next() {
            Some('*') => {
                star = Some((cursor, index));
                cursor += 1;
            }
            Some('?') => {
                index += actual.map_or(1, char::len_utf8);
                cursor += 1;
            }
            Some(expected) if Some(expected) == actual => {
                index += expected.len_utf8();
                cursor += expected.len_utf8();
            }
            // let the last `*` swallow one more character and retry
            _ => match star {
                Some((at, swallowed)) => {
                    let Some(swallow) = input[swallowed..].chars().next() else {
                        return Some(false);
                    };
                    cursor = at + 1;
                    index = swallowed + swallow.len_utf8();
                    star = Some((at, index));
                }
                None => return Some(false),
            },
        }
    }

    Some(pattern[cursor..].chars().all(|part| part == '*'))
}

/// `sortIpAddressList(list)`: sort a `;`-separated address list, IPv6
/// before IPv4, each family ascending.
///
/// `None` when the list is empty, longer than [`MAX_ADDRESS_LIST_BYTES`],
/// or any entry is not an ip address; the caller reports that as `false`,
/// matching browsers.
pub(super) fn sort_ip_address_list(list: &str) -> Option<String> {
    if list.len() > MAX_ADDRESS_LIST_BYTES {
        return None;
    }

    let mut addresses = Vec::new();
    for entry in list.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }
        addresses.push(entry.parse::<IpAddr>().ok()?);
    }
    if addresses.is_empty() {
        return None;
    }

    addresses.sort_by(|left, right| match (left, right) {
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Less,
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Greater,
        _ => left.cmp(right),
    });
    Some(join_addresses(addresses))
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

    use crate::PacEnv;

    /// Match with an unbounded budget: the bound itself is tested apart.
    fn sh_exp_match(input: &str, pattern: &str) -> bool {
        super::sh_exp_match(input, pattern).expect("unbudgeted match cannot exhaust")
    }

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
    fn glob_matches() {
        assert!(sh_exp_match(
            "http://home.example.com/people/",
            "*/people/*"
        ));
        assert!(sh_exp_match("vpn1.example.com", "vpn?.example.com"));
        assert!(!sh_exp_match("vpn10.example.com", "vpn?.example.com"));
        assert!(!sh_exp_match("www.example.org", "*.example.com"));
        // consecutive and trailing stars, and the empty pattern
        assert!(sh_exp_match("a", "**"));
        assert!(sh_exp_match("abc", "a*"));
        assert!(sh_exp_match("", "*"));
        assert!(sh_exp_match("", ""));
        assert!(!sh_exp_match("a", ""));
        // a backtracking pattern still resolves correctly
        assert!(sh_exp_match("aaab", "*a*b"));
        assert!(!sh_exp_match("aaa", "*a*b"));
    }

    #[test]
    fn glob_question_mark_is_one_character_not_one_byte() {
        assert!(sh_exp_match("bücher.de", "b?cher.de"));
        assert!(sh_exp_match("é", "?"));
        assert!(sh_exp_match("日本.example", "??.example"));
        assert!(!sh_exp_match("bü", "b??"));
    }

    #[test]
    fn glob_spends_and_respects_the_evaluation_budget() {
        use crate::env::budget::{PacBudget, arm};

        // a match costs roughly one step per input character
        arm(PacBudget {
            lookups: 0,
            glob_steps: 1_000,
        });
        super::sh_exp_match("aaaa", "*").expect("an ample budget cannot exhaust");

        // ... and running out fails the evaluation rather than answering
        // `false`, which a client could otherwise arrange by padding its url
        arm(PacBudget {
            lookups: 0,
            glob_steps: 10,
        });
        let err = super::sh_exp_match(&"a".repeat(10_000), "*b")
            .expect_err("an exhausted budget must be an error");
        assert!(format!("{err}").contains("budget"), "{err}");
    }

    #[test]
    fn glob_answers_correctly_for_a_backtracking_pattern() {
        use crate::env::budget::{PacBudget, arm};

        // the shape a per-call step cap used to answer wrongly on: the truth
        // is `true`, and it must stay `true` while still being bounded
        let input = format!("{}b", "a".repeat(8_191));
        let pattern = format!("*{}b", "a".repeat(1_000));

        arm(PacBudget {
            lookups: 0,
            glob_steps: PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION,
        });
        let started = std::time::Instant::now();
        assert_eq!(super::sh_exp_match(&input, &pattern).ok(), Some(true));
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn glob_is_bounded_for_a_pathological_pattern() {
        use crate::env::budget::{PacBudget, arm};

        // ~2 hours of uninterruptible native work if left unbounded
        let input = "a".repeat(7_000_000);
        let pattern = format!("*{}b", "a".repeat(900_000));

        arm(PacBudget {
            lookups: 0,
            glob_steps: PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION,
        });
        let started = std::time::Instant::now();
        super::sh_exp_match(&input, &pattern)
            .expect_err("a pathological match must exhaust its budget");
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn sort_addresses_v6_first() {
        assert_eq!(
            sort_ip_address_list("10.2.3.9;2001:4898:28:3:201:2ff:feea:fc14;::1;127.0.0.1")
                .as_deref(),
            Some("::1;2001:4898:28:3:201:2ff:feea:fc14;10.2.3.9;127.0.0.1"),
        );
        assert_eq!(
            sort_ip_address_list(" 10.0.0.2 ; 10.0.0.1 ").as_deref(),
            Some("10.0.0.1;10.0.0.2"),
        );
    }

    #[test]
    fn sort_addresses_rejects_a_malformed_list() {
        // browsers answer `false` rather than silently dropping entries
        for list in ["", " ", ";", "not-an-ip", "10.0.0.1;not-an-ip", "10.0.0.1;"] {
            assert_eq!(sort_ip_address_list(list), None, "{list:?}");
        }
    }

    #[test]
    fn sort_addresses_bounds_the_list_length() {
        let entries = MAX_ADDRESS_LIST_BYTES / 4 + 1;
        let list = vec!["::1"; entries].join(";");
        assert!(list.len() > MAX_ADDRESS_LIST_BYTES);
        assert_eq!(sort_ip_address_list(&list), None);
        // a list any real caller produces is unaffected
        assert!(sort_ip_address_list(&vec!["::1"; 64].join(";")).is_some());
    }

    #[test]
    fn the_glob_budget_boundary_is_exact() {
        use crate::env::budget::{PacBudget, arm};

        // this match costs one step per input character
        let input = "aaaa";
        let cost = input.len() as u64;

        arm(PacBudget {
            lookups: 0,
            glob_steps: cost,
        });
        assert_eq!(
            super::sh_exp_match(input, "aaaa").ok(),
            Some(true),
            "a budget of exactly the cost must be enough",
        );

        arm(PacBudget {
            lookups: 0,
            glob_steps: cost - 1,
        });
        assert!(
            super::sh_exp_match(input, "aaaa").is_err(),
            "one step short must not answer",
        );
    }

    #[test]
    fn a_star_swallows_whole_characters() {
        // the star advances over multi-byte characters, so a byte-wise step
        // would land inside one and match the wrong thing
        assert!(sh_exp_match("日本語.example", "*語.example"));
        assert!(sh_exp_match("aé日.example", "*日.example"));
        assert!(!sh_exp_match("日本語.example", "*本.example"));
        assert!(sh_exp_match("é", "*"));
    }

    #[test]
    fn address_list_bounds_are_exact() {
        // entries are trimmed, so padding lands the list on the cap exactly
        let entry = "10.0.0.1;";
        let mut list = entry.repeat(MAX_ADDRESS_LIST_BYTES / entry.len());
        list.pop();
        while list.len() < MAX_ADDRESS_LIST_BYTES {
            list.push(' ');
        }

        assert_eq!(list.len(), MAX_ADDRESS_LIST_BYTES);
        assert!(sort_ip_address_list(&list).is_some(), "the cap itself");

        list.push(' ');
        assert!(sort_ip_address_list(&list).is_none(), "one byte over it");
    }

    #[test]
    fn ipv6_sorts_before_ipv4_whichever_order_it_arrives_in() {
        // a comparator that only handles one direction sorts one of these
        // two inputs wrongly
        assert_eq!(
            sort_ip_address_list("::1;10.0.0.1").as_deref(),
            Some("::1;10.0.0.1"),
        );
        assert_eq!(
            sort_ip_address_list("10.0.0.1;::1").as_deref(),
            Some("::1;10.0.0.1"),
        );
        assert_eq!(
            sort_ip_address_list("10.0.0.2;::2;10.0.0.1;::1").as_deref(),
            Some("::1;::2;10.0.0.1;10.0.0.2"),
        );
    }
}
