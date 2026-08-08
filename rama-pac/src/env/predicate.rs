//! The PAC host functions that are pure: host/string shape tests.

use std::net::IpAddr;

use rama_utils::octets::kib;
use rama_utils::thirdparty::regex::{Regex, RegexBuilder};

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

/// How `shExpMatch(str, shexp)` reads its pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacShExpMatch {
    /// What the reference implementations do: rewrite the expression into an
    /// anchored regex — escaping `.`, mapping `*` to `.*` and `?` to `.` —
    /// which leaves every other regex metacharacter live.
    ///
    /// This is the default because it is what a PAC file is written against:
    /// a pattern like `vpn[0-9].corp.example` means in rama what it means in
    /// a browser. It inherits the quirks that come with it — an unparenthesised
    /// `|` anchors only one of its branches, and a bracket expression that was
    /// meant literally (`http://[2001:db8::1]/*`) is a character class — so a
    /// deployment that would rather have neither can pick [`Self::Literal`].
    #[default]
    Reference,
    /// Treat every character but `*` and `?` literally.
    ///
    /// Diverges from browsers deliberately: a pattern means exactly what it
    /// spells, so no part of an operator's rule can be satisfied by input a
    /// client chose. A rule relying on regex metacharacters stops matching
    /// instead, which is visible in testing rather than at an attacker's
    /// choosing.
    Literal,
}

/// `shExpMatch(str, shexp)`, read per [`PacShExpMatch`].
///
/// Matching is native work no deadline can interrupt, so it is charged
/// against the evaluation's [glob budget][crate::env::budget]. Running out
/// is an error rather than a `false`: answering `false` would let a client
/// pad its own url until a rule stops matching.
pub(super) fn sh_exp_match(
    input: &str,
    pattern: &str,
    mode: PacShExpMatch,
) -> Result<bool, ShExpError> {
    match mode {
        PacShExpMatch::Reference => reference_match(input, pattern),
        PacShExpMatch::Literal => literal_match(input, pattern),
    }
}

/// Why a match could not be answered.
#[derive(Debug)]
pub(super) enum ShExpError {
    /// The evaluation spent its whole matching budget.
    BudgetExhausted,
    /// The pattern is not one this engine can compile — as in a browser,
    /// where an invalid expression throws rather than answering.
    InvalidPattern,
}

impl std::fmt::Display for ShExpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BudgetExhausted => {
                f.write_str("shExpMatch exhausted this evaluation's match budget")
            }
            Self::InvalidPattern => f.write_str("shExpMatch pattern is not a valid expression"),
        }
    }
}

impl std::error::Error for ShExpError {}

/// Largest compiled program a pattern may produce, so building one is
/// bounded however the script spells it.
const MAX_PATTERN_PROGRAM_BYTES: usize = kib(256);

/// What compiling a pattern costs against the budget, per pattern byte:
/// building the automaton is the expensive half, and a script that hands a
/// fresh pattern to every call would otherwise pay only for matching.
const COMPILE_COST_PER_BYTE: u64 = 64;

fn reference_match(input: &str, pattern: &str) -> Result<bool, ShExpError> {
    let budget = super::budget::glob_steps_left();
    let mut spent = input.len() as u64 + pattern.len() as u64;

    let compiled = if let Some(compiled) = super::budget::compiled_pattern(pattern) {
        compiled
    } else {
        spent += pattern.len() as u64 * COMPILE_COST_PER_BYTE;
        if spent > budget {
            super::budget::charge_glob_steps(spent);
            return Err(ShExpError::BudgetExhausted);
        }
        let compiled = build_pattern(pattern)?;
        super::budget::remember_pattern(pattern, &compiled);
        compiled
    };

    super::budget::charge_glob_steps(spent);
    if spent > budget {
        return Err(ShExpError::BudgetExhausted);
    }
    Ok(compiled.is_match(input))
}

/// The reference transform: `.` escaped, `*` any run, `?` any one, anchored.
fn build_pattern(pattern: &str) -> Result<Regex, ShExpError> {
    let mut source = String::with_capacity(pattern.len() + 8);
    source.push('^');
    for part in pattern.chars() {
        match part {
            '.' => source.push_str("\\."),
            '*' => source.push_str(".*"),
            '?' => source.push('.'),
            other => source.push(other),
        }
    }
    source.push('$');

    RegexBuilder::new(&source)
        .size_limit(MAX_PATTERN_PROGRAM_BYTES)
        .build()
        .map_err(|_err| ShExpError::InvalidPattern)
}

fn literal_match(input: &str, pattern: &str) -> Result<bool, ShExpError> {
    let budget = super::budget::glob_steps_left();
    let mut steps = 0_u64;
    let matched = glob_match(input, pattern, budget, &mut steps);
    super::budget::charge_glob_steps(steps);
    matched.ok_or(ShExpError::BudgetExhausted)
}

/// Glob match where `?` is exactly one character and `*` any run of them,
/// line terminators included so that no string can slip past a rule the way
/// it does through the reference `.`; nothing else is special.
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

    /// Match the way a browser would, with an unbounded budget.
    fn sh_exp_match(input: &str, pattern: &str) -> bool {
        super::sh_exp_match(input, pattern, PacShExpMatch::Reference)
            .expect("unbudgeted match cannot exhaust")
    }

    /// Match literally, the opt-in mode.
    fn literal(input: &str, pattern: &str) -> bool {
        super::sh_exp_match(input, pattern, PacShExpMatch::Literal)
            .expect("unbudgeted match cannot exhaust")
    }

    /// Arm this thread with a glob budget; a pure match spends no other.
    fn arm_glob_steps(glob_steps: u64) {
        crate::env::budget::arm(crate::env::budget::PacBudget {
            lookups: 0,
            alerts: 0,
            blocking: std::time::Duration::MAX,
            glob_steps,
        });
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

    /// Pins the deviation from the reference regex transform, which escapes
    /// only `.` and leaves every other metacharacter live, so that adopting
    /// it cannot pass unnoticed.
    #[test]
    fn literal_mode_treats_every_regex_metacharacter_literally() {
        let sh_exp_match = literal;

        // a bracket expression is a character class there, four literal
        // characters here
        assert!(sh_exp_match(
            "vpn[0-9].corp.example",
            "vpn[0-9].corp.example"
        ));
        assert!(!sh_exp_match("vpn7.corp.example", "vpn[0-9].corp.example"));

        // ... and an operator who never meant a class writes one anyway: an
        // ipv6 url spells out a set of seven single characters there, so the
        // rule stops covering its own host and starts covering strangers
        assert!(sh_exp_match(
            "http://[2001:db8::1]/x",
            "http://[2001:db8::1]/*"
        ));
        assert!(!sh_exp_match("http://d/x", "http://[2001:db8::1]/*"));

        // alternation binds looser than the anchors the transform adds, so
        // there each branch is anchored on one side only and a client picks
        // its own url into the corp branch
        assert!(sh_exp_match("a|b", "a|b"));
        assert!(!sh_exp_match("a", "a|b"));
        assert!(!sh_exp_match(
            "https://evil.test/?q=.corp.example.x",
            "*.corp.example|*.corp2.example"
        ));

        // a quantifier, a group and an escape are all just characters
        assert!(sh_exp_match("a+b", "a+b"));
        assert!(!sh_exp_match("aaab", "a+b"));
        assert!(sh_exp_match("(a)", "(a)"));
        assert!(!sh_exp_match("a", "(a)"));
        assert!(sh_exp_match("a\\b", "a\\b"));
        assert!(!sh_exp_match("a", "a\\b"));

        // `.` is the one the transform escapes, so it agrees
        assert!(sh_exp_match("a.b", "a.b"));
        assert!(!sh_exp_match("axb", "a.b"));
    }

    #[test]
    fn a_wildcard_stops_at_a_line_terminator_only_in_reference_mode() {
        // browsers build a regex whose `.` and `.*` stop at a newline, so a
        // string carrying one slips past a rule there — and here too, since
        // reference mode is what a pac file is written against
        assert!(!sh_exp_match("a\nb", "a?b"));
        assert!(!sh_exp_match(
            "https://a\n.corp.example/x",
            "https://*.corp.example/*"
        ));

        // the literal walk has no such seam
        assert!(literal("a\nb", "a?b"));
        assert!(literal(
            "https://a\n.corp.example/x",
            "https://*.corp.example/*"
        ));
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
        // a match costs roughly one step per input character
        arm_glob_steps(1_000);
        super::sh_exp_match("aaaa", "*", PacShExpMatch::Literal)
            .expect("an ample budget cannot exhaust");

        // ... and running out fails the evaluation rather than answering
        // `false`, which a client could otherwise arrange by padding its url
        arm_glob_steps(10);
        let err = super::sh_exp_match(&"a".repeat(10_000), "*b", PacShExpMatch::Literal)
            .expect_err("an exhausted budget must be an error");
        assert!(format!("{err}").contains("budget"), "{err}");
    }

    #[test]
    fn glob_answers_correctly_for_a_backtracking_pattern() {
        // the shape a per-call step cap used to answer wrongly on: the truth
        // is `true`, and it must stay `true` while still being bounded
        let input = format!("{}b", "a".repeat(8_191));
        let pattern = format!("*{}b", "a".repeat(1_000));

        arm_glob_steps(PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION);
        let started = std::time::Instant::now();
        assert_eq!(
            super::sh_exp_match(&input, &pattern, PacShExpMatch::Literal).ok(),
            Some(true),
        );
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }

    #[test]
    fn glob_is_bounded_for_a_pathological_pattern() {
        // ~2 hours of uninterruptible native work if left unbounded
        let input = "a".repeat(7_000_000);
        let pattern = format!("*{}b", "a".repeat(900_000));

        arm_glob_steps(PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION);
        let started = std::time::Instant::now();
        super::sh_exp_match(&input, &pattern, PacShExpMatch::Literal)
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
        // this match costs one step per input character
        let input = "aaaa";
        let cost = input.len() as u64;

        arm_glob_steps(cost);
        assert_eq!(
            super::sh_exp_match(input, "aaaa", PacShExpMatch::Literal).ok(),
            Some(true),
            "a budget of exactly the cost must be enough",
        );

        arm_glob_steps(cost - 1);
        assert!(
            super::sh_exp_match(input, "aaaa", PacShExpMatch::Literal).is_err(),
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

    #[test]
    fn reference_mode_reads_a_pattern_the_way_a_browser_does() {
        // the plain shapes every pac file is written in
        assert!(sh_exp_match(
            "http://home.example.com/people/",
            "*/people/*"
        ));
        assert!(sh_exp_match("vpn1.example.com", "vpn?.example.com"));
        assert!(!sh_exp_match("vpn10.example.com", "vpn?.example.com"));

        // ... and the metacharacters browsers leave live, which is the whole
        // reason this is the default
        assert!(sh_exp_match("vpn7.corp.example", "vpn[0-9].corp.example"));
        assert!(!sh_exp_match("vpnx.corp.example", "vpn[0-9].corp.example"));
        assert!(sh_exp_match("aaab", "a+b"));

        // `.` is escaped, so it is not "any character"
        assert!(!sh_exp_match("wwwXexample.com", "www.example.com"));
        assert!(sh_exp_match("www.example.com", "www.example.com"));
    }

    #[test]
    fn literal_mode_means_exactly_what_it_spells() {
        assert!(literal("http://home.example.com/people/", "*/people/*"));
        assert!(literal("vpn1.example.com", "vpn?.example.com"));

        // no metacharacter is live, so neither the useful reading nor the
        // exploitable one applies
        assert!(!literal("vpn7.corp.example", "vpn[0-9].corp.example"));
        assert!(literal("vpn[0-9].corp.example", "vpn[0-9].corp.example"));
        assert!(!literal("aaab", "a+b"));
        assert!(literal("a+b", "a+b"));

        // the alternation a client can satisfy in reference mode
        let evil = "https://evil.test/?q=.corp.example.x";
        let rule = "*.corp.example|*.corp2.example";
        assert!(
            sh_exp_match(evil, rule),
            "reference keeps the browser quirk"
        );
        assert!(!literal(evil, rule), "literal has no alternation to abuse");
    }

    #[test]
    fn an_uncompilable_pattern_is_an_error_not_an_answer() {
        // browsers throw a SyntaxError here rather than answering false
        let err = super::sh_exp_match("x", "unbalanced[", PacShExpMatch::Reference)
            .expect_err("an invalid expression cannot be matched");
        assert!(format!("{err}").contains("valid"), "{err}");

        // ... while literal mode has nothing to compile
        assert!(literal("unbalanced[", "unbalanced["));
    }

    #[test]
    fn a_backtracking_shaped_pattern_stays_linear_in_reference_mode() {
        use crate::env::budget::{PacBudget, arm};

        arm(PacBudget {
            lookups: 0,
            glob_steps: PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION,
            alerts: 0,
            blocking: std::time::Duration::from_secs(30),
        });

        // the engine is a finite automaton: what makes a backtracking matcher
        // explode is answered here in milliseconds
        let input = "a".repeat(200_000);
        let pattern = format!("*{}b", "a".repeat(2_000));
        let started = std::time::Instant::now();
        let matched = super::sh_exp_match(&input, &pattern, PacShExpMatch::Reference);
        assert_eq!(matched.ok(), Some(false));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn compiling_a_fresh_pattern_every_call_is_charged() {
        use crate::env::budget::{PacBudget, arm};

        arm(PacBudget {
            lookups: 0,
            glob_steps: 5_000,
            alerts: 0,
            blocking: std::time::Duration::from_secs(30),
        });

        // a script handing over a new pattern per call pays for building each
        // automaton, so it cannot make the host compile without end
        let mut compiled = 0;
        for index in 0..1_000 {
            if super::sh_exp_match(
                "host.example",
                &format!("*{index}.example"),
                PacShExpMatch::Reference,
            )
            .is_err()
            {
                break;
            }
            compiled += 1;
        }
        assert!(compiled < 1_000, "the budget never ran out");
    }
}
