//! The PAC host functions that are pure: host/string shape tests.

use std::net::{IpAddr, Ipv4Addr};

use rama_utils::octets::kib;
use regex_automata::{Input, meta::Regex};

use super::budget::PacBudgetState;

/// Longest list `sortIpAddressList` accepts; a real address list is a
/// handful of entries, so anything larger is script-driven work.
const MAX_ADDRESS_LIST_BYTES: usize = kib(64);

/// `isPlainHostName(host)`: true when the host carries no domain part.
pub(super) fn is_plain_host_name(host: &str) -> bool {
    // an ipv6 literal has no dots either, yet is not an unqualified name
    !host.contains('.') && host.parse::<IpAddr>().is_err()
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

/// `isValidIpAddress(ipchars)`: four dot-separated groups of one to three
/// digits, none above 255.
///
/// Deliberately not a general ip parser: the reference implementations spell
/// this as that exact regex, so a leading zero is fine here and an ipv6
/// literal is not an address at all.
pub(super) fn is_valid_ip_address(ipchars: &str) -> bool {
    let mut groups = 0;
    for group in ipchars.split('.') {
        groups += 1;
        if groups > 4
            || group.is_empty()
            || group.len() > 3
            || !group.bytes().all(|byte| byte.is_ascii_digit())
            || group.parse::<u16>().is_ok_and(|octet| octet > 255)
        {
            return false;
        }
    }
    groups == 4
}

/// Parse the dotted-decimal form accepted by [`is_valid_ip_address`].
///
/// `Ipv4Addr::from_str` deliberately rejects leading zeroes, while the PAC
/// reference accepts one to three decimal digits per octet.
pub(super) fn parse_ipv4_address(ipchars: &str) -> Option<Ipv4Addr> {
    if !is_valid_ip_address(ipchars) {
        return None;
    }

    let mut octets = [0_u8; 4];
    for (slot, group) in octets.iter_mut().zip(ipchars.split('.')) {
        *slot = group.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

/// `convert_addr(ipchars)`: a dotted quad as the signed 32-bit integer the
/// reference implementations produce.
///
/// Follows their arithmetic exactly, javascript coercion included: a group
/// that is not a number contributes zero, a missing one likewise, and the
/// result wraps into the signed range (`255.255.255.255` is `-1`), which is
/// what a script comparing against it expects.
pub(super) fn convert_addr(ipchars: &str) -> f64 {
    let mut groups = ipchars.split('.');
    let mut result: u32 = 0;
    for shift in [24_u32, 16, 8, 0] {
        let octet = groups
            .next()
            .and_then(js_to_number)
            .filter(|octet| octet.is_finite())
            .map_or(0, |octet| {
                (octet.trunc().rem_euclid(4_294_967_296.0) as u32) & 0xff
            });
        result |= octet << shift;
    }
    f64::from(result as i32)
}

/// A group as javascript's numeric coercion reads it, which is what the
/// reference's bitwise arithmetic applies.
///
/// Anything unreadable is `None` and contributes nothing, matching the `NaN`
/// that coercion produces there.
fn js_to_number(group: &str) -> Option<f64> {
    let group = group.trim_matches(is_js_string_whitespace);
    let radix = |prefix: &str, radix: u32| {
        group
            .strip_prefix(prefix)
            .or_else(|| group.strip_prefix(&prefix.to_uppercase()))
            .and_then(|digits| u64::from_str_radix(digits, radix).ok())
            .map(|value| value as f64)
    };

    radix("0x", 16)
        .or_else(|| radix("0o", 8))
        .or_else(|| radix("0b", 2))
        .or_else(|| group.parse::<f64>().ok())
}

/// ECMAScript `StringNumericLiteral` whitespace, including line terminators.
fn is_js_string_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}' | '\u{000B}' | '\u{000C}' | '\u{0020}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
                | '\n'
                | '\r'
    )
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
    /// a pattern like `vpn[0-9].corp.example` keeps its reference character
    /// class semantics. It inherits the quirks that come with the transform —
    /// an unparenthesised `|` anchors only one of its branches, and a bracket
    /// expression that was meant literally (`http://[2001:db8::1]/*`) is a
    /// character class — so a deployment that would rather have neither can
    /// pick [`Self::Literal`]. Matching uses Rust's bounded regex engine rather
    /// than ECMAScript `RegExp`; unsupported constructs and UTF-16 code-unit
    /// edge cases can therefore differ from a browser.
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
    budget: &PacBudgetState,
    input: &str,
    pattern: &str,
    mode: PacShExpMatch,
) -> Result<bool, ShExpError> {
    match mode {
        PacShExpMatch::Reference => reference_match(budget, input, pattern),
        PacShExpMatch::Literal => literal_match(budget, input, pattern),
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

/// Scratch space for one lazy DFA. The runtime-wide cache accounts its actual
/// retained size and evicts an entry if later matching would cross the cap.
const MAX_PATTERN_CACHE_BYTES: usize = kib(1_024);

/// What compiling a pattern costs against the budget, per pattern byte:
/// building the automaton is the expensive half, and a script that hands a
/// fresh pattern to every call would otherwise pay only for matching.
const COMPILE_COST_PER_BYTE: u64 = 64;

fn reference_match(
    budget_state: &PacBudgetState,
    input: &str,
    pattern: &str,
) -> Result<bool, ShExpError> {
    let budget = budget_state.glob_steps_left();
    let mut spent = input.len() as u64 + pattern.len() as u64;

    if spent > budget {
        budget_state.charge_glob_steps(spent);
        return Err(ShExpError::BudgetExhausted);
    }
    if let Some(matched) = budget_state.match_compiled_pattern(pattern, input) {
        budget_state.charge_glob_steps(spent);
        return Ok(matched);
    }

    {
        spent += pattern.len() as u64 * COMPILE_COST_PER_BYTE;
        if spent > budget {
            budget_state.charge_glob_steps(spent);
            return Err(ShExpError::BudgetExhausted);
        }
        let compiled = build_pattern(pattern)?;
        let mut cache = compiled.create_cache();
        let matched = compiled
            .search_with(&mut cache, &Input::new(input))
            .is_some();
        budget_state.remember_pattern(pattern, compiled, cache);

        budget_state.charge_glob_steps(spent);
        Ok(matched)
    }
}

/// The reference transform: `.` escaped, `*` any run, `?` any one, anchored.
fn build_pattern(pattern: &str) -> Result<Regex, ShExpError> {
    let mut source = String::with_capacity(pattern.len() + 8);
    source.push('^');
    for part in pattern.chars() {
        match part {
            '.' => source.push_str("\\."),
            // ECMAScript `.` excludes all four line terminators. Rust's dot
            // excludes only `\n`, so spell out the reference character set.
            '*' => source.push_str("[^\\n\\r\\x{2028}\\x{2029}]*"),
            '?' => source.push_str("[^\\n\\r\\x{2028}\\x{2029}]"),
            other => source.push(other),
        }
    }
    source.push('$');

    let compiled = Regex::builder()
        .configure(
            Regex::config()
                .nfa_size_limit(Some(MAX_PATTERN_PROGRAM_BYTES))
                .hybrid_cache_capacity(MAX_PATTERN_CACHE_BYTES),
        )
        .build(&source)
        .map_err(|_err| ShExpError::InvalidPattern)?;
    if compiled.memory_usage() > MAX_PATTERN_PROGRAM_BYTES {
        return Err(ShExpError::InvalidPattern);
    }
    Ok(compiled)
}

fn literal_match(
    budget_state: &PacBudgetState,
    input: &str,
    pattern: &str,
) -> Result<bool, ShExpError> {
    let budget = budget_state.glob_steps_left();
    let mut steps = 0_u64;
    let matched = glob_match(input, pattern, budget, &mut steps);
    budget_state.charge_glob_steps(steps);
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
/// `None` when the list contains no addresses, is longer than
/// [`MAX_ADDRESS_LIST_BYTES`], or any non-empty entry is not an ip address.
/// The caller reports that as `""` per Microsoft; Chromium returns `false`.
pub(super) fn sort_ip_address_list(list: &str) -> Option<String> {
    if list.len() > MAX_ADDRESS_LIST_BYTES {
        return None;
    }

    // the entries are carried as written: an address has more than one
    // spelling (`fe80::5efe:157.59.139.22` and `fe80::5efe:9d3b:8b16` are the
    // same address) and the reference hands back the one it was given
    let mut addresses = Vec::new();
    for entry in list.split(';') {
        // Chromium removes spaces and tabs anywhere, mirroring WinINet, and
        // its tokenizer skips empty entries.
        let entry: String = entry
            .chars()
            .filter(|value| !matches!(value, ' ' | '\t'))
            .collect();
        if entry.is_empty() {
            continue;
        }
        addresses.push((entry.parse::<IpAddr>().ok()?, entry));
    }
    if addresses.is_empty() {
        return None;
    }

    addresses.sort_by_key(|(address, _)| (family_rank(*address), *address));

    let mut out = String::with_capacity(list.len());
    for (_, spelling) in addresses {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&spelling);
    }
    Some(out)
}

/// IPv6 before IPv4, as the reference states outright.
fn family_rank(address: IpAddr) -> u8 {
    u8::from(address.is_ipv4())
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
        super::sh_exp_match(
            &PacBudgetState::default(),
            input,
            pattern,
            PacShExpMatch::Reference,
        )
        .expect("unbudgeted match cannot exhaust")
    }

    /// Match literally, the opt-in mode.
    fn literal(input: &str, pattern: &str) -> bool {
        super::sh_exp_match(
            &PacBudgetState::default(),
            input,
            pattern,
            PacShExpMatch::Literal,
        )
        .expect("unbudgeted match cannot exhaust")
    }

    /// A state armed with a glob budget; a pure match spends no other.
    fn armed_with_glob_steps(glob_steps: u64) -> PacBudgetState {
        let state = PacBudgetState::default();
        state.arm(crate::env::budget::PacBudget {
            lookups: 0,
            alerts: 0,
            blocking: std::time::Duration::MAX,
            glob_steps,
        });
        state
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
        // Chromium's native helper does not remove URL-literal brackets
        // when the function is called directly with script-provided text.
        assert!(is_plain_host_name("[2001:db8::1]"));
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
    fn reference_ipv4_parser_accepts_decimal_leading_zeroes() {
        assert_eq!(
            parse_ipv4_address("010.001.002.003"),
            Some(Ipv4Addr::new(10, 1, 2, 3)),
        );
        assert_eq!(parse_ipv4_address("256.1.2.3"), None);
        assert_eq!(parse_ipv4_address("1.2.3"), None);
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
    fn a_wildcard_stops_at_every_ecmascript_line_terminator_in_reference_mode() {
        // browsers build a regex whose `.` and `.*` stop at a newline, so a
        // string carrying one slips past a rule there — and here too, since
        // reference mode is what a pac file is written against
        assert!(!sh_exp_match("a\nb", "a?b"));
        assert!(!sh_exp_match(
            "https://a\n.corp.example/x",
            "https://*.corp.example/*"
        ));
        for terminator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
            assert!(
                !sh_exp_match(&format!("a{terminator}b"), "a?b"),
                "{terminator:?}",
            );
        }

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
        let ample = armed_with_glob_steps(1_000);
        super::sh_exp_match(&ample, "aaaa", "*", PacShExpMatch::Literal)
            .expect("an ample budget cannot exhaust");

        // ... and running out fails the evaluation rather than answering
        // `false`, which a client could otherwise arrange by padding its url
        let scarce = armed_with_glob_steps(10);
        let err = super::sh_exp_match(&scarce, &"a".repeat(10_000), "*b", PacShExpMatch::Literal)
            .expect_err("an exhausted budget must be an error");
        assert!(format!("{err}").contains("budget"), "{err}");
    }

    #[test]
    fn glob_answers_correctly_for_a_backtracking_pattern() {
        // the shape a per-call step cap used to answer wrongly on: the truth
        // is `true`, and it must stay `true` while still being bounded
        let input = format!("{}b", "a".repeat(8_191));
        let pattern = format!("*{}b", "a".repeat(1_000));

        let budget = armed_with_glob_steps(PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION);
        let started = std::time::Instant::now();
        assert_eq!(
            super::sh_exp_match(&budget, &input, &pattern, PacShExpMatch::Literal).ok(),
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

        let budget = armed_with_glob_steps(PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION);
        let started = std::time::Instant::now();
        super::sh_exp_match(&budget, &input, &pattern, PacShExpMatch::Literal)
            .expect_err("a pathological match must exhaust its budget");
        let elapsed = started.elapsed();
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    #[test]
    fn sort_addresses_by_family_then_numeric_value() {
        assert_eq!(
            sort_ip_address_list("10.2.3.9;2001:4898:28:3:201:2ff:feea:fc14;::1;127.0.0.1")
                .as_deref(),
            Some("::1;2001:4898:28:3:201:2ff:feea:fc14;10.2.3.9;127.0.0.1"),
        );
        assert_eq!(
            sort_ip_address_list(" 10.0.0.2 ; 10.0.0.1 ").as_deref(),
            Some("10.0.0.1;10.0.0.2"),
        );
        assert_eq!(
            sort_ip_address_list(
                "157.59.139.22;2001:4898:28:3:201:2ff:feea:fc14;fe80::5efe:157:9d3b:8b16",
            )
            .as_deref(),
            Some("2001:4898:28:3:201:2ff:feea:fc14;fe80::5efe:157:9d3b:8b16;157.59.139.22",),
        );
    }

    #[test]
    fn sort_addresses_rejects_a_malformed_list() {
        for list in ["", " ", ";", "not-an-ip", "10.0.0.1;not-an-ip"] {
            assert_eq!(sort_ip_address_list(list), None, "{list:?}");
        }
    }

    #[test]
    fn sort_addresses_skips_empty_entries_and_wininet_whitespace() {
        assert_eq!(
            sort_ip_address_list("; 10.0. 0.2 ;;\t10.0.0.1;").as_deref(),
            Some("10.0.0.1;10.0.0.2"),
        );
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

        let exact = armed_with_glob_steps(cost);
        assert_eq!(
            super::sh_exp_match(&exact, input, "aaaa", PacShExpMatch::Literal).ok(),
            Some(true),
            "a budget of exactly the cost must be enough",
        );

        let short = armed_with_glob_steps(cost - 1);
        assert!(
            super::sh_exp_match(&short, input, "aaaa", PacShExpMatch::Literal).is_err(),
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
        let err = super::sh_exp_match(
            &PacBudgetState::default(),
            "x",
            "unbalanced[",
            PacShExpMatch::Reference,
        )
        .expect_err("an invalid expression cannot be matched");
        assert!(format!("{err}").contains("valid"), "{err}");

        // ... while literal mode has nothing to compile
        assert!(literal("unbalanced[", "unbalanced["));
    }

    #[test]
    fn a_backtracking_shaped_pattern_stays_linear_in_reference_mode() {
        let budget = armed_with_glob_steps(PacEnv::DEFAULT_MAX_GLOB_STEPS_PER_EVALUATION);

        // the engine is a finite automaton: what makes a backtracking matcher
        // explode is answered here in milliseconds
        let input = "a".repeat(200_000);
        let pattern = format!("*{}b", "a".repeat(2_000));
        let started = std::time::Instant::now();
        let matched = super::sh_exp_match(&budget, &input, &pattern, PacShExpMatch::Reference);
        assert_eq!(matched.ok(), Some(false));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn compiling_a_fresh_pattern_every_call_is_charged() {
        let budget = armed_with_glob_steps(5_000);

        // a script handing over a new pattern per call pays for building each
        // automaton, so it cannot make the host compile without end
        let mut compiled = 0;
        for index in 0..1_000 {
            if super::sh_exp_match(
                &budget,
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
