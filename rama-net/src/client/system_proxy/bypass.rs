use std::net::IpAddr;

use ipnet::IpNet;

use crate::address::HostRef;

#[derive(Debug, Clone)]
pub(super) struct BypassRule {
    raw: Box<str>,
    port: Option<u16>,
    matcher: BypassMatcher,
}

#[derive(Debug, Clone)]
enum BypassMatcher {
    Never,
    Any,
    LocalName,
    Address(IpAddr),
    Network(IpNet),
    DomainSuffix(Box<str>),
    HostGlob(Box<str>),
    HostExact(Box<str>),
}

impl BypassRule {
    pub(super) fn compile(value: impl Into<String>) -> Self {
        let raw = value.into().into_boxed_str();
        let (pattern, port) = split_port(raw.trim());
        let pattern = pattern.trim_matches(['[', ']']).trim_end_matches('.');
        let matcher = if pattern.is_empty() {
            BypassMatcher::Never
        } else if pattern == "*" {
            BypassMatcher::Any
        } else if pattern.eq_ignore_ascii_case("<local>") {
            BypassMatcher::LocalName
        } else if let Ok(network) = pattern.parse::<IpNet>() {
            BypassMatcher::Network(network)
        } else if let Ok(address) = pattern.parse::<IpAddr>() {
            BypassMatcher::Address(address)
        } else if let Some(suffix) = pattern
            .strip_prefix("*.")
            .or_else(|| pattern.strip_prefix('.'))
        {
            BypassMatcher::DomainSuffix(suffix.to_ascii_lowercase().into_boxed_str())
        } else if pattern.contains('*') {
            BypassMatcher::HostGlob(pattern.to_ascii_lowercase().into_boxed_str())
        } else {
            BypassMatcher::HostExact(pattern.to_ascii_lowercase().into_boxed_str())
        };
        Self { raw, port, matcher }
    }

    pub(super) fn raw(&self) -> &str {
        &self.raw
    }

    pub(super) fn matches(&self, host: HostRef<'_>, host_text: &str, port: Option<u16>) -> bool {
        if self.port.is_some_and(|expected| port != Some(expected)) {
            return false;
        }

        match &self.matcher {
            BypassMatcher::Never => false,
            BypassMatcher::Any => true,
            BypassMatcher::LocalName => is_simple_hostname(host),
            BypassMatcher::Address(expected) => host.try_as_ip().is_ok_and(|ip| ip == *expected),
            BypassMatcher::Network(network) => {
                host.try_as_ip().is_ok_and(|ip| network.contains(&ip))
            }
            BypassMatcher::DomainSuffix(suffix) => {
                let host = normalized_host_text(host_text);
                host.eq_ignore_ascii_case(suffix)
                    || host
                        .get(..host.len().saturating_sub(suffix.len()))
                        .is_some_and(|prefix| {
                            host.ends_with_ignore_ascii_case(suffix) && prefix.ends_with('.')
                        })
            }
            BypassMatcher::HostGlob(pattern) => ascii_glob_matches(
                pattern.as_bytes(),
                normalized_host_text(host_text).as_bytes(),
            ),
            BypassMatcher::HostExact(pattern) => {
                normalized_host_text(host_text).eq_ignore_ascii_case(pattern)
            }
        }
    }
}

pub(super) fn is_simple_hostname(host: HostRef<'_>) -> bool {
    if host.try_as_ip().is_ok() {
        return false;
    }
    let text = host.to_str();
    !text.contains(['.', ':'])
}

fn split_port(pattern: &str) -> (&str, Option<u16>) {
    if let Some(bracketed) = pattern.strip_prefix('[')
        && let Some((candidate, suffix)) = bracketed.rsplit_once("]:")
        && let Ok(port) = suffix.parse::<u16>()
    {
        return (candidate, Some(port));
    }
    if pattern.bytes().filter(|byte| *byte == b':').count() == 1
        && let Some((candidate, suffix)) = pattern.rsplit_once(':')
        && let Ok(port) = suffix.parse::<u16>()
    {
        return (candidate, Some(port));
    }
    (pattern, None)
}

fn normalized_host_text(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .trim_end_matches('.')
}

fn ascii_glob_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut retry_pattern, mut retry_value) = (None, 0);

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && pattern[pattern_index] != b'*'
            && pattern[pattern_index].eq_ignore_ascii_case(&value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            pattern_index += 1;
            retry_pattern = Some(pattern_index);
            retry_value = value_index;
        } else if let Some(retry_pattern) = retry_pattern {
            pattern_index = retry_pattern;
            retry_value += 1;
            value_index = retry_value;
        } else {
            return false;
        }
    }

    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

trait EndsWithIgnoreAsciiCase {
    fn ends_with_ignore_ascii_case(&self, suffix: &str) -> bool;
}

impl EndsWithIgnoreAsciiCase for str {
    fn ends_with_ignore_ascii_case(&self, suffix: &str) -> bool {
        self.get(self.len().saturating_sub(suffix.len())..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_windows_wildcards_match_without_allocating_per_rule() {
        for (pattern, host, expected) in [
            ("192.168.*", "192.168.1.5", true),
            ("10.*", "10.20.30.40", true),
            ("*corp*", "api.CORP.example", true),
            ("*corp*", "example.test", false),
            ("ab*cd", "ab-123-cd", true),
            ("abc*def", "abcX", false),
        ] {
            let parsed = host.parse::<crate::address::Host>().unwrap();
            assert_eq!(
                BypassRule::compile(pattern).matches((&parsed).into(), host, None,),
                expected,
            );
        }
    }
}
