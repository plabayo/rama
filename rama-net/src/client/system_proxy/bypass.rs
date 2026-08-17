use ipnet::IpNet;

use crate::{
    Protocol,
    address::{HostPattern, HostRef},
};

#[derive(Debug, Clone)]
pub(super) struct BypassRule {
    raw: Box<str>,
    scheme: Option<Box<str>>,
    port: Option<u16>,
    matcher: BypassMatcher,
}

#[derive(Debug, Clone)]
enum BypassMatcher {
    LocalName,
    Network(IpNet),
    Pattern(HostPattern),
}

impl BypassRule {
    pub(super) fn compile(value: impl Into<String>) -> Option<Self> {
        let raw = value.into().into_boxed_str();
        let (scheme, pattern) = split_scheme(raw.trim());
        let scheme = scheme.map(|scheme| scheme.to_ascii_lowercase().into_boxed_str());
        let (pattern, port) = split_port(pattern);
        let matcher = if pattern.eq_ignore_ascii_case("<local>") {
            BypassMatcher::LocalName
        } else if let Ok(network) = pattern.parse::<IpNet>() {
            BypassMatcher::Network(network)
        } else {
            match pattern.parse() {
                Ok(pattern) => BypassMatcher::Pattern(pattern),
                Err(error) => {
                    rama_core::telemetry::tracing::debug!(
                        pattern = %raw,
                        error = %error,
                        "ignoring invalid system proxy bypass pattern"
                    );
                    return None;
                }
            }
        };
        Some(Self {
            raw,
            scheme,
            port,
            matcher,
        })
    }

    pub(super) fn raw(&self) -> &str {
        &self.raw
    }

    pub(super) fn matches(
        &self,
        scheme: Option<&Protocol>,
        host: HostRef<'_>,
        port: Option<u16>,
    ) -> bool {
        if self.scheme.as_deref().is_some_and(|expected| {
            !scheme.is_some_and(|actual| actual.as_str().eq_ignore_ascii_case(expected))
        }) {
            return false;
        }
        if self.port.is_some_and(|expected| port != Some(expected)) {
            return false;
        }

        match &self.matcher {
            BypassMatcher::LocalName => is_simple_hostname(host),
            BypassMatcher::Network(network) => {
                host.try_as_ip().is_ok_and(|ip| network.contains(&ip))
            }
            BypassMatcher::Pattern(pattern) => pattern.matches(host),
        }
    }
}

fn split_scheme(pattern: &str) -> (Option<&str>, &str) {
    let Some((scheme, remainder)) = pattern.split_once("://") else {
        return (None, pattern);
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        (None, pattern)
    } else {
        (Some(scheme), remainder)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Host;

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
                BypassRule::compile(pattern)
                    .unwrap()
                    .matches(None, (&parsed).into(), None,),
                expected,
            );
        }
    }

    #[test]
    fn scheme_prefixed_rules_keep_their_scheme_and_port_constraints() {
        let host = "secure.example".parse::<crate::address::Host>().unwrap();
        let rule = BypassRule::compile("HTTPS://secure.example:443").unwrap();

        assert!(rule.matches(Some(&Protocol::HTTPS), (&host).into(), Some(443)));
        assert!(!rule.matches(Some(&Protocol::HTTP), (&host).into(), Some(443)));
        assert!(!rule.matches(Some(&Protocol::HTTPS), (&host).into(), Some(8443)));
    }

    #[test]
    fn typed_exact_and_suffix_rules_use_canonical_host_semantics() {
        let exact = Host::try_from("example.com").unwrap();
        assert!(
            BypassRule::compile("EXAMPLE.COM.")
                .unwrap()
                .matches(None, exact.view(), None,)
        );

        let ipv6 = Host::try_from("2001:db8::1").unwrap();
        assert!(
            BypassRule::compile("[2001:0db8::1]")
                .unwrap()
                .matches(None, ipv6.view(), None,)
        );

        let subdomain = Host::try_from("api.example.com").unwrap();
        assert!(BypassRule::compile(".EXAMPLE.COM.").unwrap().matches(
            None,
            subdomain.view(),
            None,
        ));
        assert!(BypassRule::compile(".not a valid domain").is_none());
    }
}
