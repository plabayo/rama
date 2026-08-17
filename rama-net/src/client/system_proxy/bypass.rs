use rama_core::error::{BoxError, ErrorExt as _};

#[cfg(any(
    test,
    target_os = "android",
    target_os = "windows",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::address::Host;
use crate::{
    Protocol,
    address::{
        HostPattern, HostRef,
        ip::{ipnet::IpNet, parse_ip_net},
    },
};

#[derive(Debug, Clone, Copy)]
pub(super) enum BypassRuleSyntax {
    Rama,
    #[cfg(any(
        test,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    Gnome,
    #[cfg(any(test, target_os = "android", target_os = "windows"))]
    Wildcard,
}

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
    #[cfg(test)]
    pub(super) fn compile(value: impl Into<String>) -> Result<Self, BoxError> {
        Self::compile_with_syntax(value, BypassRuleSyntax::Rama)
    }

    pub(super) fn compile_with_syntax(
        value: impl Into<String>,
        syntax: BypassRuleSyntax,
    ) -> Result<Self, BoxError> {
        let raw = value.into().into_boxed_str();
        let (scheme, pattern) = split_scheme(raw.trim());
        let scheme = scheme.map(|scheme| scheme.to_ascii_lowercase().into_boxed_str());
        let (pattern, port) = split_port(pattern);
        let matcher = if pattern.eq_ignore_ascii_case("<local>") {
            BypassMatcher::LocalName
        } else if let Ok(network) = parse_ip_net(pattern) {
            BypassMatcher::Network(network)
        } else {
            BypassMatcher::Pattern(compile_host_pattern(pattern, syntax).map_err(|error| {
                error
                    .context("parse system proxy bypass pattern")
                    .context_str_field("pattern", raw.as_ref())
            })?)
        };
        Ok(Self {
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

fn compile_host_pattern(pattern: &str, syntax: BypassRuleSyntax) -> Result<HostPattern, BoxError> {
    match syntax {
        BypassRuleSyntax::Rama => pattern.parse(),
        #[cfg(any(
            test,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        BypassRuleSyntax::Gnome => match Host::try_from(pattern) {
            Ok(Host::Name(domain)) => Ok(HostPattern::sub(domain)),
            Ok(_) | Err(_) if pattern.contains('*') => HostPattern::try_glob(pattern.to_owned()),
            Ok(host) => Ok(HostPattern::exact(host)),
            Err(error) => Err(error),
        },
        #[cfg(any(test, target_os = "android", target_os = "windows"))]
        BypassRuleSyntax::Wildcard => {
            if pattern.contains('*') {
                return HostPattern::try_glob(pattern.to_owned());
            }
            if pattern.starts_with('.') {
                return HostPattern::try_glob(format!("*{pattern}"));
            }
            Host::try_from(pattern).map(HostPattern::exact)
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
        BypassRule::compile(".not a valid domain").unwrap_err();
    }

    #[test]
    fn abbreviated_ipv4_networks_match_ip_hosts() {
        let rule = BypassRule::compile("169.254/16").unwrap();
        assert!(rule.matches(None, Host::try_from("169.254.42.7").unwrap().view(), None,));
        assert!(!rule.matches(None, Host::try_from("169.253.42.7").unwrap().view(), None,));
    }

    #[test]
    fn wildcard_prefixed_non_subtree_patterns_fall_back_to_globs() {
        let rule = BypassRule::compile("*.corp*").unwrap();
        assert!(rule.matches(None, Host::try_from("api.corporate").unwrap().view(), None,));
        assert!(!rule.matches(None, Host::try_from("corp.example").unwrap().view(), None,));
    }

    #[test]
    fn gnome_domains_match_the_apex_and_descendants() {
        for pattern in ["example.com", ".example.com", "*.example.com"] {
            let rule = BypassRule::compile_with_syntax(pattern, BypassRuleSyntax::Gnome).unwrap();
            assert!(rule.matches(None, Host::try_from("example.com").unwrap().view(), None));
            assert!(rule.matches(
                None,
                Host::try_from("api.example.com").unwrap().view(),
                None,
            ));
            assert!(!rule.matches(None, Host::try_from("other.test").unwrap().view(), None,));
        }

        let glob = BypassRule::compile_with_syntax("*.corp*", BypassRuleSyntax::Gnome).unwrap();
        assert!(glob.matches(None, Host::try_from("api.corporate").unwrap().view(), None,));
    }

    #[test]
    fn wildcard_platform_domains_do_not_add_the_apex() {
        for pattern in [".example.com", "*.example.com"] {
            let rule =
                BypassRule::compile_with_syntax(pattern, BypassRuleSyntax::Wildcard).unwrap();
            assert!(!rule.matches(None, Host::try_from("example.com").unwrap().view(), None));
            assert!(rule.matches(
                None,
                Host::try_from("api.example.com").unwrap().view(),
                None,
            ));
        }

        let exact =
            BypassRule::compile_with_syntax("example.com", BypassRuleSyntax::Wildcard).unwrap();
        assert!(exact.matches(None, Host::try_from("example.com").unwrap().view(), None));
        assert!(!exact.matches(
            None,
            Host::try_from("api.example.com").unwrap().view(),
            None,
        ));
    }
}
