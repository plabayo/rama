use rama_core::error::{BoxError, ErrorExt as _};

#[cfg(any(
    test,
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use rama_core::error::BoxErrorExt as _;

#[cfg(any(
    test,
    target_vendor = "apple",
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

/// Host-pattern dialects used by proxy-configuration providers.
///
/// These dialects differ in two important cases:
///
/// | pattern | Rama | `NO_PROXY` / GLib | KDE | flat glob |
/// |---|---|---|---|
/// | `*` | all hosts | all hosts | unsupported | all hosts |
/// | `example.com` | exact | apex and descendants | apex and descendants | exact |
/// | `*.example.com` | apex and descendants | apex and descendants | unsupported | descendants only |
///
/// Keeping this distinction at the platform boundary prevents a native
/// bypass list from silently gaining or losing the domain apex. KDE's native
/// matcher also accepts raw string suffixes such as `notexample.com` for an
/// `example.com` rule; Rama deliberately retains DNS-label boundaries, as
/// Chromium does, rather than broadening a bypass unexpectedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BypassRuleDialect {
    Rama,
    /// Shell-shared `NO_PROXY` convention used by curl, Go, wget and Python:
    /// a plain domain covers both its apex and descendants.
    NoProxy,
    #[cfg(any(
        test,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    Glib,
    #[cfg(any(
        test,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    Kde,
    #[cfg(any(
        test,
        target_vendor = "apple",
        target_os = "android",
        target_os = "windows"
    ))]
    FlatGlob,
}

impl BypassRuleDialect {
    fn supports_standalone_wildcard(_dialect: Self) -> bool {
        #[cfg(any(
            test,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        if _dialect == Self::Kde {
            return false;
        }
        true
    }
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
    All,
    LocalName,
    Network(IpNet),
    Pattern(HostPattern),
}

impl BypassRule {
    #[cfg(test)]
    pub(super) fn compile(value: impl Into<String>) -> Result<Self, BoxError> {
        Self::compile_with_dialect(value, BypassRuleDialect::Rama)
    }

    pub(super) fn compile_with_dialect(
        value: impl Into<String>,
        dialect: BypassRuleDialect,
    ) -> Result<Self, BoxError> {
        let raw = value.into().into_boxed_str();
        let (scheme, pattern) = split_scheme(raw.trim());
        let scheme = scheme.map(|scheme| scheme.to_ascii_lowercase().into_boxed_str());
        let (pattern, port) = split_port(pattern);
        let matcher = if pattern == "*" && BypassRuleDialect::supports_standalone_wildcard(dialect)
        {
            BypassMatcher::All
        } else if pattern.eq_ignore_ascii_case("<local>") {
            BypassMatcher::LocalName
        } else if let Ok(network) = parse_ip_net(pattern) {
            BypassMatcher::Network(network)
        } else {
            BypassMatcher::Pattern(compile_host_pattern(pattern, dialect).map_err(|error| {
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

    #[cfg(test)]
    pub(super) fn matches(
        &self,
        scheme: Option<&Protocol>,
        host: HostRef<'_>,
        port: Option<u16>,
    ) -> bool {
        let host_text = self.requires_host_text().then(|| host.to_str());
        self.matches_with_host_text(scheme, host, port, host_text.as_deref())
    }

    fn requires_host_text(&self) -> bool {
        matches!(&self.matcher, BypassMatcher::Pattern(pattern) if pattern.is_glob())
    }

    fn matches_with_host_text(
        &self,
        scheme: Option<&Protocol>,
        host: HostRef<'_>,
        port: Option<u16>,
        host_text: Option<&str>,
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
            BypassMatcher::All => true,
            BypassMatcher::LocalName => is_simple_hostname(host),
            BypassMatcher::Network(network) => {
                host.try_as_ip().is_ok_and(|ip| network.contains(&ip))
            }
            BypassMatcher::Pattern(pattern) => pattern.matches_with_text(host, host_text),
        }
    }
}

pub(super) fn matches_any_rule(
    rules: &[BypassRule],
    scheme: Option<&Protocol>,
    host: HostRef<'_>,
    port: Option<u16>,
) -> bool {
    let host_text = rules
        .iter()
        .any(BypassRule::requires_host_text)
        .then(|| host.to_str());
    rules
        .iter()
        .any(|rule| rule.matches_with_host_text(scheme, host, port, host_text.as_deref()))
}

fn compile_host_pattern(
    pattern: &str,
    dialect: BypassRuleDialect,
) -> Result<HostPattern, BoxError> {
    match dialect {
        BypassRuleDialect::Rama => pattern.parse(),
        BypassRuleDialect::NoProxy => match Host::try_from(pattern) {
            Ok(Host::Name(domain)) => Ok(HostPattern::sub(domain)),
            Ok(_) | Err(_) if pattern.contains('*') => HostPattern::try_glob(pattern.to_owned()),
            Ok(host) => Ok(HostPattern::exact(host)),
            Err(error) => Err(error),
        },
        #[cfg(any(
            test,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        BypassRuleDialect::Glib => match Host::try_from(pattern) {
            Ok(Host::Name(domain)) => Ok(HostPattern::sub(domain)),
            Ok(_) | Err(_) if pattern.contains('*') => HostPattern::try_glob(pattern.to_owned()),
            Ok(host) => Ok(HostPattern::exact(host)),
            Err(error) => Err(error),
        },
        #[cfg(any(
            test,
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        BypassRuleDialect::Kde => {
            if pattern.contains(['*', '?']) {
                return Err(BoxError::from_static_str(
                    "KDE proxy exceptions do not support wildcard characters",
                ));
            }
            match Host::try_from(pattern) {
                Ok(Host::Name(domain)) => Ok(HostPattern::sub(domain)),
                Ok(host) => Ok(HostPattern::exact(host)),
                Err(error) => Err(error),
            }
        }
        #[cfg(any(
            test,
            target_vendor = "apple",
            target_os = "android",
            target_os = "windows"
        ))]
        BypassRuleDialect::FlatGlob => {
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
    fn glib_domains_match_the_apex_and_descendants() {
        for pattern in ["example.com", ".example.com", "*.example.com"] {
            let rule = BypassRule::compile_with_dialect(pattern, BypassRuleDialect::Glib).unwrap();
            assert!(rule.matches(None, Host::try_from("example.com").unwrap().view(), None));
            assert!(rule.matches(
                None,
                Host::try_from("api.example.com").unwrap().view(),
                None,
            ));
            assert!(!rule.matches(None, Host::try_from("other.test").unwrap().view(), None,));
        }

        let glob = BypassRule::compile_with_dialect("*.corp*", BypassRuleDialect::Glib).unwrap();
        assert!(glob.matches(None, Host::try_from("api.corporate").unwrap().view(), None,));
    }

    #[test]
    fn flat_glob_platform_domains_do_not_add_the_apex() {
        for pattern in [".example.com", "*.example.com"] {
            let rule =
                BypassRule::compile_with_dialect(pattern, BypassRuleDialect::FlatGlob).unwrap();
            assert!(!rule.matches(None, Host::try_from("example.com").unwrap().view(), None));
            assert!(rule.matches(
                None,
                Host::try_from("api.example.com").unwrap().view(),
                None,
            ));
        }

        let exact =
            BypassRule::compile_with_dialect("example.com", BypassRuleDialect::FlatGlob).unwrap();
        assert!(exact.matches(None, Host::try_from("example.com").unwrap().view(), None));
        assert!(!exact.matches(
            None,
            Host::try_from("api.example.com").unwrap().view(),
            None,
        ));
    }

    #[test]
    fn dialects_keep_their_distinct_apex_and_descendant_outcomes() {
        let apex = Host::try_from("example.com").unwrap();
        let child = Host::try_from("api.example.com").unwrap();
        let grandchild = Host::try_from("v1.api.example.com").unwrap();

        for (dialect, pattern, apex_matches, child_matches) in [
            (BypassRuleDialect::Rama, "example.com", true, false),
            (BypassRuleDialect::Rama, "*.example.com", true, true),
            (BypassRuleDialect::Rama, ".example.com", true, true),
            (BypassRuleDialect::NoProxy, "example.com", true, true),
            (BypassRuleDialect::NoProxy, "*.example.com", true, true),
            (BypassRuleDialect::NoProxy, ".example.com", true, true),
            (BypassRuleDialect::Glib, "example.com", true, true),
            (BypassRuleDialect::Glib, "*.example.com", true, true),
            (BypassRuleDialect::Glib, ".example.com", true, true),
            (BypassRuleDialect::Kde, "example.com", true, true),
            (BypassRuleDialect::Kde, ".example.com", true, true),
            (BypassRuleDialect::FlatGlob, "example.com", true, false),
            (BypassRuleDialect::FlatGlob, "*.example.com", false, true),
            (BypassRuleDialect::FlatGlob, ".example.com", false, true),
        ] {
            let rule = BypassRule::compile_with_dialect(pattern, dialect).unwrap();
            assert_eq!(
                rule.matches(None, apex.view(), None),
                apex_matches,
                "dialect={dialect:?} pattern={pattern:?} apex"
            );
            assert_eq!(
                rule.matches(None, child.view(), None),
                child_matches,
                "dialect={dialect:?} pattern={pattern:?} child"
            );
            assert_eq!(
                rule.matches(None, grandchild.view(), None),
                child_matches,
                "dialect={dialect:?} pattern={pattern:?} grandchild"
            );
        }

        for pattern in ["*", "*.example.com", "api-?.example.com"] {
            BypassRule::compile_with_dialect(pattern, BypassRuleDialect::Kde).unwrap_err();
        }
    }

    #[test]
    fn standalone_wildcard_matches_every_host() {
        let rule = BypassRule::compile("*").unwrap();
        for host in ["example.com", "127.0.0.1", "2001:db8::1"] {
            assert!(rule.matches(None, Host::try_from(host).unwrap().view(), None));
        }
    }
}
