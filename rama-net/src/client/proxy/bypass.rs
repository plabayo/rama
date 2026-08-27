use core::{fmt, net::IpAddr};
use std::sync::Arc;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorExt as _},
    extensions::ExtensionsRef,
};

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
        ip::{IntoCanonicalIpAddr as _, ipnet::IpNet, parse_ip_net},
    },
    input_ext::{AuthorityInputExt, ProtocolInputExt},
};

use super::{ProxyRoute, ProxyRoutes};

/// Host-pattern dialects used by proxy-configuration providers.
///
/// These dialects differ in two important cases:
///
/// | pattern | Rama | `NO_PROXY` / GLib | KDE | flat glob |
/// |---|---|---|---|---|
/// | `*` | all hosts | all hosts | unsupported | all hosts |
/// | `example.com` | exact | apex and descendants | apex and descendants | exact |
/// | `.example.com` | apex and descendants | apex and descendants | apex and descendants | descendants only |
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

/// A compiled set of proxy bypass rules.
///
/// Use [`from_no_proxy`][Self::from_no_proxy] for the conventional
/// comma-separated `NO_PROXY` syntax. Rules are parsed once when this value is
/// created; matching a request does not parse or allocate per rule.
#[derive(Debug, Clone, Default)]
pub struct BypassRules {
    rules: Arc<[BypassRule]>,
}

impl BypassRules {
    /// Parse a comma-separated bypass list using conventional `NO_PROXY`
    /// semantics.
    ///
    /// A plain domain such as `example.com` matches both the apex and its
    /// descendants. Leading-dot and `*.` forms have the same subtree behavior.
    /// Rama additionally accepts arbitrary host globs, a standalone `*`, IP
    /// addresses, CIDR networks, optional schemes, and optional ports.
    pub fn from_no_proxy(value: impl AsRef<str>) -> Result<Self, BoxError> {
        let rules = value
            .as_ref()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| BypassRule::compile_with_dialect(value, BypassRuleDialect::NoProxy))
            .collect::<Result<Arc<[_]>, _>>()?;
        Ok(Self { rules })
    }

    /// Return `true` when no rules are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub(super) fn from_compiled(rules: impl Into<Arc<[BypassRule]>>) -> Self {
        Self {
            rules: rules.into(),
        }
    }

    pub(super) fn matches_input<I>(&self, input: &I) -> bool
    where
        I: AuthorityInputExt + ProtocolInputExt,
    {
        let Some(authority) = input.authority() else {
            return false;
        };
        let protocol = input.protocol().cloned().unwrap_or_else(|| {
            if authority.port_u16() == Some(Protocol::HTTPS_DEFAULT_PORT) {
                Protocol::HTTPS
            } else {
                Protocol::HTTP
            }
        });
        matches_any_rule(
            &self.rules,
            Some(&protocol),
            authority.host.view(),
            authority.port_u16().or_else(|| protocol.default_port()),
        )
    }
}

/// Apply precompiled [`BypassRules`] to a service input.
///
/// A matching input receives [`ProxyRoute::Direct`]. Existing route decisions
/// are preserved unless [`overwrite`][Self::overwrite] is enabled. Place this
/// layer before explicit, environment, and system proxy layers to give bypass
/// rules priority.
#[derive(Debug, Clone, Default)]
pub struct ProxyBypassLayer {
    rules: BypassRules,
    overwrite: bool,
}

impl ProxyBypassLayer {
    /// Create a layer from compiled rules.
    #[must_use]
    pub fn new(rules: BypassRules) -> Self {
        Self {
            rules,
            overwrite: false,
        }
    }

    /// Replace an existing [`ProxyRoute`] or [`ProxyRoutes`] decision when a
    /// rule matches.
    #[must_use]
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }
}

impl<S> Layer<S> for ProxyBypassLayer {
    type Service = ProxyBypassService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyBypassService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyBypassService { inner, layer: self }
    }
}

/// Service produced by [`ProxyBypassLayer`].
#[derive(Clone)]
pub struct ProxyBypassService<S> {
    inner: S,
    layer: ProxyBypassLayer,
}

impl<S: fmt::Debug> fmt::Debug for ProxyBypassService<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyBypassService")
            .field("inner", &self.inner)
            .field("layer", &self.layer)
            .finish()
    }
}

impl<S, Input> Service<Input> for ProxyBypassService<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let is_routed = input.extensions().contains::<ProxyRoute>()
            || input.extensions().contains::<ProxyRoutes>();
        if (self.layer.overwrite || !is_routed) && self.layer.rules.matches_input(&input) {
            input.extensions().insert(ProxyRoute::Direct);
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
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
    pub(super) fn compile(value: impl Into<Box<str>>) -> Result<Self, BoxError> {
        Self::compile_with_dialect(value, BypassRuleDialect::Rama)
    }

    pub(super) fn compile_with_dialect(
        value: impl Into<Box<str>>,
        dialect: BypassRuleDialect,
    ) -> Result<Self, BoxError> {
        let mut raw = value.into();
        if raw.len() != raw.trim().len() {
            raw = raw.trim().into();
        }
        let (scheme, pattern) = split_scheme(raw.trim());
        let scheme = scheme.map(|scheme| scheme.to_ascii_lowercase().into_boxed_str());
        let (pattern, port) = split_port(pattern);
        let matcher = if pattern == "*" && BypassRuleDialect::supports_standalone_wildcard(dialect)
        {
            BypassMatcher::All
        } else if pattern.eq_ignore_ascii_case("<local>") {
            BypassMatcher::LocalName
        } else if let Ok(network) = parse_ip_net(pattern) {
            BypassMatcher::Network(canonical_network(network))
        } else if let Ok(address) = pattern
            .strip_prefix('[')
            .and_then(|address| address.strip_suffix(']'))
            .unwrap_or(pattern)
            .parse::<IpAddr>()
        {
            BypassMatcher::Network(address.into_canonical_ip_addr().into())
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
            BypassMatcher::Network(network) => host
                .try_as_ip()
                .is_ok_and(|ip| network.contains(&ip.into_canonical_ip_addr())),
            BypassMatcher::Pattern(pattern) => pattern.matches_with_text(host, host_text),
        }
    }
}

fn canonical_network(network: IpNet) -> IpNet {
    let IpNet::V6(network) = network else {
        return network;
    };
    let prefix = network.prefix_len();
    let Some(address) = network.network().to_ipv4_mapped() else {
        return IpNet::V6(network);
    };
    let Some(prefix) = prefix.checked_sub(96) else {
        return IpNet::V6(network);
    };
    crate::address::ip::ipnet::Ipv4Net::new(address, prefix)
        .map(IpNet::V4)
        .unwrap_or(IpNet::V6(network))
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
    use crate::{address::Host, client::ConnectRequest};
    use rama_core::service::service_fn;

    #[test]
    fn boxed_rule_text_is_reused_as_snapshot_storage() {
        let raw = Box::<str>::from("example.com");
        let address = raw.as_ptr();
        let rule = BypassRule::compile(raw).unwrap();

        assert!(core::ptr::eq(address, rule.raw.as_ptr()));
    }

    #[test]
    fn bypass_rule_text_is_trimmed_once_when_compiled() {
        let rule = BypassRule::compile("  example.com\t").unwrap();
        assert_eq!(rule.raw(), "example.com");
    }

    #[tokio::test]
    async fn direct_bypass_layer_routes_connector_inputs_without_environment_indirection() {
        let layer = ProxyBypassLayer::new(
            BypassRules::from_no_proxy("example.com,https://secure.test:443").unwrap(),
        );
        let service = layer.into_layer(service_fn(|input: ConnectRequest| async move {
            Ok::<_, BoxError>(input.extensions.get_ref::<ProxyRoute>().cloned())
        }));

        let bypassed = ConnectRequest::new("api.example.com:8443".parse().unwrap())
            .with_application_protocol(Protocol::HTTP);
        assert_eq!(
            service.serve(bypassed).await.unwrap(),
            Some(ProxyRoute::Direct)
        );

        let unmatched = ConnectRequest::new("secure.test:8443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);
        assert_eq!(service.serve(unmatched).await.unwrap(), None);
    }

    #[tokio::test]
    async fn direct_bypass_layer_infers_https_for_the_default_tls_port() {
        let service =
            ProxyBypassLayer::new(BypassRules::from_no_proxy("https://secure.test:443").unwrap())
                .into_layer(service_fn(|input: ConnectRequest| async move {
                    Ok::<_, BoxError>(input.extensions.get_ref::<ProxyRoute>().cloned())
                }));

        let input = ConnectRequest::new("secure.test:443".parse().unwrap());
        assert_eq!(
            service.serve(input).await.unwrap(),
            Some(ProxyRoute::Direct)
        );
    }

    #[tokio::test]
    async fn direct_bypass_layer_preserves_existing_route_collections() {
        let layer = ProxyBypassLayer::new(BypassRules::from_no_proxy("example.com").unwrap());
        assert!(format!("{:?}", layer.layer(())).contains("ProxyBypassService"));

        let service = layer.into_layer(service_fn(|input: ConnectRequest| async move {
            Ok::<_, BoxError>(input.extensions.get_ref::<ProxyRoute>().cloned())
        }));
        let input = ConnectRequest::new("example.com:80".parse().unwrap());
        input
            .extensions
            .insert(ProxyRoutes::new([ProxyRoute::Direct]));

        assert_eq!(service.serve(input).await.unwrap(), None);
    }

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
    fn ipv4_networks_match_ipv4_mapped_ipv6_hosts() {
        for (network, host, expected) in [
            ("10.0.0.0/8", "::ffff:10.42.1.9", true),
            ("10.0.0.0/8", "::ffff:11.42.1.9", false),
            ("0.0.0.0/0", "::ffff:203.0.113.9", true),
            ("192.0.2.9/32", "::ffff:192.0.2.9", true),
            ("192.0.2.9/32", "::ffff:192.0.2.10", false),
        ] {
            let rule = BypassRule::compile(network).unwrap();
            assert_eq!(
                rule.matches(None, Host::try_from(host).unwrap().view(), None),
                expected,
                "network={network} host={host}"
            );
        }

        let ipv6 = BypassRule::compile("2001:db8::/32").unwrap();
        assert!(ipv6.matches(None, Host::try_from("2001:db8::1").unwrap().view(), None));
        assert!(!ipv6.matches(
            None,
            Host::try_from("::ffff:192.0.2.9").unwrap().view(),
            None
        ));

        let mapped = BypassRule::compile("::ffff:10.0.0.0/104").unwrap();
        assert!(mapped.matches(None, Host::try_from("10.42.1.9").unwrap().view(), None));
        assert!(!mapped.matches(None, Host::try_from("11.42.1.9").unwrap().view(), None));
    }

    #[test]
    fn exact_ip_rules_use_canonical_network_semantics() {
        let exact = BypassRule::compile("192.0.2.9").unwrap();
        assert!(exact.matches(
            None,
            Host::try_from("::ffff:192.0.2.9").unwrap().view(),
            None,
        ));
        assert!(!exact.matches(
            None,
            Host::try_from("::ffff:192.0.2.10").unwrap().view(),
            None,
        ));

        let bracketed = BypassRule::compile("[::1]").unwrap();
        assert!(bracketed.matches(None, Host::try_from("::1").unwrap().view(), None));
        assert!(!bracketed.matches(None, Host::try_from("::2").unwrap().view(), None));
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
