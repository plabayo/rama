use std::{fmt, sync::Arc};

use arc_swap::ArcSwap;
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::Extensions,
};
use rama_net::{
    address::{Host, HostPattern},
    client::ConnectorTarget,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    #[default]
    All,
    Selected,
    None,
}

impl std::str::FromStr for ScopeMode {
    type Err = BoxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "selected" => Ok(Self::Selected),
            "none" => Ok(Self::None),
            _ => Err(BoxError::from_static_str(
                "MITM scope must be all, selected, or none",
            )),
        }
    }
}

impl fmt::Display for ScopeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::All => "all",
            Self::Selected => "selected",
            Self::None => "none",
        })
    }
}

#[derive(Serialize)]
pub struct ScopeSnapshot {
    pub mode: ScopeMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub cli_allow: Vec<String>,
    pub cli_deny: Vec<String>,
}

const MAX_RUNTIME_RULES: usize = 256;
const MAX_RULE_LENGTH: usize = 255;

#[derive(Clone, Default)]
struct RuleSet {
    sources: Arc<[String]>,
    patterns: Arc<[HostPattern]>,
}

impl fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.sources.iter()).finish()
    }
}

impl RuleSet {
    fn try_new(values: &[String], runtime: bool) -> Result<Self, BoxError> {
        if runtime && values.len() > MAX_RUNTIME_RULES {
            return Err(BoxError::from_static_str(
                "too many runtime MITM domain rules",
            ));
        }
        let mut sources = Vec::with_capacity(values.len());
        let mut patterns = Vec::with_capacity(values.len());
        for value in values {
            let value = value.trim();
            if value.is_empty() {
                return Err(BoxError::from_static_str(
                    "MITM domain pattern cannot be empty",
                ));
            }
            if runtime && value.len() > MAX_RULE_LENGTH {
                return Err(BoxError::from_static_str("MITM domain pattern is too long"));
            }
            let pattern = if let Some(host) = value.strip_prefix('=') {
                HostPattern::exact(Host::try_from(host).context("parse exact MITM host")?)
            } else if value.starts_with('.') || value.contains('*') {
                HostPattern::try_new(value.to_owned())?
            } else {
                let host = Host::try_from(value).context("parse MITM domain host")?;
                match host.try_as_domain() {
                    Ok(domain) => HostPattern::sub(domain.into_owned()),
                    Err(_) => HostPattern::exact(host),
                }
            };
            sources.push(value.to_owned());
            patterns.push(pattern);
        }
        Ok(Self {
            sources: sources.into(),
            patterns: patterns.into(),
        })
    }

    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    fn matches(&self, host: &Host) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches(host.view()))
    }
}

#[derive(Debug, Default)]
struct RuntimeRules {
    mode: ScopeMode,
    allow: RuleSet,
    deny: RuleSet,
}

struct MitmPolicyInner {
    cli_allow: RuleSet,
    cli_deny: RuleSet,
    runtime: ArcSwap<RuntimeRules>,
}

impl fmt::Debug for MitmPolicyInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmPolicyInner")
            .field("cli_allow", &self.cli_allow)
            .field("cli_deny", &self.cli_deny)
            .field("runtime", &self.runtime.load())
            .finish()
    }
}

/// Atomically updatable MITM scope shared by the ingress routing stacks and UI.
///
/// CLI rules bound the scope available to browser rules. When both CLI and
/// browser allow lists are non-empty, an observed host must match both; an
/// empty browser list leaves the CLI ceiling unchanged. A match in either deny
/// list always wins. Routing reads are lock-free.
#[derive(Debug, Clone)]
pub struct MitmPolicy(Arc<MitmPolicyInner>);

impl MitmPolicy {
    pub fn try_new(cli_allow: &[String], cli_deny: &[String]) -> Result<Self, BoxError> {
        Ok(Self(Arc::new(MitmPolicyInner {
            cli_allow: RuleSet::try_new(cli_allow, false)?,
            cli_deny: RuleSet::try_new(cli_deny, false)?,
            runtime: ArcSwap::from_pointee(RuntimeRules::default()),
        })))
    }

    #[cfg(test)]
    pub fn update_runtime(&self, allow: &[String], deny: &[String]) -> Result<(), BoxError> {
        self.update_scope(self.0.runtime.load().mode, allow, deny)
    }

    pub fn snapshot(&self) -> ScopeSnapshot {
        let rules = self.0.runtime.load();
        ScopeSnapshot {
            mode: rules.mode,
            allow: rules.allow.sources.to_vec(),
            deny: rules.deny.sources.to_vec(),
            cli_allow: self.0.cli_allow.sources.to_vec(),
            cli_deny: self.0.cli_deny.sources.to_vec(),
        }
    }

    pub fn update_scope(
        &self,
        mode: ScopeMode,
        allow: &[String],
        deny: &[String],
    ) -> Result<(), BoxError> {
        let rules = RuntimeRules {
            mode,
            allow: RuleSet::try_new(allow, true)?,
            deny: RuleSet::try_new(deny, true)?,
        };
        self.0.runtime.store(Arc::new(rules));
        Ok(())
    }

    pub fn should_inspect_host(&self, host: &Host) -> bool {
        let runtime = self.0.runtime.load();
        self.should_inspect_observed_hosts(&runtime, [host])
    }

    /// Decide before protocol peeking. Every target reaches the peeker unless
    /// explicitly denied because TLS SNI can supply another eligible host.
    pub fn should_peek_target(&self, extensions: &Extensions) -> bool {
        extensions
            .get_ref::<ConnectorTarget>()
            .is_none_or(|target| !self.is_denied(&target.0.host))
    }

    /// Decide when peeking did not reveal a more useful domain.
    pub fn should_inspect_target(&self, extensions: &Extensions) -> bool {
        self.should_inspect_target_and_host(extensions, None)
    }

    /// Decide after protocol peeking using every observed identity. A deny on
    /// either the connector target or TLS SNI wins. Otherwise either host can
    /// satisfy the effective allow scope.
    pub fn should_inspect_target_and_host(
        &self,
        extensions: &Extensions,
        host: Option<&Host>,
    ) -> bool {
        let runtime = self.0.runtime.load();
        let target = extensions
            .get_ref::<ConnectorTarget>()
            .map(|target| &target.0.host);
        self.should_inspect_observed_hosts(&runtime, target.into_iter().chain(host))
    }

    pub fn is_denied(&self, host: &Host) -> bool {
        let runtime = self.0.runtime.load();
        self.0.cli_deny.matches(host) || runtime.deny.matches(host)
    }

    fn should_inspect_observed_hosts<'a>(
        &self,
        runtime: &RuntimeRules,
        hosts: impl IntoIterator<Item = &'a Host>,
    ) -> bool {
        if runtime.mode == ScopeMode::None
            || (runtime.mode == ScopeMode::Selected && runtime.allow.is_empty())
        {
            return false;
        }
        let mut observed = false;
        let mut allowed = false;
        for host in hosts {
            observed = true;
            if self.0.cli_deny.matches(host) || runtime.deny.matches(host) {
                return false;
            }
            allowed |= (self.0.cli_allow.is_empty() || self.0.cli_allow.matches(host))
                && (runtime.allow.is_empty() || runtime.allow.matches(host));
        }
        if observed {
            allowed
        } else {
            self.0.cli_allow.is_empty() && runtime.allow.is_empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_core::extensions::Extensions;

    use super::*;

    fn host(value: &str) -> Host {
        Host::try_from(value).unwrap()
    }

    #[test]
    fn plain_domains_include_the_domain_and_label_descendants() {
        let policy = MitmPolicy::try_new(&[], &["example.test".to_owned()]).unwrap();
        assert!(!policy.should_inspect_host(&host("example.test")));
        assert!(!policy.should_inspect_host(&host("api.example.test")));
        assert!(policy.should_inspect_host(&host("notexample.test")));
        MitmPolicy::try_new(&[], &["  ".to_owned()]).unwrap_err();
    }

    #[test]
    fn runtime_allow_can_narrow_but_not_widen_the_cli_allow_ceiling() {
        let policy = MitmPolicy::try_new(&["example.test".to_owned()], &[]).unwrap();
        assert!(policy.should_inspect_host(&host("api.example.test")));
        assert!(!policy.should_inspect_host(&host("other.test")));

        policy
            .update_runtime(
                &["api.example.test".to_owned()],
                &["blocked.example.test".to_owned()],
            )
            .unwrap();
        assert!(policy.should_inspect_host(&host("api.example.test")));
        assert!(!policy.should_inspect_host(&host("www.example.test")));
        assert!(!policy.should_inspect_host(&host("blocked.example.test")));
        assert!(!policy.should_inspect_host(&host("other.test")));

        policy
            .update_runtime(&["other.test".to_owned()], &[])
            .unwrap();
        assert!(!policy.should_inspect_host(&host("other.test")));
        assert!(!policy.should_inspect_host(&host("api.example.test")));

        let runtime_only = MitmPolicy::try_new(&[], &[]).unwrap();
        runtime_only
            .update_runtime(&["other.test".to_owned()], &[])
            .unwrap();
        assert!(runtime_only.should_inspect_host(&host("other.test")));
        assert!(!runtime_only.should_inspect_host(&host("example.test")));
    }

    #[test]
    fn unmatched_targets_reach_sni_peeking_but_unknown_hosts_fail_closed() {
        let policy = MitmPolicy::try_new(&["example.test".to_owned()], &[]).unwrap();
        let extensions = Extensions::new();
        extensions.insert(ConnectorTarget("192.0.2.1:443".parse().unwrap()));
        assert!(policy.should_peek_target(&extensions));
        assert!(!policy.should_inspect_target(&extensions));
        let unmatched = Extensions::new();
        unmatched.insert(ConnectorTarget("other.test:443".parse().unwrap()));
        assert!(policy.should_peek_target(&unmatched));
        assert!(!policy.should_inspect_target(&unmatched));
        let unknown = Extensions::new();
        assert!(policy.should_peek_target(&unknown));
        assert!(!policy.should_inspect_target(&unknown));
    }

    #[test]
    fn runtime_rules_are_validated_before_replacing_the_active_policy() {
        let policy = MitmPolicy::try_new(&[], &[]).unwrap();
        policy
            .update_runtime(&["example.test".to_owned()], &[])
            .unwrap();
        assert!(
            policy
                .update_runtime(&[" ".to_owned()], &["other.test".to_owned()])
                .is_err()
        );
        assert!(policy.should_inspect_host(&host("example.test")));
        assert!(!policy.should_inspect_host(&host("other.test")));
    }

    #[test]
    fn runtime_rule_count_and_length_limits_are_inclusive() {
        let policy = MitmPolicy::try_new(&[], &[]).unwrap();
        let max_rules = vec!["example.test".to_owned(); MAX_RUNTIME_RULES];
        policy.update_runtime(&max_rules, &[]).unwrap();
        let too_many = vec!["example.test".to_owned(); MAX_RUNTIME_RULES + 1];
        assert!(policy.update_runtime(&too_many, &[]).is_err());

        let max_length = "*".repeat(MAX_RULE_LENGTH);
        policy.update_runtime(&[max_length], &[]).unwrap();
        let too_long = "*".repeat(MAX_RULE_LENGTH + 1);
        assert!(policy.update_runtime(&[too_long], &[]).is_err());

        // CLI rules are intentionally bounded by the command line rather than
        // the browser-input limits.
        MitmPolicy::try_new(&max_rules, &[]).unwrap();
    }

    #[test]
    fn leading_dot_patterns_and_unknown_host_defaults_are_explicit() {
        let unrestricted = MitmPolicy::try_new(&[], &[]).unwrap();
        assert!(unrestricted.should_inspect_target(&Extensions::new()));

        let scoped = MitmPolicy::try_new(&[".example.test".to_owned()], &[]).unwrap();
        assert!(scoped.should_inspect_host(&host("api.example.test")));
        assert!(!scoped.should_inspect_host(&host("other.test")));

        let wildcard = MitmPolicy::try_new(&["api-*.example.test".to_owned()], &[]).unwrap();
        assert!(wildcard.should_inspect_host(&host("api-one.example.test")));
        assert!(!wildcard.should_inspect_host(&host("web-one.example.test")));

        let denied_ip = MitmPolicy::try_new(&[], &["192.0.2.1".to_owned()]).unwrap();
        let extensions = Extensions::new();
        extensions.insert(ConnectorTarget("192.0.2.1:443".parse().unwrap()));
        assert!(!denied_ip.should_peek_target(&extensions));
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn selected_empty_and_none_never_inspect_including_unknown_destinations() {
        let policy = MitmPolicy::try_new(&[], &[]).unwrap();
        for mode in [ScopeMode::Selected, ScopeMode::None] {
            policy.update_scope(mode, &[], &[]).unwrap();
            assert!(!policy.should_inspect_target(&Extensions::new()));
            assert!(!policy.should_inspect_host(&Host::try_from("example.test").unwrap()));
        }
        policy
            .update_scope(ScopeMode::Selected, &["=example.test".into()], &[])
            .unwrap();
        assert!(policy.should_inspect_host(&Host::try_from("example.test").unwrap()));
        assert!(!policy.should_inspect_host(&Host::try_from("sub.example.test").unwrap()));
    }
}
