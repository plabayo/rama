//! Requirements and observations shared across a connection attempt.

use super::{ConnectionError, ConnectionErrorKind};
use crate::address::Host;
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};
use rama_utils::macros::generate_set_and_with;

/// Whether an establishment result describes a connector's fixed policy or a
/// request override. Publish this on established connections or classified
/// errors so discovery and failure caches can scope availability updates correctly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Extension)]
#[extension(tags(net))]
pub enum ConnectionPolicyScope {
    /// The connector did not classify its policy. Do not share policy failures.
    #[default]
    Unknown,
    /// The connector's fixed policy, shared by requests without overrides.
    Connector,
    /// Request-specific policy; its success or rejection says nothing about
    /// whether the same endpoint works with the connector's fixed policy.
    Request,
}

/// Requirements and observations for one connection attempt, shared with address
/// races and outer deadlines through request extensions.
///
/// An origin connector checks its effective policy before authentication using
/// [`Self::check_policy`]. Proxy/tunnel handshakes must not report as the origin.
/// The check is preflight only: the caller must still verify the authenticated
/// identity on the established connection, including pool hits.
#[derive(Debug, Default, Extension)]
#[extension(tags(net))]
pub struct ConnectionAttempt {
    authenticated_peer: Option<Host>,
    observations: Mutex<Observations>,
}

#[derive(Debug, Default)]
struct Observations {
    failure: Option<ConnectionErrorKind>,
    policy_scope: ConnectionPolicyScope,
}

impl ConnectionAttempt {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Require this peer's authenticated identity, independently of the dial target.
        pub fn authenticated_peer(mut self, peer: Host) -> Self {
            self.authenticated_peer = Some(peer);
            self
        }
    }

    /// Report the effective policy and reject an attempt that cannot authenticate
    /// its required peer. This local unavailability permits another endpoint;
    /// it is not evidence that this endpoint or its proxy route is broken.
    pub fn check_policy(
        &self,
        scope: ConnectionPolicyScope,
        authenticated_peer: Option<&Host>,
    ) -> Result<(), ConnectionError> {
        let mut observations = self.observations.lock();
        if observations.policy_scope != ConnectionPolicyScope::Request {
            observations.policy_scope = scope;
        }
        drop(observations);
        if self
            .authenticated_peer
            .as_ref()
            .is_some_and(|required| authenticated_peer != Some(required))
        {
            return Err(ConnectionError::local(
                BoxError::from_static_str(
                    "connector policy does not authenticate the required peer",
                ),
                ConnectionErrorKind::Unavailable,
            ));
        }
        Ok(())
    }

    /// Prevent request-specific DNS, routing or transport configuration from
    /// updating shared endpoint health. Later TLS classification cannot erase
    /// this restriction; all components participate in the same attempt.
    pub fn restrict_to_request_policy(&self) {
        self.observations.lock().policy_scope = ConnectionPolicyScope::Request;
    }

    /// Policy used by this attempt. Unknown is deliberately conservative for
    /// custom connectors that do not report policy scope.
    pub fn policy_scope(&self) -> ConnectionPolicyScope {
        self.observations.lock().policy_scope
    }

    /// Preserve an authentication failure across address racing and cancellation.
    pub fn reject(&self) {
        self.reject_with_kind(ConnectionErrorKind::Authentication);
    }

    /// Preserve terminal failures; authentication takes precedence regardless of
    /// address completion order. A timeout must not erase an earlier rejection.
    pub fn reject_with_kind(&self, kind: ConnectionErrorKind) {
        let mut observations = self.observations.lock();
        if kind == ConnectionErrorKind::Authentication || observations.failure.is_none() {
            observations.failure = Some(kind);
        }
    }

    /// Strongest terminal failure observed during this attempt.
    pub fn failure_kind(&self) -> Option<ConnectionErrorKind> {
        self.observations.lock().failure
    }

    #[must_use]
    pub fn failed(&self) -> bool {
        self.failure_kind().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ConnectionErrorDomain;

    #[test]
    fn peer_requirement_preserves_policy_scope_without_claiming_a_remote_failure() {
        let peer = Host::from_static("origin.example");
        let attempt = ConnectionAttempt::new().with_authenticated_peer(peer.clone());
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Unknown);
        for scope in [
            ConnectionPolicyScope::Connector,
            ConnectionPolicyScope::Request,
        ] {
            for identity in [None, Some(&Host::EXAMPLE_NAME)] {
                let error = attempt.check_policy(scope, identity).unwrap_err();
                assert_eq!(error.domain(), ConnectionErrorDomain::Local);
                assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
                assert_eq!(attempt.policy_scope(), scope);
                assert!(!attempt.failed());
            }
            attempt.check_policy(scope, Some(&peer)).unwrap();
        }
        attempt
            .check_policy(
                ConnectionPolicyScope::Connector,
                Some(&Host::from_static("ORIGIN.Example")),
            )
            .unwrap();
    }

    #[test]
    fn request_network_policy_survives_later_tls_classification() {
        let attempt = ConnectionAttempt::new();
        attempt.restrict_to_request_policy();
        attempt
            .check_policy(ConnectionPolicyScope::Connector, None)
            .unwrap();
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
    }

    #[test]
    fn policy_reporting_does_not_erase_an_address_failure() {
        let attempt = ConnectionAttempt::new();
        attempt.reject();
        attempt
            .check_policy(ConnectionPolicyScope::Request, None)
            .unwrap();
        attempt.reject_with_kind(ConnectionErrorKind::Protocol);
        assert_eq!(
            attempt.failure_kind(),
            Some(ConnectionErrorKind::Authentication)
        );
        assert_eq!(attempt.policy_scope(), ConnectionPolicyScope::Request);
    }
}
