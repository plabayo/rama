//! Additional server names authenticated on one established TLS connection.

use super::TlsServerAuthentication;
use rama_core::extensions::Extension;
use rama_net::address::Host;

/// Additional server names the peer certificate of one established connection
/// was verified for, under the same effective trust and pin policy as its primary.
///
/// A connector publishes this on the connection, next to the primary
/// [`TlsServerAuthentication`], only after checking each name against the
/// actual peer certificate. The fact is bound to that primary name.
#[derive(Debug, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsServerAuthenticatedAliases {
    primary: Host,
    aliases: Box<[Host]>,
}

impl TlsServerAuthenticatedAliases {
    /// Record `aliases` as verified on the connection authenticated as `primary`.
    ///
    /// This performs no verification itself: the publishing connector does.
    #[must_use]
    pub fn new(primary: Host, aliases: impl Into<Box<[Host]>>) -> Self {
        Self {
            primary,
            aliases: aliases.into(),
        }
    }

    /// The primary name these aliases were verified against.
    #[must_use]
    pub fn primary(&self) -> &Host {
        &self.primary
    }

    /// Whether `name` is the primary or one of the verified aliases.
    #[must_use]
    pub fn covers(&self, name: &Host) -> bool {
        &self.primary == name || self.aliases.contains(name)
    }

    /// Whether `name` is covered while `current` still names the bound primary.
    #[must_use]
    pub fn authenticates(&self, current: &TlsServerAuthentication, name: &Host) -> bool {
        current.0.as_ref() == Some(&self.primary) && self.covers(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_require_the_current_authenticated_primary() {
        let primary = Host::from_static("a.example");
        let alias = Host::from_static("b.example");
        let fact = TlsServerAuthenticatedAliases::new(primary.clone(), vec![alias.clone()]);
        let current = TlsServerAuthentication(Some(primary.clone()));
        assert!(fact.authenticates(&current, &alias));
        assert!(fact.authenticates(&current, &primary));
        assert!(!fact.authenticates(&TlsServerAuthentication(None), &alias));
        assert!(!fact.authenticates(
            &TlsServerAuthentication(Some(Host::from_static("other.example"))),
            &alias
        ));
        assert!(!fact.authenticates(&current, &Host::from_static("unknown.example")));
    }
}
