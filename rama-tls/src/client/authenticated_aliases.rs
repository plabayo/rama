//! Additional server names authenticated on one established TLS connection.

use rama_core::extensions::Extension;
use rama_net::tls::ServerName;

use super::TlsServerAuthentication;

/// Additional server names the peer certificate of one established connection
/// was verified for, under the same effective trust and pin policy as its primary.
///
/// A connector publishes this on the connection, next to the primary
/// [`TlsServerAuthentication`], only after checking each name against the
/// actual peer certificate. The fact is bound to that primary name.
#[derive(Debug, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls), scope(connection))]
pub struct TlsServerAuthenticatedAliases {
    primary: ServerName,
    aliases: Box<[ServerName]>,
}

impl TlsServerAuthenticatedAliases {
    /// Record `aliases` as verified on the connection authenticated as `primary`.
    ///
    /// This performs no verification itself: the publishing connector does.
    #[must_use]
    pub fn new(primary: ServerName, aliases: impl Into<Box<[ServerName]>>) -> Self {
        Self {
            primary,
            aliases: aliases.into(),
        }
    }

    /// The primary name these aliases were verified against.
    #[must_use]
    pub fn primary(&self) -> &ServerName {
        &self.primary
    }

    /// Whether `name` is the primary or one of the verified aliases.
    #[must_use]
    pub fn covers(&self, name: &ServerName) -> bool {
        &self.primary == name || self.aliases.contains(name)
    }

    /// Whether `name` is covered while `current` still names the bound primary.
    #[must_use]
    pub fn authenticates(&self, current: &TlsServerAuthentication, name: &ServerName) -> bool {
        current.0.as_ref() == Some(&self.primary) && self.covers(name)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rama_net::address::Domain;

    use super::*;

    fn name(name: &'static str) -> ServerName {
        ServerName::from(Domain::from_static(name))
    }

    #[test]
    fn aliases_require_the_current_authenticated_primary() {
        let primary = name("a.example");
        let alias = name("b.example");
        let fact = TlsServerAuthenticatedAliases::new(primary.clone(), vec![alias.clone()]);
        let current = TlsServerAuthentication(Some(primary.clone()));
        assert!(fact.authenticates(&current, &alias));
        assert!(fact.authenticates(&current, &primary));
        assert!(!fact.authenticates(&TlsServerAuthentication(None), &alias));
        assert!(!fact.authenticates(
            &TlsServerAuthentication(Some(name("other.example"))),
            &alias
        ));
        assert!(!fact.authenticates(&current, &name("unknown.example")));
    }

    #[test]
    fn authenticated_aliases_keep_dns_and_address_identities_distinct() {
        let bare = name("192.0.2.1");
        let dotted = name("192.0.2.1.");
        let address = ServerName::from(IpAddr::from([192, 0, 2, 1]));
        let fact = TlsServerAuthenticatedAliases::new(bare.clone(), vec![bare.clone()]);
        assert!(fact.covers(&address));
        assert!(!fact.covers(&dotted));
        assert!(fact.authenticates(&TlsServerAuthentication(Some(address.clone())), &bare));
        assert!(!fact.authenticates(&TlsServerAuthentication(Some(dotted.clone())), &bare));
        assert_ne!(
            fact,
            TlsServerAuthenticatedAliases::new(dotted, vec![address])
        );
    }
}
