use rama_core::extensions::Extensions;

use crate::{
    SecureTransport,
    client::ClientHello,
    server::{EchServerObservation, ServerEchAccepted},
};

/// Client hellos of one completed server handshake. With accepted ECH the
/// wire carries the outer hello while the handshake used the decrypted inner.
#[derive(Debug, Clone, Copy)]
pub struct ServerClientHellos<'a> {
    wire: Option<&'a ClientHello>,
    ech_inner: Option<&'a ClientHello>,
    ech_accepted: Option<bool>,
}

impl<'a> ServerClientHellos<'a> {
    /// Pair the handshake's effective hello with the server's ECH observations.
    #[must_use]
    pub fn new(
        effective: Option<&'a ClientHello>,
        ech_accepted: Option<ServerEchAccepted>,
        ech_outer: Option<&'a EchServerObservation>,
    ) -> Self {
        let ech_accepted = ech_accepted.map(|accepted| accepted.0);
        if ech_accepted == Some(true) {
            Self {
                wire: ech_outer.map(|observation| &observation.outer),
                ech_inner: effective,
                ech_accepted,
            }
        } else {
            Self {
                wire: effective,
                ech_inner: None,
                ech_accepted,
            }
        }
    }

    /// Read the hellos a server handshake stored in its connection extensions.
    #[must_use]
    pub fn from_extensions(extensions: &'a Extensions) -> Self {
        Self::new(
            extensions
                .get_ref::<SecureTransport>()
                .and_then(SecureTransport::client_hello),
            extensions.get_ref::<ServerEchAccepted>().copied(),
            extensions.get_ref::<EchServerObservation>(),
        )
    }

    /// The hello as sent on the wire: the ECH outer when ECH was accepted.
    #[must_use]
    pub fn wire(&self) -> Option<&'a ClientHello> {
        self.wire
    }

    /// The decrypted inner hello, present only when ECH was accepted.
    #[must_use]
    pub fn ech_inner(&self) -> Option<&'a ClientHello> {
        self.ech_inner
    }

    /// The hello the handshake used: the ECH inner when accepted, else the wire hello.
    #[must_use]
    pub fn effective(&self) -> Option<&'a ClientHello> {
        if self.ech_accepted == Some(true) {
            self.ech_inner
        } else {
            self.wire
        }
    }

    /// ECH acceptance as reported by the server, `None` when it reported none.
    #[must_use]
    pub fn ech_accepted(&self) -> Option<bool> {
        self.ech_accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CipherSuite, CompressionAlgorithm, ProtocolVersion};

    fn hello(suite: u16) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::from(suite)],
            vec![CompressionAlgorithm::from(0)],
            vec![],
        )
    }

    fn suite(hello: Option<&ClientHello>) -> Option<CipherSuite> {
        hello.map(|hello| hello.cipher_suites()[0])
    }

    #[test]
    fn accepted_ech_splits_wire_outer_from_effective_inner() {
        let extensions = Extensions::new();
        extensions.insert(SecureTransport::with_client_hello(hello(1)));
        extensions.insert(ServerEchAccepted::new(true));
        extensions.insert(EchServerObservation::new(hello(2)));
        let hellos = ServerClientHellos::from_extensions(&extensions);
        assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(2)));
        assert_eq!(suite(hellos.ech_inner()), Some(CipherSuite::from(1)));
        assert_eq!(suite(hellos.effective()), Some(CipherSuite::from(1)));
        assert_eq!(hellos.ech_accepted(), Some(true));
    }

    #[test]
    fn nested_handshake_does_not_inherit_outer_ech_observations() {
        let proxy = Extensions::new();
        proxy.insert(ServerEchAccepted::new(true));
        proxy.insert(EchServerObservation::new(hello(2)));
        let origin = proxy.fork_nested_connection(&rama_core::extensions::NoConnectionTransfer);
        origin.insert(SecureTransport::with_client_hello(hello(3)));

        let hellos = ServerClientHellos::from_extensions(&origin);
        assert_eq!(hellos.ech_accepted(), None);
        assert!(origin.get_ref::<EchServerObservation>().is_none());
        assert!(hellos.ech_inner().is_none());
        assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(3)));
    }

    #[test]
    fn accepted_ech_without_outer_keeps_the_inner_effective() {
        let inner = hello(1);
        let hellos =
            ServerClientHellos::new(Some(&inner), Some(ServerEchAccepted::new(true)), None);
        assert!(hellos.wire().is_none());
        assert_eq!(suite(hellos.effective()), Some(CipherSuite::from(1)));
    }

    #[test]
    fn rejected_or_unreported_ech_uses_the_wire_hello() {
        let wire = hello(1);
        let outer = EchServerObservation::new(hello(2));
        for accepted in [None, Some(ServerEchAccepted::new(false))] {
            let hellos = ServerClientHellos::new(Some(&wire), accepted, Some(&outer));
            assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(1)));
            assert_eq!(suite(hellos.effective()), Some(CipherSuite::from(1)));
            assert!(hellos.ech_inner().is_none());
            assert_eq!(hellos.ech_accepted(), accepted.map(|accepted| accepted.0));
        }
    }

    #[test]
    fn accepted_ech_without_inner_has_no_effective_hello() {
        let outer = EchServerObservation::new(hello(2));
        let hellos =
            ServerClientHellos::new(None, Some(ServerEchAccepted::new(true)), Some(&outer));
        assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(2)));
        assert!(hellos.effective().is_none());
    }
}
