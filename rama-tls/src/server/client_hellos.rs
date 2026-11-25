use std::sync::Arc;

use rama_core::extensions::{Extension, Extensions};

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
    /// Separate observations are used when no completed snapshot is published.
    #[must_use]
    pub fn from_extensions(extensions: &'a Extensions) -> Self {
        if let Some(published) = extensions.get_ref::<ServerHandshakeHellos>() {
            return published.hellos();
        }
        let observed = extensions
            .get_ref::<SecureTransport>()
            .and_then(SecureTransport::client_hello);
        let accepted = extensions.get_ref::<ServerEchAccepted>().copied();
        let outer = extensions.get_ref::<EchServerObservation>();
        if let Some(published) = extensions.get_ref::<ServerHandshakeHellos>() {
            return published.hellos();
        }
        Self::new(observed, accepted, outer)
    }

    /// Own this complete view for publication to another observation store.
    fn snapshot(self) -> ServerHandshakeHellos {
        ServerHandshakeHellos {
            ech_accepted: self.ech_accepted,
            wire: self.wire.cloned(),
            ech_inner: self.ech_inner.cloned(),
        }
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

/// The ECH outcome and client hellos of one completed server handshake, published as
/// one value so a concurrent reader never pairs an outcome with another state's hello.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls), scope(connection))]
pub struct ServerHandshakeHellos {
    ech_accepted: Option<bool>,
    wire: Option<ClientHello>,
    ech_inner: Option<ClientHello>,
}

impl ServerHandshakeHellos {
    /// Share a published handshake snapshot, or retain the unreported wire view.
    #[must_use]
    pub fn capture(extensions: &Extensions) -> Arc<Self> {
        extensions
            .get_arc::<Self>()
            .unwrap_or_else(|| Arc::new(ServerClientHellos::from_extensions(extensions).snapshot()))
    }

    /// The hellos as [`ServerClientHellos`] reads them.
    #[must_use]
    pub fn hellos(&self) -> ServerClientHellos<'_> {
        ServerClientHellos {
            wire: self.wire.as_ref(),
            ech_inner: self.ech_inner.as_ref(),
            ech_accepted: self.ech_accepted,
        }
    }
}

/// Publish a completed server handshake's ECH outcome and effective hello on its connection.
///
/// `ech_accepted` is `None` when the server has no ECH keys. With accepted ECH the
/// wire hello already in `extensions` moves to [`EchServerObservation`] and is never
/// left as the effective hello, even when the decrypted inner is unavailable. With
/// rejected ECH and no captured hello, the observed wire hello stays the effective one.
/// The [`ServerHandshakeHellos`] snapshot is inserted before the separate values.
pub fn publish_server_client_hellos(
    extensions: &Extensions,
    ech_accepted: Option<bool>,
    effective: Option<ClientHello>,
) {
    let observed = extensions
        .get_ref::<SecureTransport>()
        .and_then(SecureTransport::client_hello)
        .cloned();
    if ech_accepted == Some(true) {
        extensions.insert(ServerHandshakeHellos {
            ech_accepted,
            wire: observed.clone(),
            ech_inner: effective.clone(),
        });
        if let Some(outer) = observed {
            extensions.insert(EchServerObservation::new(outer));
        }
        extensions.insert(
            effective
                .map(SecureTransport::with_client_hello)
                .unwrap_or_default(),
        );
    } else {
        let keep_observed = ech_accepted == Some(false) && effective.is_none();
        let wire = if keep_observed {
            observed
        } else {
            effective.clone()
        };
        extensions.insert(ServerHandshakeHellos {
            ech_accepted,
            wire,
            ech_inner: None,
        });
        if !keep_observed || !extensions.contains::<SecureTransport>() {
            extensions.insert(
                effective
                    .map(SecureTransport::with_client_hello)
                    .unwrap_or_default(),
            );
        }
    }
    if let Some(accepted) = ech_accepted {
        extensions.insert(ServerEchAccepted::new(accepted));
    }
}

#[cfg(test)]
mod tests {
    use rama_core::extensions::NoExtensionsTransfer;

    use super::*;
    use crate::{CipherSuite, CompressionAlgorithm, ProtocolVersion};

    /// Extensions holding the wire hello observed before the handshake.
    fn with_wire_hello(suite: u16) -> Extensions {
        let extensions = Extensions::new();
        extensions.insert(SecureTransport::with_client_hello(hello(suite)));
        extensions
    }

    #[test]
    fn separately_published_acceptance_uses_the_explicit_outer() {
        let extensions = with_wire_hello(2);
        extensions.insert(ServerEchAccepted::new(true));
        extensions.insert(EchServerObservation::new(hello(3)));
        let hellos = ServerClientHellos::from_extensions(&extensions);
        assert_eq!(hellos.ech_accepted(), Some(true));
        assert_eq!(suite(hellos.ech_inner()), Some(CipherSuite::from(2)));
        assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(3)));
    }

    #[test]
    fn separately_published_acceptance_without_an_outer_withholds_the_wire_view() {
        let extensions = with_wire_hello(2);
        extensions.insert(ServerEchAccepted::new(true));
        let hellos = ServerClientHellos::from_extensions(&extensions);
        assert!(hellos.wire().is_none());
        assert_eq!(suite(hellos.effective()), Some(CipherSuite::from(2)));
    }

    #[test]
    fn capturing_a_completed_handshake_shares_the_published_snapshot() {
        let extensions = with_wire_hello(2);
        publish_server_client_hellos(&extensions, Some(true), Some(hello(1)));
        let published = extensions.get_arc::<ServerHandshakeHellos>().unwrap();
        let captured = ServerHandshakeHellos::capture(&extensions);
        assert!(Arc::ptr_eq(&published, &captured));
    }

    #[test]
    fn published_hellos_follow_the_ech_outcome() {
        // (accepted, effective inner, expected wire, expected effective)
        // A rejection without its own capture keeps the observed wire hello.
        for (accepted, effective, wire, expected) in [
            (true, Some(1), Some(2), Some(1)),
            (true, None, Some(2), None),
            (false, Some(2), Some(2), Some(2)),
            (false, None, Some(2), Some(2)),
        ] {
            let extensions = with_wire_hello(2);
            publish_server_client_hellos(&extensions, Some(accepted), effective.map(hello));
            // The snapshot and the separate values agree.
            let separate = ServerClientHellos::new(
                extensions
                    .get_ref::<SecureTransport>()
                    .and_then(SecureTransport::client_hello),
                extensions.get_ref::<ServerEchAccepted>().copied(),
                extensions.get_ref::<EchServerObservation>(),
            );
            for hellos in [ServerClientHellos::from_extensions(&extensions), separate] {
                assert_eq!(hellos.ech_accepted(), Some(accepted));
                assert_eq!(suite(hellos.wire()), wire.map(CipherSuite::from));
                assert_eq!(suite(hellos.effective()), expected.map(CipherSuite::from));
            }
            assert_eq!(
                extensions.get_ref::<EchServerObservation>().is_some(),
                accepted
            );
        }
        // Without an observed or captured hello there is none to report.
        let extensions = Extensions::new();
        publish_server_client_hellos(&extensions, Some(false), None);
        assert!(
            ServerClientHellos::from_extensions(&extensions)
                .effective()
                .is_none()
        );
    }

    #[test]
    fn a_reader_during_publication_never_takes_the_wire_hello_for_the_inner() {
        // The snapshot precedes the separate values, so the stale wire hello is never the inner.
        let extensions = with_wire_hello(2);
        extensions.insert(ServerHandshakeHellos {
            ech_accepted: Some(true),
            wire: Some(hello(2)),
            ech_inner: None,
        });
        let hellos = ServerClientHellos::from_extensions(&extensions);
        assert_eq!(hellos.ech_accepted(), Some(true));
        assert_eq!(suite(hellos.wire()), Some(CipherSuite::from(2)));
        assert!(hellos.effective().is_none());
    }

    #[test]
    fn servers_without_ech_keys_publish_no_ech_outcome() {
        let extensions = with_wire_hello(2);
        publish_server_client_hellos(&extensions, None, Some(hello(2)));
        assert!(extensions.get_ref::<ServerEchAccepted>().is_none());
        assert!(extensions.get_ref::<EchServerObservation>().is_none());
        assert_eq!(
            suite(ServerClientHellos::from_extensions(&extensions).effective()),
            Some(CipherSuite::from(2))
        );
    }

    #[test]
    fn published_ech_facts_stay_on_their_own_connection() {
        // A connection nested on another one, as a tunnelled endpoint is.
        let tunnel = with_wire_hello(5);
        let connection = tunnel.fork_connection(&NoExtensionsTransfer::new());
        publish_server_client_hellos(&connection, Some(true), Some(hello(1)));
        assert!(connection.get_ref::<EchServerObservation>().is_none());
        assert!(tunnel.get_ref::<ServerEchAccepted>().is_none());
        assert_eq!(
            suite(
                tunnel
                    .get_ref::<SecureTransport>()
                    .and_then(SecureTransport::client_hello)
            ),
            Some(CipherSuite::from(5))
        );

        // A request stream forked from the connection reads the connection's facts.
        let stream = connection.fork();
        let hellos = ServerClientHellos::from_extensions(&stream);
        assert_eq!(hellos.ech_accepted(), Some(true));
        assert!(hellos.wire().is_none());
        assert_eq!(suite(hellos.effective()), Some(CipherSuite::from(1)));
    }

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
        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
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
