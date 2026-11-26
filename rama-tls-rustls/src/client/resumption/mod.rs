use std::sync::Arc;

use rama_core::combinators::Either;
use rama_crypto::platform_verifier::PlatformVerifier;
use rama_tls::client::{
    ServerTrustKey, ServerTrustSnapshot, ServerVerificationScope, TlsServerTrust,
};

use crate::dep::rustls::{
    NamedGroup,
    client::{
        ClientSessionMemoryCache, ClientSessionStore, Tls12ClientSessionValue,
        Tls13ClientSessionValue,
    },
    pki_types::ServerName,
};

/// Sessions of a retained configuration, offered only while its trust generation
/// is current and a reload trigger can still report operating system trust changes.
#[derive(Debug)]
pub(super) struct PlatformSessions {
    trust: TlsServerTrust,
    key: ServerTrustKey,
    platform: Arc<PlatformVerifier>,
    sessions: ClientSessionMemoryCache,
}

impl PlatformSessions {
    pub(super) fn new(
        trust: &TlsServerTrust,
        key: ServerTrustKey,
        platform: Arc<PlatformVerifier>,
    ) -> Self {
        Self {
            trust: trust.clone(),
            key,
            platform,
            sessions: ClientSessionMemoryCache::new(256),
        }
    }

    // Runs inside the handshake: a generation that needs a trust-store read is not current.
    fn current(&self) -> bool {
        ServerTrustSnapshot::read_ready(&self.trust)
            .is_some_and(|snapshot| snapshot.key() == self.key)
            && ServerVerificationScope::allows_resumption::<()>(
                Some(&self.trust),
                &Either::B(self.platform.clone()),
            )
    }
}

impl ClientSessionStore for PlatformSessions {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        self.sessions.set_kx_hint(name, group);
    }

    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        self.sessions.kx_hint(name)
    }

    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.sessions.set_tls12_session(name, value);
    }

    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.current()
            .then(|| self.sessions.tls12_session(name))
            .flatten()
    }

    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.sessions.remove_tls12_session(name);
    }

    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.sessions.insert_tls13_ticket(name, value);
    }

    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.current()
            .then(|| self.sessions.take_tls13_ticket(name))
            .flatten()
    }
}
