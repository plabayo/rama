#![cfg(any(feature = "aws-lc", feature = "ring"))]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use rama_core::error::BoxError;
use rama_crypto::pki_types::ServerName;
use rama_tls::client::{ClientHandshake, TlsClientConfig};
use rama_tls_rustls::{
    client::{RustlsClientConfigExt, RustlsTlsConnectorConfig},
    dep::rustls::{
        ClientConfig, ClientConnection, NamedGroup,
        client::{
            ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
            Tls13ClientSessionValue,
        },
    },
};

/// Observe actual session reads by the native handshake engine.
#[derive(Debug)]
struct Store {
    inner: ClientSessionMemoryCache,
    reads: AtomicUsize,
}

impl ClientSessionStore for Store {
    fn set_kx_hint(&self, name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(name, group);
    }

    fn kx_hint(&self, name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(name)
    }

    fn set_tls12_session(&self, name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.inner.set_tls12_session(name, value);
    }

    fn tls12_session(&self, name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.tls12_session(name)
    }

    fn remove_tls12_session(&self, name: &ServerName<'static>) {
        self.inner.remove_tls12_session(name);
    }

    fn insert_tls13_ticket(&self, name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.inner.insert_tls13_ticket(name, value);
    }

    fn take_tls13_ticket(&self, name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.take_tls13_ticket(name)
    }
}

fn first_flight(mode: ClientHandshake, store: Arc<Store>) -> Result<Vec<u8>, BoxError> {
    let config = TlsClientConfig::new()
        .with_client_handshake(mode)
        .with_modify_rustls_config(move |mut native| {
            // An explicit offer remains authoritative over a custom store hook.
            native.resumption = Resumption::store(store.clone());
            Ok(native)
        });
    let native = ClientConfig::try_from(RustlsTlsConnectorConfig::from_extensions(
        config.as_extensions(),
    ))?;
    let mut connection =
        ClientConnection::new(Arc::new(native), ServerName::try_from("example.test")?)?;
    let mut output = Vec::new();
    connection.write_tls(&mut output)?;
    Ok(output)
}

#[test]
fn full_offer_does_not_consult_a_custom_session_store() {
    for mode in [ClientHandshake::Auto, ClientHandshake::Full] {
        let store = Arc::new(Store {
            inner: ClientSessionMemoryCache::new(16),
            reads: AtomicUsize::new(0),
        });
        let output = first_flight(mode, store.clone()).unwrap();
        assert!(!output.is_empty());
        let reads = store.reads.load(Ordering::Relaxed);
        assert_eq!(reads > 0, mode == ClientHandshake::Auto);
    }
}

#[test]
fn unsupported_required_offer_does_not_fall_back_to_an_automatic_offer() {
    let store = Arc::new(Store {
        inner: ClientSessionMemoryCache::new(16),
        reads: AtomicUsize::new(0),
    });
    let error = first_flight(ClientHandshake::Resumed, store.clone()).unwrap_err();
    assert!(error.to_string().contains("required session offers"));
    assert_eq!(store.reads.load(Ordering::Relaxed), 0);
}
