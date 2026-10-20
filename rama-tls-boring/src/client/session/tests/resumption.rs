use std::ptr;

use super::*;

#[tokio::test]
async fn sessions_resume_only_when_opted_in() {
    for version in VERSIONS {
        let server = Server::new(version);
        let disabled = connector(&server, None);
        for _ in 0..3 {
            assert_eq!(
                connect(&disabled, &server, "a.test", no_overrides).await,
                FULL
            );
        }
        let enabled = connector(&server, Some(cache()));
        assert_eq!(
            connect(&enabled, &server, "a.test", no_overrides).await,
            FULL
        );
        for _ in 0..3 {
            let handshake = connect(&enabled, &server, "a.test", no_overrides).await;
            assert_eq!(handshake, RESUMED, "{version:?}");
        }
    }
}

#[tokio::test]
async fn sessions_stay_with_their_server_identity() {
    for version in VERSIONS {
        let server = Server::new(version);
        let connector = connector(&server, Some(cache()));
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "b.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(
            connect(&connector, &server, "b.test", no_overrides).await,
            RESUMED
        );
    }
}

#[tokio::test]
async fn sessions_stay_with_their_connector() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = cache();
        let first = connector(&server, Some(store.clone()));
        let second = connector(&server, Some(store));
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        // A shared store does not make another connector's sessions resumable.
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&first.clone(), &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            RESUMED
        );
    }
}

#[tokio::test]
async fn sessions_stay_with_their_security_policy_across_wire_variants() {
    let verify_disabled = |extensions: &Extensions| {
        extensions.insert(TlsServerVerify(ServerVerifyMode::Disable));
    };
    let http2 = |extensions: &Extensions| {
        extensions.insert(TlsAlpn::http_2());
    };
    for version in VERSIONS {
        let server = Server::new(version);
        let connector = connector(&server, Some(cache()));
        // An unverified session never resumes a verified handshake, nor the reverse.
        assert_eq!(
            connect(&connector, &server, "a.test", verify_disabled).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            FULL
        );
        // Another ALPN is a wire variant of the same policy.
        assert_eq!(connect(&connector, &server, "a.test", http2).await, RESUMED);
        assert_eq!(
            connect(&connector, &server, "a.test", verify_disabled).await,
            RESUMED
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(connect(&connector, &server, "a.test", http2).await, RESUMED);
    }
}

/// Hands out every session it holds, whatever key it is asked for.
#[derive(Default)]
struct PromiscuousStore(Mutex<Vec<TlsClientSession>>);

impl TlsClientSessionStore for PromiscuousStore {
    fn put(&self, session: TlsClientSession) {
        self.0.lock().push(session);
    }

    fn take(&self, _: &TlsClientSessionKey) -> Option<TlsClientSession> {
        self.0.lock().pop()
    }
}

#[tokio::test]
async fn a_store_cannot_move_sessions_across_keys() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = Arc::new(PromiscuousStore::default());
        let first = connector(&server, Some(store.clone()));
        let second = connector(&server, Some(store.clone()));
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        assert!(!store.0.lock().is_empty(), "positive control");
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            FULL
        );
        store.0.lock().clear();
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        assert!(!store.0.lock().is_empty(), "positive control");
        assert_eq!(connect(&first, &server, "b.test", no_overrides).await, FULL);
    }
}

#[tokio::test]
async fn tls12_sessions_are_reused_and_tls13_tickets_offered_once() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = Arc::new(RecordingStore::default());
        let connector = connector(&server, Some(store.clone()));
        connect(&connector, &server, "a.test", no_overrides).await;
        store.put.lock().clear();
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        let taken = store.taken.lock().pop().unwrap();
        let put_back = store
            .put
            .lock()
            .iter()
            .any(|session| ptr::eq(session.session(), taken.session()));
        assert_eq!(put_back, version == SslVersion::TLS1_2, "{version:?}");
        assert_eq!(taken.is_single_use(), version == SslVersion::TLS1_3);
        assert_eq!(taken.key().server(), &Host::from_static("a.test"));
    }
}
